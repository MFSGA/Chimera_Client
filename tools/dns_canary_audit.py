#!/usr/bin/env python3
"""Offline, fail-closed audit of *pre-recorded* macOS DNS canary tcpdump text.

This tool never opens a socket, invokes tcpdump/scutil, or changes OS settings.
It only interprets the supplied packet logs. Its strongest negative conclusion
is scoped to those logs; it never proves system-wide DNS leak freedom.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
MAX_CAPTURE_BYTES = 128 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_CANARY_EVENTS = 5000

PACKET = re.compile(
    r"^(?P<timestamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?|"
    r"\d\d:\d\d:\d\d(?:\.\d+)?)\s+"
    r"(?P<family>IP6?)\s+(?P<src>\S+)\s+>\s+(?P<dst>\S+):\s*"
    r"(?P<details>.*)$"
)
QUESTION = re.compile(
    r"(?<![A-Za-z0-9_])(?P<qtype>[A-Za-z][A-Za-z0-9]{0,15})\?"
    r"\s+(?P<qname>[A-Za-z0-9_.-]+)(?=\s|$)"
)
PACKET_PREFIX = re.compile(
    r"^(?:\d{4}-\d\d-\d\d\s+)?\d\d:\d\d:\d\d(?:\.\d+)?\s+IP6?\b"
)
INTERFACE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,31}$")
LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
KNOWN_MANIFEST_FIELDS = {
    "schema_version", "case_id", "canary_qname", "captures",
    "expected_physical_interfaces", "expected_tun_interfaces",
    "resolver_snapshot", "resolver_snapshot_recorded_at_utc",
}


class AuditError(ValueError):
    """Invalid audit evidence or manifest: no result should be trusted."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def normalize_canary(value: Any) -> str:
    if not isinstance(value, str):
        raise AuditError("canary_qname must be an ASCII DNS name")
    name = value.rstrip(".").lower()
    if not name or len(name) > 253 or "." not in name:
        raise AuditError("canary_qname must be a full, non-root DNS name")
    try:
        name.encode("ascii")
    except UnicodeEncodeError as error:
        raise AuditError("canary_qname must be ASCII/IDNA-normalized") from error
    if any(not LABEL.fullmatch(part) for part in name.split(".")):
        raise AuditError("canary_qname contains an invalid DNS label")
    return name


def evidence_path(folder: Path, user_path: Any) -> Path:
    if not isinstance(user_path, str) or not user_path:
        raise AuditError("capture/snapshot path must be a nonempty relative path")
    relative = Path(user_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise AuditError("capture/snapshot paths must stay inside the manifest folder")
    path = (folder / relative).resolve()
    if not path.is_relative_to(folder.resolve()):
        raise AuditError("capture/snapshot symlink leaves the manifest folder")
    if not path.is_file():
        raise AuditError("capture/snapshot file does not exist")
    if path.stat().st_size > MAX_CAPTURE_BYTES:
        raise AuditError("capture exceeds 128 MiB; split it into smaller files")
    return path


def port_53_destination(token: str) -> str | None:
    """tcpdump -n encodes a UDP/TCP port after the final dot, even for IPv6."""
    host, sep, port = token.rpartition(".")
    if not sep or port != "53":
        return None
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return None
    return host


def parse_packet(line: str, canary: str, include_endpoints: bool) -> dict[str, str] | None:
    match = PACKET.match(line.strip())
    if match is None:
        return None
    destination = port_53_destination(match["dst"])
    if destination is None:
        return None
    question = QUESTION.search(match["details"])
    if question is None or question["qname"].rstrip(".").lower() != canary:
        return None
    payload = match["details"]
    transport = "tcp" if "Flags [" in payload else "udp"
    result = {
        "timestamp_local": match["timestamp"],  # supplied logs do not carry timezone
        "ip_family": "ipv6" if match["family"] == "IP6" else "ipv4",
        "transport": transport,
        "qtype": question["qtype"].upper(),
        "qname": canary,
        "packet_line_sha256": hashlib.sha256(line.encode("utf-8")).hexdigest(),
    }
    if include_endpoints:
        result["source_endpoint"] = match["src"]
        result["destination_endpoint"] = match["dst"]
    return result


def expected_interfaces(manifest: dict[str, Any], key: str) -> list[str]:
    raw = manifest.get(key)
    if not isinstance(raw, list) or not raw:
        raise AuditError(f"{key} must be a nonempty array of interface names")
    if any(not isinstance(x, str) or not INTERFACE.fullmatch(x) for x in raw):
        raise AuditError(f"{key} contains an invalid interface")
    if len(set(raw)) != len(raw):
        raise AuditError(f"{key} contains duplicate interfaces")
    return raw


def _load_manifest(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        raise AuditError("manifest exceeds 256 KiB; reject oversized evidence inventory")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AuditError("cannot read valid JSON manifest") from error
    if not isinstance(manifest, dict) or manifest.get("schema_version") != SCHEMA_VERSION:
        raise AuditError("manifest schema_version must be 1")
    unknown = set(manifest) - KNOWN_MANIFEST_FIELDS
    if unknown:
        raise AuditError(f"unknown manifest fields: {', '.join(sorted(unknown))}")
    case = manifest.get("case_id")
    if not isinstance(case, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", case):
        raise AuditError("case_id must be 1-64 alphanumeric/underscore/hyphen characters")
    return manifest


def parse_operator_window(spec: dict[str, Any]) -> tuple[datetime, datetime] | None:
    """Parse operator-declared (not independently attested) capture times."""
    start_raw, end_raw = spec.get("started_at_utc"), spec.get("ended_at_utc")
    if start_raw is None and end_raw is None:
        return None
    if start_raw is None or end_raw is None:
        raise AuditError("capture window must include both start and end")

    def timestamp(value: Any) -> datetime:
        if not isinstance(value, str):
            raise AuditError("capture window timestamps must be strings")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise AuditError("invalid ISO-8601 capture window timestamp") from error
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise AuditError("capture windows require timezone-aware ISO-8601 timestamps")
        return parsed.astimezone(timezone.utc)

    start, end = timestamp(start_raw), timestamp(end_raw)
    if start >= end:
        raise AuditError("capture window start must be before end")
    return start, end


def parse_packet_utc_offset(raw: Any) -> timezone | None:
    """An operator-supplied fixed offset for tcpdump -tttt local timestamps."""
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise AuditError("packet_time_utc_offset must be a signed HH:MM offset")
    match = re.fullmatch(r"([+-])(\d{2}):(\d{2})", raw)
    if match is None:
        raise AuditError("packet_time_utc_offset must be a signed HH:MM offset")
    hours, minutes = int(match[2]), int(match[3])
    if hours > 14 or minutes > 59 or (hours == 14 and minutes != 0):
        raise AuditError("packet_time_utc_offset is outside the valid UTC offset range")
    delta = timedelta(hours=hours, minutes=minutes)
    return timezone(delta if match[1] == "+" else -delta)


def observed_packet_utc(raw: str, offset: timezone | None) -> datetime | None:
    """Do not guess a date or timezone from a time-only tcpdump line."""
    if offset is None or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?", raw
    ):
        return None
    try:
        return datetime.fromisoformat(raw).replace(tzinfo=offset).astimezone(timezone.utc)
    except ValueError:
        return None


def analyze_manifest(manifest_path: Path, *, include_endpoints: bool = False) -> dict[str, Any]:
    """Analyze user-provided files only. No OS probing, packets, DNS or subprocesses."""
    manifest_path = manifest_path.resolve()
    manifest_sha256 = sha256_file(manifest_path)
    manifest = _load_manifest(manifest_path)
    folder = manifest_path.parent
    canary = normalize_canary(manifest.get("canary_qname"))
    expected = {
        "physical": expected_interfaces(manifest, "expected_physical_interfaces"),
        "tun": expected_interfaces(manifest, "expected_tun_interfaces"),
    }
    raw_captures = manifest.get("captures")
    if not isinstance(raw_captures, list) or not 1 <= len(raw_captures) <= 16:
        raise AuditError("captures must contain 1 to 16 recorded logs")

    # The shared time window is needed *while* streaming each capture, not
    # after all files have been read. Only operator assertions are available;
    # packet timestamps provide an additional, narrower sanity check.
    windows = [
        parse_operator_window(spec) if isinstance(spec, dict) else None
        for spec in raw_captures
    ]
    shared_window: tuple[datetime, datetime] | None = None
    if all(window is not None for window in windows):
        latest_start = max(window[0] for window in windows if window is not None)
        earliest_end = min(window[1] for window in windows if window is not None)
        if latest_start < earliest_end:
            shared_window = (latest_start, earliest_end)

    summaries: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    seen_interfaces: set[tuple[str, str]] = set()
    seen_paths: set[Path] = set()
    seen_file_ids: set[tuple[int, int]] = set()
    missing_offsets: list[str] = []
    by_role_inside_window = {"physical": 0, "tun": 0}
    for spec, window in zip(raw_captures, windows):
        required = {"role", "interface", "path"}
        optional = {"started_at_utc", "ended_at_utc", "packet_time_utc_offset"}
        if (not isinstance(spec, dict) or not required.issubset(spec)
                or set(spec) - required - optional):
            raise AuditError("each capture requires role, interface, path and optional window")
        packet_offset = parse_packet_utc_offset(spec.get("packet_time_utc_offset"))
        role, interface = spec["role"], spec["interface"]
        if role not in ("physical", "tun"):
            raise AuditError("capture role must be physical or tun")
        if not isinstance(interface, str) or not INTERFACE.fullmatch(interface):
            raise AuditError("capture interface is invalid")
        if role == "tun" and not re.fullmatch(r"utun[0-9]+", interface):
            raise AuditError("macOS tun captures must name a utun interface")
        if role == "physical" and (interface.startswith("utun") or interface == "lo0"):
            raise AuditError("physical captures cannot be assigned to utun/loopback interfaces")
        key = (role, interface)
        if key in seen_interfaces:
            raise AuditError("duplicate capture role/interface")
        if interface not in expected[role]:
            raise AuditError("capture interface is not in the declared inventory")
        if packet_offset is None:
            missing_offsets.append(f"missing_packet_time_utc_offset:{role}:{interface}")
        seen_interfaces.add(key)
        file_path = evidence_path(folder, spec["path"])
        if file_path in seen_paths:
            raise AuditError("a capture file cannot represent two interfaces")
        stat = file_path.stat()
        inode_key = (stat.st_dev, stat.st_ino)
        if inode_key in seen_file_ids:
            raise AuditError("captures for two interfaces cannot refer to the same underlying file")
        seen_file_ids.add(inode_key)
        seen_paths.add(file_path)
        packet_lines = 0
        port53_packet_lines = 0
        candidate_dns_query_lines = 0
        unparsed_dns_payload_lines = 0
        unparsed_packet_or_canary_lines = 0
        invalid_timestamp_lines = 0
        outside_declared_window_lines = 0
        port53_packets_inside_window = 0
        canary_queries_inside_window = 0
        canary_queries = 0
        input_digest = hashlib.sha256()
        size_before = file_path.stat().st_size
        with file_path.open("rb") as capture:
            for raw_line in capture:
                input_digest.update(raw_line)
                try:
                    line = raw_line.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise AuditError("capture must be UTF-8 tcpdump text") from error
                # Count packet lines as evidence the supplied text really contains
                # tcpdump-style records. This does not prove a capture window.
                match = PACKET.match(line.strip())
                packet_utc = (
                    observed_packet_utc(match["timestamp"], packet_offset)
                    if match is not None else None
                )
                if match is not None:
                    packet_lines += 1
                    if (port_53_destination(match["src"])
                            or port_53_destination(match["dst"])):
                        port53_packet_lines += 1
                        if packet_offset is not None and packet_utc is None:
                            invalid_timestamp_lines += 1
                        if packet_utc is not None and window is not None:
                            if not window[0] <= packet_utc < window[1]:
                                outside_declared_window_lines += 1
                        if packet_utc is not None and shared_window is not None:
                            if shared_window[0] <= packet_utc < shared_window[1]:
                                port53_packets_inside_window += 1
                    if port_53_destination(match["dst"]):
                        if QUESTION.search(match["details"]):
                            candidate_dns_query_lines += 1
                        else:
                            # TCP handshake/control packets (length 0) are not
                            # evidence of a dropped DNS question. Nonempty TCP
                            # segments and undecoded UDP payloads ARE a blind
                            # spot: refuse a negative verdict for those logs.
                            payload = match["details"]
                            sizes = re.findall(r"\blength\s+(\d+)\b", payload)
                            if any(int(size) > 0 for size in sizes):
                                unparsed_dns_payload_lines += 1
                event = parse_packet(line, canary, include_endpoints)
                # A verbose/multiline tcpdump header or an undecoded line
                # that mentions this canary must never count as negative
                # evidence merely because our strict packet decoder missed it.
                if (match is None
                        and (PACKET_PREFIX.match(line.strip())
                             or canary in line.lower())):
                    unparsed_packet_or_canary_lines += 1
                elif match is not None and canary in line.lower() and event is None:
                    unparsed_packet_or_canary_lines += 1
                if event is not None:
                    canary_queries += 1
                    if packet_utc is not None:
                        event["observed_at_utc"] = packet_utc.isoformat()
                        if (shared_window is not None
                                and shared_window[0] <= packet_utc < shared_window[1]):
                            canary_queries_inside_window += 1
                            by_role_inside_window[role] += 1
                    if len(events) == MAX_CANARY_EVENTS:
                        raise AuditError("more than 5000 canary queries; split the capture")
                    events.append({"role": role, "interface": interface, **event})
        # Hash the *exact bytes parsed* rather than merely the file found at
        # the end. A capture overwritten during analysis invalidates evidence.
        size_after = file_path.stat().st_size
        if (size_before != size_after
                or input_digest.hexdigest() != sha256_file(file_path)):
            raise AuditError("capture changed while it was being analyzed")
        summaries.append({
            "role": role,
            "interface": interface,
            "operator_declared_window_utc": (
                {"start": window[0].isoformat(), "end": window[1].isoformat()}
                if window else None
            ),
            "capture_sha256": input_digest.hexdigest(),
            "capture_bytes": size_before,
            "packet_lines": packet_lines,
            "port53_packet_lines": port53_packet_lines,
            "parsed_dns_question_lines": candidate_dns_query_lines,
            "unparsed_dns_payload_lines": unparsed_dns_payload_lines,
            "unparsed_packet_or_canary_lines": unparsed_packet_or_canary_lines,
            "invalid_packet_timestamp_lines": invalid_timestamp_lines,
            "packets_outside_declared_window": outside_declared_window_lines,
            "port53_packets_in_shared_window": port53_packets_inside_window,
            "canary_queries_in_shared_window": canary_queries_inside_window,
            "packet_time_utc_offset": spec.get("packet_time_utc_offset"),
            "canary_queries": canary_queries,
        })

    missing: list[str] = []
    for role in ("physical", "tun"):
        for interface in expected[role]:
            if (role, interface) not in seen_interfaces:
                missing.append(f"missing_{role}_capture:{interface}")
    missing.extend(missing_offsets)
    overlapping_window = (
        {"start": shared_window[0].isoformat(), "end": shared_window[1].isoformat()}
        if shared_window is not None else None
    )
    if any(window is None for window in windows):
        missing.append("capture_windows_missing_for_one_or_more_interfaces")
    elif shared_window is None:
        missing.append("declared_capture_windows_do_not_overlap")
    if any(s["invalid_packet_timestamp_lines"] > 0 for s in summaries):
        missing.append("one_or_more_undated_or_invalid_packet_timestamps")
    if any(s["packets_outside_declared_window"] > 0 for s in summaries):
        missing.append("one_or_more_packet_timestamps_outside_declared_window")
    if shared_window is not None:
        if any(s["role"] == "physical"
               and s["port53_packets_in_shared_window"] == 0
               and s["packet_time_utc_offset"] is not None for s in summaries):
            missing.append("one_or_more_physical_captures_have_no_port53_packet_in_shared_window")
        if by_role_inside_window["tun"] == 0:
            missing.append("no_tun_canary_in_shared_capture_window")
    if any(summary["packet_lines"] == 0 for summary in summaries):
        missing.append("one_or_more_captures_have_no_packet_lines")
    if any(summary["port53_packet_lines"] == 0 for summary in summaries):
        missing.append("one_or_more_captures_have_no_port53_packet_lines")
    if any(summary["unparsed_dns_payload_lines"] > 0 for summary in summaries):
        missing.append("one_or_more_captures_have_undecoded_dns_payloads")
    if any(summary["unparsed_packet_or_canary_lines"] > 0 for summary in summaries):
        missing.append("one_or_more_captures_have_unparsed_packet_or_canary_lines")
    snapshot_result: dict[str, Any] = {"provided": False}
    if "resolver_snapshot" in manifest:
        path = evidence_path(folder, manifest["resolver_snapshot"])
        if path.stat().st_size > MAX_SNAPSHOT_BYTES:
            raise AuditError("scutil snapshot exceeds 4 MiB; reject oversized evidence")
        snapshot_bytes = path.read_bytes()
        snapshot_digest = hashlib.sha256(snapshot_bytes).hexdigest()
        if not snapshot_bytes:
            missing.append("empty_resolver_snapshot")
        try:
            snapshot_text = snapshot_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise AuditError("scutil snapshot must be UTF-8 text") from error
        lines = snapshot_text.splitlines()
        # This deliberately checks only *shape*, not the correctness of the
        # macOS service-scoped resolver order or its ownership. No nameserver
        # addresses or search domains are copied into the report.
        headers = sum(
            re.fullmatch(r"DNS configuration(?: \(for scoped queries\))?", line.strip())
            is not None for line in lines
        )
        resolvers = sum(
            re.fullmatch(r"\s*resolver #\d+\s*", line) is not None
            for line in lines
        )
        nameservers = sum(
            re.fullmatch(r"\s*nameserver\[\d+\]\s*:\s*\S+.*", line) is not None
            for line in lines
        )
        if not (headers and resolvers and nameservers):
            missing.append("unrecognized_scutil_dns_snapshot")
        snapshot_at_raw = manifest.get("resolver_snapshot_recorded_at_utc")
        snapshot_at = None
        if snapshot_at_raw is None:
            missing.append("missing_scutil_dns_snapshot_recorded_at_utc")
        else:
            if not isinstance(snapshot_at_raw, str):
                raise AuditError("scutil snapshot timestamp must be timezone-aware ISO-8601")
            try:
                candidate = datetime.fromisoformat(
                    snapshot_at_raw.replace("Z", "+00:00")
                )
            except ValueError as error:
                raise AuditError("invalid scutil snapshot timestamp") from error
            if candidate.tzinfo is None or candidate.utcoffset() is None:
                raise AuditError("scutil snapshot timestamp must be timezone-aware ISO-8601")
            snapshot_at = candidate.astimezone(timezone.utc)
            if (shared_window is not None
                    and not shared_window[0] <= snapshot_at < shared_window[1]):
                missing.append("scutil_dns_snapshot_outside_shared_capture_window")
        if sha256_file(path) != snapshot_digest:
            raise AuditError("scutil snapshot changed while it was being analyzed")
        snapshot_result = {
            "provided": True,
            "sha256": snapshot_digest,
            "bytes": len(snapshot_bytes),
            "resolver_sections": resolvers,
            "nameserver_entries": nameservers,
            "recorded_at_utc": snapshot_at.isoformat() if snapshot_at else None,
            "structure_recognized": bool(headers and resolvers and nameservers),
        }
    else:
        missing.append("missing_scutil_dns_resolver_snapshot")

    by_role = {
        role: sum(summary["canary_queries"] for summary in summaries if summary["role"] == role)
        for role in ("physical", "tun")
    }
    if by_role["physical"]:
        verdict = "PHYSICAL_CANARY_PLAINTEXT_DNS_OBSERVED"
    elif missing or by_role["tun"] == 0:
        if by_role["tun"] == 0:
            missing.append("no_canary_dns_question_observed_on_utun")
        verdict = "NOT_VERIFIED"
    else:
        verdict = "NO_PHYSICAL_CANARY_OBSERVED_IN_SUPPLIED_LOGS"

    if sha256_file(manifest_path) != manifest_sha256:
        raise AuditError("manifest changed while it was being analyzed")

    return {
        "schema_version": SCHEMA_VERSION,
        "manifest_sha256": manifest_sha256,
        "case_id": manifest["case_id"],
        "canary_qname": canary,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "system_zero_leak_verified": False,
        "coverage_issues": missing,
        "declared_interface_inventory": expected,
        "operator_declared_capture_overlap_utc": overlapping_window,
        "resolver_snapshot": snapshot_result,
        "captures": summaries,
        "canary_query_counts": by_role,
        "canary_queries_in_shared_window": by_role_inside_window,
        "canary_queries": events,
        "limitations": [
            "Only supplied tcpdump text for UDP/TCP destination port 53 is examined.",
            "The interface inventory, capture completeness and declared UTC time windows are operator claims, not independently proven.",
            "The supplied scutil snapshot is hashed, not interpreted or verified for priority/ownership.",
            "No inference about encrypted DNS (DoH/DoT/DoQ), mDNS, DNS Proxy, NIC bypass or system-wide zero leak.",
            "Packet timestamps are converted using operator-supplied fixed UTC offsets; actual OS clock sync and capture windows are not independently attested.",
        ],
    }


def write_private_report(
    output: Path, content: str, *, overwrite: bool,
    manifest_path: Path, report: dict[str, Any]
) -> None:
    """Write mode-0600 JSON atomically, never truncating evidence or following links."""
    manifest_path = manifest_path.resolve()
    if sha256_file(manifest_path) != report["manifest_sha256"]:
        raise AuditError("manifest changed before the report could be saved")
    manifest = _load_manifest(manifest_path)
    inputs = {manifest_path}
    evidence_folder = manifest_path.parent
    if len(manifest["captures"]) != len(report["captures"]):
        raise AuditError("report does not match the evidence inventory")
    for capture, summary in zip(manifest["captures"], report["captures"]):
        if (capture["role"], capture["interface"]) != (
            summary["role"], summary["interface"]
        ):
            raise AuditError("report does not match the evidence inventory")
        file_path = evidence_path(evidence_folder, capture["path"])
        inputs.add(file_path)
        if (sha256_file(file_path) != summary["capture_sha256"]
                or file_path.stat().st_size != summary["capture_bytes"]):
            raise AuditError("capture changed before the report could be saved")
    if "resolver_snapshot" in manifest:
        snapshot = evidence_path(evidence_folder, manifest["resolver_snapshot"])
        inputs.add(snapshot)
        if (sha256_file(snapshot) != report["resolver_snapshot"]["sha256"]
                or snapshot.stat().st_size != report["resolver_snapshot"]["bytes"]):
            raise AuditError("resolver snapshot changed before the report could be saved")
    if output.resolve() in inputs:
        raise AuditError("report output must not overwrite the manifest or input evidence")

    # mkstemp always creates a 0600 file. Link for no-overwrite (atomic
    # EEXIST); replace for explicit overwrite (does not follow a symlink).
    handle, pending = tempfile.mkstemp(prefix=".dns-canary-", dir=output.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as report:
            report.write(content)
            report.flush()
            os.fsync(report.fileno())
        if overwrite:
            os.replace(pending, output)
        else:
            os.link(pending, output)
    finally:
        if os.path.exists(pending):
            os.unlink(pending)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline macOS DNS-canary analysis; NEVER probes or changes the host network"
    )
    parser.add_argument("manifest", type=Path, help="manifest JSON; evidence paths are relative to it")
    parser.add_argument("--output", type=Path, help="write JSON report (refuses overwrite by default)")
    parser.add_argument("--overwrite", action="store_true", help="permit replacing an existing report")
    parser.add_argument(
        "--include-endpoints", action="store_true",
        help="include IP:port endpoints in report (could contain sensitive network information)",
    )
    args = parser.parse_args(argv)
    try:
        report = analyze_manifest(args.manifest, include_endpoints=args.include_endpoints)
        content = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            write_private_report(
                args.output, content,
                overwrite=args.overwrite,
                manifest_path=args.manifest,
                report=report,
            )
            print(f"case={report['case_id']} verdict={report['verdict']} report={args.output}")
        else:
            sys.stdout.write(content)
    except (AuditError, OSError, UnicodeError) as error:
        print(f"DNS canary audit failed: {error}", file=sys.stderr)
        return 2
    # CI consumers can distinguish observed leakage and missing evidence.
    return {
        "NO_PHYSICAL_CANARY_OBSERVED_IN_SUPPLIED_LOGS": 0,
        "PHYSICAL_CANARY_PLAINTEXT_DNS_OBSERVED": 3,
        "NOT_VERIFIED": 4,
    }[report["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
