#!/usr/bin/env python3
"""Aggregate independent, offline macOS DNS canary cases without network access.

The matrix has a user-declared list of required cases. It never asserts full
system-wide leak freedom, even if every supplied case is clean.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import dns_canary_audit as audit

SCHEMA_VERSION = 1
MAX_MATRIX_BYTES = 256 * 1024
MAX_CASES = 32
CASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
GOOD = "NO_PHYSICAL_CANARY_OBSERVED_IN_SUPPLIED_CASES"
LEAK = "PHYSICAL_CANARY_PLAINTEXT_DNS_OBSERVED"
UNKNOWN = "NOT_VERIFIED"

# A concrete, nonempty acceptance checklist. These labels are operator
# assertions rather than technical proof that the corresponding OS scenario
# occurred; no profile can establish complete system-level leak freedom.
MACOS_DNS_EGRESS_V1 = (
    "wifi_a_aaaa",
    "tcp_53",
    "ipv6",
    "network_change",
    "sleep_resume",
    "dns_upstream_failure",
    "tun_or_dns_proxy_unavailable",
)


def _matrix_manifest(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_MATRIX_BYTES:
        raise audit.AuditError("matrix manifest exceeds 256 KiB")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise audit.AuditError("cannot read valid JSON matrix manifest") from error
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        raise audit.AuditError("matrix schema_version must be 1")
    required_keys = {"schema_version", "matrix_id", "required_cases", "cases"}
    if not required_keys.issubset(data) or set(data) - required_keys - {"profile"}:
        raise audit.AuditError("unknown or missing matrix manifest fields")
    if "profile" in data and data["profile"] != "macos_dns_egress_v1":
        raise audit.AuditError("unknown macOS DNS acceptance profile")
    matrix_id = data["matrix_id"]
    if not isinstance(matrix_id, str) or CASE_ID.fullmatch(matrix_id) is None:
        raise audit.AuditError("matrix_id must be a 1..64 character safe ID")
    required = data["required_cases"]
    specs = data["cases"]
    if (not isinstance(required, list) or not 1 <= len(required) <= MAX_CASES):
        raise audit.AuditError("required_cases must have 1..32 entries")
    if (not isinstance(specs, list) or not 1 <= len(specs) <= MAX_CASES):
        raise audit.AuditError("cases must have 1..32 entries")
    if any(not isinstance(cid, str) or CASE_ID.fullmatch(cid) is None for cid in required):
        raise audit.AuditError("required_cases contains an invalid case ID")
    if len(set(required)) != len(required):
        raise audit.AuditError("duplicate required_cases IDs")
    return data


def summarize_canary_protocols(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Only protocol metadata and counts; never reproduce QNAME or IP endpoints."""
    grouped: dict[str, dict[tuple[str, str, str], int]] = {
        "physical": {}, "tun": {},
    }
    for event in events:
        role = event["role"]
        key = (event["ip_family"], event["transport"], event["qtype"])
        grouped[role][key] = grouped[role].get(key, 0) + 1
    return {
        role: [
            {"ip_family": family, "transport": transport, "qtype": qtype, "count": count}
            for (family, transport, qtype), count in sorted(grouped[role].items())
        ]
        for role in ("physical", "tun")
    }


def analyze_matrix(matrix_path: Path) -> dict[str, Any]:
    """Read an audit matrix and its child case evidence, with no OS probes."""
    matrix_path = matrix_path.resolve()
    base = matrix_path.parent
    matrix_sha256 = audit.sha256_file(matrix_path)
    data = _matrix_manifest(matrix_path)
    case_summaries: list[dict[str, Any]] = []
    case_paths: set[Path] = set()
    case_files: set[tuple[int, int]] = set()
    seen_ids: set[str] = set()
    seen_canary: set[str] = set()
    seen_stimulus: set[str] = set()
    seen_capture_hash: set[str] = set()
    profile_evidence_issues: set[str] = set()
    profile_enabled = data.get("profile") == "macos_dns_egress_v1"
    counts = {"no_physical_observed": 0, "unverified": 0, "physical_observed": 0}
    for spec in data["cases"]:
        if not isinstance(spec, dict) or set(spec) != {"case_id", "manifest"}:
            raise audit.AuditError("each case needs exactly case_id and manifest")
        case_id, relative_path = spec["case_id"], spec["manifest"]
        if not isinstance(case_id, str) or CASE_ID.fullmatch(case_id) is None:
            raise audit.AuditError("invalid case_id in matrix")
        if case_id in seen_ids:
            raise audit.AuditError("duplicate case_id in matrix")
        seen_ids.add(case_id)
        case_manifest = audit.evidence_path(base, relative_path)
        if case_manifest in case_paths:
            raise audit.AuditError("duplicate case manifest file")
        case_paths.add(case_manifest)
        key = (case_manifest.stat().st_dev, case_manifest.stat().st_ino)
        if key in case_files:
            raise audit.AuditError("different cases use the same underlying manifest file")
        case_files.add(key)
        child = audit.analyze_manifest(case_manifest)
        if child["case_id"] != case_id:
            raise audit.AuditError("case_id differs from its child manifest")
        if profile_enabled:
            # The names of acceptance scenarios must also agree with the
            # *actual* observed canary QTYPE/transport and address family.
            # This only checks decoded packet facts, not whether a network
            # switch, sleep or DNS failure truly happened on the OS.
            shared = child["operator_declared_capture_overlap_utc"]
            stimulus_raw = child["canary_stimulus"]["at_utc"]
            eligible: list[dict[str, Any]] = []
            if shared is not None and stimulus_raw is not None:
                shared_start = datetime.fromisoformat(shared["start"])
                shared_end = datetime.fromisoformat(shared["end"])
                stimulus_start = datetime.fromisoformat(stimulus_raw)
                stimulus_end = stimulus_start + timedelta(
                    seconds=child["canary_stimulus"]["deadline_seconds"]
                )
                for event in child["canary_queries"]:
                    if event["role"] != "tun" or "observed_at_utc" not in event:
                        continue
                    moment = datetime.fromisoformat(event["observed_at_utc"])
                    if (shared_start <= moment < shared_end
                            and stimulus_start <= moment <= stimulus_end):
                        eligible.append(event)
            qtypes = {event["qtype"] for event in eligible}
            if case_id == "wifi_a_aaaa" and not {"A", "AAAA"}.issubset(qtypes):
                profile_evidence_issues.add("profile_wifi_a_aaaa_questions_missing")
            if case_id == "tcp_53" and not any(
                event["transport"] == "tcp" for event in eligible
            ):
                profile_evidence_issues.add("profile_tcp_53_tun_query_missing")
            if case_id == "ipv6" and not any(
                event["ip_family"] == "ipv6" and event["qtype"] == "AAAA"
                for event in eligible
            ):
                profile_evidence_issues.add("profile_ipv6_tun_question_missing")
            canary = child["canary_qname"]
            if canary in seen_canary:
                profile_evidence_issues.add("profile_reused_canary_qname")
            seen_canary.add(canary)
            stimulus = child["canary_stimulus"]["at_utc"]
            if stimulus is not None:
                if stimulus in seen_stimulus:
                    profile_evidence_issues.add("profile_reused_stimulus_timestamp")
                seen_stimulus.add(stimulus)
            for capture in child["captures"]:
                digest = capture["capture_sha256"]
                if digest in seen_capture_hash:
                    profile_evidence_issues.add("profile_reused_capture_bytes")
                seen_capture_hash.add(digest)
        verdict = child["verdict"]
        if verdict == "NO_PHYSICAL_CANARY_OBSERVED_IN_SUPPLIED_LOGS":
            counts["no_physical_observed"] += 1
        elif verdict == LEAK:
            counts["physical_observed"] += 1
        elif verdict == UNKNOWN:
            counts["unverified"] += 1
        else:
            raise audit.AuditError("unrecognized child canary verdict")
        case_summaries.append({
            "case_id": case_id,
            "verdict": verdict,
            "manifest_sha256": child["manifest_sha256"],
            "coverage_issues": child["coverage_issues"],
            "review_flags": child["review_flags"],
            "canary_queries_after_stimulus": child["canary_queries_after_stimulus"],
            "observed_canary_protocols": summarize_canary_protocols(child["canary_queries"]),
            "capture_digests": [
                {
                    "role": item["role"],
                    "interface": item["interface"],
                    "capture_sha256": item["capture_sha256"],
                    "stats_sha256": item["tcpdump_stats"].get("sha256"),
                }
                for item in child["captures"]
            ],
            "resolver_snapshot_sha256": child["resolver_snapshot"].get("sha256"),
        })
    if audit.sha256_file(matrix_path) != matrix_sha256:
        raise audit.AuditError("matrix manifest changed during analysis")
    missing = [cid for cid in data["required_cases"] if cid not in seen_ids]
    profile = data.get("profile")
    missing_profile_cases = [
        cid for cid in MACOS_DNS_EGRESS_V1
        if cid not in data["required_cases"] or cid not in seen_ids
    ] if profile else []
    if counts["physical_observed"]:
        verdict = LEAK
    elif missing or missing_profile_cases or profile_evidence_issues or counts["unverified"]:
        verdict = UNKNOWN
    else:
        verdict = GOOD
    return {
        "schema_version": SCHEMA_VERSION,
        "matrix_id": data["matrix_id"],
        "profile": profile or "user_declared",
        "missing_profile_cases": missing_profile_cases,
        "profile_evidence_issues": sorted(profile_evidence_issues),
        "matrix_sha256": matrix_sha256,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "system_zero_leak_verified": False,
        "required_cases": data["required_cases"],
        "missing_cases": missing,
        "case_counts": counts,
        "cases": case_summaries,
        "limitations": [
            "The builtin macOS profile is an operator scenario checklist, not proof the named OS scenarios occurred.",
            "An unprofiled required scenario list is supplied entirely by the operator.",
            "Individual cases rely on operator-declared capture and DNS stimulus timestamps.",
            "A clean matrix only means the supplied plaintext UDP/TCP 53 cases did not show a physical canary.",
            "Missing services, encrypted DNS, system DNS ownership and real interface coverage remain unverified.",
        ],
    }


def _stable_report(report: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in report.items() if key != "generated_at_utc"}


def write_private_matrix(
    output: Path, text: str, *, overwrite: bool,
    matrix_path: Path, report: dict[str, Any],
) -> None:
    """Refuse changed evidence; create private JSON without following symlinks."""
    # Re-analyze before writing because a case's raw log or tcpdump stderr
    # could have been replaced *after* the first matrix pass. The generated_at
    # timestamp is deliberately excluded from this integrity comparison.
    current = analyze_matrix(matrix_path)
    if _stable_report(current) != _stable_report(report):
        raise audit.AuditError("matrix evidence changed before report was saved")
    inputs = {matrix_path.resolve()}
    data = _matrix_manifest(matrix_path.resolve())
    for spec in data["cases"]:
        child_manifest_path = audit.evidence_path(
            matrix_path.resolve().parent, spec["manifest"]
        )
        inputs.add(child_manifest_path)
        child = audit._load_manifest(child_manifest_path)
        folder = child_manifest_path.parent
        for capture in child["captures"]:
            inputs.add(audit.evidence_path(folder, capture["path"]))
            if "tcpdump_stats_path" in capture:
                inputs.add(audit.evidence_path(folder, capture["tcpdump_stats_path"]))
        if "resolver_snapshot" in child:
            inputs.add(audit.evidence_path(folder, child["resolver_snapshot"]))
    if output.resolve() in inputs:
        raise audit.AuditError("matrix output must not overwrite raw input evidence")
    handle, temporary = tempfile.mkstemp(prefix=".dns-matrix-", dir=output.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temporary, output)
        else:
            os.link(temporary, output)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline-only multi-scenario DNS canary evidence matrix"
    )
    parser.add_argument("matrix", type=Path)
    parser.add_argument("--output", type=Path, help="private JSON report; no overwrite by default")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = analyze_matrix(args.matrix)
        content = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            write_private_matrix(
                args.output, content, overwrite=args.overwrite,
                matrix_path=args.matrix, report=report,
            )
            print(f"matrix={report['matrix_id']} verdict={report['verdict']} report={args.output}")
        else:
            sys.stdout.write(content)
    except (audit.AuditError, OSError, UnicodeError) as error:
        print(f"DNS canary matrix audit failed: {error}", file=sys.stderr)
        return 2
    return {GOOD: 0, LEAK: 3, UNKNOWN: 4}[report["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
