#!/usr/bin/env python3
"""Regression tests for the offline DNS-canary audit: no real DNS or capture."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import dns_canary_audit as audit  # noqa: E402


PHYSICAL_NOISE = (
    "2026-11-06 07:00:00.000001 IP 192.0.2.11.51111 > 9.9.9.9.53: "
    "125+ A? unrelated.private.example. (44)\n"
    "2026-11-06 07:00:00.000002 IP 9.9.9.9.53 > 192.0.2.11.51111: "
    "125 1/0/0 A 203.0.113.7 (60)\n"
)
TUN_CANARY = (
    "2026-11-06 07:00:00.000003 IP 192.0.2.50.58899 > 192.0.2.53.53: "
    "841+ [1au] A? CAnary.Evidence.Example.Test. (68)\n"
    "2026-11-06 07:00:00.000004 IP6 2001:db8::10.53535 > 2001:db8::53.53: "
    "Flags [P.], seq 1:88, ack 1, length 88: 842+ AAAA? "
    "canary.evidence.example.test. (83)\n"
)
PHYSICAL_LEAK = (
    "2026-11-06 07:00:00.000005 IP6 2001:db8::2.53123 > 2001:4860:4860::8888.53: "
    "1002+ AAAA? canary.evidence.example.test. (64)\n"
    "2026-11-06 07:00:00.000006 IP 192.0.2.50.51234 > 8.8.8.8.53: "
    "Flags [P.], seq 1:52, ack 1, length 52: "
    "999+ [1au] HTTPS? canary.evidence.example.test. (67)\n"
)
CANARY = "canary.evidence.example.test"


class AuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        (self.folder / "en0.log").write_text(PHYSICAL_NOISE, encoding="utf-8")
        (self.folder / "utun7.log").write_text(TUN_CANARY, encoding="utf-8")
        (self.folder / "en0.stats.txt").write_text(
            "2 packets captured\n2 packets received by filter\n0 packets dropped by kernel\n",
            encoding="utf-8",
        )
        (self.folder / "utun7.stats.txt").write_text(
            "2 packets captured\n2 packets received by filter\n0 packets dropped by kernel\n",
            encoding="utf-8",
        )
        (self.folder / "scutil-dns.txt").write_text(
            "DNS configuration\nresolver #1\n  nameserver[0] : 192.0.2.53\n",
            encoding="utf-8",
        )
        self.manifest = {
            "schema_version": 1,
            "case_id": "wifi_up_ipv4_ipv6",
            "canary_qname": "CaNaRy.Evidence.Example.Test.",
            "canary_stimulus_at_utc": "2026-11-06T15:00:00Z",
            "canary_observation_deadline_seconds": 30,
            "expected_physical_interfaces": ["en0"],
            "expected_tun_interfaces": ["utun7"],
            "resolver_snapshot": "scutil-dns.txt",
            "resolver_snapshot_recorded_at_utc": "2026-11-06T15:00:20Z",
            "captures": [
                {"role": "physical", "interface": "en0", "path": "en0.log",
                 "tcpdump_stats_path": "en0.stats.txt",
                 "started_at_utc": "2026-11-06T15:00:00Z",
                 "ended_at_utc": "2026-11-06T15:05:00Z",
                 "packet_time_utc_offset": "-08:00"},
                {"role": "tun", "interface": "utun7", "path": "utun7.log",
                 "tcpdump_stats_path": "utun7.stats.txt",
                 "started_at_utc": "2026-11-06T15:00:00Z",
                 "ended_at_utc": "2026-11-06T15:06:00Z",
                 "packet_time_utc_offset": "-08:00"},
            ],
        }

    def save_manifest(self) -> Path:
        path = self.folder / "manifest.json"
        path.write_text(json.dumps(self.manifest), encoding="utf-8")
        return path

    def test_checked_in_synthetic_examples_cover_all_verdicts(self) -> None:
        examples = Path(__file__).resolve().parents[1] / "examples" / "dns_canary"
        for manifest_name, expected_verdict, expected_exit in [
            ("manifest.json", "NO_PHYSICAL_CANARY_OBSERVED_IN_SUPPLIED_LOGS", 0),
            ("manifest-leak.json", "PHYSICAL_CANARY_PLAINTEXT_DNS_OBSERVED", 3),
            ("manifest-incomplete.json", "NOT_VERIFIED", 4),
        ]:
            with self.subTest(manifest=manifest_name):
                capture = io.StringIO()
                with contextlib.redirect_stdout(capture):
                    exit_code = audit.main([str(examples / manifest_name)])
                self.assertEqual(exit_code, expected_exit)
                report = json.loads(capture.getvalue())
                self.assertEqual(report["verdict"], expected_verdict)
                self.assertFalse(report["system_zero_leak_verified"])

    def test_clean_scope_report_never_claims_system_zero_leak(self) -> None:
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["verdict"], "NO_PHYSICAL_CANARY_OBSERVED_IN_SUPPLIED_LOGS")
        self.assertFalse(result["system_zero_leak_verified"])
        self.assertEqual(
            result["manifest_sha256"],
            hashlib.sha256((self.folder / "manifest.json").read_bytes()).hexdigest(),
        )
        self.assertEqual(result["canary_query_counts"], {"physical": 0, "tun": 2})
        self.assertEqual(result["coverage_issues"], [])
        self.assertEqual(
            {(event["ip_family"], event["transport"], event["qtype"]) for event in result["canary_queries"]},
            {("ipv4", "udp", "A"), ("ipv6", "tcp", "AAAA")},
        )
        self.assertTrue(result["resolver_snapshot"]["sha256"])
        self.assertFalse(result["resolver_snapshot"].get("content"))

    def test_negative_verdict_requires_explicit_canary_stimulus_metadata(self) -> None:
        del self.manifest["canary_stimulus_at_utc"]
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn("missing_canary_stimulus_at_utc", report["coverage_issues"])

    def test_stale_utun_canary_before_stimulus_is_not_negative_evidence(self) -> None:
        self.manifest["canary_stimulus_at_utc"] = "2026-11-06T15:00:02Z"
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn("no_utun_canary_observed_after_stimulus", report["coverage_issues"])

    def test_capture_must_cover_entire_stimulus_deadline(self) -> None:
        self.manifest["canary_stimulus_at_utc"] = "2026-11-06T15:04:50Z"
        self.manifest["canary_observation_deadline_seconds"] = 30
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn("capture_does_not_cover_stimulus_deadline", report["coverage_issues"])

    def test_stimulus_deadline_is_strictly_bounded(self) -> None:
        for value in (0, -1, 301, True, "30", None):
            with self.subTest(value=value):
                self.manifest["canary_observation_deadline_seconds"] = value
                with self.assertRaisesRegex(audit.AuditError, "deadline"):
                    audit.analyze_manifest(self.save_manifest())

    def test_stimulus_timestamp_is_timezone_aware(self) -> None:
        for value in ("2026-11-06T15:00:00", "tomorrow", 42):
            with self.subTest(value=value):
                self.manifest["canary_stimulus_at_utc"] = value
                with self.assertRaisesRegex(audit.AuditError, "stimulus"):
                    audit.analyze_manifest(self.save_manifest())

    def test_extreme_future_stimulus_cannot_overflow_deadline(self) -> None:
        self.manifest["canary_stimulus_at_utc"] = "9999-12-31T23:59:59Z"
        with self.assertRaisesRegex(audit.AuditError, "stimulus deadline"):
            audit.analyze_manifest(self.save_manifest())

    def test_tun_canary_observed_in_stimulus_window_is_counted(self) -> None:
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["canary_queries_after_stimulus"], {
            "physical": 0, "tun": 2
        })
        self.assertEqual(
            report["canary_stimulus"]["at_utc"], "2026-11-06T15:00:00+00:00"
        )
        self.assertEqual(report["canary_stimulus"]["deadline_seconds"], 30)
        self.assertEqual(report["verdict"], "NO_PHYSICAL_CANARY_OBSERVED_IN_SUPPLIED_LOGS")

    def test_physical_canary_observation_still_wins_if_stimulus_missing(self) -> None:
        del self.manifest["canary_stimulus_at_utc"]
        (self.folder / "en0.log").write_text(PHYSICAL_LEAK, encoding="utf-8")
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "PHYSICAL_CANARY_PLAINTEXT_DNS_OBSERVED")

    def test_no_private_dns_names_or_ip_endpoints_leak_into_default_report(self) -> None:
        result = json.dumps(audit.analyze_manifest(self.save_manifest()))
        self.assertNotIn("unrelated.private.example", result)
        self.assertNotIn("2001:db8::10", result)
        self.assertNotIn("192.0.2.50", result)
        self.assertNotIn("8.8.8.8", result)
        self.assertNotIn("nameserver[0]", result)
        self.assertIn(CANARY, result)

    def test_physical_ipv4_ipv6_tcp_and_udp_canary_reports_real_leak(self) -> None:
        (self.folder / "en0.log").write_text(
            PHYSICAL_NOISE + PHYSICAL_LEAK, encoding="utf-8"
        )
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["verdict"], "PHYSICAL_CANARY_PLAINTEXT_DNS_OBSERVED")
        self.assertEqual(result["canary_query_counts"]["physical"], 2)
        self.assertEqual(
            {(event["ip_family"], event["transport"], event["qtype"]) for event in result["canary_queries"]
             if event["role"] == "physical"},
            {("ipv6", "udp", "AAAA"), ("ipv4", "tcp", "HTTPS")},
        )
        self.assertFalse(result["system_zero_leak_verified"])

    def test_response_does_not_count_as_outgoing_dns_request(self) -> None:
        (self.folder / "en0.log").write_text(
            "2026-11-06 07:00:02.0 IP 9.9.9.9.53 > 192.0.2.11.51512: "
            "100 1/0/0 A 192.0.2.7 (61)\n", encoding="utf-8"
        )
        self.assertEqual(
            audit.analyze_manifest(self.save_manifest())["canary_query_counts"]["physical"],
            0,
        )

    def test_dangerous_substring_is_not_equal_to_canary_qname(self) -> None:
        (self.folder / "en0.log").write_text(
            "2026-11-06 07:00:02.0 IP 10.0.0.2.5111 > 8.8.8.8.53: "
            "14+ A? canary.evidence.example.test.attacker.invalid. (44)\n",
            encoding="utf-8",
        )
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["canary_query_counts"]["physical"], 0)

    def test_missing_physical_interface_is_not_verified(self) -> None:
        self.manifest["expected_physical_interfaces"].append("en1")
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["verdict"], "NOT_VERIFIED")
        self.assertIn("missing_physical_capture:en1", result["coverage_issues"])

    def test_missing_tun_canary_is_not_verified(self) -> None:
        (self.folder / "utun7.log").write_text(
            "2026-11-06 07:00:01 IP 192.0.2.3.50234 > 192.0.2.53.53: "
            "5+ A? different.example.test. (32)\n", encoding="utf-8"
        )
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["verdict"], "NOT_VERIFIED")
        self.assertIn("no_canary_dns_question_observed_on_utun", result["coverage_issues"])

    def test_empty_physical_capture_is_not_verified(self) -> None:
        (self.folder / "en0.log").write_text("", encoding="utf-8")
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["verdict"], "NOT_VERIFIED")
        self.assertIn("one_or_more_captures_have_no_packet_lines", result["coverage_issues"])

    def test_unfiltered_non_dns_packets_are_not_capture_coverage(self) -> None:
        # A wrongly supplied HTTP capture must not count as physical port-53 coverage.
        (self.folder / "en0.log").write_text(
            "2026-11-06 07:00:01.000001 IP 192.0.2.10.51234 > 192.0.2.11.443: "
            "Flags [P.], seq 1:25, ack 1, length 24\n",
            encoding="utf-8",
        )
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["verdict"], "NOT_VERIFIED")
        self.assertIn(
            "one_or_more_captures_have_no_port53_packet_lines",
            result["coverage_issues"],
        )

    def test_missing_capture_stats_cannot_prove_no_drop(self) -> None:
        del self.manifest["captures"][0]["tcpdump_stats_path"]
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn("missing_tcpdump_stats:physical:en0", report["coverage_issues"])

    def test_kernel_drops_invalidate_negative_evidence(self) -> None:
        (self.folder / "en0.stats.txt").write_text(
            "2 packets captured\n3 packets received by filter\n1 packet dropped by kernel\n",
            encoding="utf-8",
        )
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn("tcpdump_kernel_packets_dropped:physical:en0", report["coverage_issues"])

    def test_stats_capture_count_mismatch_invalidates_negative_result(self) -> None:
        (self.folder / "utun7.stats.txt").write_text(
            "3 packets captured\n3 packets received by filter\n0 packets dropped by kernel\n",
            encoding="utf-8",
        )
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn("tcpdump_capture_count_mismatch:tun:utun7", report["coverage_issues"])

    def test_malformed_stats_are_not_silently_accepted(self) -> None:
        (self.folder / "en0.stats.txt").write_text(
            "tcpdump started but never stopped\n", encoding="utf-8"
        )
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn("incomplete_tcpdump_stats:physical:en0", report["coverage_issues"])

    def test_stats_provenance_is_recorded_without_raw_stderr(self) -> None:
        report = audit.analyze_manifest(self.save_manifest())
        summary = report["captures"][0]["tcpdump_stats"]
        self.assertEqual(summary["captured"], 2)
        self.assertEqual(summary["dropped_by_kernel"], 0)
        self.assertEqual(len(summary["sha256"]), 64)
        self.assertNotIn("packets received by filter", json.dumps(report))

    def test_physical_canary_wins_even_if_kernel_drops_packets(self) -> None:
        (self.folder / "en0.log").write_text(PHYSICAL_LEAK, encoding="utf-8")
        (self.folder / "en0.stats.txt").write_text(
            "2 packets captured\n3 packets received by filter\n1 packet dropped by kernel\n",
            encoding="utf-8",
        )
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "PHYSICAL_CANARY_PLAINTEXT_DNS_OBSERVED")
        self.assertIn("tcpdump_kernel_packets_dropped:physical:en0", report["coverage_issues"])

    def test_interface_drops_are_not_silently_ignored(self) -> None:
        (self.folder / "en0.stats.txt").write_text(
            "2 packets captured\n2 packets received by filter\n"
            "0 packets dropped by kernel\n1 packet dropped by interface\n",
            encoding="utf-8",
        )
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn("tcpdump_interface_packets_dropped:physical:en0",
                      report["coverage_issues"])

    def test_duplicate_tcpdump_stats_file_cannot_impersonate_two_interfaces(self) -> None:
        self.manifest["captures"][1]["tcpdump_stats_path"] = "en0.stats.txt"
        with self.assertRaisesRegex(audit.AuditError, "same underlying"):
            audit.analyze_manifest(self.save_manifest())

    def test_tcpdump_stats_cannot_alias_the_capture_file(self) -> None:
        self.manifest["captures"][0]["tcpdump_stats_path"] = "en0.log"
        with self.assertRaisesRegex(audit.AuditError, "same underlying"):
            audit.analyze_manifest(self.save_manifest())

    def test_tcpdump_stats_changed_after_analysis_is_rejected_before_report(self) -> None:
        import unittest.mock
        manifest = self.save_manifest()
        output = self.folder / "never-written.json"
        real_analysis = audit.analyze_manifest

        def mutate_stats_after_analysis(path: Path, **kwargs: object) -> dict:
            report = real_analysis(path, **kwargs)
            (self.folder / "en0.stats.txt").write_text(
                "2 packets captured\n2 packets received by filter\n"
                "1 packet dropped by kernel\n",
                encoding="utf-8",
            )
            return report

        with unittest.mock.patch.object(audit, "analyze_manifest",
                                       side_effect=mutate_stats_after_analysis):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    audit.main([str(manifest), "--output", str(output)]), 2
                )
        self.assertFalse(output.exists())

    def test_stats_larger_than_64kib_are_rejected(self) -> None:
        (self.folder / "en0.stats.txt").write_bytes(b"x" * (64 * 1024 + 1))
        with self.assertRaisesRegex(audit.AuditError, "tcpdump stats exceeds"):
            audit.analyze_manifest(self.save_manifest())

    def test_capture_windows_required_for_negative_assessment(self) -> None:
        del self.manifest["captures"][0]["started_at_utc"]
        del self.manifest["captures"][0]["ended_at_utc"]
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["verdict"], "NOT_VERIFIED")
        self.assertIn("capture_windows_missing_for_one_or_more_interfaces",
                      result["coverage_issues"])

    def test_missing_tz_offset_must_not_make_negative_result_look_verified(self) -> None:
        del self.manifest["captures"][0]["packet_time_utc_offset"]
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn(
            "missing_packet_time_utc_offset:physical:en0",
            report["coverage_issues"],
        )

    def test_packet_times_outside_declared_window_cannot_pass(self) -> None:
        # Manifest window claims 15:00-15:05Z but actual observed traffic was
        # at 14:59Z, before both physical and utun logs started.
        (self.folder / "en0.log").write_text(
            PHYSICAL_NOISE.replace("07:00:00", "06:59:00"), encoding="utf-8"
        )
        (self.folder / "utun7.log").write_text(
            TUN_CANARY.replace("07:00:00", "06:59:00"), encoding="utf-8"
        )
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn(
            "one_or_more_packet_timestamps_outside_declared_window",
            report["coverage_issues"],
        )
        self.assertIn(
            "no_tun_canary_in_shared_capture_window",
            report["coverage_issues"],
        )

    def test_canary_outside_overlap_is_insufficient_even_if_captured(self) -> None:
        # Files overlap 15:00-15:05Z, but the canary itself appears at 15:05:30Z.
        (self.folder / "utun7.log").write_text(
            TUN_CANARY.replace("07:00:00", "07:05:30"), encoding="utf-8"
        )
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn(
            "no_tun_canary_in_shared_capture_window",
            report["coverage_issues"],
        )

    def test_wrong_offset_disagrees_with_declared_utc_window(self) -> None:
        self.manifest["captures"][0]["packet_time_utc_offset"] = "+00:00"
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn(
            "one_or_more_packet_timestamps_outside_declared_window",
            report["coverage_issues"],
        )

    def test_invalid_timezone_offset_is_rejected(self) -> None:
        for value in ("PST", "-8:00", "-25:00", "+00:99", ""):
            with self.subTest(value=value):
                self.manifest["captures"][0]["packet_time_utc_offset"] = value
                with self.assertRaisesRegex(audit.AuditError, "offset"):
                    audit.analyze_manifest(self.save_manifest())

    def test_undated_tcpdump_packet_cannot_support_negative_verdict(self) -> None:
        (self.folder / "en0.log").write_text(
            PHYSICAL_NOISE.replace("2026-11-06 ", ""), encoding="utf-8"
        )
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn(
            "one_or_more_undated_or_invalid_packet_timestamps",
            report["coverage_issues"],
        )

    def test_observed_physical_leak_overrides_missing_timezone(self) -> None:
        del self.manifest["captures"][0]["packet_time_utc_offset"]
        (self.folder / "en0.log").write_text(PHYSICAL_LEAK, encoding="utf-8")
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "PHYSICAL_CANARY_PLAINTEXT_DNS_OBSERVED")
        self.assertIn("missing_packet_time_utc_offset:physical:en0", report["coverage_issues"])

    def test_valid_packet_time_is_normalized_to_utc(self) -> None:
        report = audit.analyze_manifest(self.save_manifest())
        times = [event["observed_at_utc"] for event in report["canary_queries"]]
        self.assertEqual(times, [
            "2026-11-06T15:00:00.000003+00:00",
            "2026-11-06T15:00:00.000004+00:00",
        ])
        self.assertEqual(report["captures"][0]["port53_packets_in_shared_window"], 2)
        self.assertEqual(report["canary_queries_in_shared_window"], {"physical": 0, "tun": 2})

    def test_non_overlapping_capture_windows_are_not_verified(self) -> None:
        self.manifest["captures"][1]["started_at_utc"] = "2026-11-06T15:10:00Z"
        self.manifest["captures"][1]["ended_at_utc"] = "2026-11-06T15:15:00Z"
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["verdict"], "NOT_VERIFIED")
        self.assertIn("declared_capture_windows_do_not_overlap", result["coverage_issues"])

    def test_invalid_capture_timestamp_is_rejected(self) -> None:
        self.manifest["captures"][0]["started_at_utc"] = "2026-11-06T15:00:00"
        with self.assertRaisesRegex(audit.AuditError, "timezone-aware"):
            audit.analyze_manifest(self.save_manifest())
        self.manifest["captures"][0]["started_at_utc"] = "2026-11-06T15:09:00Z"
        with self.assertRaisesRegex(audit.AuditError, "before end"):
            audit.analyze_manifest(self.save_manifest())

    def test_snapshot_with_arbitrary_text_is_not_verified(self) -> None:
        (self.folder / "scutil-dns.txt").write_text(
            "not a resolver snapshot", encoding="utf-8"
        )
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn("unrecognized_scutil_dns_snapshot", report["coverage_issues"])
        self.assertNotIn("not a resolver snapshot", json.dumps(report))

    def test_scutil_snapshot_timestamp_must_be_within_overlap(self) -> None:
        self.manifest["resolver_snapshot_recorded_at_utc"] = "2026-11-06T15:10:00Z"
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn("scutil_dns_snapshot_outside_shared_capture_window",
                      report["coverage_issues"])

    def test_scutil_snapshot_timestamp_missing_is_not_verified(self) -> None:
        del self.manifest["resolver_snapshot_recorded_at_utc"]
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn("missing_scutil_dns_snapshot_recorded_at_utc",
                      report["coverage_issues"])

    def test_scutil_snapshot_timestamp_requires_timezone(self) -> None:
        self.manifest["resolver_snapshot_recorded_at_utc"] = "2026-11-06T15:00:20"
        with self.assertRaisesRegex(audit.AuditError, "timezone-aware"):
            audit.analyze_manifest(self.save_manifest())

    def test_scutil_snapshot_needs_actual_resolver_nameserver(self) -> None:
        (self.folder / "scutil-dns.txt").write_text(
            "DNS configuration\nresolver #1\n  flags : Request A records\n",
            encoding="utf-8"
        )
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn("unrecognized_scutil_dns_snapshot", report["coverage_issues"])

    def test_scutil_snapshot_lookalike_header_does_not_count(self) -> None:
        (self.folder / "scutil-dns.txt").write_text(
            "DNS configuration IS NOT FROM SCUTIL\n"
            "resolver #1\n"
            "nameserver[0] : 192.0.2.53\n",
            encoding="utf-8",
        )
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn("unrecognized_scutil_dns_snapshot", report["coverage_issues"])

    def test_scutil_snapshot_is_size_bounded(self) -> None:
        (self.folder / "scutil-dns.txt").write_bytes(b"x" * (4 * 1024 * 1024 + 1))
        with self.assertRaisesRegex(audit.AuditError, "scutil snapshot exceeds"):
            audit.analyze_manifest(self.save_manifest())

    def test_snapshot_metadata_is_limited_to_counts_not_server_addresses(self) -> None:
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["resolver_snapshot"]["resolver_sections"], 1)
        self.assertEqual(report["resolver_snapshot"]["nameserver_entries"], 1)
        self.assertNotIn("192.0.2.53", json.dumps(report))

    def test_scutil_scoped_physical_resolver_is_review_flag_not_leak_claim(self) -> None:
        (self.folder / "scutil-dns.txt").write_text(
            "DNS configuration\n"
            "resolver #1\n"
            "  nameserver[0] : 192.0.2.53\n"
            "  if_index : 17 (utun7)\n"
            "\nDNS configuration (for scoped queries)\n"
            "resolver #1\n"
            "  nameserver[0] : 192.0.2.1\n"
            "  if_index : 5 (en0)\n"
            "  flags : Scoped, Request A records\n",
            encoding="utf-8",
        )
        report = audit.analyze_manifest(self.save_manifest())
        snap = report["resolver_snapshot"]
        self.assertEqual(snap["resolver_sections"], 2)
        self.assertEqual(snap["scoped_resolvers"], 1)
        self.assertEqual(snap["physical_scoped_resolvers"], 1)
        self.assertIn("physical_scoped_dns_resolver_present", report["review_flags"])
        self.assertEqual(report["verdict"], "NO_PHYSICAL_CANARY_OBSERVED_IN_SUPPLIED_LOGS")
        self.assertFalse(report["system_zero_leak_verified"])
        self.assertNotIn("192.0.2.1", json.dumps(report))

    def test_scutil_scoped_utun_is_not_physical_resolver(self) -> None:
        (self.folder / "scutil-dns.txt").write_text(
            "DNS configuration\nresolver #1\n  nameserver[0] : 192.0.2.53\n"
            "DNS configuration (for scoped queries)\n"
            "resolver #1\n  nameserver[0] : 192.0.2.53\n"
            "  if_index : 17 (utun7)\n",
            encoding="utf-8",
        )
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["resolver_snapshot"]["physical_scoped_resolvers"], 0)
        self.assertNotIn("physical_scoped_dns_resolver_present", report["review_flags"])

    def test_scutil_scoped_resolver_without_interface_is_review_flag(self) -> None:
        (self.folder / "scutil-dns.txt").write_text(
            "DNS configuration\nresolver #1\n  nameserver[0] : 192.0.2.53\n"
            "DNS configuration (for scoped queries)\n"
            "resolver #1\n  nameserver[0] : 192.0.2.1\n"
            "  if_index : 5\n",
            encoding="utf-8",
        )
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["resolver_snapshot"]["unknown_scoped_interfaces"], 1)
        self.assertIn("scoped_resolver_interface_unknown", report["review_flags"])

    def test_scutil_scoped_flag_in_default_section_is_review_flag(self) -> None:
        (self.folder / "scutil-dns.txt").write_text(
            "DNS configuration\n"
            "resolver #1\n  nameserver[0] : 192.0.2.1\n"
            "  if_index : 5 (en0)\n"
            "  flags : Supplemental, Scoped, Request A records\n",
            encoding="utf-8",
        )
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["resolver_snapshot"]["physical_scoped_resolvers"], 1)
        self.assertIn("physical_scoped_dns_resolver_present", report["review_flags"])

    def test_unscoped_physical_resolver_is_not_mislabeled_scoped(self) -> None:
        (self.folder / "scutil-dns.txt").write_text(
            "DNS configuration\n"
            "resolver #1\n  nameserver[0] : 192.0.2.1\n"
            "  if_index : 5 (en0)\n  flags : Request A records\n",
            encoding="utf-8",
        )
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["resolver_snapshot"]["physical_scoped_resolvers"], 0)
        self.assertNotIn("physical_scoped_dns_resolver_present", report["review_flags"])

    def test_missing_scutil_snapshot_is_not_verified(self) -> None:
        del self.manifest["resolver_snapshot"]
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["verdict"], "NOT_VERIFIED")
        self.assertIn("missing_scutil_dns_resolver_snapshot", result["coverage_issues"])

    def test_positive_leak_outweighs_incomplete_capture(self) -> None:
        (self.folder / "en0.log").write_text(PHYSICAL_LEAK, encoding="utf-8")
        (self.folder / "utun7.log").write_text("", encoding="utf-8")
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["verdict"], "PHYSICAL_CANARY_PLAINTEXT_DNS_OBSERVED")
        self.assertIn("one_or_more_captures_have_no_packet_lines", result["coverage_issues"])

    def test_endpoint_details_are_opt_in(self) -> None:
        report = audit.analyze_manifest(self.save_manifest(), include_endpoints=True)
        self.assertIn("source_endpoint", report["canary_queries"][0])
        self.assertIn("destination_endpoint", report["canary_queries"][0])
        self.assertEqual(report["canary_queries"][0]["destination_endpoint"], "192.0.2.53.53")

    def test_oversized_manifest_rejected_before_json_parsing(self) -> None:
        path = self.folder / "oversized-manifest.json"
        path.write_bytes(b" " * (256 * 1024 + 1))
        with self.assertRaisesRegex(audit.AuditError, "manifest exceeds"):
            audit.analyze_manifest(path)

    def test_invalid_manifest_field_is_rejected_instead_of_ignored(self) -> None:
        self.manifest["coverage_complete"] = True
        with self.assertRaisesRegex(audit.AuditError, "unknown manifest fields"):
            audit.analyze_manifest(self.save_manifest())

    def test_invalid_canary_name_is_rejected(self) -> None:
        for name in ("", "*.example.test", "one", "example..test", "https://example.test",
                     "éxample.test", "-bad.example.test"):
            with self.subTest(name=name):
                self.manifest["canary_qname"] = name
                with self.assertRaises(audit.AuditError):
                    audit.analyze_manifest(self.save_manifest())

    def test_path_traversal_and_symlink_escape_rejected(self) -> None:
        self.manifest["captures"][0]["path"] = "../outside.log"
        with self.assertRaisesRegex(audit.AuditError, "paths must stay"):
            audit.analyze_manifest(self.save_manifest())
        external = self.folder.parent / (self.folder.name + "-external.log")
        external.write_text(PHYSICAL_NOISE, encoding="utf-8")
        self.addCleanup(external.unlink)
        (self.folder / "outside-link.log").symlink_to(external)
        self.manifest["captures"][0]["path"] = "outside-link.log"
        with self.assertRaisesRegex(audit.AuditError, "symlink leaves"):
            audit.analyze_manifest(self.save_manifest())

    def test_mislabeled_utun_must_not_be_treated_as_physical_capture(self) -> None:
        # A manifest role typo could invert a physical-leak verdict.
        self.manifest["expected_tun_interfaces"] = ["en9"]
        self.manifest["captures"][1]["interface"] = "en9"
        with self.assertRaisesRegex(audit.AuditError, "utun"):
            audit.analyze_manifest(self.save_manifest())

        self.manifest["expected_tun_interfaces"] = ["utun7"]
        self.manifest["captures"][1]["interface"] = "utun7"
        self.manifest["expected_physical_interfaces"] = ["utun7"]
        self.manifest["captures"][0]["interface"] = "utun7"
        with self.assertRaisesRegex(audit.AuditError, "physical"):
            audit.analyze_manifest(self.save_manifest())

    def test_hardlinked_capture_files_cannot_impersonate_two_interfaces(self) -> None:
        import os
        os.link(self.folder / "en0.log", self.folder / "same-bytes-other-name.log")
        self.manifest["captures"][1]["path"] = "same-bytes-other-name.log"
        with self.assertRaisesRegex(audit.AuditError, "same underlying"):
            audit.analyze_manifest(self.save_manifest())

    def test_duplicate_capture_file_and_interface_rejected(self) -> None:
        self.manifest["captures"][1]["path"] = "en0.log"
        with self.assertRaisesRegex(audit.AuditError, "file cannot represent"):
            audit.analyze_manifest(self.save_manifest())
        self.manifest["captures"][1] = self.manifest["captures"][0].copy()
        with self.assertRaisesRegex(audit.AuditError, "duplicate capture"):
            audit.analyze_manifest(self.save_manifest())

    def test_cli_writes_report_and_refuses_implicit_overwrite(self) -> None:
        manifest = self.save_manifest()
        output = self.folder / "audit-report.json"
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(audit.main([str(manifest), "--output", str(output)]), 0)
        self.assertIn("NO_PHYSICAL_CANARY_OBSERVED", out.getvalue())
        self.assertTrue(output.exists())
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(audit.main([str(manifest), "--output", str(output)]), 2)
        self.assertIn("File exists", err.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(audit.main([str(manifest), "--output", str(output), "--overwrite"]), 0)

    def test_report_file_is_private_and_cannot_overwrite_input_evidence(self) -> None:
        manifest = self.save_manifest()
        private_report = self.folder / "private-report.json"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(audit.main([str(manifest), "--output", str(private_report)]), 0)
        self.assertEqual(private_report.stat().st_mode & 0o777, 0o600)

        original = manifest.read_bytes()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(
                audit.main([str(manifest), "--output", str(manifest), "--overwrite"]), 2
            )
        self.assertEqual(manifest.read_bytes(), original)

        raw_capture = self.folder / "en0.log"
        capture_bytes = raw_capture.read_bytes()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(
                audit.main([str(manifest), "--output", str(raw_capture), "--overwrite"]), 2
            )
        self.assertEqual(raw_capture.read_bytes(), capture_bytes)

    def test_overwriting_report_symlink_does_not_modify_its_target(self) -> None:
        manifest = self.save_manifest()
        secret = self.folder / "private-note.txt"
        secret.write_text("keep me unchanged", encoding="utf-8")
        link = self.folder / "report-symlink.json"
        link.symlink_to(secret)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                audit.main([str(manifest), "--output", str(link), "--overwrite"]), 0
            )
        self.assertFalse(link.is_symlink())
        self.assertEqual(secret.read_text(encoding="utf-8"), "keep me unchanged")

    def test_cli_exits_nonzero_on_detected_leak_and_unverified(self) -> None:
        manifest = self.save_manifest()
        (self.folder / "en0.log").write_text(PHYSICAL_LEAK, encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(audit.main([str(manifest)]), 3)
        (self.folder / "en0.log").write_text("", encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(audit.main([str(manifest)]), 4)

    def test_multiline_verbose_tcpdump_canary_is_not_silently_ignored(self) -> None:
        # A -vv style header may split the IPv4 header from the address line.
        # The parser must refuse a negative result if this format appears.
        (self.folder / "en0.log").write_text(
            PHYSICAL_NOISE +
            "2026-11-06 07:00:02.000001 IP (tos 0x0, ttl 64, proto UDP (17), length 64)\n"
            "    192.0.2.50.51234 > 8.8.8.8.53: "
            "991+ A? canary.evidence.example.test. (52)\n",
            encoding="utf-8",
        )
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["verdict"], "NOT_VERIFIED")
        self.assertIn(
            "one_or_more_captures_have_unparsed_packet_or_canary_lines",
            result["coverage_issues"],
        )

    def test_unparsed_timestamped_ip_line_is_evidence_gap(self) -> None:
        (self.folder / "en0.log").write_text(
            PHYSICAL_NOISE +
            "2026-11-06 07:00:02.000001 IP (tos 0x0, ttl 64, proto UDP (17), length 64)\n",
            encoding="utf-8",
        )
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["verdict"], "NOT_VERIFIED")

    def test_unparsed_outbound_dns_payload_cannot_prove_no_leak(self) -> None:
        (self.folder / "en0.log").write_text(
            PHYSICAL_NOISE +
            "2026-11-06 07:00:02.000001 IP 192.0.2.50.51234 > 8.8.8.8.53: "
            "Flags [P.], seq 1:37, ack 1, win 256, length 36\n",
            encoding="utf-8",
        )
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["verdict"], "NOT_VERIFIED")
        self.assertIn(
            "one_or_more_captures_have_undecoded_dns_payloads",
            result["coverage_issues"],
        )
        self.assertEqual(result["captures"][0]["unparsed_dns_payload_lines"], 1)

    def test_tcp_syn_without_payload_does_not_mark_undecoded_dns(self) -> None:
        (self.folder / "en0.log").write_text(
            PHYSICAL_NOISE +
            "2026-11-06 07:00:02.000001 IP 192.0.2.50.51234 > 8.8.8.8.53: "
            "Flags [S], seq 1, win 256, length 0\n",
            encoding="utf-8",
        )
        (self.folder / "en0.stats.txt").write_text(
            "3 packets captured\n3 packets received by filter\n0 packets dropped by kernel\n",
            encoding="utf-8",
        )
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["verdict"], "NO_PHYSICAL_CANARY_OBSERVED_IN_SUPPLIED_LOGS")
        self.assertEqual(result["captures"][0]["unparsed_dns_payload_lines"], 0)

    def test_undecoded_udp_length_cannot_prove_no_leak(self) -> None:
        (self.folder / "en0.log").write_text(
            PHYSICAL_NOISE +
            "2026-11-06 07:00:02.000001 IP 192.0.2.50.51234 > 8.8.8.8.53: "
            "UDP, length 61\n",
            encoding="utf-8",
        )
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["verdict"], "NOT_VERIFIED")

    def test_manifest_mutated_during_analysis_is_rejected(self) -> None:
        import unittest.mock
        original = audit._load_manifest

        def mutate_after_read(path: Path) -> dict:
            manifest = original(path)
            path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            return manifest

        with unittest.mock.patch.object(audit, "_load_manifest", side_effect=mutate_after_read):
            with self.assertRaisesRegex(audit.AuditError, "manifest changed"):
                audit.analyze_manifest(self.save_manifest())

    def test_manifest_changed_between_analysis_and_report_write_is_rejected(self) -> None:
        import unittest.mock
        manifest = self.save_manifest()
        output = self.folder / "never-written.json"
        original = audit.analyze_manifest

        def mutate_after_analysis(path: Path, **kwargs: object) -> dict:
            result = original(path, **kwargs)
            path.write_text(json.dumps(self.manifest, indent=2), encoding="utf-8")
            return result

        with unittest.mock.patch.object(audit, "analyze_manifest",
                                        side_effect=mutate_after_analysis):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    audit.main([str(manifest), "--output", str(output)]), 2
                )
        self.assertFalse(output.exists())

    def test_capture_changed_after_analysis_cannot_be_saved_as_trusted_report(self) -> None:
        import unittest.mock
        manifest = self.save_manifest()
        output = self.folder / "must-not-exist.json"
        real_analysis = audit.analyze_manifest

        def change_capture_after_analysis(path: Path, **kwargs: object) -> dict:
            result = real_analysis(path, **kwargs)
            (self.folder / "en0.log").write_text(
                PHYSICAL_NOISE + PHYSICAL_LEAK, encoding="utf-8"
            )
            return result

        with unittest.mock.patch.object(
            audit, "analyze_manifest", side_effect=change_capture_after_analysis
        ):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    audit.main([str(manifest), "--output", str(output)]), 2
                )
        self.assertFalse(output.exists())

    def test_scutil_snapshot_changed_after_analysis_cannot_be_reported(self) -> None:
        import unittest.mock
        manifest = self.save_manifest()
        output = self.folder / "must-not-exist.json"
        real_analysis = audit.analyze_manifest

        def change_snapshot_after_analysis(path: Path, **kwargs: object) -> dict:
            result = real_analysis(path, **kwargs)
            (self.folder / "scutil-dns.txt").write_text(
                "modified snapshot after verification", encoding="utf-8"
            )
            return result

        with unittest.mock.patch.object(
            audit, "analyze_manifest", side_effect=change_snapshot_after_analysis
        ):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    audit.main([str(manifest), "--output", str(output)]), 2
                )
        self.assertFalse(output.exists())

    def test_report_limitations_are_separate_and_explicit(self) -> None:
        report = audit.analyze_manifest(self.save_manifest())
        limitations = report["limitations"]
        self.assertGreaterEqual(len(limitations), 5)
        self.assertTrue(any("scutil" in limitation for limitation in limitations))
        self.assertTrue(any("time" in limitation for limitation in limitations))
        self.assertTrue(any("DoH" in limitation for limitation in limitations))

    def test_capture_mutated_during_analysis_is_rejected(self) -> None:
        import unittest.mock
        original = audit.sha256_file

        def mutate_then_hash(path: Path) -> str:
            if path.name == "en0.log":
                path.write_text(PHYSICAL_NOISE + PHYSICAL_LEAK, encoding="utf-8")
            return original(path)

        with unittest.mock.patch.object(audit, "sha256_file", side_effect=mutate_then_hash):
            with self.assertRaisesRegex(audit.AuditError, "capture changed"):
                audit.analyze_manifest(self.save_manifest())

    def test_non_utf8_capture_is_invalid_evidence(self) -> None:
        (self.folder / "en0.log").write_bytes(b"2026-11-06 bad dns capture" + bytes([0xff, 0x80]))
        with self.assertRaisesRegex(audit.AuditError, "UTF-8"):
            audit.analyze_manifest(self.save_manifest())

    def test_no_network_socket_or_subprocess_is_ever_opened(self) -> None:
        # Offline pure file analysis. This test fails if executable logic
        # starts probing the environment (rather than reading evidence files).
        import unittest.mock
        with unittest.mock.patch("socket.socket", side_effect=AssertionError("network called")):
            with unittest.mock.patch("subprocess.run", side_effect=AssertionError("subprocess called")):
                result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["canary_query_counts"]["tun"], 2)


if __name__ == "__main__":
    unittest.main()
