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
    "125+ A? calibration.evidence.example.test. (44)\n"
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
            "tcpdump: listening on en0, link-type EN10MB (Ethernet)\n"
            "2 packets captured\n2 packets received by filter\n0 packets dropped by kernel\n",
            encoding="utf-8",
        )
        (self.folder / "utun7.stats.txt").write_text(
            "tcpdump: listening on utun7, link-type RAW\n"
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
            "physical_calibration_qname": "calibration.evidence.example.test",
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
        (self.folder / "en0.log").write_text(
            PHYSICAL_NOISE +
            "2026-11-06 07:00:00.000012 IP 192.0.2.90.50221 > 8.8.8.8.53: "
            "123+ A? unrelated.private.example. (50)\n", encoding="utf-8",
        )
        (self.folder / "en0.stats.txt").write_text(
            "tcpdump: listening on en0, link-type EN10MB (Ethernet)\n"
            "3 packets captured\n3 packets received by filter\n"
            "0 packets dropped by kernel\n", encoding="utf-8",
        )
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

    def test_calibration_is_required_for_negative_physical_egress_claim(self) -> None:
        del self.manifest["physical_calibration_qname"]
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn("missing_physical_calibration_qname", report["coverage_issues"])

    def test_wrong_calibration_domain_does_not_confirm_interface(self) -> None:
        self.manifest["physical_calibration_qname"] = "different-calibration.example.test"
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn("no_physical_calibration_observed:en0", report["coverage_issues"])

    def test_calibration_before_protected_stimulus_does_not_prove_overlap(self) -> None:
        # The physical NIC was active earlier; the protected query happened
        # later. An old calibration does not prove DNS visibility at that time.
        self.manifest["canary_stimulus_at_utc"] = "2026-11-06T15:00:02Z"
        (self.folder / "utun7.log").write_text(
            TUN_CANARY.replace("07:00:00.", "07:00:03."),
            encoding="utf-8",
        )
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["canary_queries_after_stimulus"]["tun"], 2)
        self.assertEqual(result["verdict"], "NOT_VERIFIED")
        self.assertIn(
            "no_physical_calibration_observed:en0", result["coverage_issues"]
        )

    def test_calibration_and_protected_canary_must_be_distinct(self) -> None:
        self.manifest["physical_calibration_qname"] = CANARY
        with self.assertRaisesRegex(audit.AuditError, "distinct"):
            audit.analyze_manifest(self.save_manifest())

    def test_invalid_calibration_qname_is_rejected(self) -> None:
        self.manifest["physical_calibration_qname"] = "*.not-dns.example.test"
        with self.assertRaises(audit.AuditError):
            audit.analyze_manifest(self.save_manifest())

    def test_explicit_physical_calibration_is_counted_without_exposing_endpoints(self) -> None:
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["physical_calibration_counts"], {"en0": 1})
        self.assertEqual(
            report["physical_calibration_qname_sha256"],
            hashlib.sha256(b"calibration.evidence.example.test").hexdigest(),
        )
        self.assertNotIn("calibration.evidence.example.test", json.dumps(report))
        self.assertEqual(report["verdict"], "NO_PHYSICAL_CANARY_OBSERVED_IN_SUPPLIED_LOGS")
        self.assertNotIn("9.9.9.9", json.dumps(report))
        self.assertNotIn("192.0.2.11", json.dumps(report))

    def test_positive_physical_canary_not_hidden_by_missing_calibration(self) -> None:
        del self.manifest["physical_calibration_qname"]
        (self.folder / "en0.log").write_text(PHYSICAL_LEAK, encoding="utf-8")
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "PHYSICAL_CANARY_PLAINTEXT_DNS_OBSERVED")

    def test_missing_physical_interface_is_not_verified(self) -> None:
        self.manifest["expected_physical_interfaces"].append("en1")
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["verdict"], "NOT_VERIFIED")
        self.assertIn("missing_physical_capture:en1", result["coverage_issues"])

    def test_double_trailing_dot_in_physical_calibration_cannot_confirm_coverage(self) -> None:
        (self.folder / "en0.log").write_text(
            PHYSICAL_NOISE.replace(
                "calibration.evidence.example.test.",
                "calibration.evidence.example.test..",
            ),
            encoding="utf-8",
        )
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["verdict"], "NOT_VERIFIED")
        self.assertIn("no_physical_calibration_observed:en0", result["coverage_issues"])

    def test_double_trailing_dot_in_tun_canary_cannot_count_as_query(self) -> None:
        (self.folder / "utun7.log").write_text(
            TUN_CANARY.replace(
                "CAnary.Evidence.Example.Test.",
                "CAnary.Evidence.Example.Test..",
            ).replace(
                "canary.evidence.example.test.",
                "canary.evidence.example.test..",
            ),
            encoding="utf-8",
        )
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["verdict"], "NOT_VERIFIED")
        self.assertEqual(result["canary_queries_after_stimulus"]["tun"], 0)

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

    def test_tcpdump_statistics_must_bind_to_declared_interface(self) -> None:
        (self.folder / "en0.stats.txt").write_text(
            "tcpdump: listening on en1, link-type EN10MB (Ethernet)\n"
            "2 packets captured\n2 packets received by filter\n"
            "0 packets dropped by kernel\n", encoding="utf-8"
        )
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn(
            "tcpdump_stats_interface_unconfirmed:physical:en0",
            report["coverage_issues"],
        )

    def test_tcpdump_statistics_without_interface_header_not_verified(self) -> None:
        (self.folder / "en0.stats.txt").write_text(
            "2 packets captured\n2 packets received by filter\n"
            "0 packets dropped by kernel\n", encoding="utf-8"
        )
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn(
            "tcpdump_stats_interface_unconfirmed:physical:en0",
            report["coverage_issues"],
        )

    def test_tcpdump_interface_binding_is_reported_without_raw_stderr(self) -> None:
        report = audit.analyze_manifest(self.save_manifest())
        self.assertTrue(report["captures"][0]["tcpdump_stats"]["interface_confirmed"])
        self.assertTrue(report["captures"][1]["tcpdump_stats"]["interface_confirmed"])
        self.assertNotIn("tcpdump: listening on", json.dumps(report))

    def test_two_independent_physical_interfaces_are_analyzed(self) -> None:
        self.manifest["expected_physical_interfaces"].append("en1")
        self.manifest["captures"].append({
            "role": "physical",
            "interface": "en1",
            "path": "en1.log",
            "tcpdump_stats_path": "en1.stats.txt",
            "started_at_utc": "2026-11-06T15:00:00Z",
            "ended_at_utc": "2026-11-06T15:04:00Z",
            "packet_time_utc_offset": "-08:00",
        })
        (self.folder / "en1.log").write_text(
            "2026-11-06 07:00:00.000010 IP 192.0.2.80.53004 > 9.9.9.9.53: "
            "122+ A? calibration.evidence.example.test. (44)\n", encoding="utf-8",
        )
        (self.folder / "en1.stats.txt").write_text(
            "tcpdump: listening on en1, link-type EN10MB (Ethernet)\n"
            "1 packet captured\n1 packet received by filter\n"
            "0 packets dropped by kernel\n", encoding="utf-8",
        )
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["verdict"], "NO_PHYSICAL_CANARY_OBSERVED_IN_SUPPLIED_LOGS")
        self.assertEqual(result["canary_query_counts"], {"physical": 0, "tun": 2})
        self.assertEqual(result["coverage_issues"], [])

    def test_second_physical_nic_canary_remains_positive_evidence(self) -> None:
        self.manifest["expected_physical_interfaces"].append("en1")
        self.manifest["captures"].append({
            "role": "physical", "interface": "en1", "path": "en1.log",
            "tcpdump_stats_path": "en1.stats.txt",
            "started_at_utc": "2026-11-06T15:00:00Z",
            "ended_at_utc": "2026-11-06T15:04:00Z",
            "packet_time_utc_offset": "-08:00",
        })
        (self.folder / "en1.log").write_text(
            "2026-11-06 07:00:00.000009 IP 192.0.2.90.50002 > 9.9.9.9.53: "
            "100+ A? calibration.evidence.example.test. (55)\n"
            "2026-11-06 07:00:00.000010 IP6 2001:db8::9.50003 > "
            "2001:4860:4860::8888.53: 101+ AAAA? "
            "canary.evidence.example.test. (55)\n", encoding="utf-8",
        )
        (self.folder / "en1.stats.txt").write_text(
            "tcpdump: listening on en1, link-type EN10MB (Ethernet)\n"
            "2 packets captured\n2 packets received by filter\n"
            "0 packets dropped by kernel\n", encoding="utf-8",
        )
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["verdict"], "PHYSICAL_CANARY_PLAINTEXT_DNS_OBSERVED")
        self.assertEqual(result["canary_query_counts"], {"physical": 1, "tun": 2})
        self.assertEqual(result["coverage_issues"], [])
        self.assertEqual(result["canary_queries"][-1]["interface"], "en1")

    def test_physical_query_not_hidden_by_mismatched_tcpdump_header(self) -> None:
        (self.folder / "en0.log").write_text(PHYSICAL_LEAK, encoding="utf-8")
        (self.folder / "en0.stats.txt").write_text(
            "tcpdump: listening on en1, link-type EN10MB (Ethernet)\n"
            "2 packets captured\n2 packets received by filter\n"
            "0 packets dropped by kernel\n", encoding="utf-8",
        )
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["verdict"], "PHYSICAL_CANARY_PLAINTEXT_DNS_OBSERVED")
        self.assertIn(
            "tcpdump_stats_interface_unconfirmed:physical:en0",
            result["coverage_issues"],
        )

    def test_copied_packet_log_cannot_be_used_for_second_nic(self) -> None:
        self.manifest["expected_physical_interfaces"].append("en1")
        self.manifest["captures"].append({
            "role": "physical", "interface": "en1", "path": "en1.log",
            "tcpdump_stats_path": "en1.stats.txt",
            "started_at_utc": "2026-11-06T15:00:00Z",
            "ended_at_utc": "2026-11-06T15:04:00Z",
            "packet_time_utc_offset": "-08:00",
        })
        (self.folder / "en1.log").write_bytes((self.folder / "en0.log").read_bytes())
        (self.folder / "en1.stats.txt").write_text(
            "tcpdump: listening on en1, link-type EN10MB (Ethernet)\n"
            "2 packets captured\n2 packets received by filter\n"
            "0 packets dropped by kernel\n", encoding="utf-8",
        )
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["verdict"], "NOT_VERIFIED")
        self.assertIn("identical_capture_content_across_interfaces",
                      result["coverage_issues"])

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

    def test_received_by_filter_must_be_reported_for_negative_evidence(self) -> None:
        (self.folder / "en0.stats.txt").write_text(
            "tcpdump: listening on en0, link-type EN10MB (Ethernet)\n"
            "2 packets captured\n0 packets dropped by kernel\n",
            encoding="utf-8",
        )
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn("incomplete_tcpdump_stats:physical:en0", report["coverage_issues"])

    def test_received_count_mismatch_is_an_evidence_gap(self) -> None:
        for count in (1, 3):
            with self.subTest(received=count):
                (self.folder / "en0.stats.txt").write_text(
                    "tcpdump: listening on en0, link-type EN10MB (Ethernet)\n"
                    f"2 packets captured\n{count} packets received by filter\n"
                    "0 packets dropped by kernel\n", encoding="utf-8",
                )
                report = audit.analyze_manifest(self.save_manifest())
                self.assertEqual(report["verdict"], "NOT_VERIFIED")
                self.assertIn(
                    "tcpdump_filter_count_inconsistent:physical:en0",
                    report["coverage_issues"],
                )

    def test_mixed_dns_and_http_packets_in_capture_are_not_verified(self) -> None:
        (self.folder / "en0.log").write_text(
            PHYSICAL_NOISE +
            "2026-11-06 07:00:00.000010 IP 192.0.2.80.45678 > 192.0.2.81.443: "
            "Flags [P.], seq 1:20, ack 1, length 19\n", encoding="utf-8",
        )
        (self.folder / "en0.stats.txt").write_text(
            "tcpdump: listening on en0, link-type EN10MB (Ethernet)\n"
            "3 packets captured\n3 packets received by filter\n"
            "0 packets dropped by kernel\n", encoding="utf-8",
        )
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn(
            "one_or_more_captures_have_non_port53_packets",
            report["coverage_issues"],
        )
        self.assertEqual(report["captures"][0]["non_port53_packet_lines"], 1)

    def test_inbound_only_dns_replies_do_not_prove_outgoing_dns_coverage(self) -> None:
        (self.folder / "en0.log").write_text(
            "2026-11-06 07:00:00.000010 IP 9.9.9.9.53 > 192.0.2.80.34567: "
            "120 1/0/0 A 203.0.113.1 (64)\n", encoding="utf-8",
        )
        (self.folder / "en0.stats.txt").write_text(
            "tcpdump: listening on en0, link-type EN10MB (Ethernet)\n"
            "1 packet captured\n1 packet received by filter\n"
            "0 packets dropped by kernel\n", encoding="utf-8",
        )
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn(
            "one_or_more_physical_captures_lack_outgoing_port53_packets",
            report["coverage_issues"],
        )

    def test_physical_canary_is_reported_even_with_unfiltered_packets(self) -> None:
        (self.folder / "en0.log").write_text(
            PHYSICAL_LEAK +
            "2026-11-06 07:00:00.000010 IP 192.0.2.80.45678 > 192.0.2.81.443: "
            "Flags [P.], seq 1:20, ack 1, length 19\n", encoding="utf-8",
        )
        (self.folder / "en0.stats.txt").write_text(
            "tcpdump: listening on en0, link-type EN10MB (Ethernet)\n"
            "3 packets captured\n3 packets received by filter\n"
            "0 packets dropped by kernel\n", encoding="utf-8",
        )
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "PHYSICAL_CANARY_PLAINTEXT_DNS_OBSERVED")
        self.assertIn(
            "one_or_more_captures_have_non_port53_packets",
            report["coverage_issues"],
        )

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

    def test_boolean_schema_version_is_not_integer_version_1(self) -> None:
        self.manifest["schema_version"] = True
        with self.assertRaisesRegex(audit.AuditError, "schema_version"):
            audit.analyze_manifest(self.save_manifest())

    def test_duplicate_top_level_json_keys_are_rejected(self) -> None:
        manifest = self.save_manifest()
        raw = manifest.read_text(encoding="utf-8")
        original = '"case_id": "wifi_up_ipv4_ipv6"'
        self.assertIn(original, raw)
        manifest.write_text(raw.replace(
            original, '"case_id": "shadow", "case_id": "wifi_up_ipv4_ipv6"'
        ), encoding="utf-8")
        with self.assertRaisesRegex(audit.AuditError, "duplicate JSON"):
            audit.analyze_manifest(manifest)

    def test_deeply_nested_json_rejected_without_unhandled_recursion_error(self) -> None:
        manifest = self.save_manifest()
        manifest.write_text(
            '{"schema_version":1,"unused":' + "[" * 2000 + "0" + "]" * 2000 + "}",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(audit.AuditError, "nested JSON"):
            audit.analyze_manifest(manifest)

    def test_oversized_json_integer_rejected_before_parsing(self) -> None:
        manifest = self.save_manifest()
        raw = manifest.read_text(encoding="utf-8")
        raw = raw.replace('"canary_observation_deadline_seconds": 30',
                          '"canary_observation_deadline_seconds": ' + "9" * 5000)
        manifest.write_text(raw, encoding="utf-8")
        with self.assertRaisesRegex(audit.AuditError, "JSON integer exceeds"):
            audit.analyze_manifest(manifest)

    def test_floating_point_json_is_invalid_audit_evidence(self) -> None:
        manifest = self.save_manifest()
        raw = manifest.read_text(encoding="utf-8")
        raw = raw.replace('"canary_observation_deadline_seconds": 30',
                          '"canary_observation_deadline_seconds": 1.5')
        manifest.write_text(raw, encoding="utf-8")
        with self.assertRaisesRegex(audit.AuditError, "floating-point JSON"):
            audit.analyze_manifest(manifest)

    def test_nonstandard_json_nan_is_rejected(self) -> None:
        path = self.save_manifest()
        raw = path.read_text(encoding="utf-8")
        self.assertIn('"canary_observation_deadline_seconds": 30', raw)
        path.write_text(
            raw.replace('"canary_observation_deadline_seconds": 30',
                        '"canary_observation_deadline_seconds": NaN'),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(audit.AuditError, "nonstandard JSON"):
            audit.analyze_manifest(path)

    def test_duplicate_nested_capture_json_keys_are_rejected(self) -> None:
        manifest = self.save_manifest()
        raw = manifest.read_text(encoding="utf-8")
        first = '"role": "physical"'
        self.assertIn(first, raw)
        manifest.write_text(
            raw.replace(first, '"role": "tun", "role": "physical"', 1),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(audit.AuditError, "duplicate JSON"):
            audit.analyze_manifest(manifest)

    def test_excessive_tcpdump_counter_digits_are_incomplete_evidence(self) -> None:
        (self.folder / "en0.stats.txt").write_text(
            "tcpdump: listening on en0, link-type EN10MB (Ethernet)\n"
            + ("9" * 5000) +
            " packets captured\n2 packets received by filter\n"
            "0 packets dropped by kernel\n",
            encoding="utf-8",
        )
        result = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(result["verdict"], "NOT_VERIFIED")
        self.assertIn("incomplete_tcpdump_stats:physical:en0", result["coverage_issues"])

    def test_invalid_manifest_field_is_rejected_instead_of_ignored(self) -> None:
        self.manifest["coverage_complete"] = True
        with self.assertRaisesRegex(audit.AuditError, "unknown manifest fields"):
            audit.analyze_manifest(self.save_manifest())

    def test_multiple_trailing_root_dots_are_invalid_dns_names(self) -> None:
        self.manifest["canary_qname"] = "canary.evidence.example.test.."
        with self.assertRaisesRegex(audit.AuditError, "trailing"):
            audit.analyze_manifest(self.save_manifest())
        self.manifest["canary_qname"] = CANARY
        self.manifest["physical_calibration_qname"] = "calibration.evidence.example.test.."
        with self.assertRaisesRegex(audit.AuditError, "trailing"):
            audit.analyze_manifest(self.save_manifest())

    def test_one_optional_terminal_root_dot_remains_valid(self) -> None:
        self.manifest["canary_qname"] = CANARY + "."
        self.manifest["physical_calibration_qname"] = "calibration.evidence.example.test."
        report = audit.analyze_manifest(self.save_manifest())
        self.assertEqual(report["verdict"], "NO_PHYSICAL_CANARY_OBSERVED_IN_SUPPLIED_LOGS")
        self.assertEqual(report["canary_qname"], CANARY)

    def test_invalid_canary_name_is_rejected(self) -> None:
        for name in ("", "*.example.test", "one", "example..test", "https://example.test",
                     "éxample.test", "-bad.example.test"):
            with self.subTest(name=name):
                self.manifest["canary_qname"] = name
                with self.assertRaises(audit.AuditError):
                    audit.analyze_manifest(self.save_manifest())

    def test_excessively_long_evidence_filename_is_auditable_error(self) -> None:
        self.manifest["resolver_snapshot"] = "x" * 300
        with self.assertRaisesRegex(audit.AuditError, "path component exceeds"):
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
            "tcpdump: listening on en0, link-type EN10MB (Ethernet)\n"
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

    def test_hashing_cannot_continue_past_global_evidence_limit(self) -> None:
        from unittest.mock import patch
        candidate = self.folder / "oversized-for-hash.txt"
        candidate.write_bytes(b"0123456789")
        with patch.object(audit, "MAX_CAPTURE_BYTES", 8):
            with self.assertRaisesRegex(audit.AuditError, "hashing exceeds"):
                audit.sha256_file(candidate)

    def test_bounded_file_reader_enforces_cap_at_actual_read(self) -> None:
        path = self.folder / "growing-evidence.txt"
        path.write_bytes(b"123456789")
        with self.assertRaisesRegex(audit.AuditError, "exceeds test limit"):
            audit.read_bounded_bytes(path, 8, "evidence exceeds test limit")
        self.assertEqual(
            audit.read_bounded_bytes(path, 9, "evidence exceeds test limit"),
            b"123456789",
        )

    def test_capture_size_limit_is_checked_while_streaming(self) -> None:
        # Simulate a capture that passed an earlier size precheck but grew
        # before the stream was consumed, without writing 128 MiB in tests.
        from unittest.mock import patch
        manifest = self.save_manifest()
        def accepted_path(folder: Path, name: str) -> Path:
            return (folder / name).resolve()
        with patch.object(audit, "MAX_CAPTURE_BYTES", 50):
            with patch.object(audit, "evidence_path", side_effect=accepted_path):
                with self.assertRaisesRegex(audit.AuditError, "capture exceeds"):
                    audit.analyze_manifest(manifest)

    def test_nul_bytes_in_capture_are_rejected_as_nontext_evidence(self) -> None:
        path = self.folder / "en0.log"
        path.write_bytes(path.read_bytes() + b"\x00")
        with self.assertRaisesRegex(audit.AuditError, "NUL"):
            audit.analyze_manifest(self.save_manifest())

    def test_nul_bytes_in_tcpdump_stats_are_rejected(self) -> None:
        path = self.folder / "en0.stats.txt"
        path.write_bytes(path.read_bytes() + b"\x00")
        with self.assertRaisesRegex(audit.AuditError, "NUL"):
            audit.analyze_manifest(self.save_manifest())

    def test_nul_bytes_in_scutil_snapshot_are_rejected(self) -> None:
        path = self.folder / "scutil-dns.txt"
        path.write_bytes(path.read_bytes() + b"\x00")
        with self.assertRaisesRegex(audit.AuditError, "NUL"):
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
