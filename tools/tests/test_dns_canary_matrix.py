#!/usr/bin/env python3
"""All-offline regression tests for a multi-case macOS DNS canary matrix."""
from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import dns_canary_matrix as matrix  # noqa: E402
import dns_canary_audit as audit  # noqa: E402


EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "dns_canary"


class MatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        for ident, sample in [
            ("wifi", "manifest.json"),
            ("tcp53", "manifest.json"),
            ("ipv6", "manifest.json"),
        ]:
            directory = self.folder / ident
            directory.mkdir()
            for name in (
                "en0.txt", "utun7.txt", "scutil-dns.txt",
                "en0.stats.txt", "utun7.stats.txt",
            ):
                shutil.copyfile(EXAMPLES / name, directory / name)
            manifest = json.loads((EXAMPLES / sample).read_text(encoding="utf-8"))
            manifest["case_id"] = ident
            (directory / "manifest.json").write_text(
                json.dumps(manifest, indent=2) + "\n", encoding="utf-8",
            )
        self.matrix = {
            "schema_version": 1,
            "matrix_id": "dns_synthetic_acceptance",
            "required_cases": ["wifi", "tcp53", "ipv6"],
            "cases": [
                {"case_id": ident, "manifest": f"{ident}/manifest.json"}
                for ident in ("wifi", "tcp53", "ipv6")
            ],
        }

    def write_matrix(self) -> Path:
        path = self.folder / "matrix.json"
        path.write_text(json.dumps(self.matrix, indent=2) + "\n", encoding="utf-8")
        return path

    def change_case(self, ident: str, name: str, content: str) -> None:
        (self.folder / ident / name).write_text(content, encoding="utf-8")

    def test_clean_user_declared_matrix_cannot_claim_system_zero_leak(self) -> None:
        report = matrix.analyze_matrix(self.write_matrix())
        self.assertEqual(report["verdict"], "NO_PHYSICAL_CANARY_OBSERVED_IN_SUPPLIED_CASES")
        self.assertFalse(report["system_zero_leak_verified"])
        self.assertEqual(report["case_counts"]["no_physical_observed"], 3)
        self.assertEqual(report["case_counts"]["unverified"], 0)
        self.assertEqual(report["case_counts"]["physical_observed"], 0)
        self.assertEqual(report["missing_cases"], [])
        self.assertEqual([x["case_id"] for x in report["cases"]], ["wifi", "tcp53", "ipv6"])
        self.assertNotIn("canary.evidence.example.test", json.dumps(report))
        self.assertNotIn("192.0.2.53", json.dumps(report))
        self.assertEqual(len(report["matrix_sha256"]), 64)
        for case in report["cases"]:
            self.assertEqual(case["canary_queries_after_stimulus"], {"physical": 0, "tun": 2})
            self.assertEqual(case["observed_canary_protocols"]["physical"], [])
            self.assertEqual(case["observed_canary_protocols"]["tun"], [
                {"ip_family": "ipv4", "transport": "udp", "qtype": "A", "count": 1},
                {"ip_family": "ipv6", "transport": "tcp", "qtype": "AAAA", "count": 1},
            ])

    def test_missing_required_case_makes_matrix_unverified(self) -> None:
        self.matrix["cases"].pop()
        report = matrix.analyze_matrix(self.write_matrix())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertEqual(report["missing_cases"], ["ipv6"])
        self.assertEqual(report["case_counts"]["no_physical_observed"], 2)

    def test_unverified_child_case_makes_matrix_unverified(self) -> None:
        manifest = self.folder / "tcp53" / "manifest.json"
        original = json.loads(manifest.read_text())
        original["expected_physical_interfaces"].append("en1")
        manifest.write_text(json.dumps(original), encoding="utf-8")
        report = matrix.analyze_matrix(self.write_matrix())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertEqual(report["case_counts"]["unverified"], 1)
        self.assertEqual(report["cases"][1]["verdict"], "NOT_VERIFIED")
        self.assertNotIn("192.0.2.53", json.dumps(report))

    def test_physical_canary_wins_over_unverified_and_missing_cases(self) -> None:
        self.matrix["cases"].pop()
        self.change_case(
            "wifi", "en0.txt",
            "2026-11-06 07:00:00.000001 IP 192.0.2.50.51234 > 8.8.8.8.53: "
            "42+ A? canary.evidence.example.test. (53)\n"
            "2026-11-06 07:00:00.000002 IP6 2001:db8::2.53000 > "
            "2001:4860:4860::8888.53: "
            "44+ AAAA? canary.evidence.example.test. (61)\n",
        )
        report = matrix.analyze_matrix(self.write_matrix())
        self.assertEqual(report["verdict"], "PHYSICAL_CANARY_PLAINTEXT_DNS_OBSERVED")
        self.assertEqual(report["missing_cases"], ["ipv6"])
        self.assertEqual(report["case_counts"]["physical_observed"], 1)
        self.assertEqual(report["cases"][0]["observed_canary_protocols"]["physical"], [
            {"ip_family": "ipv4", "transport": "udp", "qtype": "A", "count": 1},
            {"ip_family": "ipv6", "transport": "udp", "qtype": "AAAA", "count": 1},
        ])
        self.assertFalse(report["system_zero_leak_verified"])

    def test_builtin_macos_profile_cannot_be_self_declared_complete_with_wifi_only(self) -> None:
        self.matrix["profile"] = "macos_dns_egress_v1"
        self.matrix["required_cases"] = ["wifi"]
        self.matrix["cases"] = self.matrix["cases"][:1]
        report = matrix.analyze_matrix(self.write_matrix())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertEqual(report["profile"], "macos_dns_egress_v1")
        self.assertIn("tcp_53", report["missing_profile_cases"])
        self.assertIn("sleep_resume", report["missing_profile_cases"])
        self.assertIn("tun_or_dns_proxy_unavailable", report["missing_profile_cases"])
        self.assertFalse(report["system_zero_leak_verified"])

    def test_builtin_profile_scenarios_are_required_even_if_user_omits_them(self) -> None:
        self.matrix["profile"] = "macos_dns_egress_v1"
        report = matrix.analyze_matrix(self.write_matrix())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertGreaterEqual(len(report["missing_profile_cases"]), 5)

    def test_builtin_profile_reused_canary_and_captures_are_not_complete(self) -> None:
        # Merely copying one positive-looking capture into seven different
        # folder names must not satisfy the builtin acceptance checklist.
        self.matrix["profile"] = "macos_dns_egress_v1"
        self.matrix["required_cases"] = list(matrix.MACOS_DNS_EGRESS_V1)
        self.matrix["cases"] = []
        for scenario in matrix.MACOS_DNS_EGRESS_V1:
            destination = self.folder / scenario
            shutil.copytree(self.folder / "wifi", destination, dirs_exist_ok=True)
            child_path = destination / "manifest.json"
            child = json.loads(child_path.read_text(encoding="utf-8"))
            child["case_id"] = scenario
            child_path.write_text(json.dumps(child, indent=2), encoding="utf-8")
            self.matrix["cases"].append({
                "case_id": scenario, "manifest": f"{scenario}/manifest.json"
            })
        result = matrix.analyze_matrix(self.write_matrix())
        self.assertEqual(result["missing_profile_cases"], [])
        self.assertEqual(result["case_counts"]["no_physical_observed"], 7)
        self.assertEqual(result["verdict"], "NOT_VERIFIED")
        self.assertIn(
            "profile_reused_canary_qname", result["profile_evidence_issues"]
        )
        self.assertIn(
            "profile_reused_capture_bytes", result["profile_evidence_issues"]
        )
        self.assertIn(
            "profile_reused_stimulus_timestamp",
            result["profile_evidence_issues"],
        )
        self.assertNotIn("canary.evidence.example.test", json.dumps(result))

    def test_builtin_profile_checks_actual_dns_question_and_transport(self) -> None:
        # A human case label is insufficient: a purported TCP/53 case with
        # only UDP evidence, or an IPv6 case with only IPv4, cannot pass.
        for scenario, required_issue in (
            ("wifi_a_aaaa", "profile_wifi_a_aaaa_questions_missing"),
            ("tcp_53", "profile_tcp_53_tun_query_missing"),
            ("ipv6", "profile_ipv6_tun_question_missing"),
        ):
            with self.subTest(scenario=scenario):
                target = self.folder / scenario
                shutil.copytree(self.folder / "wifi", target, dirs_exist_ok=True)
                target_manifest = target / "manifest.json"
                child = json.loads(target_manifest.read_text(encoding="utf-8"))
                child["case_id"] = scenario
                target_manifest.write_text(json.dumps(child), encoding="utf-8")
                self.change_case(
                    scenario, "utun7.txt",
                    "2026-11-06 07:00:00.000003 IP 192.0.2.50.58899 > "
                    "192.0.2.53.53: 841+ A? canary.evidence.example.test. (68)\n",
                )
                self.change_case(
                    scenario, "utun7.stats.txt",
                    "tcpdump: listening on utun7, link-type RAW\n"
                    "1 packet captured\n1 packet received by filter\n"
                    "0 packets dropped by kernel\n",
                )
                self.matrix["profile"] = "macos_dns_egress_v1"
                self.matrix["required_cases"] = [scenario]
                self.matrix["cases"] = [
                    {"case_id": scenario, "manifest": f"{scenario}/manifest.json"}
                ]
                result = matrix.analyze_matrix(self.write_matrix())
                self.assertEqual(result["case_counts"]["no_physical_observed"], 1)
                self.assertIn(required_issue, result["profile_evidence_issues"])
                self.assertEqual(result["verdict"], "NOT_VERIFIED")

    def test_distinct_synthetic_profile_cases_only_prove_supplied_logs(self) -> None:
        # Seven distinct *synthetic* captures exercise the shape of a full
        # profile. They do not prove the named OS events actually happened.
        self.matrix["profile"] = "macos_dns_egress_v1"
        self.matrix["required_cases"] = list(matrix.MACOS_DNS_EGRESS_V1)
        self.matrix["cases"] = []
        for i, scenario in enumerate(matrix.MACOS_DNS_EGRESS_V1, start=1):
            destination = self.folder / scenario
            shutil.copytree(self.folder / "wifi", destination, dirs_exist_ok=True)
            manifest_path = destination / "manifest.json"
            child = json.loads(manifest_path.read_text(encoding="utf-8"))
            child["case_id"] = scenario
            child["canary_qname"] = f"canary-{i}.evidence.example.test"
            child["physical_calibration_qname"] = f"calibration-{i}.evidence.example.test"
            child["canary_stimulus_at_utc"] = f"2026-11-06T15:00:{i:02d}Z"
            child["resolver_snapshot_recorded_at_utc"] = "2026-11-06T15:00:20Z"
            manifest_path.write_text(json.dumps(child), encoding="utf-8")
            (destination / "utun7.txt").write_text(
                (destination / "utun7.txt").read_text()
                .replace("canary.evidence.example.test", f"canary-{i}.evidence.example.test")
                .replace("07:00:00.", f"07:00:{i:02d}."),
                encoding="utf-8",
            )
            (destination / "en0.txt").write_text(
                (destination / "en0.txt").read_text()
                .replace("calibration.evidence.example.test", f"calibration-{i}.evidence.example.test")
                .replace("07:00:00.", f"07:00:{i:02d}."),
                encoding="utf-8",
            )
            self.matrix["cases"].append({
                "case_id": scenario, "manifest": f"{scenario}/manifest.json",
            })
        report = matrix.analyze_matrix(self.write_matrix())
        self.assertEqual(report["missing_profile_cases"], [])
        self.assertEqual(report["profile_evidence_issues"], [])
        self.assertEqual(report["case_counts"]["no_physical_observed"], 7)
        self.assertEqual(report["verdict"], "NO_PHYSICAL_CANARY_OBSERVED_IN_SUPPLIED_CASES")
        self.assertFalse(report["system_zero_leak_verified"])
        self.assertTrue(any("operator" in item for item in report["limitations"]))
        self.assertNotIn("canary-1.evidence.example.test", json.dumps(report))

    def test_profile_reused_physical_calibration_name_is_not_fresh_evidence(self) -> None:
        # Two independent captures, unique protected canaries and timestamps,
        # but intentionally the SAME physical calibration domain.
        second = self.folder / "tcp53"
        manifest_path = second / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["canary_qname"] = "another-canary.evidence.example.test"
        manifest["canary_stimulus_at_utc"] = "2026-11-06T15:00:01Z"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        (second / "utun7.txt").write_text(
            (second / "utun7.txt").read_text()
            .replace("canary.evidence.example.test", "another-canary.evidence.example.test")
            .replace("07:00:00.", "07:00:01."),
            encoding="utf-8",
        )
        (second / "en0.txt").write_text(
            (second / "en0.txt").read_text().replace("07:00:00.", "07:00:01."),
            encoding="utf-8",
        )
        self.matrix["profile"] = "macos_dns_egress_v1"
        self.matrix["required_cases"] = ["wifi", "tcp53"]
        self.matrix["cases"] = self.matrix["cases"][:2]
        report = matrix.analyze_matrix(self.write_matrix())
        self.assertEqual(report["case_counts"]["no_physical_observed"], 2)
        self.assertIn(
            "profile_reused_physical_calibration_qname",
            report["profile_evidence_issues"],
        )

    def test_unrecognized_profile_is_rejected(self) -> None:
        self.matrix["profile"] = "ignore_missing_cases"
        with self.assertRaisesRegex(audit.AuditError, "profile"):
            matrix.analyze_matrix(self.write_matrix())

    def test_duplicate_case_identifiers_rejected(self) -> None:
        self.matrix["cases"].append(self.matrix["cases"][0])
        with self.assertRaisesRegex(audit.AuditError, "duplicate"):
            matrix.analyze_matrix(self.write_matrix())

    def test_required_case_ids_must_be_unique(self) -> None:
        self.matrix["required_cases"].append("wifi")
        with self.assertRaisesRegex(audit.AuditError, "duplicate"):
            matrix.analyze_matrix(self.write_matrix())

    def test_untrusted_case_id_mismatch_fails_instead_of_silently_remapping(self) -> None:
        self.matrix["cases"][0]["case_id"] = "pretend_wifi"
        with self.assertRaisesRegex(audit.AuditError, "case_id"):
            matrix.analyze_matrix(self.write_matrix())

    def test_boolean_schema_version_is_rejected(self) -> None:
        self.matrix["schema_version"] = True
        with self.assertRaisesRegex(audit.AuditError, "schema_version"):
            matrix.analyze_matrix(self.write_matrix())

    def test_duplicate_matrix_profile_key_is_rejected(self) -> None:
        self.matrix["profile"] = "macos_dns_egress_v1"
        path = self.write_matrix()
        raw = path.read_text(encoding="utf-8")
        self.assertIn('"profile": "macos_dns_egress_v1"', raw)
        path.write_text(raw.replace(
            '"profile": "macos_dns_egress_v1"',
            '"profile": "unsupported", "profile": "macos_dns_egress_v1"',
            1,
        ), encoding="utf-8")
        with self.assertRaisesRegex(audit.AuditError, "duplicate JSON"):
            matrix.analyze_matrix(path)

    def test_deeply_nested_matrix_json_fails_closed(self) -> None:
        path = self.write_matrix()
        path.write_text(
            '{"schema_version":1,"unused":' + "[" * 2000 + "0" + "]" * 2000 + "}",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(audit.AuditError, "nested JSON"):
            matrix.analyze_matrix(path)

    def test_extremely_long_matrix_integer_is_rejected_before_parsing(self) -> None:
        path = self.write_matrix()
        raw = path.read_text(encoding="utf-8")
        path.write_text(
            raw.replace('"schema_version": 1', '"schema_version": ' + "9" * 5000),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(audit.AuditError, "JSON integer exceeds"):
            matrix.analyze_matrix(path)

    def test_floating_point_matrix_json_is_rejected(self) -> None:
        path = self.write_matrix()
        raw = path.read_text(encoding="utf-8")
        path.write_text(
            raw.replace('"schema_version": 1', '"schema_version": 1.0'),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(audit.AuditError, "floating-point JSON"):
            matrix.analyze_matrix(path)

    def test_nonstandard_json_infinity_is_rejected(self) -> None:
        path = self.write_matrix()
        raw = path.read_text(encoding="utf-8")
        self.assertIn('"required_cases": [', raw)
        path.write_text(
            raw.replace('"required_cases": [', '"required_cases": [Infinity, ', 1),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(audit.AuditError, "nonstandard JSON"):
            matrix.analyze_matrix(path)

    def test_duplicate_nested_case_path_is_rejected(self) -> None:
        path = self.write_matrix()
        raw = path.read_text(encoding="utf-8")
        token = '"manifest": "wifi/manifest.json"'
        self.assertIn(token, raw)
        path.write_text(raw.replace(
            token, '"manifest": "outside.json", "manifest": "wifi/manifest.json"',
            1,
        ), encoding="utf-8")
        with self.assertRaisesRegex(audit.AuditError, "duplicate JSON"):
            matrix.analyze_matrix(path)

    def test_unknown_fields_rejected(self) -> None:
        self.matrix["all_cases_verified"] = True
        with self.assertRaisesRegex(audit.AuditError, "unknown"):
            matrix.analyze_matrix(self.write_matrix())

    def test_case_path_traversal_and_external_symlink_rejected(self) -> None:
        self.matrix["cases"][0]["manifest"] = "../elsewhere.json"
        with self.assertRaisesRegex(audit.AuditError, "paths"):
            matrix.analyze_matrix(self.write_matrix())
        external = self.folder.parent / (self.folder.name + "-outside.json")
        external.write_text("{}", encoding="utf-8")
        self.addCleanup(external.unlink)
        (self.folder / "external.json").symlink_to(external)
        self.matrix["cases"][0]["manifest"] = "external.json"
        with self.assertRaisesRegex(audit.AuditError, "symlink"):
            matrix.analyze_matrix(self.write_matrix())

    def test_matrix_requires_nonempty_required_scenarios(self) -> None:
        self.matrix["required_cases"] = []
        with self.assertRaisesRegex(audit.AuditError, "required_cases"):
            matrix.analyze_matrix(self.write_matrix())

    def test_unexpected_case_is_included_but_cannot_hide_missing_requirements(self) -> None:
        self.matrix["required_cases"] = ["wifi", "tcp53", "hard_disconnection"]
        report = matrix.analyze_matrix(self.write_matrix())
        self.assertEqual(report["verdict"], "NOT_VERIFIED")
        self.assertIn("hard_disconnection", report["missing_cases"])
        self.assertEqual(report["case_counts"]["no_physical_observed"], 3)

    def test_cli_exit_codes(self) -> None:
        path = self.write_matrix()
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(matrix.main([str(path)]), 0)
        self.assertEqual(json.loads(stdout.getvalue())["system_zero_leak_verified"], False)
        self.matrix["cases"].pop()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(matrix.main([str(self.write_matrix())]), 4)

    def test_private_report_write_atomic_and_no_overwrite_without_flag(self) -> None:
        manifest = self.write_matrix()
        output = self.folder / "summary.json"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(matrix.main([str(manifest), "--output", str(output)]), 0)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(matrix.main([str(manifest), "--output", str(output)]), 2)
            self.assertEqual(matrix.main([
                str(manifest), "--output", str(manifest), "--overwrite",
            ]), 2)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(matrix.main([
                str(manifest), "--output", str(output), "--overwrite",
            ]), 0)

    def test_matrix_report_cannot_overwrite_child_raw_evidence(self) -> None:
        manifest = self.write_matrix()
        for relative in (
            "wifi/en0.txt",
            "wifi/utun7.stats.txt",
            "wifi/scutil-dns.txt",
        ):
            with self.subTest(path=relative):
                target = self.folder / relative
                original = target.read_bytes()
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(
                        matrix.main([
                            str(manifest), "--output", str(target), "--overwrite"
                        ]), 2
                    )
                self.assertEqual(target.read_bytes(), original)

    def test_matrix_report_replaces_symlink_not_symlink_target(self) -> None:
        manifest = self.write_matrix()
        private = self.folder / "private-note.txt"
        private.write_text("unchanged", encoding="utf-8")
        output = self.folder / "matrix-link.json"
        output.symlink_to(private)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(matrix.main([
                str(manifest), "--output", str(output), "--overwrite"
            ]), 0)
        self.assertFalse(output.is_symlink())
        self.assertEqual(private.read_text(encoding="utf-8"), "unchanged")

    def test_case_evidence_changed_after_analysis_prevents_saving_matrix(self) -> None:
        import unittest.mock
        path = self.write_matrix()
        output = self.folder / "must-not-exist.json"
        original = matrix.analyze_matrix

        def tamper_after_analysis(manifest: Path) -> dict:
            report = original(manifest)
            self.change_case("wifi", "en0.txt", "evidence replaced after analysis")
            return report

        with unittest.mock.patch.object(matrix, "analyze_matrix", side_effect=tamper_after_analysis):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(matrix.main([
                    str(path), "--output", str(output),
                ]), 2)
        self.assertFalse(output.exists())

    def test_no_network_access_or_subprocesses(self) -> None:
        import unittest.mock
        with unittest.mock.patch("socket.socket", side_effect=AssertionError("socket")):
            with unittest.mock.patch("subprocess.run", side_effect=AssertionError("subprocess")):
                result = matrix.analyze_matrix(self.write_matrix())
        self.assertEqual(result["case_counts"]["no_physical_observed"], 3)


if __name__ == "__main__":
    unittest.main()
