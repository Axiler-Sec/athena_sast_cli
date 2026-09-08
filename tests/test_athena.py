import json
import subprocess
import tempfile
import unittest
from pathlib import Path

CLI = "python3 athena.py"


class TestExitCodes(unittest.TestCase):
    def test_clean_exits_0(self):
        r = subprocess.run(
            f"{CLI} scan tests/targets/clean_app.py --fail-on low",
            shell=True,
            capture_output=True,
        )
        assert r.returncode == 0

    def test_bad_exits_1(self):
        r = subprocess.run(
            f"{CLI} scan tests/targets/bad_python.py --fail-on high",
            shell=True,
            capture_output=True,
        )
        assert r.returncode == 1

    def test_bad_target_exits_2(self):
        r = subprocess.run(
            f"{CLI} scan /nonexistent --fail-on high",
            shell=True,
            capture_output=True,
        )
        assert r.returncode == 2


class TestOWASPMapping(unittest.TestCase):
    def test_findings_have_owasp_id(self):
        r = subprocess.run(
            f"{CLI} scan tests/targets/bad_python.py --format json",
            shell=True,
            capture_output=True,
            text=True,
        )
        d = json.loads(r.stdout)
        for f in d["findings"]:
            assert "owasp_id" in f
            assert f["owasp_id"].startswith("CICD-SEC-")

    def test_summary_has_owasp_risk_breakdown(self):
        r = subprocess.run(
            f"{CLI} scan tests/targets/bad_python.py --format json",
            shell=True,
            capture_output=True,
            text=True,
        )
        d = json.loads(r.stdout)
        assert "by_owasp_risk" in d["summary"]

    def test_pipeline_scan_detects_owasp_sec8(self):
        r = subprocess.run(
            f"{CLI} scan tests/targets/bad_pipeline.yml --format json",
            shell=True,
            capture_output=True,
            text=True,
        )
        d = json.loads(r.stdout)
        owasp_ids = [f["owasp_id"] for f in d["findings"]]
        assert "CICD-SEC-8" in owasp_ids

    def test_pipeline_scan_detects_owasp_sec6(self):
        r = subprocess.run(
            f"{CLI} scan tests/targets/bad_pipeline.yml --format json",
            shell=True,
            capture_output=True,
            text=True,
        )
        d = json.loads(r.stdout)
        owasp_ids = [f["owasp_id"] for f in d["findings"]]
        assert "CICD-SEC-6" in owasp_ids


class TestSARIF(unittest.TestCase):
    def test_sarif_valid_schema(self):
        r = subprocess.run(
            f"{CLI} scan tests/targets/bad_python.py --format sarif",
            shell=True,
            capture_output=True,
            text=True,
        )
        s = json.loads(r.stdout)
        assert s["version"] == "2.1.0"
        assert "$schema" in s

    def test_sarif_rules_have_owasp_tags(self):
        r = subprocess.run(
            f"{CLI} scan tests/targets/bad_python.py --format sarif",
            shell=True,
            capture_output=True,
            text=True,
        )
        s = json.loads(r.stdout)
        for rule in s["runs"][0]["tool"]["driver"]["rules"]:
            tags = rule.get("properties", {}).get("tags", [])
            assert any("CICD-SEC" in t for t in tags), f"Rule {rule['id']} missing OWASP tag"

    def test_sarif_results_have_owasp_property(self):
        r = subprocess.run(
            f"{CLI} scan tests/targets/bad_python.py --format sarif",
            shell=True,
            capture_output=True,
            text=True,
        )
        s = json.loads(r.stdout)
        for result in s["runs"][0]["results"]:
            assert "owasp_id" in result.get("properties", {})

    def test_sarif_source_is_cli_normalized(self):
        r = subprocess.run(
            f"{CLI} scan tests/targets/bad_python.py --format sarif",
            shell=True,
            capture_output=True,
            text=True,
        )
        s = json.loads(r.stdout)
        assert s["runs"][0]["properties"]["sarif_source"] == "cli_normalized"


class TestJSONSchema(unittest.TestCase):
    def test_schema_version_present(self):
        r = subprocess.run(
            f"{CLI} scan tests/targets/bad_python.py --format json",
            shell=True,
            capture_output=True,
            text=True,
        )
        d = json.loads(r.stdout)
        assert d["schema_version"] == "1.0"
        assert d["tool"] == "athena"
        assert "owasp_standard" in d


class TestSpecificRules(unittest.TestCase):
    def test_ath001_hardcoded_secret(self):
        r = subprocess.run(
            f"{CLI} scan tests/targets/bad_python.py --format json",
            shell=True,
            capture_output=True,
            text=True,
        )
        d = json.loads(r.stdout)
        ids = [f["rule_id"] for f in d["findings"]]
        assert "ATH001" in ids

    def test_ath030_public_s3(self):
        r = subprocess.run(
            f"{CLI} scan tests/targets/bad_tf.tf --format json",
            shell=True,
            capture_output=True,
            text=True,
        )
        d = json.loads(r.stdout)
        ids = [f["rule_id"] for f in d["findings"]]
        assert "ATH030" in ids

    def test_clean_has_zero_findings(self):
        r = subprocess.run(
            f"{CLI} scan tests/targets/clean_app.py --format json",
            shell=True,
            capture_output=True,
            text=True,
        )
        d = json.loads(r.stdout)
        assert d["summary"]["total_findings"] == 0

    def test_pipeline_ath040_041_047(self):
        r = subprocess.run(
            f"{CLI} scan tests/targets/bad_pipeline.yml --format json",
            shell=True,
            capture_output=True,
            text=True,
        )
        d = json.loads(r.stdout)
        ids = [f["rule_id"] for f in d["findings"]]
        assert "ATH040" in ids
        assert "ATH041" in ids
        assert "ATH047" in ids


class TestCLICommands(unittest.TestCase):
    def test_owasp_command_lists_all_10_risks(self):
        r = subprocess.run(f"{CLI} owasp", shell=True, capture_output=True, text=True)
        for i in range(1, 11):
            assert f"CICD-SEC-{i}" in r.stdout

    def test_rules_command_shows_owasp_id(self):
        r = subprocess.run(f"{CLI} rules", shell=True, capture_output=True, text=True)
        assert "CICD-SEC" in r.stdout

    def test_owasp_risk_filter(self):
        r = subprocess.run(
            f"{CLI} scan tests/targets/bad_python.py --format json --owasp-risk CICD-SEC-6",
            shell=True,
            capture_output=True,
            text=True,
        )
        d = json.loads(r.stdout)
        for f in d["findings"]:
            assert f["owasp_id"] == "CICD-SEC-6"

    def test_output_file_written(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "results.json"
            subprocess.run(
                f"{CLI} scan tests/targets/bad_python.py --format json --output {out}",
                shell=True,
            )
            assert out.exists()
            d = json.loads(out.read_text())
            assert "findings" in d

    def test_help_has_no_api_key_flag(self):
        r = subprocess.run(f"{CLI} --help", shell=True, capture_output=True, text=True)
        assert "--api-key" not in r.stdout
        assert "--token" not in r.stdout

    def test_junit_groups_by_owasp(self):
        r = subprocess.run(
            f"{CLI} scan tests/targets/bad_python.py --format junit",
            shell=True,
            capture_output=True,
            text=True,
        )
        assert "<testsuites" in r.stdout
        assert "CICD-SEC-" in r.stdout


if __name__ == "__main__":
    unittest.main()
