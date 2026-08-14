import unittest

from repoguard.sarif import to_sarif
from repoguard.scanner import Finding


class SarifTests(unittest.TestCase):
    def test_sarif_document_contains_rule_and_location(self):
        finding = Finding(
            rule_id="RG101",
            severity="medium",
            path=".github/workflows/ci.yml",
            line=8,
            message="Workflow grants write-all permissions",
        )
        document = to_sarif([finding])

        self.assertEqual(document["version"], "2.1.0")
        run = document["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "RepoGuard")
        self.assertEqual(run["tool"]["driver"]["rules"][0]["id"], "RG101")
        result = run["results"][0]
        self.assertEqual(result["level"], "warning")
        location = result["locations"][0]["physicalLocation"]
        self.assertEqual(location["artifactLocation"]["uri"], ".github/workflows/ci.yml")
        self.assertEqual(location["region"]["startLine"], 8)

    def test_rules_are_deduplicated(self):
        findings = [
            Finding("RG003", "high", "a.txt", 1, "GitHub token-like value detected"),
            Finding("RG003", "high", "b.txt", 2, "GitHub token-like value detected"),
        ]
        document = to_sarif(findings)
        rules = document["runs"][0]["tool"]["driver"]["rules"]
        self.assertEqual(len(rules), 1)
        self.assertEqual(len(document["runs"][0]["results"]), 2)


if __name__ == "__main__":
    unittest.main()
