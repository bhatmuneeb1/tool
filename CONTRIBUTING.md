# Contributing to RepoGuard

Thanks for helping improve RepoGuard.

## Good contributions

- new high-signal defensive rules with tests
- false-positive reductions
- safer file parsing
- performance improvements
- JSON or CI integration improvements
- documentation and examples

## Development

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
repoguard . --fail-on high
```

## Rule guidelines

A new rule should have a clear security rationale, a stable rule ID, a documented severity, at least one positive test, and ideally a negative test demonstrating that obvious benign input is not flagged.

Avoid rules that require network access or upload repository content to third parties.

## Pull requests

Keep changes focused, explain the security or maintenance benefit, and include tests for behavior changes.
