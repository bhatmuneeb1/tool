# RepoGuard

RepoGuard is a lightweight, dependency-free security hygiene scanner for local source repositories. It is designed for maintainers who want a fast pre-commit or CI check for common high-signal mistakes before code is published.

## What it checks

- Private key material accidentally committed to text files
- Common GitHub token formats
- AWS access-key identifiers
- Risky GitHub Actions settings such as `permissions: write-all`
- `pull_request_target` workflows that deserve manual review
- Python `subprocess` usage with `shell=True`
- Obvious hard-coded password assignments

RepoGuard is intentionally conservative. It is not a replacement for dedicated secret scanners, SAST products, dependency analysis, or code review.

## Install

```bash
python -m pip install -e .
```

## Usage

Scan the current repository:

```bash
repoguard .
```

JSON output:

```bash
repoguard . --format json
```

SARIF 2.1.0 output for code-scanning integrations:

```bash
repoguard . --format sarif > repoguard.sarif
```

Fail when a high-severity finding is present:

```bash
repoguard . --fail-on high
```

Formats and exit policy can be combined:

```bash
repoguard . --format sarif --fail-on high > repoguard.sarif
```

You can also run it without installation:

```bash
python -m repoguard.cli .
```

## Example

```text
HIGH RG001 config/dev.pem:1 Private key material detected
MEDIUM RG101 .github/workflows/release.yml:8 Workflow grants write-all permissions

2 finding(s): 1 high, 1 medium
```

## Integration model

RepoGuard can be used locally, as a pre-commit-style check, or inside CI. JSON is convenient for custom automation, while SARIF provides a standard interchange format understood by many code-scanning systems. RepoGuard itself does not upload findings anywhere.

## Philosophy

The project favors transparent, auditable checks with no network access. Scans remain on the local machine unless a user explicitly runs RepoGuard in their own CI environment.

## Development

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
repoguard . --fail-on high
```

## Contributing

Bug fixes, new high-signal rules, false-positive reductions, tests, documentation, and output-format improvements are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

MIT License.
