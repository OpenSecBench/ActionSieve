# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ActionSieve, please report it
responsibly. **Do not open a public issue.**

Email: james@gnuinter.net

Include:

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Any suggested fix

You should receive an acknowledgment within 48 hours. We will work with you
to understand and address the issue before any public disclosure.

## Scope

ActionSieve is a static analysis tool that parses CI/CD pipeline definitions.
Security-relevant areas include:

- **YAML parsing** — must use `safe_load` only, never `yaml.load`
- **File handling** — size limits, path traversal prevention
- **No code execution** — the scanner must never execute code from scanned repos
- **No repo-controlled config** — scanned repos cannot suppress findings
  without explicit `--trust-repo-profile`

## Supported Versions

| Version | Supported |
| ------- | --------- |
| latest  | Yes       |

## Security Design Principles

- No `eval()`, `exec()`, or `subprocess` with `shell=True` on user input
- No importing or executing code from scanned repositories
- File size caps on parsed files (1MB per workflow)
- Recursion depth limits for composite action resolution
- Reference CI workflows use `pull_request` (not `pull_request_target`),
  pin all action refs to SHA
