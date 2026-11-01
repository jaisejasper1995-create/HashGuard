
# HashGuard

**SHA-256 File Integrity Monitoring | Python | Software QA**

HashGuard is a lightweight command-line tool that detects changes to files within a monitored directory.

It creates a JSON baseline containing SHA-256 fingerprints and compares future scans against that baseline.

Built using Python's standard library, with automated regression tests and a focus on predictable failure handling.

## Features

- Recursive folder scanning
- SHA-256 fingerprint calculation
- JSON baseline creation
- Detection of modified files
- Detection of missing files
- Detection of newly added files
- Human-readable PASS/FAIL reporting
- Distinct exit codes for automation
- Baseline overwrite protection
- Automated regression testing

## Requirements

- Python 3.10 or newer
- No third-party dependencies

## Quick Start

Clone or download the repository, then open a terminal in its directory.

Create a baseline:

```bash
python hashguard.py create ./my_folder ./baseline.json
```

Verify folder integrity:

```bash
python hashguard.py verify ./my_folder ./baseline.json
```

The monitored folder must already exist.

**Important:** Store the baseline outside the monitored folder.

## Example Output

Successful verification:

```text
PASS: Folder integrity verified (3 files).
```

Detected changes:

```text
FAIL: MISSING: alpha.txt
FAIL: ADDED: delta.txt
FAIL: MODIFIED: beta.txt
FAIL: 1 missing, 1 added, 1 modified.
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | File integrity violation |
| 2 | Invalid input or operational error |

These codes allow scripts and automated workflows to distinguish successful verification from integrity failures and execution errors.

## Run Automated Tests

```bash
python -m unittest -v test_hashguard
```

The initial regression suite contains 14 tests covering baseline creation, clean verification, modifications, missing files, added files, multiple violations, overwrite protection, invalid baseline formats, nested directories, and error handling.

The suite was reported passing locally during development. GitHub Actions execution must be verified separately.

## GitHub Actions

The repository includes a workflow configured to run the automated tests on Python 3.10, 3.11, 3.12, and 3.13.

Workflow results should be inspected on GitHub before claiming continuous integration has passed.

## Security and Limitations

HashGuard detects differences between current files and a previously recorded baseline. It is not a complete security monitoring system.

- SHA-256 detects content differences; it does not identify who made a change.
- Baselines are not digitally signed or authenticated.
- Anyone able to modify the baseline may be able to conceal changes.
- Baselines should be protected separately from monitored files.
- File permissions, ownership, timestamps, and metadata are not monitored.
- Symbolic links are not supported.
- Empty directories are not tracked.
- Concurrent file modifications during scanning may affect results.
- HashGuard does not continuously monitor files or send alerts.
- A successful comparison does not prove that files are safe or free from malware.

For stronger integrity assurance, store and protect trusted baseline fingerprints independently.

## Project Validation

Development verification includes:

- Manual positive and negative tests
- Independent SHA-256 comparison using PowerShell
- Automated Python regression tests
- Corrupted baseline rejection
- Command-line exit-code checks
- Separate-directory execution testing
- Source and test-script SHA-256 evidence records

These checks establish tested behavior, not a formal security certification.

## Project Philosophy

**I test the claim — not just the demo.**

HashGuard was developed as a practical software quality assurance project emphasizing reproducible tests, visible failures, and evidence-backed validation.
