# Testing Guide

This document explains how to set up a Python environment for the Secure QR Code
Tool and how to execute the automated test suite.

## Prerequisites

- Python 3.10 or newer. The project uses features that require at least this
  version.
- A recent version of `pip` and `venv` (both ship with the official CPython
  installers).
- Git (optional, but recommended if you plan to clone the repository).

## 1. Create and activate a virtual environment

From the repository root, create an isolated Python environment to avoid mixing
project dependencies with your global site-packages. The following commands use
a Unix-like shell; adjust the activation command accordingly for Windows (for
example, `Scripts\\activate.bat`).

```bash
python -m venv .venv
source .venv/bin/activate
```

## 2. Install the project and testing dependencies

Install the package in editable mode so that the `secure_qr_tool` modules are
available on the Python path. The core runtime dependencies (such as
`cryptography` and `mnemonic`) are specified in `pyproject.toml` and will be
pulled in automatically.

```bash
pip install --upgrade pip
pip install -e .
pip install pytest
```

The GUI-only extras are not required for the tests. If you want to exercise the
optional QR code rendering paths during manual testing, you can install them
with `pip install -e .[ui]`.

## 3. Run the full test suite

With the virtual environment active and the dependencies installed, invoke
`pytest` from the repository root:

```bash
pytest
```

Pytest discovers the modules under `tests/` and executes them with the
configuration declared in `pyproject.toml` (which adds `src/` to `PYTHONPATH`
and enables quiet output).

## 4. Run specific tests (optional)

Pytest provides several filters if you only need to run a subset of the suite:

- By file: `pytest tests/test_security.py`
- By test name: `pytest -k roundtrip`
- With verbose output: `pytest -vv`

## 5. Generate coverage reports (optional)

To check how much of the code base is exercised by the tests, install the
`pytest-cov` plugin and run pytest with the coverage options:

```bash
pip install pytest-cov
pytest --cov=secure_qr_tool --cov-report=term-missing
```

This command prints a line-by-line summary of uncovered statements so you can
identify gaps in test coverage.

## 6. Deactivate the virtual environment

When you are done testing, leave the virtual environment so that subsequent
shell sessions use your global Python interpreter again:

```bash
deactivate
```

Following the steps above ensures that you reproduce the same testing
environment used in continuous integration and can verify changes locally
before committing them.
