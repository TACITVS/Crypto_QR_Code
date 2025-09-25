# Secure QR Code Tool

A refactored and fully tested version of the Secure QR Code Tool. The desktop
application allows you to generate BIP-39 compatible mnemonic phrases, encrypt
them with AES-256-GCM and store the ciphertext as JSON or a QR code. The
project separates the core cryptographic components from the GUI so that the
security-critical code can be audited and unit tested independently.

## Features

- **Strong encryption** – AES-256-GCM with PBKDF2-HMAC key derivation and a
  configurable work factor.
- **Mnemonic workflow** – generates 24-word recovery phrases using the
  `mnemonic` library and exposes checksum helpers.
- **QR interoperability** – save encrypted payloads as QR code images when
  `segno` is installed, or import payloads from existing QR images.
- **Modular architecture** – the package exposes reusable components for
  encryption, mnemonic handling and QR management. The GUI lives in
  `secure_qr_tool.app` and imports the core modules lazily, allowing automated
  tests to run without a graphical environment.

## Project layout

```
├── docs/
│   └── screenshots/
│       └── ui_overview.svg
├── src/
│   └── secure_qr_tool/
│       ├── app.py
│       ├── config.py
│       ├── icon.py
│       ├── network.py
│       ├── qr.py
│       ├── security.py
│       ├── state.py
│       └── __main__.py
└── tests/
    └── test_security.py
```

## Running the GUI

Install the mandatory dependencies plus the `ui` optional extras and launch the
application via the console script:

```bash
pip install .[ui]
secure-qr-tool
```

On environments without a GUI you can still leverage the encryption helpers by
importing the package in your own scripts.

## Tests

Run the automated test-suite with:

```bash
pytest
```

## Screenshot

![Application layout](docs/screenshots/ui_overview.svg)

## How it works

1. The user sets an in-memory master password on the lock screen. The password
   is wrapped in `SecureString`, a bytearray-backed helper that wipes memory
   once it falls out of scope.
2. Generating a mnemonic triggers the `MnemonicManager`, creating a new 24-word
   phrase and displaying a checksum to validate manual backups.
3. Encryption is executed in a worker thread using `CryptoManager`. The worker
   serialises the salt, nonce and ciphertext (all base64 encoded) so that the
   result can be persisted as JSON or encoded as a QR code.
4. Decrypting an existing payload reverses the process, presenting the
   recovered mnemonic alongside its checksum for manual verification.

The refactor introduces strict separation between the UI layer and the core
logic, making the security-sensitive portions easy to unit test and audit.
