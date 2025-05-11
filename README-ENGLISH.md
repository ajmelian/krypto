# Krypto

Krypto is a controller for **encryption**, **decryption**, and **inspection** of documents using **XChaCha20-Poly1305**. The encryption key is derived from:

* A global system *pepper*.
* The persistent identifier (*persistentId*) returned by Cl\@ve after authentication.

This approach ensures that only the user authenticated with the same *persistentId* can decrypt the documents.

---

## Table of Contents

* [Features](#features)
* [Requirements](#requirements)
* [Installation](#installation)
* [Environment Variables](#environment-variables)
* [Usage](#usage)

  * [Commands](#commands)
  * [Examples](#examples)
* [Security and Compliance](#security-and-compliance)
* [Contributing](#contributing)
* [License](#license)
* [Authors](#authors)

---

## Features

* Encrypt and decrypt files with **XChaCha20-Poly1305**.
* Key derivation using *pepper* and *persistentId* for maximum security.
* Inspection of encrypted files to verify validity.
* Developed following **secure development** and **clean code** guidelines.
* **Adaptable** code for any project, under the license terms.
* Easy-to-use command-line interface.

## Requirements

* PHP **8.2** or higher with **ext-sodium** enabled.
* Access to the PHP CLI.
* Cl\@ve service to obtain the user’s *persistentId*.

## Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/your-username/your-repo.git
   cd your-repo
   ```
2. Copy or move `Krypto.php` to your desired directory.
3. (Optional) Make it executable:

   ```bash
   chmod +x Krypto.php
   ```

## Environment Variables

Before using the tool, set the following environment variables:

* `KRYPT_PEPPER`: The system-wide secret pepper.
* `PERSISTENT_ID`: The persistent identifier provided by Cl\@ve.

For example:

```bash
export KRYPT_PEPPER="mySecretPepper"
export PERSISTENT_ID="XYZ123456"
```

## Usage

### Commands

| Action    | Syntax                          | Description                              |
| --------- | ------------------------------- | ---------------------------------------- |
| `encrypt` | `php Krypto.php encrypt <file>` | Encrypts the specified file.             |
| `decrypt` | `php Krypto.php decrypt <file>` | Decrypts the encrypted file.             |
| `analyze` | `php Krypto.php analyze <file>` | Checks if the file is validly encrypted. |

### Examples

```bash
# Encrypt a document
php Krypto.php encrypt document.txt

# Decrypt a document
php Krypto.php decrypt document.txt.encrypted

# Analyze an encrypted document
php Krypto.php analyze document.txt.encrypted
```

## Security and Compliance

### Time to break without `PERSISTENT_ID`

Breaking the encryption without the `persistentId` or the *pepper* requires, in practice, a brute-force attack against the 32-byte key derived via Argon2id with moderate parameters (approx. 0.7 s and 256 MiB per derivation on a 2.8 GHz CPU). Attempting a space of 2³² possible *persistentId* values would take around **95 years** on a single CPU, and larger spaces become infeasible (billions of years).

### Exclusivity of Access

The symmetric key is generated solely from `pepper | persistentId`. Without the same `persistentId` obtained via Cl\@ve or access to the global pepper, no attacker can derive the same key. Therefore, **only the authenticated user** who encrypted the document can decrypt it.

### “Only-4-your-eyes” Policy

Cryptographically, XChaCha20-Poly1305 with a unique per-user key satisfies exclusive confidentiality: no one else has access to the key. For full organizational compliance, it is recommended to accompany this with access logs and audits.

### GDPR (Art. 32) and NIS2 (Art. 21) Compliance

* **GDPR** requires “pseudonymization and encryption of personal data” as an appropriate technical measure. Krypto provides state-of-the-art encryption for data at rest, fulfilling this requirement, although GDPR also demands key management, DPIA, and breach notification processes.
* **NIS2** prescribes appropriate technical measures, including encryption, to manage risks in information systems. Krypto provides the required cryptographic layer, but should be complemented by incident response plans, vulnerability management, and staff training.

## Contributing

All contributions are welcome! Please submit pull requests or open *issues* to suggest improvements.

## License

This project is released under the **GNU General Public License**. See the [LICENSE](LICENSE) file for details.

## Authors

* **Aythami Melián Perdomo** ([ajmelper@gmail.com](mailto:ajmelper@gmail.com))

