Overview

This project is a Flask-based web application that signs and verifies files using ECDSA (SECP256R1) with SHA-256. It ensures file integrity and authenticity by generating a digital signature with a private key and validating it with a corresponding public key. The system demonstrates how cryptography can be applied in a practical web environment alongside secure development practices.

Features

The application supports file signing and verification, encrypted private key storage using a passphrase, and automatic key generation if keys do not already exist. It includes secure file handling through temporary files, logging with rotation for monitoring and audit purposes, and is deployed behind an Nginx reverse proxy enforcing HTTPS with TLS 1.2 and 1.3. Additional security headers such as HSTS, CSP and X-Frame-Options are applied to improve overall security posture.

How It Works

During signing, a file is uploaded and signed using the ECDSA private key, producing a signature file that is returned to the user. For verification, the original file and signature are uploaded and validated using the public key. If the verification succeeds, the file is confirmed as authentic and unchanged; otherwise, it is flagged as invalid.

Tech Stack

The system is built using Python and Flask, with the cryptography library handling ECDSA and SHA-256 operations. Nginx is used as a reverse proxy to provide TLS, enforce HTTPS and apply additional security controls.

Security Notes

The private key is encrypted at rest and protected with restricted file permissions. HTTPS is enforced with a strong TLS configuration, and file uploads are handled securely to reduce common risks. Logging is implemented to track key events such as signing and verification.

Limitations

This project is designed as a demonstration and does not implement a full PKI or certificate-based trust model. It uses self-signed certificates for TLS and does not include authentication or access control mechanisms.
