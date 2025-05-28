# Secure File Storage

[![Build](https://github.com/milosz275/secure-file-storage/actions/workflows/ci.yml/badge.svg)](https://github.com/milosz275/secure-file-storage/actions/workflows/ci.yml)
[![CodeQL](https://github.com/milosz275/secure-file-storage/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/milosz275/secure-file-storage/actions/workflows/github-code-scanning/codeql)

Secure File Storage is a secure, encrypted file storage solution developed in Python. It combines strong encryption, modular architecture, logging and basic access control.

- [Github](https://github.com/milosz275/secure-file-storage)
- [PyPi](https://pypi.org/project/secure-file-storage-milosz275)

## Features

- AES-256 encryption for file storage
- User authentication with hashed passwords
- Encrypted metadata storage using SQLite
- Access logs (who accessed which file and when)
- Containerized deployment
- CI/CD pipeline with linting and tests (GitHub Actions)

## Security Principles

- Confidentiality: AES encryption
- Integrity: file hashing and verification
- Accountability: access logs
- Compliance: inspired by ISO27001 & GDPR concepts

## DevOps

- Docker for reproducibility
- Pytest unit tests
- CI/CD with GitHub Actions

## Usage

Access web interface at `http://localhost:5000`

### Docker

```bash
docker-compose up
```

### Manual

```bash
git clone https://github.com/milosz275/secure-file-storage.git
cd secure-file-storage
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install --upgrade pip
python3 secure_file_storage/src/setup_env.py
python3 -m secure_file_storage.main
```
