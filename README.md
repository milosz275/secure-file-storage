# Secure File Storage

[![CI](https://github.com/milosz275/secure-file-storage/actions/workflows/ci.yml/badge.svg)](https://github.com/milosz275/secure-file-storage/actions/workflows/ci.yml)
[![Build and Push to GitHub Container Registry](https://github.com/milosz275/secure-file-storage/actions/workflows/docker-github-publish.yml/badge.svg)](https://github.com/milosz275/secure-file-storage/actions/workflows/docker-github-publish.yml)
[![Build and Push to Docker Hub](https://github.com/milosz275/secure-file-storage/actions/workflows/dockerhub-publish.yml/badge.svg)](https://github.com/milosz275/secure-file-storage/actions/workflows/dockerhub-publish.yml)
[![CodeQL Advanced](https://github.com/milosz275/secure-file-storage/actions/workflows/codeql.yml/badge.svg)](https://github.com/milosz275/secure-file-storage/actions/workflows/codeql.yml)

Secure File Storage is a secure, encrypted file storage solution developed in Python. It combines strong encryption, modular architecture, logging and basic access control.

- [Github](https://github.com/milosz275/secure-file-storage)
- [PyPi](https://pypi.org/project/secure-file-storage-milosz275)
- [Dockerhub](https://hub.docker.com/repository/docker/mlsh/secure-file-storage/general)

## Features

- AES-256 encryption for secure file storage
- User authentication with hashed passwords and session management
- Encrypted file metadata stored securely in SQLite
- Audit logging capturing file access and user actions
- Containerized deployment using Docker and Docker Compose
- Continuous Integration and Deployment pipeline with linting and tests (GitHub Actions)

## Security Principles

- Confidentiality: AES-256 encryption ensures stored files remain confidential
- Integrity: File hashing verifies integrity of uploaded files
- Accountability: Access logs provide traceability of user actions
- Compliance: Architecture inspired by ISO27001 and GDPR principles to promote security-by-design and privacy awareness

## DevOps

- Docker for consistent environment and easy deployment
- Unit tests with Pytest
- CI/CD pipeline configured with GitHub Actions for automated testing and code quality checks

## Usage

Access web interface at `http://localhost:5000`.

### Pip package

```bash
pip install secure-file-storage-milosz275
secure-file-storage
```

### Docker

From Docker hub container registry:

```bash
docker pull mlsh/secure-file-storage:latest
docker run -d -p 5000:5000 mlsh/secure-file-storage:latest
```

From GitHub container registry:

```bash
docker pull ghcr.io/milosz275/secure-file-storage:latest
docker run -d -p 5000:5000 ghcr.io/milosz275/secure-file-storage:latest
```

Manually on cloned repository:

```bash
export COMPOSE_BAKE=true
docker-compose build
docker-compose up
```

### Manual setup

```bash
git clone https://github.com/milosz275/secure-file-storage.git
cd secure-file-storage
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install --upgrade pip
python3 secure_file_storage/src/setup_env.py
gunicorn --log-level warning -w 4 -b 0.0.0.0:5000 secure_file_storage.main:app
```
