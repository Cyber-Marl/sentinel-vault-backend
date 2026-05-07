# SentinelVault Backend 🛡️

SentinelVault is an enterprise-grade secure document management system backend. It is designed with a "Security First" philosophy, focusing on the CIA triad: Confidentiality, Integrity, and Availability.

## 🚀 Core Security Features

- **Application-Level Encryption**: All files are encrypted using `cryptography.fernet` (AES-128 in CBC mode) in-memory before being stored on the disk.
- **Integrity Verification**: SHA-256 hashes are calculated upon upload and re-verified during every download to detect any data tampering or corruption.
- **Immutable Audit Trail**: Every sensitive action (Auth, CRUD, Downloads) is recorded in a centralized audit log including timestamps, user roles, and source IP addresses.
- **Role-Based Access Control (RBAC)**: Fine-grained permissions for `ADMIN`, `MANAGER`, and `VIEWER` roles.
- **JWT Authentication**: Secure stateless authentication using `djangorestframework-simplejwt`.

## 🛠️ Tech Stack

- **Framework**: Django 5.0 + Django REST Framework
- **Language**: Python 3.12+
- **Database**: PostgreSQL (Production) / SQLite (Development)
- **Encryption**: Fernet (Symmetric Encryption)
- **Auth**: JSON Web Tokens (JWT)

## 📦 Installation & Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Cyber-Marl/sentinel-vault-backend.git
   cd sentinel-vault-backend
   ```

2. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Windows: .\venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Variables**:
   Create a `.env` file based on `.env.example`:
   ```bash
   cp .env.example .env
   # Generate a new FERNET_KEY and SECRET_KEY
   ```

5. **Run Migrations**:
   ```bash
   python manage.py migrate
   ```

6. **Start the server**:
   ```bash
   python manage.py runserver 8080
   ```

## 🔒 Security Considerations

- **Encryption Keys**: Never commit your `.env` file. Rotate the `FERNET_KEY` periodically in a production environment.
- **Soft Deletes**: Documents are never hard-deleted from the database to preserve forensic history.
