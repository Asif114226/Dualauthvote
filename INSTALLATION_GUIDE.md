# Installation Guide — Windows + VS Code

## 1. PHP

Verify:

```powershell
php -v
php -m | findstr /I "pdo_mysql curl fileinfo openssl"
```

If `php` is not recognized, add the directory containing `php.exe` to Windows PATH and reopen the terminal.

## 2. Composer

Verify:

```powershell
composer -V
```

Then:

```powershell
composer install
```

## 3. MySQL

Start MySQL and import `database.sql`.

Example with the MySQL client:

```powershell
mysql -u root -p < database.sql
```

Or import the file using phpMyAdmin/MySQL Workbench.

## 4. Environment

Copy:

`.env.example` → `.env`

Set:

- `DB_HOST`
- `DB_PORT`
- `DB_NAME`
- `DB_USER`
- `DB_PASSWORD`
- `ADMIN_TOKEN`
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_SECURE`
- `SMTP_USER`
- `SMTP_PASS`

Do not put real credentials into `.env.example`.

## 5. Start PHP

From the project root:

```powershell
php -S localhost:8000
```

Open:

`http://localhost:8000/`

## 6. OTP

For Gmail SMTP, use an App Password rather than a normal Gmail password. Keep it only in `.env`.


## 8. Troubleshooting

### `404` for PHP API
Use the PHP server URL, not VS Code Live Server.

### Database connection failed
Check MySQL is running and `.env` credentials match.

### OTP cannot be sent
Check SMTP host, port, secure mode, username and App Password.

Start the FastAPI service on port 5001.

### Admin authentication required
Open `/admin.html` and provide the exact `ADMIN_TOKEN` from `.env`.

### Browser camera unavailable
Use a secure origin or localhost and grant camera permission. Camera capture alone is not face recognition.


### Local OTP troubleshooting

For local development without SMTP credentials, set `OTP_DEV_MODE=1` in `.env`; the OTP is printed in the Flask terminal. For email delivery, configure valid SMTP host, port, security mode, username, and app password, then set `OTP_DEV_MODE=0`. Do not deploy with development OTP mode enabled.



## NID document review

Registration requires front and back NID images. They are stored in the private `private_nid_storage/` directory and referenced in the database. In the admin panel, open **NID Verification** to review images and approve or reject a submission. Protect the database and private storage with backups and filesystem permissions.
