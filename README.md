# Dual-Auth Vote — Python Backend Edition

This version keeps the supplied HTML/CSS/JavaScript interface and replaces the PHP API with a Flask (Python) backend. The existing frontend calls paths such as `api/login.php`; Flask intentionally supports those same URLs, so the HTML does not need to be rewritten just to change backend language.

## Run on Windows / VS Code

1. Install Python 3.10 or newer.
2. Run these commands in the project folder:

```powershell
py -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
# Keep the existing .env file unchanged; do not copy over it
python app.py
```

3. Preserve the existing `.env` file and its values during this update. For a separate deployment, review secret values and SMTP configuration securely before exposing the application. With `OTP_DEV_MODE=1`, a development OTP is printed in the Flask terminal; use properly configured SMTP and `OTP_DEV_MODE=0` for email delivery.
4. Open `http://127.0.0.1:8000` (do not use VS Code Live Server). The `/services.html` navigation URL is supported and serves `services/services.html`.

The app creates `dual_auth_voting.sqlite3` automatically on first run; no MySQL or XAMPP is required for the local demo. Existing PHP/MySQL database records are not automatically migrated. See `MIGRATION.md` if you need to migrate data.

## Registration / OTP

With default development settings, the OTP is printed in the terminal running `python app.py`. This is for local testing only. To send actual email, configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, and optionally `SMTP_FROM` in `.env`, then set `OTP_DEV_MODE=0`.

## Admin and election workflow

Open `admin.html`. When prompted, enter the exact `ADMIN_TOKEN` value from `.env`. Admin can add candidates, publish notices, start/stop/schedule voting and view vote counts. Use `ballot.html` after voter login.

## Important limitations / safety

- This is an academic prototype, not a certified election system. Do not use it for a legally binding election or expose it publicly with real NID data.
- NID format/duplicate checks do not verify identity against Bangladesh government records.
- Camera photo capture, face matching, liveness detection, and passkey authentication are not implemented as verified identity checks. The interface labels these as unavailable and allows NID/PIN sign-in instead.
- Default development OTP mode prints secrets to the terminal. Disable it and configure SMTP before any non-demo use.
- Change the development secret values, back up the database, and have the application/security design independently reviewed before deployment.

## Files

- `app.py`: Flask backend and API routes
- `requirements.txt`: Python dependencies
- `dual_auth_voting.sqlite3`: local database, created on first run and intentionally excluded from the source ZIP
- `api/`: intentionally no PHP files; legacy `.php` URL paths are compatibility routes served by Flask





## Biometric prototype limits

Face-photo capture is only a local camera preview. Face matching, anti-spoofing/liveness, and server-verified passkey enrollment/authentication are not implemented. Those steps must not be described or used as identity verification. Users can skip them and sign in with NID and PIN. This academic voting prototype is not suitable for a real or legally binding election.
## NID image storage and review

Registration requires front and back NID images. The server validates file signatures and size, stores the images in the private `private_nid_storage/` directory, and records the paths and review status in SQLite. Administrators can review submissions in the admin panel and approve or reject them. NID images contain sensitive personal information; this academic prototype should not be exposed publicly with real identity documents.



Do not replace the existing `.env` file when updating this project. The runtime reads its current values as configured.


## Recent maintenance notes
- Candidate removal is handled by the authenticated admin API: candidates without votes are deleted; candidates with recorded votes are deactivated to preserve audit/history integrity.
- Admins can download an administrative PDF report and voters can download a vote-submission receipt after a vote exists.
- Face photo capture can submit a private image for administrator review. This is **not** automated face matching, liveness detection, or a production-grade biometric identity check. Do not use this application for a real public election without independent security, privacy, legal, accessibility, and election-integrity review.
- The app's current NID check validates format and admin review; it is not connected to an official Bangladesh NID verification service.
- `.env` was preserved unchanged as requested. Treat SMTP credentials and admin tokens as secrets; rotate them if this ZIP has been shared beyond trusted operators.


## Face registration and login verification update

- After registration, sign in and open `face-registration.html` to capture a face photo and 128-value face descriptor. The photo is saved in private storage and the descriptor is stored in SQLite for review/matching.
- Admin must approve the submitted face in the admin panel. Login then redirects approved voters to `face-verification.html`; a successful descriptor comparison unlocks the ballot for that session.
- The browser loads face-api.js and its model weights from jsDelivr/GitHub, so an internet connection is required for the face model.
- This is a prototype only, not production-grade identity verification: the descriptor is produced in the browser and can be forged by a technically capable client. Before any real election use, move face detection/matching and liveness checks to a trusted server-side service, protect biometric templates at rest, perform security/privacy review, and test with real devices.
