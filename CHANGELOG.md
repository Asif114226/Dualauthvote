# Changelog


### Fixed
- Made registration OTPs expire consistently and single-use after registration.
- Removed the SMTP credential accidentally present in the example environment file.

## Integration / hardening build

### Problems identified
- README referenced a missing `server.js`.
- Frontend mixed PHP APIs with an absent Node backend.
- Login was client-side only.
- Ballot candidates were hard-coded.
- Vote submission was only an alert and did not write to MySQL.
- Election controls were client-side only.
- Admin notice/candidate actions were client-side only.
- Notices had hard-coded sample entries before the API response.
- OTP verification lacked complete attempt/rate-limit hardening.
- Biometric UI contained simulated face/liveness success.
- NID upload trusted browser MIME metadata.
- A malformed `<script->` tag existed in Registration.html.

### Repaired
- Added PHP session authentication and logout.
- Added CSRF endpoint and protection.
- Added real login API.
- Added database-backed candidate filtering.
- Added transactional vote API.
- Added database-backed election controls.
- Added live vote-count API.
- Connected admin notice and candidate operations.
- Hardened OTP and upload handling.
- Removed fake biometric success claims.
- Fixed malformed Registration.html script tag.
- Added lightweight responsive motion and reduced-motion support.

### Preserved

### Not claimed as implemented
Real face recognition, liveness anti-spoofing, fingerprint/WebAuthn enrollment, official government NID verification and certified secret-ballot cryptography.

## NID document storage and administrator review

- Replaced the old image-reading step with required front/back NID uploads during registration.
- Added signature/extension and size validation and private storage outside the public uploads directory.
- Added database-backed pending/approved/rejected review states and administrator-only image viewing and decisions.
- Added an NID Verification section to the admin panel.
- Preserved the existing `.env` file unchanged.


## UI and backend integration update (2026-10-26)
- Added a polished green/red/blue admin access gate and shared responsive navigation/animations across pages.
- Added Google Translate (English/Bengali) controls on public pages, excluding Registration, Login and Admin as requested.
- Added required primary and secondary phone fields to registration, server-side validation, SQLite schema migration, and admin review display.
- Added NID-match reminder to registration.
- Connected vote-count filters to backend aggregation for division/district/upazila/ward.
- Styled voter receipt and admin election report PDFs with green/red/blue branding; voter receipt includes the stored enrollment/verification face image when available and is auto-requested after a successful vote.
- Preserved the existing `.env` file byte-for-byte. Private NID images, local voter database, and bundled virtual environment are excluded from the delivery ZIP for privacy/portability; the app initializes a fresh database on startup.
