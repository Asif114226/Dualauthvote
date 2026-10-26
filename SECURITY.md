# Security Notes

## Implemented controls

- PDO prepared statements with native prepares.
- `password_hash()` / `password_verify()`.
- Secure HTTP-only, SameSite session cookies.
- Session ID regeneration after authentication.
- CSRF tokens for state-changing API requests.
- OTP hashing, expiration, five-attempt limit and request throttling.
- Generic authentication errors to reduce account enumeration.
- Server-side validation for NID, passwords, uploads and candidate/vote inputs.
- Randomized upload filenames and MIME detection using Fileinfo.
- Upload directory protection against PHP/script execution under Apache.
- Role checks for admin and voter APIs.
- Transaction + row locking + unique constraint for vote submission.
- Audit events that avoid storing passwords, OTPs or selected candidate IDs.
- Security headers such as `X-Content-Type-Options`, `X-Frame-Options` and `Referrer-Policy`.
- Secrets kept in `.env`, excluded from distribution.

## Remaining risks / limitations

1. HTTPS is required in production. The local PHP development server is not a production server.
2. Admin authentication currently uses an environment secret; production should use a dedicated admin identity system with MFA.
3. The project has no independently audited cryptographic ballot-separation protocol.
4. The current vote table links voter ID and candidate ID. This is suitable for a project/demo but does not provide strong ballot secrecy for a national election.
5. Face recognition and liveness are not implemented as real security controls.
6. WebAuthn/fingerprint credential enrollment and verification are not implemented.
8. Upload serving should be reviewed again when deployed behind Apache/Nginx.
9. Rate limiting is currently implemented for registration OTP requests; production should add broader IP/account/device rate limits.
10. Independent penetration testing, privacy assessment, threat modeling, cryptographic review and electoral certification are required before any real election use.

Never represent this project as tamper-proof, legally certified, or ready for a national election without those independent controls.
