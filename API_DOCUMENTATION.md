# API Documentation

All endpoints are same-origin and return JSON unless noted.

## Public / voter endpoints

### GET `/api/csrf.php`
Returns a session-bound CSRF token.

### POST `/api/send-otp.php`
Form fields: `email`.

Requires CSRF. Sends a registration OTP.

### POST `/api/verify-otp.php`
Form fields: `email`, `otp`.

Requires CSRF. Verifies a registration OTP.

### POST `/api/registration.php`
Multipart fields: `fullName`, `guardianName`, `nid`, `division`, `district`, `upazila`, `ward`, `email`, `otp`, `password`, `duressPassword`, `nid_front`, and `nid_back`. Both NID images are required and limited to 5 MB each.

Requires CSRF. Creates the voter.

### POST `/api/login.php`
Form fields: `nid`, `password`.

Requires CSRF. Starts a secure voter session.

### POST `/api/logout.php`
Requires authenticated session + CSRF.

### GET `/api/me.php`
Returns the current voter session.

### GET `/api/candidates.php`
Optional query filters: `position`, `division`, `district`, `upazila`, `ward`.

### POST `/api/vote.php`
Requires voter session + CSRF. Form field: `candidate_id`.

The API verifies election status, voter eligibility, candidate area and one-vote-per-voter constraints inside a transaction.

### GET `/api/vote-count.php`
Returns aggregate vote statistics and candidate totals.


### POST `/api/admin-login.php`
Form field: `token`. Requires CSRF.

### GET/POST `/api/election-control.php`
Admin only. GET reads state. POST actions: `start`, `stop`, `schedule`.

### GET/POST/DELETE `/api/candidates.php`
Admin only for write operations. Supports candidate creation/deactivation.

### POST `/api/notice-upload.php`
Admin only. Multipart fields: `title`, `message`, optional `notice_file`.

### GET `/api/notices.php`
Returns published notices.

## Error format

```json
{
  "success": false,
  "message": "Human-readable safe error"
}
```

Sensitive server exceptions are written to the server error log rather than returned to the browser.
### NID review endpoints

- `GET /api/admin/nid-submissions.php` — administrator-only list of submitted NID documents.
- `GET /api/admin/nid-image.php?id=<document_id>&side=front|back` — administrator-only private image view.
- `POST /api/admin/nid-decision.php` — administrator-only approve/reject decision; requires CSRF token. Rejections require a reason.

