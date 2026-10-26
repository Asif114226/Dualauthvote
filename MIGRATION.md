# Backend replacement notes

The PHP API implementation and Composer vendor directory have been removed from this edition. Flask handles the legacy frontend API URLs (for example, `/api/login.php`) so existing `fetch()` calls keep working.

The default database is SQLite for a low-friction local setup. It is created automatically. The previous MySQL `database.sql` schema is retained as a reference only; this version does not automatically import its data. If you need existing voter/candidate/vote records, make a secure backup first and arrange a deliberate, reviewed migration. Never copy real voter NID/password/biometric data into an unprotected development environment.


NID front and back images are stored in the private `private_nid_storage/` directory, with review metadata in the `nid_documents` table. Back up this directory alongside the database and restrict filesystem access.
