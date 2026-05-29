# EMRFlow — OpenEMR Self-Service Password Reset

> **Compatible with:** OpenEMR 7.0.2 Patch 3 and 8.0.0 Patch 3 (both tested); also verified against the 8.1 development build
> **Maintained by:** Facets Novum LLC (Darrell Henry)
> **Files:** 3 (drop-in, no other modifications required)

---

## What This Does

Adds a **public-facing password change and reset page** to any OpenEMR installation. OpenEMR has no built-in way for users to change or reset their passwords without being logged in — if a therapist forgets their password, an admin has to manually reset it in the database.

This package solves that with two secure, self-service flows:

1. **Password change** — user knows their current password and wants to update it
   - Enter username + current password → verify → set new password
   - Email field is locked in the UI by default; see [Optional: allow email changes](#optional-allow-email-changes-in-the-password-change-flow) below

2. **Email-link reset** — user forgot their password (or it's their first login)
   - Enter email address → receive a one-time reset link → click link → set new password
   - Email is the identity proof; email changes are always locked in this flow

### Security Features

- Password policy: 8+ characters, uppercase, lowercase, digits, special characters
- Reuse prevention: cannot reuse current password or last 4 passwords
- One-time tokens stored as SHA-256 hashes (plaintext token never persisted)
- CSRF protection on all forms
- Rate limiting on token verification attempts
- HTTPOnly session cookies, SAMEORIGIN framing, strict referrer policy
- Audit trail via `password_token_verify_log` table

---

## Installation

**This is a drop-in overlay.** Extract into your OpenEMR `public_html` directory and it's ready to use.

```bash
# 1. Back up (always)
cd /path/to/openemr
tar czf ~/openemr-backup-$(date +%Y%m%d).tar.gz public_html/

# 2. Extract the package into public_html
cd /path/to/openemr/public_html
unzip /path/to/emrflow-openemr-password-reset.zip -o

# 3. Verify
#    Navigate to https://your-domain.com/change_password.php
#    You should see the password change form.
```

**That's it.** No config files to edit, no database migrations to run.

### What Gets Installed

```
public_html/
├── change_password.php              ← Public UI (the page users visit)
├── change_password_process.php      ← Backend processor (handles both flows)
└── library/
    └── password_status.inc.php      ← Table management + helper functions
```

These 3 files do not modify any existing OpenEMR files. They are standalone additions.

### Database Tables (Auto-Created)

The following tables are created automatically on first use — no manual SQL needed:

| Table | Purpose |
|---|---|
| `password_setup_tokens` | One-time tokens for password reset (SHA-256 hashed) |
| `users_password_baseline` | Snapshot of original password hash for change tracking |
| `users_password_status` | Per-user status flag (default / changed) + timestamps |
| `password_token_verify_log` | Rate-limiting log for token verification attempts |

### Email Configuration (Required for Reset-Link Flow)

The email-link flow sends a one-time reset link to the user's email. For this to work:

1. OpenEMR must have SMTP configured:
   - Admin → Config → Notifications → **Email Notification Settings**
   - Set SMTP host, port, username, password, and encryption type
2. The "From" address uses `$GLOBALS['patient_reminder_sender_email']`
3. **Without email configured**, only the legacy flow works (username + current password → change password). The email-link flow will silently fail to send.

### Optional: allow email changes in the password-change flow

The UI ships with the email field **locked** in both flows. The lock is controlled by a single flag near the top of `change_password.php`:

```php
$lockEmail = true; // line ~203
```

Set it to `false` and the password-change flow (username + current password) will allow the user to update their `google_signin_email` at the same time as their password. All the backend logic (email format validation, uniqueness check against the `users` table, the `UPDATE users SET google_signin_email` SQL) is already in place — the flag is purely a UI gate.

Two notes:

1. **The email-link reset flow ignores this flag.** It is always locked, because the email is the identity proof in that flow. You cannot change identity in the same transaction that is proving it.
2. **Why it ships locked.** EMRFlow (the upstream maintainer's product) uses `google_signin_email` as an identity key in downstream Firestore lookups; allowing arbitrary email changes would orphan those records. If your OpenEMR install does not have downstream systems keyed on the email column, flipping the flag is safe.

### Verification Checklist

After installation:

- [ ] Navigate to `https://your-domain.com/change_password.php` — form loads
- [ ] Test legacy flow: enter a valid username + password → verify → change password → log in with new password
- [ ] Test email flow: enter a valid email → receive reset link → click link → set password → log in
- [ ] Verify password policy: try a weak password (e.g., "abc") → should be rejected
- [ ] Verify reuse prevention: try to "change" to the same password → should be rejected

---

## How to Onboard Therapists

### Option A: Temporary Password
1. Create the therapist's OpenEMR account (Admin → Users → Add User)
2. Set a temporary password (e.g., `Welcome1!`)
3. Tell the therapist: "Go to `https://your-domain.com/change_password.php`, enter your username and the temporary password, then set your own."

### Option B: Email-Link (No Temporary Password Needed)
1. Create the therapist's OpenEMR account
2. Make sure their **email address** is set in their OpenEMR user profile
3. Tell the therapist: "Go to `https://your-domain.com/change_password.php`, click 'Forgot password / first-time setup', enter your email, and follow the link to set your password."

Option B is preferred — no temporary password to communicate or forget.

---

## Uninstalling

To remove the password reset feature:

```bash
cd /path/to/openemr/public_html
rm change_password.php change_password_process.php library/password_status.inc.php
```

The 4 database tables can be dropped if desired (they're inert without the PHP files):
```sql
DROP TABLE IF EXISTS password_setup_tokens;
DROP TABLE IF EXISTS users_password_baseline;
DROP TABLE IF EXISTS users_password_status;
DROP TABLE IF EXISTS password_token_verify_log;
```

No other OpenEMR files are affected.

---

## Compatibility

- **OpenEMR:** 7.0.2 Patch 3 and 8.0.0 Patch 3 (both tested). Uses only `sqlQuery()`, `sqlStatement()`, `AuthHash`, and `$GLOBALS`, which are stable across OpenEMR 7.x, 8.0, and 8.1. On a clean 8.0.0(3) install both flows were verified end to end: auto table creation, the username + current-password change flow (with `users_secure` history shift), the email-link reset flow, password-policy enforcement, and reuse prevention against the last 5 passwords. The same battery was re-run against the 8.1 development build (8.1.0-dev) with identical results.
- **PHP:** 8.0+ required
- **Dependencies:** None beyond OpenEMR's core (no Composer packages needed)

## Contributing

Found a bug? Have a suggestion? Open an issue or pull request on this repo. We respond to all submissions.

## License

This project is licensed under the **GNU General Public License v3.0** — the same license as OpenEMR itself. See [LICENSE](LICENSE) for the full text.

Copyright (c) 2026 Facets Novum LLC.

---

## About EMRFlow

This package is built and maintained by **[Facets Novum](https://emrflow.com)**, makers of **EMRFlow** — the therapy documentation and billing platform for OpenEMR.

If your organization needs:
- **FHIR R4 integration** with OpenEMR (automatic patient/practitioner/location sync)
- **AI-powered clinical notes** (voice dictation → SOAP/DAP notes in seconds)
- **Automated insurance claim submission** (eligibility checks, 837P generation, ERA posting)
- **Solo practice mode** (independent therapists — no EHR required)

Visit **[emrflow.com](https://emrflow.com)** or email **darrell@facetsnovum.com** to schedule a demo.
