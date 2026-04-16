# EMRFlow — OpenEMR Self-Service Password Reset

> **Compatible with:** OpenEMR 7.0.2 Patch 3 (may work on adjacent versions)
> **Maintained by:** Facets Novum LLC (Darrell Henry)
> **Files:** 3 (drop-in, no other modifications required)

---

## What This Does

Adds a **public-facing password change and reset page** to any OpenEMR installation. OpenEMR has no built-in way for users to change or reset their passwords without being logged in — if a therapist forgets their password, an admin has to manually reset it in the database.

This package solves that with two secure, self-service flows:

1. **Password change** — user knows their current password and wants to update it
   - Enter username + current password → verify → set new password
   - Optionally update email address at the same time

2. **Email-link reset** — user forgot their password (or it's their first login)
   - Enter email address → receive a one-time reset link → click link → set new password
   - Email is the identity proof; email changes are disabled in this flow

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

- **OpenEMR:** 7.0.2 Patch 3 (tested). Should work on 7.x generally — uses only `sqlQuery()`, `sqlStatement()`, `AuthHash`, and `$GLOBALS` which are stable across OpenEMR 7.x.
- **PHP:** 8.0+ required
- **Dependencies:** None beyond OpenEMR's core (no Composer packages needed)

## License

Proprietary to Facets Novum LLC. The underlying OpenEMR integration points use OpenEMR's GPL-3.0-licensed APIs.
