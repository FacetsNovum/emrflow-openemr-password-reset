# EMRFlow: OpenEMR Self-Service Password Reset

> **Compatible with:** OpenEMR 7.0.2 Patch 3 and 8.0.0 Patch 3 (both tested); also verified against the 8.1 development build
> **Maintained by:** Facets Novum LLC (Darrell Henry)
> **Files:** 3 (drop-in, no other modifications required)

---

## What This Does

Adds a **public-facing password change and reset page** to any OpenEMR installation. OpenEMR has no built-in way for users to change or reset their passwords without being logged in. If a therapist forgets their password, an admin has to manually reset it in the database.

This package solves that with two secure, self-service flows:

1. **Password change**: user knows their current password and wants to update it
   - Enter username + current password → verify → set new password
   - Email field is locked in the UI by default; see [Optional: allow email changes](#optional-allow-email-changes-in-the-password-change-flow) below

2. **Email-link reset**: user forgot their password (or it's their first login)
   - Enter email address → receive a one-time reset link → click link → set new password
   - Email is the identity proof; email changes are always locked in this flow

### Security Features

- Password policy: 8+ characters, uppercase, lowercase, digits, special characters
- Reuse prevention: cannot reuse current password or last 4 passwords
- One-time tokens stored as SHA-256 hashes (plaintext token never persisted)
- CSRF protection on all forms
- Rate limiting on token verification attempts
- Rate limiting on every reset-link request, matched or not: 5 an hour per IP address and 3 an hour per email (the email is stored only as a SHA-256 hash)
- No account enumeration: every reset-link request gets the same answer after the same minimum time (about one second), whether or not the email matches an account
- The username is sent only in the reset email, to the address on file; the page never shows it and it never goes in a URL
- Links in emails are built from the site's configured address (`site_addr_oath`), never the request's Host header, so a forged Host can't point a real person's reset email at another site
- No Bcc of reset links; deactivated users get no link
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

The following tables are created automatically on first use, with no manual SQL needed:

| Table | Purpose |
|---|---|
| `password_setup_tokens` | One-time tokens for password reset (SHA-256 hashed) |
| `users_password_baseline` | Snapshot of original password hash for change tracking |
| `users_password_status` | Per-user status flag (default / changed) + timestamps |
| `password_token_verify_log` | Rate-limiting log for token verification attempts |
| `password_reset_requests` | Every reset-link request (IP address and a hashed email) for the request rate limit; rows older than a day are pruned |

### Email Configuration (Required for Reset-Link Flow)

The email-link flow sends a one-time reset link to the user's email. For this to work:

1. The server must be able to send mail with PHP's `mail()` (a working sendmail or MTA on the host).
2. OpenEMR's **site address** must be set to your site's `https://` address: Admin → Config → Connectors → **Site Address Override** (`site_addr_oath`), for example `https://ehr.example.com`. The reset link, the "Site:" line and the sender (`no-reply@<that host>`) all come from it. **If it is empty or not `https://`, no reset email is sent** (the page still shows its usual answer, and the reason is written to the PHP error log).
3. **Without these**, only the legacy flow works (username + current password → change password).

### Optional: allow email changes in the password-change flow

The UI ships with the email field **locked** in both flows. The lock is controlled by a single flag near the top of `change_password.php`:

```php
$lockEmail = true; // line ~203
```

Set it to `false` and the password-change flow (username + current password) will allow the user to update their `google_signin_email` at the same time as their password. All the backend logic (email format validation, uniqueness check against the `users` table, the `UPDATE users SET google_signin_email` SQL) is already in place. The flag is purely a UI gate.

Two notes:

1. **The email-link reset flow ignores this flag.** It is always locked, because the email is the identity proof in that flow. You cannot change identity in the same transaction that is proving it.
2. **Why it ships locked.** EMRFlow (the upstream maintainer's product) uses `google_signin_email` as an identity key in downstream Firestore lookups; allowing arbitrary email changes would orphan those records. If your OpenEMR install does not have downstream systems keyed on the email column, flipping the flag is safe.

### Branding (white-label)

The page ships EMRFlow-branded by default, but it is fully white-label. All branding is driven by a single `$brand` config block at the top of `change_password.php`. Nothing else needs to change:

```php
$brand = [
    'name'     => 'EMRFlow',                               // wordmark in the header ('' hides it)
    'tagline'  => 'Secure password management for OpenEMR', // small line under the card
    'accent'   => '#006699',                               // header band + chrome color
    'cta'      => '#E8913A',                               // primary button fill
    'cta_text' => '#1F2937',                               // text on the primary button (must contrast with cta)
    'logo'     => null,                                    // optional logo path relative to this file; null = built-in mark
];
```

- Set `accent` to any `#rrggbb` hex; the page derives all related shades (hover, depth, light tint, the wordmark accent) automatically, so you only pick one color.
- Point `logo` at an image (e.g. `'sites/default/images/your-logo.png'`) to replace the built-in lock mark.
- Set `name` to `''` to hide the wordmark, or to your own organization's name. The two-tone treatment is applied only to the default `EMRFlow` wordmark; any other name renders plain.
- Leave `cta_text` readable against `cta`: light text on a light button (or dark on dark) fails contrast. The defaults pair dark text `#1F2937` on amber, which passes WCAG AA.

The page has **no external dependencies**: no CDN, Bootstrap, jQuery, or web fonts. It renders entirely from inline CSS and SVG, so it works on locked-down or offline installs and never phones home.

### Verification Checklist

After installation:

- [ ] Navigate to `https://your-domain.com/change_password.php`, form loads
- [ ] Test legacy flow: enter a valid username + password → verify → change password → log in with new password
- [ ] Test email flow: enter a valid email → receive an email with your username and a reset link → click link → set password → log in
- [ ] Enter an email that has no account: the page shows the same answer as for a real one
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

Option B is preferred: no temporary password to communicate or forget.

---

## Uninstalling

To remove the password reset feature:

```bash
cd /path/to/openemr/public_html
rm change_password.php change_password_process.php library/password_status.inc.php
```

The 5 database tables can be dropped if desired (they're inert without the PHP files):
```sql
DROP TABLE IF EXISTS password_setup_tokens;
DROP TABLE IF EXISTS users_password_baseline;
DROP TABLE IF EXISTS users_password_status;
DROP TABLE IF EXISTS password_token_verify_log;
DROP TABLE IF EXISTS password_reset_requests;
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

This project is licensed under the **GNU General Public License v3.0**, the same license as OpenEMR itself. See [LICENSE](LICENSE) for the full text.

Copyright (c) 2026 Facets Novum LLC.

---

## About EMRFlow

This package is built and maintained by **[Facets Novum](https://emrflow.com)**, makers of **EMRFlow**, the therapy documentation and billing platform for OpenEMR.

If your organization needs:
- **FHIR R4 integration** with OpenEMR (automatic patient/practitioner/location sync)
- **AI-powered clinical notes** (voice dictation → SOAP/DAP notes in seconds)
- **Automated insurance claim submission** (eligibility checks, 837P generation, ERA posting)
- **Solo practice mode** (independent therapists, no EHR required)

Visit **[emrflow.com](https://emrflow.com)** or email **darrell@facetsnovum.com** to schedule a demo.
