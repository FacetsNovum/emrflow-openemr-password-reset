<?php
// ─── EMRFlow Modifications ─────────────────────────────────────────────
// EMRFlow CUSTOM FILE
// Modified by: Facets Novum LLC (Darrell Henry)
// Purpose: Public password change/reset UI, no OpenEMR login required
// WHY: OpenEMR has no public-facing password change mechanism. Therapists who forget
//      their password or need initial setup cannot access the built-in password change
//      (which requires being logged in). This provides two secure flows: legacy credential
//      verification and email-based one-time token reset.
// ──────────────────────────────────────────────────────────────────────

/**
 * Public Password Change Entry Point
 * Accessible without login at: https://your-domain.com/change_password.php
 *
 * Supports two secure flows:
 *  1) Verify with username + current password (legacy) -> token -> update password/email
 *  2) Email a one-time setup/reset link (no login required) -> token -> update password
 *     (Email is the identity proof; email changes are disabled for this token type)
 *
 * @package   OpenEMR
 * @link      https://www.open-emr.org
 * @author    Darrell Henry
 * @copyright Copyright (c) 2026 Facets Novum, LLC
 * @license   https://github.com/openemr/openemr/blob/master/LICENSE GNU General Public License 3
 */

/**
 * /public_html/change_password.php
 *
 * Public Password Change Entry Point (no login required)
 *
 * Supports two secure flows:
 *  1) Legacy: Verify with username + current password -> short-lived legacy token -> update password (+ optional email change)
 *  2) Email-link: Email a one-time setup/reset link -> hashed token -> update password ONLY
 *     (Email is identity proof; email changes are locked for this token type)
 *
 * IMPORTANT:
 *  - NO output before headers (no BOM, no whitespace before <?php)
 *  - This file assumes OpenEMR is installed in /public_html
 *
 * @package   OpenEMR
 * @link      https://www.open-emr.org
 * @author    Darrell Henry
 * @copyright Copyright (c) 2026 Facets Novum, LLC
 * @license   https://github.com/openemr/openemr/blob/master/LICENSE GNU General Public License 3
 */

declare(strict_types=1);

// ─── Branding (white-label) ────────────────────────────────────────────
// This page ships EMRFlow-branded by default. To rebrand for your own
// organization, edit the values below. Nothing else needs to change.
//   name     : wordmark text shown in the header ('' hides it)
//   tagline  : small line shown under the card ('' hides it)
//   accent   : header band + chrome color, any #rrggbb hex
//   cta      : primary button fill color
//   cta_text : text color on the primary button (must contrast with cta)
//   logo     : optional path to a logo image relative to this file; null = built-in mark
// All related shades (hover, deep, tint) are derived automatically from `accent`.
$brand = [
    'name'     => 'EMRFlow',
    'tagline'  => 'Secure password management for your EHR account',
    'accent'   => '#006699',
    'cta'      => '#E8913A',
    'cta_text' => '#1F2937',
    'logo'     => null,
];
// ────────────────────────────────────────────────────────────────────────

// -----------------------
// Session + headers
// -----------------------
ini_set('session.use_cookies', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Lax');
ini_set('session.cookie_secure', '1');

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Basic hardening headers (safe for standalone)
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');

// -----------------------
// Site resolution (CRITICAL: never infer from host)
// -----------------------
function resolveSiteId(): string
{
    $raw = $_POST['site'] ?? $_GET['site'] ?? '';
    $raw = is_string($raw) ? trim($raw) : '';

    if ($raw === '') {
        $raw = 'default';
    }

    // allow only OpenEMR site dir name chars
    if (preg_match('/[^A-Za-z0-9\-.]/', $raw)) {
        return 'default';
    }

    // must exist as directory under this OpenEMR install
    $dir = __DIR__ . '/sites/' . $raw;
    if (!is_dir($dir)) {
        return 'default';
    }

    return $raw;
}

$site_id = resolveSiteId();

// Now safe to bootstrap OpenEMR
$ignoreAuth = true;
$sessionAllowWrite = true;

require_once __DIR__ . "/sites/{$site_id}/sqlconf.php";
if (!isset($config) || (int)$config !== 1) {
    // If OpenEMR isn't configured, send to setup.
    header("Location: setup.php?site=" . urlencode($site_id));
    exit;
}

require_once __DIR__ . "/interface/globals.php";

// Password table helpers (single source of truth)
require_once __DIR__ . "/library/password_status.inc.php";
if (function_exists('ensurePasswordTables')) {
    ensurePasswordTables();
}

// -----------------------
// CSRF
// -----------------------
function pwdGenerateCsrfToken(): string
{
    $now = time();
    $ttl = 3600;

    if (empty($_SESSION['pwd_csrf_token']) || empty($_SESSION['pwd_csrf_time'])) {
        $_SESSION['pwd_csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['pwd_csrf_time'] = $now;
    } elseif (($now - (int)$_SESSION['pwd_csrf_time']) > $ttl) {
        $_SESSION['pwd_csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['pwd_csrf_time'] = $now;
    }

    return (string)$_SESSION['pwd_csrf_token'];
}

function pwdSanitizeUsername(string $v): string
{
    // Conservative allowlist; for prefill only
    return preg_replace('/[^A-Za-z0-9@._-]/', '', $v);
}

function pwdSanitizeEmailPrefill(string $v): string
{
    $v = strtolower(trim($v));
    $v = preg_replace('/[\s\x00-\x1F\x7F]+/', '', $v);
    return substr($v, 0, 254);
}

// -----------------------
// Cancel handler (server-side source of truth)
// -----------------------
if (isset($_GET['cancelled'])) {
    unset($_SESSION['last_user_id']);

    $u = '';
    if (!empty($_GET['username']) && is_string($_GET['username'])) {
        $u = pwdSanitizeUsername($_GET['username']);
    } elseif (!empty($_SESSION['last_username']) && is_string($_SESSION['last_username'])) {
        $u = pwdSanitizeUsername($_SESSION['last_username']);
    }

    header(
        "Location: change_password.php?step=request"
        . "&site=" . urlencode($site_id)
        . ($u !== '' ? "&username=" . urlencode($u) : "")
        . "&success=" . urlencode("Password change cancelled. You can start a new request below.")
    );
    exit;
}

// -----------------------
// Inputs
// -----------------------
$step    = $_GET['step'] ?? 'request';
$token   = $_GET['token'] ?? '';
$error   = $_GET['error'] ?? '';
$success = $_GET['success'] ?? '';

$step  = is_string($step) ? $step : 'request';
$token = is_string($token) ? $token : '';
$error = is_string($error) ? $error : '';
$success = is_string($success) ? $success : '';

// Prefill username: URL wins, else session fallback
$prefillUsername = '';
if (!empty($_GET['username']) && is_string($_GET['username'])) {
    $prefillUsername = pwdSanitizeUsername($_GET['username']);
} elseif (!empty($_SESSION['last_username']) && is_string($_SESSION['last_username'])) {
    $prefillUsername = pwdSanitizeUsername($_SESSION['last_username']);
}

// Prefill email (optional convenience)
$prefillEmail = '';
if (!empty($_GET['email']) && is_string($_GET['email'])) {
    $prefillEmail = pwdSanitizeEmailPrefill($_GET['email']);
}

$csrfToken = pwdGenerateCsrfToken();

// -----------------------
// Resolve current email (only for update step)
// -----------------------
$currentEmail = '';
// Email-change toggle for the password-change flow (username + current password).
//
//   true:  email field is read-only in the UI; user sees "This email is locked
//           for security. Contact your administrator to change it." The default.
//   false: user can update their google_signin_email at the same time as their
//           password. The backend (validation, uniqueness check, UPDATE SQL) is
//           already wired; this flag is purely a UI gate.
//
// Why locked by default: EMRFlow uses google_signin_email as an identity key in
// downstream Firestore lookups, so arbitrary email changes would orphan those
// records. If your OpenEMR install has no downstream systems keyed on the email
// column, flip this to false. See README → "Optional: allow email changes".
//
// Note: the email-link reset flow ($isEmailLink) ignores this flag and is always
// locked, because email is the identity proof in that flow.
$lockEmail  = function_exists('pwdEmailChangeLocked') ? pwdEmailChangeLocked() : true;
$isEmailLink  = false;
$isEmailLocked = ($lockEmail || $isEmailLink);

if ($step === 'update' && $token !== '') {
    // 1) Email-link (password_setup_tokens) via library
    $row = function_exists('fetchValidPasswordSetupToken') ? fetchValidPasswordSetupToken($token) : null;
    if (!empty($row) && !empty($row['user_id'])) {
        $isEmailLink  = true;
        $currentEmail = (string)($row['google_signin_email'] ?? '');
    } else {
        // 2) Legacy token fallback (password_change_tokens)
        $tokenData = sqlQuery(
            "SELECT user_id
               FROM password_change_tokens
              WHERE token = ?
                AND used = 0
                AND expiry > NOW()
              LIMIT 1",
            [$token]
        );

        if (!empty($tokenData['user_id'])) {
            $emailResult = sqlQuery(
                "SELECT google_signin_email FROM users WHERE id = ?",
                [(int)$tokenData['user_id']]
            );
            $currentEmail = (string)($emailResult['google_signin_email'] ?? '');
        } else {
            $step = 'request';
            $error = 'Invalid or expired link. Please start over.';
            $token = '';
        }
    }
}

// If starting fresh, clear request-scoped session state
if ($step === 'request' && empty($_POST)) {
    unset($_SESSION['last_user_id']);

    // Keep last_username intentionally for prefill UX.
    if (!empty($_SESSION['pwd_csrf_time']) && (time() - (int)$_SESSION['pwd_csrf_time'] > 3600)) {
        unset($_SESSION['pwd_csrf_token'], $_SESSION['pwd_csrf_time']);
    }
}

// -----------------------
// Output helpers (works with or without OpenEMR text()/attr())
// -----------------------
function h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
}

function t_out(string $s): string
{
    // Use OpenEMR text() when available (handles translations + escaping)
    if (function_exists('text')) {
        return text($s);
    }
    return h($s);
}

function a_out(string $s): string
{
    // Use OpenEMR attr() when available (attribute escaping)
    if (function_exists('attr')) {
        return attr($s);
    }
    return h($s);
}

// -----------------------
// Brand palette: derive all shades from the single $brand['accent'] hex
// -----------------------
function pwdSafeHex(string $v, string $fallback): string
{
    return preg_match('/^#[0-9a-fA-F]{6}$/', $v) ? strtolower($v) : $fallback;
}

function pwdHexMix(string $hex, string $mix, float $w): string
{
    $hex = ltrim($hex, '#');
    $mix = ltrim($mix, '#');
    $r = hexdec(substr($hex, 0, 2)); $g = hexdec(substr($hex, 2, 2)); $b = hexdec(substr($hex, 4, 2));
    $mr = hexdec(substr($mix, 0, 2)); $mg = hexdec(substr($mix, 2, 2)); $mb = hexdec(substr($mix, 4, 2));
    return sprintf(
        '#%02x%02x%02x',
        (int)round($r + ($mr - $r) * $w),
        (int)round($g + ($mg - $g) * $w),
        (int)round($b + ($mb - $b) * $w)
    );
}

$bName    = isset($brand['name']) ? (string)$brand['name'] : 'EMRFlow';
$bTagline = isset($brand['tagline']) ? (string)$brand['tagline'] : '';
$bLogo    = (isset($brand['logo']) && is_string($brand['logo']) && $brand['logo'] !== '') ? $brand['logo'] : null;
$cBrand   = pwdSafeHex((string)($brand['accent'] ?? ''), '#006699');
$cCta     = pwdSafeHex((string)($brand['cta'] ?? ''), '#e8913a');
$cCtaText = pwdSafeHex((string)($brand['cta_text'] ?? ''), '#1f2937');

$cBrandDark = pwdHexMix($cBrand, '#000000', 0.18);
$cBrandDeep = pwdHexMix($cBrand, '#000000', 0.40);
$cBrandTint = pwdHexMix($cBrand, '#ffffff', 0.90);
$cBrandInk  = pwdHexMix($cBrand, '#000000', 0.20);
$cBrandLite = pwdHexMix($cBrand, '#ffffff', 0.70);
$cCtaDark   = pwdHexMix($cCta, '#000000', 0.12);

$favLetter = $bName !== '' ? strtoupper(substr($bName, 0, 1)) : 'P';
$favColor  = '%23' . ltrim($cBrand, '#');

// Step-aware subtitle shown under the brand wordmark
$headerSubtitle = 'Reset your password';
if ($step === 'update') {
    $headerSubtitle = 'Choose a new password';
} elseif ($step === 'complete') {
    $headerSubtitle = 'Password updated';
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>Reset password<?= $bName !== '' ? ' · ' . h($bName) : '' ?></title>

    <?php
    $faviconPaths = [
        'public/images/logos/core/favicon/favicon.ico',
        'favicon.ico',
        'sites/default/favicon.ico',
        'sites/' . $site_id . '/images/favicon.ico',
        'interface/themes/images/favicon.ico',
        'images/favicon.ico'
    ];

    $faviconFound = false;
    foreach ($faviconPaths as $path) {
        if (file_exists(__DIR__ . '/' . $path) || file_exists($path)) {
            // Prefer relative href for browser
            echo '<link rel="icon" type="image/x-icon" href="' . h($path) . '">';
            echo '<link rel="shortcut icon" href="' . h($path) . '">';
            $faviconFound = true;
            break;
        }
    }
    if (!$faviconFound) {
        echo '<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><rect width=%22100%22 height=%22100%22 rx=%2222%22 fill=%22' . $favColor . '%22/><text x=%2250%22 y=%2268%22 font-size=%2256%22 font-family=%22Arial,sans-serif%22 font-weight=%22700%22 fill=%22white%22 text-anchor=%22middle%22>' . h($favLetter) . '</text></svg>">';
    }
    ?>

    <style>
        :root {
            --brand: <?= $cBrand ?>;          /* brand chrome (header band) */
            --brand-dark: <?= $cBrandDark ?>;
            --brand-deep: <?= $cBrandDeep ?>; /* depth color */
            --brand-tint: <?= $cBrandTint ?>; /* light container tint */
            --brand-ink: <?= $cBrandInk ?>;   /* readable brand text on tint */
            --accent: <?= $cCta ?>;          /* primary CTA fill */
            --accent-dark: <?= $cCtaDark ?>;
            --accent-text: <?= $cCtaText ?>;  /* text on CTA (must pass contrast) */
            --bg: #EEEEEE;             /* scaffold */
            --surface: #FFFFFF;
            --ink: #111827;            /* primary text */
            --ink-muted: #49454F;      /* muted text (M3 onSurfaceVariant) */
            --line: #d7dbdf;           /* input border */
            --hairline: rgba(17,17,17,0.06);
            --success: #43A047;
            --warning: #B45309;
            --error: #B91C1C;
            --radius-card: 16px;
            --radius-ctl: 10px;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        html, body { height: 100%; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--ink);
            min-height: 100vh;
            display: flex;
            padding: 24px 16px;
            -webkit-font-smoothing: antialiased;
            line-height: 1.4;
        }
        /* margin:auto centers the card when it fits, but lets the page scroll
           (nothing clipped) when the content is taller than the viewport. */
        .wrap { width: 100%; max-width: 460px; margin: auto; }

        .card {
            background: var(--surface);
            border-radius: var(--radius-card);
            border: 1px solid var(--hairline);
            box-shadow: 0 1px 2px rgba(0,0,0,0.04), 0 10px 30px rgba(0,0,0,0.06);
            overflow: hidden;
        }

        /* Brand header band: solid brand color, like the app AppBar */
        .brand { background: var(--brand); color: #fff; padding: 24px 28px; }
        .brand-row { display: flex; align-items: center; gap: 12px; }
        .brand-mark {
            width: 40px; height: 40px; border-radius: 11px;
            background: #fff; display: inline-flex;
            align-items: center; justify-content: center; flex: 0 0 auto;
        }
        .brand-logo { height: 32px; width: auto; display: block; }
        .wordmark { font-size: 22px; font-weight: 700; letter-spacing: -0.2px; }
        .wordmark span { color: <?= $cBrandLite ?>; }   /* lighter brand tint */
        .brand-sub { margin-top: 12px; font-size: 14px; color: rgba(255,255,255,0.85); }

        .body { padding: 28px; }

        /* Alerts, app chip pattern: colored icon + text on ~10% tint */
        .alert {
            display: flex; gap: 10px; align-items: flex-start;
            padding: 12px 14px; border-radius: var(--radius-ctl);
            font-size: 14px; margin-bottom: 18px; line-height: 1.45;
        }
        .alert svg { flex: 0 0 auto; width: 20px; height: 20px; margin-top: 1px; }
        .alert-success { color: #2f7d33; background: rgba(67,160,71,0.10); border: 1px solid rgba(67,160,71,0.25); }
        .alert-danger  { color: var(--error); background: rgba(185,28,28,0.08); border: 1px solid rgba(185,28,28,0.22); }
        .alert-info    { color: var(--brand-ink); background: var(--brand-tint); border: 1px solid rgba(0,0,0,0.10); }

        .group { margin-bottom: 18px; }
        label.lbl { display: block; font-size: 13.5px; font-weight: 600; color: var(--ink); margin-bottom: 7px; }
        label.lbl .req-star { color: var(--error); }

        .field { position: relative; }
        .control {
            width: 100%; padding: 12px 14px; font-size: 15px; color: var(--ink);
            background: #fff; border: 1px solid var(--line); border-radius: var(--radius-ctl);
            transition: border-color 0.15s ease, box-shadow 0.15s ease;
        }
        .control:focus { outline: none; border-color: var(--brand); box-shadow: 0 0 0 3px rgba(0,0,0,0.08); }
        .control[readonly] { background: #f3f4f6; color: #6b7280; cursor: not-allowed; }
        .has-reveal .control { padding-right: 46px; }

        .reveal {
            position: absolute; right: 8px; top: 50%; transform: translateY(-50%);
            background: none; border: none; padding: 6px; cursor: pointer;
            color: #6b7280; display: inline-flex; border-radius: 8px; line-height: 0;
            transition: color 0.15s ease, background 0.15s ease;
        }
        .reveal:hover { color: var(--brand); background: rgba(0,0,0,0.05); }
        .reveal svg { width: 20px; height: 20px; }

        .hint { display: flex; gap: 6px; align-items: flex-start; font-size: 12.5px; color: #6b7280; margin-top: 7px; }
        .hint svg { flex: 0 0 auto; width: 14px; height: 14px; margin-top: 1px; }

        /* Buttons: brand CTA (configurable), brand-outline secondary */
        .btn {
            width: 100%; padding: 13px 16px; border: none; border-radius: var(--radius-ctl);
            font-size: 15px; font-weight: 600; cursor: pointer; text-decoration: none;
            display: inline-flex; align-items: center; justify-content: center; gap: 8px;
            transition: background 0.15s ease, border-color 0.15s ease, color 0.15s ease;
        }
        .btn svg { width: 18px; height: 18px; }
        .btn-primary { background: var(--accent); color: var(--accent-text); }
        .btn-primary:hover:not(:disabled) { background: var(--accent-dark); }
        .btn-secondary { background: transparent; color: var(--brand); border: 1px solid var(--brand); }
        .btn-secondary:hover:not(:disabled) { background: var(--brand-tint); }
        .btn-ghost { background: transparent; color: var(--ink-muted); }
        .btn-ghost:hover:not(:disabled) { background: rgba(0,0,0,0.05); }
        .btn-ghost.danger { color: var(--error); }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .btn + .btn { margin-top: 10px; }

        .divider {
            display: flex; align-items: center; gap: 12px; margin: 22px 0;
            color: #9aa1a8; font-size: 12px; text-transform: uppercase; letter-spacing: 0.6px;
        }
        .divider::before, .divider::after { content: ''; flex: 1; height: 1px; background: #e5e8eb; }

        /* Password strength + requirements */
        .strength { margin-top: 10px; height: 5px; background: #e5e8eb; border-radius: 3px; overflow: hidden; display: none; }
        .strength-bar { height: 100%; width: 0%; border-radius: 3px; transition: width 0.25s ease; background: var(--error); }
        .strength-bar.strength-weak { background: var(--error); }
        .strength-bar.strength-medium { background: var(--warning); }
        .strength-bar.strength-strong { background: var(--success); }

        .req-box { margin-top: 12px; padding: 12px 14px; background: #f7f8f9; border-radius: var(--radius-ctl); font-size: 13px; }
        .req-box strong { font-size: 12.5px; color: #374151; font-weight: 600; }
        .req-list { list-style: none; margin: 8px 0 0; padding: 0; }
        .req { display: flex; align-items: center; gap: 8px; padding: 4px 0; color: var(--ink-muted); }
        .req .tick { flex: 0 0 auto; width: 16px; text-align: center; color: #c4c9ce; font-size: 13px; }
        .req .tick::before { content: "\25CB"; }     /* ○ */
        .req.valid { color: #2f7d33; }
        .req.valid .tick { color: var(--success); }
        .req.valid .tick::before { content: "\2713"; } /* ✓ */

        .match { font-size: 13px; margin-top: 6px; font-weight: 500; display: none; }
        .feedback { display: block; font-size: 13px; margin-top: 7px; }

        .current-email {
            padding: 11px 13px; background: var(--brand-tint); border-radius: var(--radius-ctl);
            font-size: 13.5px; color: var(--brand-ink); margin-bottom: 10px;
        }
        .current-email strong { color: var(--brand-deep); }
        .current-email .locked { margin-top: 6px; font-size: 12.5px; display: flex; gap: 6px; align-items: center; }
        .current-email .locked svg { width: 13px; height: 13px; }

        /* Completed state */
        .done { text-align: center; padding: 8px 0 4px; }
        .done .badge {
            width: 64px; height: 64px; border-radius: 50%; margin: 0 auto 16px;
            background: rgba(67,160,71,0.12); display: flex; align-items: center; justify-content: center;
        }
        .done .badge svg { width: 34px; height: 34px; }
        .done h3 { font-size: 19px; color: var(--ink); margin-bottom: 6px; }
        .done p { color: var(--ink-muted); font-size: 14.5px; margin-bottom: 22px; line-height: 1.5; }

        .footnote { text-align: center; margin-top: 16px; font-size: 12px; color: #9aa1a8; }

        .spinner {
            display: inline-block; width: 16px; height: 16px;
            border: 2px solid transparent; border-top-color: currentColor;
            border-radius: 50%; animation: spin 0.7s linear infinite;
        }
        @keyframes spin { to { transform: rotate(360deg); } }

        /* Cancel modal */
        .modal-overlay {
            display: none; position: fixed; inset: 0; z-index: 1000;
            background: rgba(0,0,0,0.45); padding: 20px;
        }
        .modal-overlay.active { display: flex; align-items: center; justify-content: center; }
        .modal {
            background: #fff; border-radius: var(--radius-card); padding: 24px;
            max-width: 380px; width: 100%; box-shadow: 0 20px 50px rgba(0,0,0,0.25);
        }
        .modal h3 { font-size: 17px; color: var(--ink); margin-bottom: 8px; }
        .modal p { color: var(--ink-muted); font-size: 14px; line-height: 1.5; margin-bottom: 20px; }
        .modal-actions { display: flex; gap: 10px; }
        .modal-actions .btn { margin-top: 0; }

        @media (max-width: 520px) {
            .body { padding: 22px; }
            .brand { padding: 20px 22px; }
        }
    </style>
</head>
<body>
<main class="wrap">
    <section class="card" role="region" aria-label="Password reset">
        <header class="brand">
            <div class="brand-row">
                <?php if ($bLogo && (file_exists(__DIR__ . '/' . $bLogo) || file_exists($bLogo))): ?>
                    <img class="brand-logo" src="<?= h($bLogo) ?>" alt="<?= a_out($bName !== '' ? $bName : 'Logo') ?>">
                <?php else: ?>
                    <span class="brand-mark" aria-hidden="true">
                        <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="<?= h($cBrand) ?>" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="9" rx="2"></rect><path d="M8 11V7a4 4 0 0 1 8 0v4"></path></svg>
                    </span>
                <?php endif; ?>
                <?php if ($bName !== ''): ?>
                    <span class="wordmark"><?php if ($bName === 'EMRFlow'): ?>EMR<span>Flow</span><?php else: ?><?= t_out($bName) ?><?php endif; ?></span>
                <?php endif; ?>
            </div>
            <p class="brand-sub"><?= t_out($headerSubtitle) ?></p>
        </header>

        <div class="body">

            <?php if ($error !== ''): ?>
                <div class="alert alert-danger">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l9 16H3z"></path><path d="M12 10v4"></path><path d="M12 17h.01"></path></svg>
                    <span><?= t_out($error) ?></span>
                </div>
            <?php endif; ?>

            <?php if ($success !== ''): ?>
                <div class="alert alert-success">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"></circle><path d="M8.5 12.5l2.5 2.5 4.5-5"></path></svg>
                    <span><?= t_out($success) ?></span>
                </div>
            <?php endif; ?>

            <?php if ($step === 'request'): ?>

                <!-- Legacy flow: username + current password -->
                <form id="requestForm" method="POST" action="change_password_process.php">
                    <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                    <input type="hidden" name="action" value="request">
                    <input type="hidden" name="site" value="<?= h($site_id) ?>">

                    <div class="group">
                        <label class="lbl" for="username">Username</label>
                        <div class="field">
                            <input
                                type="text"
                                id="username"
                                name="username"
                                class="control"
                                placeholder="Your EHR username"
                                required
                                autocomplete="username"
                                value="<?= h($prefillUsername) ?>"
                            >
                        </div>
                    </div>

                    <div class="group">
                        <label class="lbl" for="current_password">Current password</label>
                        <div class="field has-reveal">
                            <input type="password" name="current_password" id="current_password" class="control" placeholder="Your current password" required autocomplete="current-password">
                            <button type="button" class="reveal" data-target="current_password" aria-label="Show password" onclick="toggleReveal(this)"></button>
                        </div>
                    </div>

                    <button type="submit" class="btn btn-primary">Continue</button>
                </form>

                <div class="divider">or</div>

                <!-- Email-link flow: email one-time setup/reset link -->
                <div class="alert alert-info">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2"></rect><path d="M3 7l9 6 9-6"></path></svg>
                    <span>Don't know your current password? We can email you a one-time setup and reset link.</span>
                </div>

                <form id="emailLinkForm" method="POST" action="change_password_process.php">
                    <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                    <input type="hidden" name="action" value="request_link">
                    <input type="hidden" name="site" value="<?= h($site_id) ?>">

                    <div class="group">
                        <label class="lbl" for="email">Sign-in email</label>
                        <div class="field">
                            <input
                                type="email"
                                id="email"
                                name="email"
                                class="control"
                                placeholder="The email on your EHR account"
                                required
                                autocomplete="email"
                                value="<?= h($prefillEmail) ?>"
                            >
                        </div>
                        <div class="hint">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="9" rx="2"></rect><path d="M8 11V7a4 4 0 0 1 8 0v4"></path></svg>
                            <span>If the account exists, we will email a secure link. Please check your spam or junk folder.</span>
                        </div>
                    </div>

                    <button type="submit" class="btn btn-secondary">Email me a one-time link</button>
                </form>

            <?php elseif ($step === 'update' && $token !== ''): ?>

                <?php if ($error === ''): ?>
                    <div class="alert alert-success">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"></circle><path d="M8.5 12.5l2.5 2.5 4.5-5"></path></svg>
                        <span>Identity verified. Choose a new password<?= $isEmailLink ? '' : ' and confirm your sign-in email' ?> below.</span>
                    </div>
                <?php endif; ?>

                <form id="updateForm" method="POST" action="change_password_process.php">
                    <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                    <input type="hidden" name="action" value="update">
                    <input type="hidden" name="token" value="<?= h($token) ?>">
                    <input type="hidden" name="site" value="<?= h($site_id) ?>">

                    <div class="group">
                        <label class="lbl" for="new_password">New password</label>
                        <div class="field has-reveal">
                            <input type="password" name="new_password" id="new_password" class="control" placeholder="Enter a new password" required autocomplete="new-password">
                            <button type="button" class="reveal" data-target="new_password" aria-label="Show password" onclick="toggleReveal(this)"></button>
                        </div>
                        <div class="strength" id="password-strength">
                            <div class="strength-bar" id="password-strength-bar"></div>
                        </div>
                        <div class="req-box">
                            <strong>Password must contain</strong>
                            <ul class="req-list" id="password-requirements">
                                <li id="req-length" class="req"><span class="tick"></span> At least 8 characters</li>
                                <li id="req-uppercase" class="req"><span class="tick"></span> One uppercase letter</li>
                                <li id="req-lowercase" class="req"><span class="tick"></span> One lowercase letter</li>
                                <li id="req-number" class="req"><span class="tick"></span> One number</li>
                                <li id="req-special" class="req"><span class="tick"></span> One special character</li>
                            </ul>
                        </div>
                    </div>

                    <div class="group">
                        <label class="lbl" for="confirm_password">Confirm new password</label>
                        <div class="field has-reveal">
                            <input type="password" name="confirm_password" id="confirm_password" class="control" placeholder="Re-enter the new password" required autocomplete="new-password">
                            <button type="button" class="reveal" data-target="confirm_password" aria-label="Show password" onclick="toggleReveal(this)"></button>
                        </div>
                        <small id="password-match" class="match"></small>
                    </div>

                    <div class="group">
                        <label class="lbl" for="new_email">Sign-in email <span class="req-star">*</span></label>

                        <?php if ($currentEmail !== ''): ?>
                            <div class="current-email">
                                Current: <strong><?= t_out($currentEmail) ?></strong>
                                <?php if ($isEmailLink): ?>
                                    <div class="locked">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="9" rx="2"></rect><path d="M8 11V7a4 4 0 0 1 8 0v4"></path></svg>
                                        Email changes are disabled for one-time email links.
                                    </div>
                                <?php endif; ?>
                            </div>
                        <?php endif; ?>

                        <div class="field">
                            <input
                                type="email"
                                name="new_email"
                                id="new_email"
                                class="control"
                                placeholder="Enter email address"
                                value="<?= a_out($currentEmail) ?>"
                                required
                                <?= $isEmailLocked ? 'readonly' : '' ?>
                            >
                        </div>

                        <div class="hint">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="9" rx="2"></rect><path d="M8 11V7a4 4 0 0 1 8 0v4"></path></svg>
                            <span><?php if ($isEmailLocked): ?>This email is locked for security. Contact your administrator to change it.<?php else: ?>Your sign-in email is required and must be unique.<?php endif; ?></span>
                        </div>
                    </div>

                    <button type="submit" class="btn btn-primary" id="submitBtn" disabled>
                        <?= $isEmailLink ? 'Update password' : 'Update password and email' ?>
                    </button>

                    <button type="button" class="btn btn-ghost" onclick="confirmCancel()">Cancel</button>
                </form>

            <?php elseif ($step === 'complete'): ?>

                <div class="done">
                    <div class="badge">
                        <svg viewBox="0 0 24 24" fill="none" stroke="#43A047" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"></circle><path d="M8 12.5l2.5 2.5 5.5-6"></path></svg>
                    </div>
                    <h3>Password updated</h3>
                    <p><?= t_out($success !== '' ? $success : 'Your password has been updated. You can now sign in with your new password.') ?></p>

                    <a href="interface/login/login.php?site=<?= h($site_id) ?>" class="btn btn-primary">Go to sign in</a>
                    <a href="change_password.php?site=<?= h($site_id) ?>" class="btn btn-secondary">Reset another password</a>
                </div>

            <?php else: ?>
                <div class="alert alert-danger">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l9 16H3z"></path><path d="M12 10v4"></path><path d="M12 17h.01"></path></svg>
                    <span>Invalid request. Please start over.</span>
                </div>
            <?php endif; ?>

        </div>
    </section>
    <?php if ($bTagline !== '' || $bName !== ''): ?>
    <p class="footnote"><?= t_out($bTagline) ?><?= ($bTagline !== '' && $bName !== '') ? ' · ' : '' ?><?= $bName !== '' ? t_out($bName) : '' ?></p>
    <?php endif; ?>
</main>

<script>
    // Inline SVG icon strings for the password reveal toggle
    var EYE = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
    var EYE_OFF = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3l18 18"></path><path d="M10.6 10.6a3 3 0 0 0 4.2 4.2"></path><path d="M9.9 4.6A10.9 10.9 0 0 1 12 4.5c6.5 0 10 7 10 7a18 18 0 0 1-3.2 4.3"></path><path d="M6.1 6.1A18 18 0 0 0 2 11.5s3.5 7 10 7a10.9 10.9 0 0 0 3.4-.5"></path></svg>';

    // Initialize each reveal button with the eye icon
    document.querySelectorAll('.reveal').forEach(function (b) { b.innerHTML = EYE; });

    function toggleReveal(btn) {
        var field = document.getElementById(btn.getAttribute('data-target'));
        if (!field) return;
        var show = field.type === 'password';
        field.type = show ? 'text' : 'password';
        btn.innerHTML = show ? EYE_OFF : EYE;
        btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    }

    function checkPasswordStrength(password) {
        var strength = 0;
        var requirements = {
            length: password.length >= 8,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            number: /[0-9]/.test(password),
            special: /[^A-Za-z0-9]/.test(password)
        };

        Object.keys(requirements).forEach(function (req) {
            var element = document.getElementById('req-' + req);
            if (!element) return;
            if (requirements[req]) {
                element.classList.add('valid');
                strength++;
            } else {
                element.classList.remove('valid');
            }
        });

        var strengthBar = document.getElementById('password-strength-bar');
        var strengthContainer = document.getElementById('password-strength');

        if (password.length > 0) {
            strengthContainer.style.display = 'block';
            strengthBar.style.width = ((strength / 5) * 100) + '%';
            strengthBar.className = 'strength-bar';
            if (strength <= 2) strengthBar.classList.add('strength-weak');
            else if (strength <= 4) strengthBar.classList.add('strength-medium');
            else strengthBar.classList.add('strength-strong');
        } else {
            strengthContainer.style.display = 'none';
        }

        return strength === 5;
    }

    if (document.getElementById('new_password')) {
        var newPassword = document.getElementById('new_password');
        var confirmPassword = document.getElementById('confirm_password');
        var submitBtn = document.getElementById('submitBtn');
        var matchIndicator = document.getElementById('password-match');

        newPassword.addEventListener('input', function () {
            checkPasswordStrength(this.value);
            validatePasswords();
        });

        confirmPassword.addEventListener('input', validatePasswords);

        function validatePasswords() {
            var isStrong = checkPasswordStrength(newPassword.value);
            var passwordsMatch = newPassword.value === confirmPassword.value;

            if (confirmPassword.value.length > 0) {
                matchIndicator.style.display = 'block';
                if (passwordsMatch) {
                    matchIndicator.textContent = '✓ Passwords match';
                    matchIndicator.style.color = 'var(--success)';
                } else {
                    matchIndicator.textContent = '✗ Passwords do not match';
                    matchIndicator.style.color = 'var(--error)';
                }
            } else {
                matchIndicator.style.display = 'none';
            }

            submitBtn.disabled = !(isStrong && passwordsMatch && confirmPassword.value.length > 0);
        }
    }

    document.querySelectorAll('form').forEach(function (form) {
        form.addEventListener('submit', function () {
            var submitBtn = this.querySelector('button[type="submit"]');
            if (submitBtn && !submitBtn.disabled) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<span class="spinner"></span> Processing...';
            }
        });
    });

    // Email availability check (disabled for email-link tokens because email is locked read-only)
    var isEmailLink = <?= $isEmailLink ? 'true' : 'false' ?>;

    if (!isEmailLink && document.getElementById('new_email')) {
        var emailField = document.getElementById('new_email');
        var emailFeedback = document.createElement('small');
        emailFeedback.id = 'email-feedback';
        emailFeedback.className = 'feedback';
        emailFeedback.style.display = 'none';
        emailField.parentNode.parentNode.appendChild(emailFeedback);

        var emailCheckTimeout;

        emailField.addEventListener('input', function () {
            clearTimeout(emailCheckTimeout);
            var email = this.value.trim();
            var currentEmail = <?= json_encode($currentEmail) ?>;

            if (!email || email === currentEmail) { emailFeedback.style.display = 'none'; return; }
            if (!email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) { emailFeedback.style.display = 'none'; return; }

            emailFeedback.style.display = 'block';
            emailFeedback.style.color = '#6b7280';
            emailFeedback.innerHTML = '<span class="spinner" style="width:12px;height:12px;border-width:2px;"></span> Checking availability...';

            emailCheckTimeout = setTimeout(function () { checkEmailAvailability(email); }, 450);
        });

        function checkEmailAvailability(email) {
            var token = <?= json_encode($token) ?>;
            var site = <?= json_encode($site_id) ?>;

            fetch('change_password_process.php?action=check_email&email=' + encodeURIComponent(email) +
                  '&token=' + encodeURIComponent(token) +
                  '&site=' + encodeURIComponent(site))
                .then(function (response) { return response.json(); })
                .then(function (data) {
                    if (data.available) {
                        emailFeedback.style.color = 'var(--success)';
                        emailFeedback.innerHTML = '✓ Email available';
                    } else {
                        emailFeedback.style.color = 'var(--error)';
                        emailFeedback.innerHTML = '✗ Email already in use';
                    }
                })
                .catch(function () { emailFeedback.style.display = 'none'; });
        }
    }

    function confirmCancel() { showCancelModal(); }

    function showCancelModal() {
        var existingModal = document.querySelector('.modal-overlay');
        if (existingModal) existingModal.remove();

        var modal = document.createElement('div');
        modal.className = 'modal-overlay';
        modal.innerHTML =
            '<div class="modal">' +
                '<h3>Cancel password change?</h3>' +
                '<p>Anything you have entered will be lost and you will need to start over.</p>' +
                '<div class="modal-actions">' +
                    '<button class="btn btn-secondary" id="modalCancelBtn">Go back</button>' +
                    '<button class="btn btn-ghost danger" id="modalConfirmBtn">Yes, cancel</button>' +
                '</div>' +
            '</div>';

        document.body.appendChild(modal);
        setTimeout(function () { modal.classList.add('active'); }, 10);

        document.getElementById('modalCancelBtn').addEventListener('click', closeCancelModal);
        document.getElementById('modalConfirmBtn').addEventListener('click', proceedCancel);

        modal.addEventListener('click', function (e) { if (e.target === modal) closeCancelModal(); });
    }

    function closeCancelModal() {
        var modal = document.querySelector('.modal-overlay');
        if (modal) {
            modal.classList.remove('active');
            setTimeout(function () { modal.remove(); }, 200);
        }
    }

    // update step has no username input; server will use session fallback
    function proceedCancel() {
        window.location.href = 'change_password.php?site=<?= h($site_id) ?>&cancelled=1';
    }

    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeCancelModal(); });
</script>
</body>
</html>
