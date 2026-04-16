<?php
// ─── EMRFlow Modifications ─────────────────────────────────────────────
// EMRFlow CUSTOM FILE
// Modified by: Facets Novum LLC (Darrell Henry)
// Purpose: Public password change/reset UI — no OpenEMR login required
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

// -----------------------
// Session + headers
// -----------------------
ini_set('session.use_cookies', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_httponly', '1');

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
$lockEmail  = true; // If 'true', then ALWAYS: "This email is locked for security. Contact your administrator to change it."; otherwise 'false' allows user to change
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

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Change Password - OpenEMR</title>

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
        echo '<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🏥</text></svg>">';
    }
    ?>

    <link rel="stylesheet" href="public/assets/bootstrap/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">

    <style>
        :root {
            --primary-color: #0d6efd;
            --success-color: #198754;
            --danger-color: #dc3545;
            --warning-color: #ffc107;
            --light-bg: #f8f9fa;
            --dark-text: #212529;
            --border-radius: 12px;
            --box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container-wrapper { max-width: 550px; width: 100%; }
        .card {
            background: white;
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow);
            overflow: hidden;
            animation: slideUp 0.5s ease-out;
        }
        @keyframes slideUp { from { opacity:0; transform: translateY(30px);} to {opacity:1; transform: translateY(0);} }
        .card-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .card-header i { font-size: 48px; margin-bottom: 15px; display: block; }
        .card-header h2 { margin: 0; font-size: 24px; font-weight: 600; }
        .card-header p { margin: 10px 0 0 0; opacity: 0.9; font-size: 14px; }
        .card-body { padding: 40px; }
        .form-group { margin-bottom: 25px; }
        .form-label { display:block; margin-bottom:8px; font-weight:500; color:var(--dark-text); font-size:14px; }
        .form-label i { margin-right:8px; color:var(--primary-color); }
        .input-wrapper { position: relative; }
        .form-control {
            width:100%;
            padding:12px 45px 12px 15px;
            border:2px solid #e0e0e0;
            border-radius:8px;
            font-size:15px;
            transition: all 0.3s ease;
        }
        .form-control:focus { outline:none; border-color:var(--primary-color); box-shadow:0 0 0 3px rgba(13,110,253,0.1); }
        .toggle-password {
            position:absolute;
            right:15px;
            top:50%;
            transform: translateY(-50%);
            cursor:pointer;
            color:#6c757d;
            transition: color 0.3s ease;
        }
        .toggle-password:hover { color: var(--primary-color); }
        .password-strength { margin-top:10px; height:4px; background:#e0e0e0; border-radius:2px; overflow:hidden; display:none; }
        .password-strength-bar { height:100%; width:0%; transition: all 0.3s ease; }
        .strength-weak { background: var(--danger-color); }
        .strength-medium { background: var(--warning-color); }
        .strength-strong { background: var(--success-color); }
        .password-requirements { margin-top:15px; padding:15px; background:var(--light-bg); border-radius:8px; font-size:13px; }
        .password-requirements ul { list-style:none; margin:10px 0 0 0; padding:0; }
        .password-requirements li { padding:5px 0; color:#6c757d; }
        .password-requirements li i { margin-right:8px; width:16px; }
        .password-requirements li.valid { color: var(--success-color); }

        .btn {
            width:100%;
            padding:14px;
            border:none;
            border-radius:8px;
            font-size:16px;
            font-weight:600;
            cursor:pointer;
            transition: all 0.3s ease;
            display:flex;
            align-items:center;
            justify-content:center;
            gap:10px;
        }
        .btn-primary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color:white; }
        .btn-primary:hover:not(:disabled) { transform: translateY(-2px); box-shadow:0 6px 20px rgba(102,126,234,0.4); }
        .btn-success { background: var(--success-color); color:white; }
        .btn-success:hover:not(:disabled) { background:#157347; transform: translateY(-2px); box-shadow:0 6px 20px rgba(25,135,84,0.4); }
        .btn-secondary { background:#6c757d; color:white; }
        .btn-secondary:hover:not(:disabled) { background:#5c636a; transform: translateY(-2px); box-shadow:0 6px 20px rgba(108,117,125,0.4); }
        .btn:disabled { opacity:0.6; cursor:not-allowed; transform:none !important; }

        .alert {
            padding:15px 20px;
            border-radius:8px;
            margin-bottom:25px;
            display:flex;
            align-items:center;
            gap:12px;
            animation: slideDown 0.3s ease-out;
        }
        @keyframes slideDown { from {opacity:0; transform: translateY(-10px);} to {opacity:1; transform: translateY(0);} }
        .alert-success { background:#d1e7dd; color:#0f5132; border:1px solid #badbcc; }
        .alert-danger { background:#f8d7da; color:#842029; border:1px solid #f5c2c7; }
        .alert-info { background:#cff4fc; color:#055160; border:1px solid #b6effb; }
        .alert i { font-size:20px; }

        .progress-steps { display:flex; justify-content:space-between; margin-bottom:30px; position:relative; }
        .progress-steps::before {
            content:'';
            position:absolute;
            top:20px;
            left:25%;
            right:25%;
            height:2px;
            background:#e0e0e0;
            z-index:0;
        }
        .progress-step { flex:1; text-align:center; position:relative; z-index:1; }
        .progress-step-circle {
            width:40px; height:40px; border-radius:50%;
            background:white; border:3px solid #e0e0e0;
            margin:0 auto 10px;
            display:flex; align-items:center; justify-content:center;
            font-weight:600; transition: all 0.3s ease;
        }
        .progress-step.active .progress-step-circle { border-color:var(--primary-color); background:var(--primary-color); color:white; }
        .progress-step.completed .progress-step-circle { border-color:var(--success-color); background:var(--success-color); color:white; }
        .progress-step-label { font-size:12px; color:#6c757d; font-weight:500; }
        .progress-step.active .progress-step-label { color: var(--primary-color); }

        .current-email-display {
            background: var(--light-bg);
            padding: 12px 15px;
            border-radius: 8px;
            margin-bottom: 15px;
            font-size: 14px;
            color: #6c757d;
            border-left: 3px solid var(--primary-color);
        }
        .current-email-display strong { color: var(--dark-text); }

        .spinner {
            display:inline-block;
            width:16px; height:16px;
            border:2px solid rgba(255,255,255,0.3);
            border-radius:50%;
            border-top-color:white;
            animation: spin 0.8s linear infinite;
        }
        @keyframes spin { to { transform: rotate(360deg); } }

        .success-icon { text-align:center; padding:20px; }
        .success-icon i { font-size:64px; color:var(--success-color); margin-bottom:20px; }
        .success-icon h3 { margin-bottom:10px; color:var(--dark-text); }
        .success-icon p { color:#6c757d; margin-bottom:30px; }

        .modal-overlay {
            display:none;
            position:fixed;
            top:0; left:0; right:0; bottom:0;
            background: rgba(0,0,0,0.5);
            z-index:1000;
            animation: fadeIn 0.3s ease-out;
        }
        .modal-overlay.active {
            display:flex;
            align-items:center;
            justify-content:center;
        }
        .modal-content {
            background:white;
            border-radius: var(--border-radius);
            padding:30px;
            max-width:400px;
            width:90%;
            box-shadow: var(--box-shadow);
            animation: slideUp 0.3s ease-out;
        }
        .modal-header { display:flex; align-items:center; gap:15px; margin-bottom:20px; }
        .modal-header i { font-size:32px; color: var(--warning-color); }
        .modal-header h3 { margin:0; color: var(--dark-text); }
        .modal-body { margin-bottom:25px; color:#6c757d; line-height:1.6; }
        .modal-actions { display:flex; gap:10px; }
        .modal-actions .btn { flex:1; }

        @keyframes fadeIn { from {opacity:0;} to {opacity:1;} }

        #email-feedback { display:block; font-size:13px; margin-top:8px; }
        #email-feedback i { margin-right:5px; }

        .divider {
            margin: 28px 0;
            display:flex;
            align-items:center;
            gap:12px;
            color:#6c757d;
            font-size:13px;
        }
        .divider::before, .divider::after {
            content:'';
            flex:1;
            height:1px;
            background:#e0e0e0;
        }

        @media (max-width: 576px) {
            .card-body { padding:25px; }
            .card-header { padding:25px; }
            .progress-step-label { font-size:10px; }
            .progress-step-circle { width:35px; height:35px; }
        }
    </style>
</head>
<body>
<div class="container-wrapper">
    <div class="card">
        <div class="card-header">
            <i class="fas fa-shield-alt"></i>
            <h2>Account Security</h2>
            <p>Update your password and email address</p>
        </div>
        <div class="card-body">

            <?php if ($error !== ''): ?>
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle"></i>
                    <span><?= t_out($error) ?></span>
                </div>
            <?php endif; ?>

            <?php if ($success !== ''): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i>
                    <span><?= t_out($success) ?></span>
                </div>
            <?php endif; ?>

            <?php if ($step === 'request'): ?>
                <div class="progress-steps">
                    <div class="progress-step active">
                        <div class="progress-step-circle">1</div>
                        <div class="progress-step-label">Verify Identity</div>
                    </div>
                    <div class="progress-step">
                        <div class="progress-step-circle">2</div>
                        <div class="progress-step-label">Update Details</div>
                    </div>
                </div>

                <!-- Legacy flow: username + current password -->
                <form id="requestForm" method="POST" action="change_password_process.php">
                    <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                    <input type="hidden" name="action" value="request">
                    <input type="hidden" name="site" value="<?= h($site_id) ?>">

                    <div class="form-group">
                        <label class="form-label"><i class="fas fa-user"></i>Username</label>
                        <input
                            type="text"
                            name="username"
                            class="form-control"
                            placeholder="Enter your username"
                            required
                            autocomplete="username"
                            value="<?= h($prefillUsername) ?>"
                        >
                    </div>

                    <div class="form-group">
                        <label class="form-label"><i class="fas fa-lock"></i>Current Password</label>
                        <div class="input-wrapper">
                            <input type="password" name="current_password" id="current_password" class="form-control" placeholder="Enter your current password" required autocomplete="current-password">
                            <i class="fas fa-eye toggle-password" onclick="togglePassword('current_password')"></i>
                        </div>
                    </div>

                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-arrow-right"></i>
                        Continue
                    </button>
                </form>

                <div class="divider">or</div>

                <!-- Email-link flow: email one-time setup/reset link -->
                <div class="alert alert-info">
                    <i class="fas fa-envelope"></i>
                    <span>If you don’t know your current password, we can email you a one-time setup/reset link.</span>
                </div>

                <form id="emailLinkForm" method="POST" action="change_password_process.php">
                    <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                    <input type="hidden" name="action" value="request_link">
                    <input type="hidden" name="site" value="<?= h($site_id) ?>">

                    <div class="form-group">
                        <label class="form-label"><i class="fas fa-envelope"></i>Sign-in Email</label>
                        <input
                            type="email"
                            name="email"
                            class="form-control"
                            placeholder="Enter the email on your OpenEMR account"
                            required
                            autocomplete="email"
                            value="<?= h($prefillEmail) ?>"
                        >
                        <small style="display:block; margin-top:8px; color:#6c757d; font-size:13px;">
                            <i class="fas fa-lock"></i> We will email a secure link if the account exists. Please check your spam/junk folder.
                        </small>
                    </div>

                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-paper-plane"></i>
                        Email Me a One-Time Link
                    </button>
                </form>

            <?php elseif ($step === 'update' && $token !== ''): ?>

                <div class="progress-steps">
                    <div class="progress-step completed">
                        <div class="progress-step-circle"><i class="fas fa-check"></i></div>
                        <div class="progress-step-label">Verify Identity</div>
                    </div>
                    <div class="progress-step active">
                        <div class="progress-step-circle">2</div>
                        <div class="progress-step-label">Update Details</div>
                    </div>
                </div>

                <?php if ($error === ''): ?>
                    <div class="alert alert-success">
                        <i class="fas fa-check-circle"></i>
                        <span>Identity verified! Update your password <?= $isEmailLink ? '' : 'and email ' ?>below.</span>
                    </div>
                <?php endif; ?>

                <form id="updateForm" method="POST" action="change_password_process.php">
                    <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                    <input type="hidden" name="action" value="update">
                    <input type="hidden" name="token" value="<?= h($token) ?>">
                    <input type="hidden" name="site" value="<?= h($site_id) ?>">

                    <div class="form-group">
                        <label class="form-label"><i class="fas fa-key"></i>New Password</label>
                        <div class="input-wrapper">
                            <input type="password" name="new_password" id="new_password" class="form-control" placeholder="Enter new password" required autocomplete="new-password">
                            <i class="fas fa-eye toggle-password" onclick="togglePassword('new_password')"></i>
                        </div>
                        <div class="password-strength" id="password-strength">
                            <div class="password-strength-bar" id="password-strength-bar"></div>
                        </div>
                        <div class="password-requirements">
                            <strong>Password must contain:</strong>
                            <ul id="password-requirements">
                                <li id="req-length"><i class="fas fa-circle"></i> At least 8 characters</li>
                                <li id="req-uppercase"><i class="fas fa-circle"></i> One uppercase letter</li>
                                <li id="req-lowercase"><i class="fas fa-circle"></i> One lowercase letter</li>
                                <li id="req-number"><i class="fas fa-circle"></i> One number</li>
                                <li id="req-special"><i class="fas fa-circle"></i> One special character</li>
                            </ul>
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="form-label"><i class="fas fa-check-double"></i>Confirm New Password</label>
                        <div class="input-wrapper">
                            <input type="password" name="confirm_password" id="confirm_password" class="form-control" placeholder="Confirm new password" required autocomplete="new-password">
                            <i class="fas fa-eye toggle-password" onclick="togglePassword('confirm_password')"></i>
                        </div>
                        <small id="password-match" style="display:none; margin-top:5px;"></small>
                    </div>

                    <div class="form-group">
                        <label class="form-label">
                            <i class="fas fa-envelope"></i>
                            Sign-in Email <span style="color: var(--danger-color);">*</span>
                        </label>

                        <?php if ($currentEmail !== ''): ?>
                            <div class="current-email-display">
                                <i class="fas fa-info-circle"></i> Current: <strong><?= t_out($currentEmail) ?></strong>
                                <?php if ($isEmailLink): ?>
                                    <div style="margin-top:6px; font-size:13px;">
                                        <i class="fas fa-lock"></i> Email changes are disabled for one-time email links.
                                    </div>
                                <?php endif; ?>
                            </div>
                        <?php endif; ?>

                        <input
                            type="email"
                            name="new_email"
                            id="new_email"
                            class="form-control"
                            placeholder="Enter email address"
                            value="<?= a_out($currentEmail) ?>"
                            required
                            <?= $isEmailLocked ? 'readonly' : '' ?>
                        >

                        <small style="display:block; margin-top:8px; color:#6c757d; font-size:13px;">
                            <i class="fas fa-lightbulb"></i>
                            <?php if ($isEmailLocked): ?>
                                This email is locked for security. Contact your administrator to change it.
                            <?php else: ?>
                                Email address is required for Sign-in and must be unique.
                            <?php endif; ?>
                        </small>
                    </div>

                    <button type="submit" class="btn btn-success" id="submitBtn" disabled>
                        <i class="fas fa-save"></i>
                        <?= $isEmailLink ? 'Update Password' : 'Update Password & Email' ?>
                    </button>

                    <button type="button" class="btn btn-secondary" onclick="confirmCancel()" style="margin-top:10px;">
                        <i class="fas fa-times"></i>
                        Cancel
                    </button>
                </form>

            <?php elseif ($step === 'complete'): ?>

                <div class="progress-steps">
                    <div class="progress-step completed">
                        <div class="progress-step-circle"><i class="fas fa-check"></i></div>
                        <div class="progress-step-label">Verify Identity</div>
                    </div>
                    <div class="progress-step completed">
                        <div class="progress-step-circle"><i class="fas fa-check"></i></div>
                        <div class="progress-step-label">Update Details</div>
                    </div>
                </div>

                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i>
                    <span><?= t_out($success !== '' ? $success : 'Your account has been updated successfully!') ?></span>
                </div>

                <div class="success-icon">
                    <i class="fas fa-check-circle"></i>
                    <h3>All Set!</h3>
                    <p>Your password has been changed and your account is secure.</p>

                    <a href="change_password.php?site=<?= h($site_id) ?>"
                       class="btn btn-primary" style="text-decoration:none;">
                        <i class="fas fa-redo"></i>
                        Start Over
                    </a>
                </div>

            <?php else: ?>
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle"></i>
                    <span>Invalid request. Please start over.</span>
                </div>
            <?php endif; ?>

        </div>
    </div>
</div>

<script src="public/assets/jquery/dist/jquery.min.js"></script>
<script>
    function togglePassword(fieldId) {
        const field = document.getElementById(fieldId);
        const icon = field.nextElementSibling;

        if (field.type === 'password') {
            field.type = 'text';
            icon.classList.remove('fa-eye');
            icon.classList.add('fa-eye-slash');
        } else {
            field.type = 'password';
            icon.classList.remove('fa-eye-slash');
            icon.classList.add('fa-eye');
        }
    }

    function checkPasswordStrength(password) {
        let strength = 0;
        const requirements = {
            length: password.length >= 8,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            number: /[0-9]/.test(password),
            special: /[^A-Za-z0-9]/.test(password)
        };

        Object.keys(requirements).forEach(req => {
            const element = document.getElementById(`req-${req}`);
            if (!element) return;

            if (requirements[req]) {
                element.classList.add('valid');
                element.querySelector('i').classList.remove('fa-circle');
                element.querySelector('i').classList.add('fa-check-circle');
                strength++;
            } else {
                element.classList.remove('valid');
                element.querySelector('i').classList.remove('fa-check-circle');
                element.querySelector('i').classList.add('fa-circle');
            }
        });

        const strengthBar = document.getElementById('password-strength-bar');
        const strengthContainer = document.getElementById('password-strength');

        if (password.length > 0) {
            strengthContainer.style.display = 'block';
            const percentage = (strength / 5) * 100;
            strengthBar.style.width = percentage + '%';

            strengthBar.className = 'password-strength-bar';
            if (strength <= 2) strengthBar.classList.add('strength-weak');
            else if (strength <= 4) strengthBar.classList.add('strength-medium');
            else strengthBar.classList.add('strength-strong');
        } else {
            strengthContainer.style.display = 'none';
        }

        return strength === 5;
    }

    if (document.getElementById('new_password')) {
        const newPassword = document.getElementById('new_password');
        const confirmPassword = document.getElementById('confirm_password');
        const submitBtn = document.getElementById('submitBtn');
        const matchIndicator = document.getElementById('password-match');

        newPassword.addEventListener('input', function() {
            checkPasswordStrength(this.value);
            validatePasswords();
        });

        confirmPassword.addEventListener('input', validatePasswords);

        function validatePasswords() {
            const isStrong = checkPasswordStrength(newPassword.value);
            const passwordsMatch = newPassword.value === confirmPassword.value;

            if (confirmPassword.value.length > 0) {
                matchIndicator.style.display = 'block';
                if (passwordsMatch) {
                    matchIndicator.textContent = '✓ Passwords match';
                    matchIndicator.style.color = 'var(--success-color)';
                } else {
                    matchIndicator.textContent = '✗ Passwords do not match';
                    matchIndicator.style.color = 'var(--danger-color)';
                }
            } else {
                matchIndicator.style.display = 'none';
            }

            submitBtn.disabled = !(isStrong && passwordsMatch && confirmPassword.value.length > 0);
        }
    }

    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function() {
            const submitBtn = this.querySelector('button[type="submit"]');
            if (submitBtn && !submitBtn.disabled) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<span class="spinner"></span> Processing...';
            }
        });
    });

    // Email availability check (disabled for email-link tokens because email is locked read-only)
    const isEmailLink = <?= $isEmailLink ? 'true' : 'false' ?>;

    if (!isEmailLink && document.getElementById('new_email')) {
        const emailField = document.getElementById('new_email');
        const emailFeedback = document.createElement('small');
        emailFeedback.id = 'email-feedback';
        emailFeedback.style.display = 'none';
        emailField.parentNode.appendChild(emailFeedback);

        let emailCheckTimeout;

        emailField.addEventListener('input', function() {
            clearTimeout(emailCheckTimeout);
            const email = this.value.trim();
            const currentEmail = <?= json_encode($currentEmail) ?>;

            if (!email || email === currentEmail) {
                emailFeedback.style.display = 'none';
                return;
            }

            if (!email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
                emailFeedback.style.display = 'none';
                return;
            }

            emailFeedback.style.display = 'block';
            emailFeedback.style.color = '#6c757d';
            emailFeedback.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Checking availability...';

            emailCheckTimeout = setTimeout(function() {
                checkEmailAvailability(email);
            }, 450);
        });

        function checkEmailAvailability(email) {
            const token = <?= json_encode($token) ?>;
            const site = <?= json_encode($site_id) ?>;

            fetch('change_password_process.php?action=check_email&email=' + encodeURIComponent(email) +
                  '&token=' + encodeURIComponent(token) +
                  '&site=' + encodeURIComponent(site))
                .then(response => response.json())
                .then(data => {
                    if (data.available) {
                        emailFeedback.style.color = 'var(--success-color)';
                        emailFeedback.innerHTML = '<i class="fas fa-check-circle"></i> Email available';
                    } else {
                        emailFeedback.style.color = 'var(--danger-color)';
                        emailFeedback.innerHTML = '<i class="fas fa-times-circle"></i> Email already in use';
                    }
                })
                .catch(() => {
                    emailFeedback.style.display = 'none';
                });
        }
    }

    function confirmCancel() { showCancelModal(); }

    function showCancelModal() {
        const existingModal = document.querySelector('.modal-overlay');
        if (existingModal) existingModal.remove();

        const modal = document.createElement('div');
        modal.className = 'modal-overlay';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <i class="fas fa-exclamation-triangle"></i>
                    <h3>Cancel Password Change?</h3>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to cancel? Any information you've entered will be lost and you'll need to start over.</p>
                </div>
                <div class="modal-actions">
                    <button class="btn btn-secondary" id="modalCancelBtn">
                        <i class="fas fa-arrow-left"></i>
                        Go Back
                    </button>
                    <button class="btn btn-primary" id="modalConfirmBtn">
                        <i class="fas fa-check"></i>
                        Yes, Cancel
                    </button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
        setTimeout(() => modal.classList.add('active'), 10);

        document.getElementById('modalCancelBtn').addEventListener('click', closeCancelModal);
        document.getElementById('modalConfirmBtn').addEventListener('click', proceedCancel);

        modal.addEventListener('click', function(e) {
            if (e.target === modal) closeCancelModal();
        });
    }

    function closeCancelModal() {
        const modal = document.querySelector('.modal-overlay');
        if (modal) {
            modal.classList.remove('active');
            setTimeout(() => modal.remove(), 300);
        }
    }

    // update step has no username input; server will use session fallback
    function proceedCancel() {
        window.location.href =
            'change_password.php?site=<?= h($site_id) ?>' +
            '&cancelled=1';
    }

    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') closeCancelModal();
    });
</script>
</body>
</html>
