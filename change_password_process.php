<?php
// ─── EMRFlow Modifications ─────────────────────────────────────────────
// EMRFlow CUSTOM FILE
// Modified by: Facets Novum LLC (Darrell Henry)
// Purpose: Backend processor for public password change/reset flows
// WHY: Companion to change_password.php — handles token verification, password hashing
//      (via OpenEMR's AuthHash), and users_secure table updates outside the normal
//      authenticated session, enabling password resets without admin intervention.
// ──────────────────────────────────────────────────────────────────────

/**
 * /public_html/change_password_process.php
 *
 * Processes public password change flows for OpenEMR.
 *
 * Flows:
 *  1) Legacy verify: username + current password -> legacy token -> update password (+ optional email)
 *  2) Email-link reset: email -> one-time hashed token -> update password ONLY (email locked)
 *
 * IMPORTANT:
 *  - NO output (no BOM, no whitespace before <?php)
 *  - All table/schema helpers live in /library/password_status.inc.php
 *
 * Companion files:
 *  - /public_html/change_password.php (UI)
 *  - /public_html/library/password_status.inc.php (tables + helpers)
 *
 * @package   OpenEMR
 * @license   https://github.com/openemr/openemr/blob/master/LICENSE GNU General Public License 3
 */

declare(strict_types=1);

use OpenEMR\Common\Auth\AuthHash;

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

header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');

/**
 * Check whether a column exists (safe across OpenEMR installs).
 * Uses INFORMATION_SCHEMA (no SHOW ... LIKE).
 */
function columnExists(string $table, string $column): bool
{
    if ($table === '' || $column === '') return false;
    if (preg_match('/[^A-Za-z0-9_]/', $table) || preg_match('/[^A-Za-z0-9_]/', $column)) return false;

    $row = sqlQuery(
        "SELECT 1 AS ok
           FROM INFORMATION_SCHEMA.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME = ?
            AND COLUMN_NAME = ?
          LIMIT 1",
        [$table, $column]
    );

    return !empty($row['ok']);
}

/**
 * Enforce "new password must not match current password or last N history entries".
 *
 * Returns null if OK, otherwise returns a user-facing error string.
 *
 * Notes:
 * - Uses OpenEMR's AuthHash passwordVerify (supports OpenEMR's hash formats).
 * - Adapts if password_history columns don't exist.
 * - Silent-fails (returns null) if users_secure row is missing.
 */
function validatePasswordNotReused(int $userId, string $newPassword, int $historyCount = 4): ?string
{
    // If AuthHash isn't available for some reason, fail open (don’t block password reset).
    if (!class_exists(AuthHash::class)) {
        return null;
    }

    // users_secure.password should exist; histories may not.
    $fields = ['password'];
    for ($i = 1; $i <= $historyCount; $i++) {
        $col = 'password_history' . $i;
        if (columnExists('users_secure', $col)) {
            $fields[] = $col;
        }
    }

    $sql = "SELECT " . implode(", ", $fields) . " FROM users_secure WHERE id = ? LIMIT 1";
    $secureResult = sqlQuery($sql, [$userId]);
    if (empty($secureResult)) {
        return null;
    }

    try {
        $authHash = new AuthHash();

        // Current password
        if (!empty($secureResult['password']) && $authHash->passwordVerify($newPassword, (string)$secureResult['password'])) {
            return 'New password must be different from your current password.';
        }

        // History
        for ($i = 1; $i <= $historyCount; $i++) {
            $col = 'password_history' . $i;
            if (!array_key_exists($col, $secureResult)) {
                continue; // column not present
            }
            if (!empty($secureResult[$col]) && $authHash->passwordVerify($newPassword, (string)$secureResult[$col])) {
                // "last 5" = current + 4 history
                return 'Cannot reuse any of your last 5 passwords.';
            }
        }
    } catch (Throwable $e) {
        // Don’t leak details to user; log only.
        error_log("[PWD] Error checking password reuse for user {$userId}: " . $e->getMessage());
        return null;
    }

    return null;
}


// -----------------------
// Site resolution
// -----------------------
function resolveSiteId(): string
{
    $raw = $_POST['site'] ?? $_GET['site'] ?? '';
    $raw = is_string($raw) ? trim($raw) : '';

    if ($raw === '') {
        $raw = 'default';
    }

    if (preg_match('/[^A-Za-z0-9\-.]/', $raw)) {
        return 'default';
    }

    $dir = __DIR__ . '/sites/' . $raw;
    if (!is_dir($dir)) {
        return 'default';
    }

    return $raw;
}

$site_id = resolveSiteId();

// Bootstrap OpenEMR (no auth)
$ignoreAuth = true;
$sessionAllowWrite = true;

require_once __DIR__ . "/sites/{$site_id}/sqlconf.php";
if (!isset($config) || (int)$config !== 1) {
    header("Location: setup.php?site=" . urlencode($site_id));
    exit;
}

require_once __DIR__ . "/interface/globals.php";

// Load table + helper single source of truth
require_once __DIR__ . "/library/password_status.inc.php";

// Best-effort initialize required tables (does not throw to UI)
if (function_exists('ensurePasswordTables')) {
    ensurePasswordTables();
}

// -----------------------
// Utility helpers
// -----------------------
function redirectToChangePassword(string $site, array $params): void
{
    $params['site'] = $site;
    header("Location: change_password.php?" . http_build_query($params));
    exit;
}

function jsonResponse(array $payload, int $statusCode = 200): void
{
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload);
    exit;
}

function getClientIp(): string
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    return is_string($ip) ? substr($ip, 0, 64) : '';
}

function getUserAgent(): string
{
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    return is_string($ua) ? substr($ua, 0, 500) : '';
}

function sanitizeUsername(string $v): string
{
    $v = trim($v);
    return (string)preg_replace('/[^A-Za-z0-9@._-]/', '', $v);
}

function normalizeEmail(string $v): string
{
    $v = strtolower(trim($v));
    $v = preg_replace('/[\s\x00-\x1F\x7F]+/', '', $v);
    return substr($v, 0, 254);
}

function isValidEmail(string $email): bool
{
    if ($email === '' || strlen($email) > 254) {
        return false;
    }
    return (bool)filter_var($email, FILTER_VALIDATE_EMAIL);
}

function validateCsrfOrDie(string $site_id): void
{
    $posted = $_POST['csrf_token'] ?? '';
    $posted = is_string($posted) ? $posted : '';

    $sess = $_SESSION['pwd_csrf_token'] ?? '';
    $sess = is_string($sess) ? $sess : '';

    $t = $_SESSION['pwd_csrf_time'] ?? 0;
    $t = is_numeric($t) ? (int)$t : 0;

    if ($sess === '' || $posted === '' || !hash_equals($sess, $posted)) {
        redirectToChangePassword($site_id, [
            'step' => 'request',
            'error' => 'Security check failed. Please try again.',
        ]);
    }

    // 1 hour TTL
    if ($t <= 0 || (time() - $t) > 3600) {
        unset($_SESSION['pwd_csrf_token'], $_SESSION['pwd_csrf_time']);
        redirectToChangePassword($site_id, [
            'step' => 'request',
            'error' => 'Session expired. Please try again.',
        ]);
    }
}

// Must match UI checks
function passwordMeetsPolicy(string $pwd): bool
{
    if (strlen($pwd) < 8) return false;
    if (!preg_match('/[A-Z]/', $pwd)) return false;
    if (!preg_match('/[a-z]/', $pwd)) return false;
    if (!preg_match('/[0-9]/', $pwd)) return false;
    if (!preg_match('/[^A-Za-z0-9]/', $pwd)) return false;
    return true;
}

// -----------------------
// Email sending (dependency-light)
// -----------------------
function sendResetEmail(string $toEmail, string $link): bool
{
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $from = "no-reply@" . preg_replace('/[^A-Za-z0-9\.\-]/', '', (string)$host);
    if (empty($from) || strpos($from, '@') === false) {
        $from = "no-reply@localhost";
    }
    
    $hostFull = 'https://' . $host . '/change_password.php';
    
    $subject = "OpenEMR Password Reset Link: Self Requested";
    $body =
        "A password reset was requested for your OpenEMR account.\n\n" .
        "Use this link to set a new password:\n{$link}\n\n" .
        "If you did not request this, you can ignore this email.\n\n" .
        "Site: {$hostFull}\n";

    
    $Bcc = $from;
    $from_name = "No Reply";
    $headers = array();
    $headers[] = 'From: '. $from_name .' <'. $from .'>';
    $headers[] = 'Content-Type: text/plain; charset=UTF-8';
    $headers[] = 'Bcc: ' . $Bcc;
    
    // error_log("Bcc: $Bcc, from_name: $from_name, headers: ". print_r($headers, true));
    
    /* ORIG:
    $fromHost = $_SERVER['HTTP_HOST'] ?? 'localhost';
    
    $headers =
        "From: no-reply@{$fromHost}\r\n" .
        "Content-Type: text/plain; charset=UTF-8\r\n";

    return @mail($toEmail, $subject, $body, $headers);
    */
    
    $sent = @mail($toEmail, $subject, $body, implode("\r\n", $headers));
    if (!$sent) {
        error_log("[PWD] mail() failed for password reset email to: " . substr($toEmail, 0, 3) . '***');
    }
    return $sent;
}

// -----------------------
// Account update helpers
// -----------------------
function updateUsersSecurePassword(int $userId, string $newPlainPassword): bool
{
    if (!class_exists(AuthHash::class)) {
        error_log("[PWD] AuthHash missing; cannot safely enforce history + hashing.");
        return false; // fail CLOSED if you want enforcement
    }

    $authHash = new AuthHash();

    // Determine which history columns exist on this install
    $historyCols = [];
    for ($i = 1; $i <= 4; $i++) {
        $col = "password_history{$i}";
        if (columnExists('users_secure', $col)) {
            $historyCols[] = $col;
        }
    }

    // Pull current password + existing histories (only the ones that exist)
    $selectCols = array_merge(['password'], $historyCols);
    $secure = sqlQuery(
        "SELECT " . implode(", ", $selectCols) . " FROM users_secure WHERE id = ? LIMIT 1",
        [$userId]
    );

    $currentHash = (string)($secure['password'] ?? '');

    // Build new hash using OpenEMR’s hashing
    $newHash = $authHash->passwordHash($newPlainPassword);
    if (empty($newHash)) {
        error_log("[PWD] passwordHash returned empty for user {$userId}");
        return false;
    }

    // If no users_secure row yet, just insert new password
    $exists = sqlQuery("SELECT id FROM users_secure WHERE id = ? LIMIT 1", [$userId]);
    if (empty($exists)) {
        sqlStatement("INSERT INTO users_secure (id, password) VALUES (?, ?)", [$userId, $newHash]);
        return true;
    }

    // If no history columns exist, just update password
    if (empty($historyCols)) {
        sqlStatement("UPDATE users_secure SET password = ? WHERE id = ?", [$newHash, $userId]);
        return true;
    }

    // Shift histories DOWN (4 <- 3 <- 2 <- 1) and store current password into history1
    // We’ll build updates only for columns that exist.
    $updates = [];
    $params  = [];

    // Work backwards so we don’t overwrite values
    for ($i = count($historyCols); $i >= 1; $i--) {
        $col = $historyCols[$i - 1];

        if ($i === 1) {
            // history1 gets the previous password hash
            $updates[] = "`{$col}` = ?";
            $params[]  = $currentHash;
        } else {
            // historyN gets the prior history(N-1) value if present in $secure
            $prevCol = $historyCols[$i - 2];
            $updates[] = "`{$col}` = ?";
            $params[]  = (string)($secure[$prevCol] ?? '');
        }
    }

    // Finally update password
    $updates[] = "`password` = ?";
    $params[]  = $newHash;

    $params[] = $userId;

    sqlStatement(
        "UPDATE users_secure SET " . implode(", ", $updates) . " WHERE id = ?",
        $params
    );

    return true;
}


function updateUsersGoogleSigninEmail(int $userId, string $newEmail): void
{
    sqlStatement("UPDATE users SET google_signin_email = ? WHERE id = ?", [$newEmail, $userId]);
}

function isEmailAvailable(string $email, ?int $excludeUserId = null): bool
{
    if ($excludeUserId !== null) {
        $row = sqlQuery(
            "SELECT id FROM users WHERE google_signin_email = ? AND id <> ? LIMIT 1",
            [$email, $excludeUserId]
        );
    } else {
        $row = sqlQuery("SELECT id FROM users WHERE google_signin_email = ? LIMIT 1", [$email]);
    }
    return empty($row);
}

// -----------------------
// Routing
// -----------------------
$action = $_POST['action'] ?? $_GET['action'] ?? '';
$action = is_string($action) ? trim($action) : '';

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$method = is_string($method) ? strtoupper($method) : 'GET';

// GET: check_email endpoint for UI (legacy flow only).
// Requires a valid legacy token to prevent unauthenticated email enumeration.
if ($method === 'GET' && $action === 'check_email') {
    $email = $_GET['email'] ?? '';
    $token = $_GET['token'] ?? '';

    $email = is_string($email) ? normalizeEmail($email) : '';
    $token = is_string($token) ? trim($token) : '';

    // A valid legacy token is required — this endpoint is not public.
    if ($token === '' || !function_exists('fetchValidLegacyPasswordChangeToken')) {
        jsonResponse(['available' => false], 200);
    }
    $legacy = fetchValidLegacyPasswordChangeToken($token);
    if (empty($legacy['user_id'])) {
        jsonResponse(['available' => false], 200);
    }

    // Rate limit: reuse the token-verification throttle
    if (function_exists('shouldThrottlePasswordTokenVerify') && shouldThrottlePasswordTokenVerify()) {
        jsonResponse(['available' => false], 200);
    }

    if (!isValidEmail($email)) {
        jsonResponse(['available' => false], 200);
    }

    $excludeUserId = (int)$legacy['user_id'];
    jsonResponse(['available' => isEmailAvailable($email, $excludeUserId)], 200);
}

// POST actions require CSRF
if ($method === 'POST') {
    validateCsrfOrDie($site_id);
}

// -----------------------
// POST: action=request (legacy verify username + current_password)
// -----------------------
if ($method === 'POST' && $action === 'request') {
    $username = $_POST['username'] ?? '';
    $currentPassword = $_POST['current_password'] ?? '';

    $username = is_string($username) ? sanitizeUsername($username) : '';
    $currentPassword = is_string($currentPassword) ? $currentPassword : '';

    if ($username === '' || $currentPassword === '') {
        redirectToChangePassword($site_id, [
            'step' => 'request',
            'error' => 'Please enter your username and current password.',
        ]);
    }

    $ip = getClientIp();
    if (function_exists('shouldThrottlePasswordTokenVerify') && shouldThrottlePasswordTokenVerify($ip, 120)) {
        redirectToChangePassword($site_id, [
            'step' => 'request',
            'error' => 'Too many attempts. Please wait and try again.',
        ]);
    }

    $user = sqlQuery(
        "SELECT id, username, google_signin_email
           FROM users
          WHERE username = ?
          LIMIT 1",
        [$username]
    );

    if (empty($user['id'])) {
        redirectToChangePassword($site_id, [
            'step' => 'request',
            'username' => $username,
            'error' => 'Invalid username or password.',
        ]);
    }

    $userId = (int)$user['id'];

    $secure = sqlQuery("SELECT password FROM users_secure WHERE id = ? LIMIT 1", [$userId]);
    $hash = (string)($secure['password'] ?? '');

    // Use OpenEMR's AuthHash for verification — handles bcrypt + legacy hash formats
    // from older OpenEMR versions (pre-upgrade SHA-based hashes).
    $authHashVerifier = new AuthHash();
    if ($hash === '' || !$authHashVerifier->passwordVerify($currentPassword, $hash)) {
        redirectToChangePassword($site_id, [
            'step' => 'request',
            'username' => $username,
            'error' => 'Invalid username or password.',
        ]);
    }

    // Create legacy token via helper (raw token stored in legacy table)
    if (!function_exists('createLegacyPasswordChangeToken')) {
        redirectToChangePassword($site_id, [
            'step' => 'request',
            'error' => 'Password reset system is not available. Contact your administrator.',
        ]);
    }

    $token = createLegacyPasswordChangeToken($userId, 1800); // 30 minutes
    if ($token === null || $token === '') {
        redirectToChangePassword($site_id, [
            'step' => 'request',
            'error' => 'Unable to start password change. Please try again.',
        ]);
    }

    session_regenerate_id(true);
    $_SESSION['last_user_id'] = $userId;
    $_SESSION['last_username'] = $username;

    redirectToChangePassword($site_id, [
        'step' => 'update',
        'token' => $token,
        'username' => $username,
    ]);
}

// -----------------------
// POST: action=request_link (email-link flow)
// -----------------------
if ($method === 'POST' && $action === 'request_link') {
    
    // error_log("1. PRE sendResetEmail...");
    
    $email = $_POST['email'] ?? '';
    $email = is_string($email) ? normalizeEmail($email) : '';

    if (!isValidEmail($email)) {
        redirectToChangePassword($site_id, [
            'step' => 'request',
            'error' => 'Please enter a valid email address.',
        ]);
    }

    $ip = getClientIp();

    // Always show generic success (no enumeration)
    $genericSuccess = 'If an account exists for that email, a secure link has been sent. Please check your spam/junk folder.';

    // error_log("2. PRE sendResetEmail...email: $email, ip: $ip");
 
    if (function_exists('rateLimitPasswordSetupRequest') && rateLimitPasswordSetupRequest($ip, 5)) {
        redirectToChangePassword($site_id, ['step' => 'request', 'success' => $genericSuccess]);
    }

    $user = sqlQuery(
        "SELECT id, username, google_signin_email
           FROM users
          WHERE google_signin_email = ?
          LIMIT 1",
        [$email]
    );

    if (empty($user['id'])) {
        redirectToChangePassword($site_id, ['step' => 'request', 'success' => $genericSuccess]);
    }

    $userId = (int)$user['id'];

    if (!function_exists('createPasswordSetupToken')) {
        // Soft fail without disclosure
        redirectToChangePassword($site_id, ['step' => 'request', 'success' => $genericSuccess]);
    }

    // 30 min TTL, hashed-only storage
    $rawToken = createPasswordSetupToken($userId, 1800);
    if ($rawToken === null || $rawToken === '') {
        redirectToChangePassword($site_id, ['step' => 'request', 'success' => $genericSuccess]);
    }

    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $https = $_SERVER['HTTPS'] ?? '';
    $scheme = (!empty($https) && $https !== 'off') ? 'https' : 'http';

    $link = "{$scheme}://{$host}/change_password.php?step=update&site=" .
        urlencode($site_id) . "&token=" . urlencode($rawToken);

    
    // Best-effort email send; never disclose
    sendResetEmail($email, $link);

    $_SESSION['last_username'] = (string)($user['username'] ?? '');

    redirectToChangePassword($site_id, ['step' => 'request', 'success' => $genericSuccess]);
}

// -----------------------
// POST: action=update (apply new password, maybe email)
// -----------------------
if ($method === 'POST' && $action === 'update') {
    $token = $_POST['token'] ?? '';
    $newPassword = $_POST['new_password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';
    $newEmail = $_POST['new_email'] ?? '';

    $token = is_string($token) ? trim($token) : '';
    $newPassword = is_string($newPassword) ? $newPassword : '';
    $confirmPassword = is_string($confirmPassword) ? $confirmPassword : '';
    $newEmail = is_string($newEmail) ? normalizeEmail($newEmail) : '';

    if ($token === '' || $newPassword === '' || $confirmPassword === '') {
        redirectToChangePassword($site_id, [
            'step' => 'request',
            'error' => 'Missing required information. Please start over.',
        ]);
    }

    $ip = getClientIp();
    if (function_exists('shouldThrottlePasswordTokenVerify') && shouldThrottlePasswordTokenVerify($ip, 120)) {
        redirectToChangePassword($site_id, [
            'step' => 'request',
            'error' => 'Too many attempts. Please wait and try again.',
        ]);
    }

    if ($newPassword !== $confirmPassword) {
        redirectToChangePassword($site_id, [
            'step' => 'update',
            'token' => $token,
            'error' => 'Passwords do not match.',
        ]);
    }

    if (!passwordMeetsPolicy($newPassword)) {
        redirectToChangePassword($site_id, [
            'step' => 'update',
            'token' => $token,
            'error' => 'Password does not meet complexity requirements.',
        ]);
    }

    // Determine token type
    $isEmailLink = false;
    $userId = 0;

    if (function_exists('fetchValidPasswordSetupToken')) {
        $t = fetchValidPasswordSetupToken($token);
        if (!empty($t['user_id'])) {
            $isEmailLink = true;
            $userId = (int)$t['user_id'];
        }
    }

    if (!$isEmailLink) {
        if (!function_exists('fetchValidLegacyPasswordChangeToken')) {
            redirectToChangePassword($site_id, [
                'step' => 'request',
                'error' => 'Invalid or expired link. Please start over.',
            ]);
        }

        $legacy = fetchValidLegacyPasswordChangeToken($token);
        if (empty($legacy['user_id'])) {
            redirectToChangePassword($site_id, [
                'step' => 'request',
                'error' => 'Invalid or expired link. Please start over.',
            ]);
        }
        $userId = (int)$legacy['user_id'];
    }

    // Block reuse of current or recent passwords (current + last 4 history = "last 5")
    $reuseError = validatePasswordNotReused($userId, $newPassword, 4);
    if ($reuseError !== null) {
        redirectToChangePassword($site_id, [
            'step'  => 'update',
            'token' => $token,
            'error' => $reuseError
        ]);
    }

    // Update password
    if (!updateUsersSecurePassword($userId, $newPassword)) {
        redirectToChangePassword($site_id, [
            'step' => 'update',
            'token' => $token,
            'error' => 'Unable to update password. Please contact your administrator.',
        ]);
    }

    // Update email ONLY for legacy flow
    if (!$isEmailLink) {
        if (!isValidEmail($newEmail)) {
            redirectToChangePassword($site_id, [
                'step' => 'update',
                'token' => $token,
                'error' => 'Please enter a valid email address.',
            ]);
        }

        if (!isEmailAvailable($newEmail, $userId)) {
            redirectToChangePassword($site_id, [
                'step' => 'update',
                'token' => $token,
                'error' => 'That email address is already in use.',
            ]);
        }

        updateUsersGoogleSigninEmail($userId, $newEmail);
    }

    // Mark token used
    if ($isEmailLink) {
        if (function_exists('markPasswordSetupTokenUsed')) {
            markPasswordSetupTokenUsed($token);
        }
        if (function_exists('cleanupPasswordSetupTokens')) {
            cleanupPasswordSetupTokens(30);
        }
    } else {
        // IMPORTANT: schema-agnostic legacy mark-used (no used_at assumptions)
        if (function_exists('markLegacyPasswordChangeTokenUsed')) {
            markLegacyPasswordChangeTokenUsed($token);
        } else {
            // Absolute fallback: used only (no used_at)
            sqlStatement("UPDATE `password_change_tokens` SET `used` = 1 WHERE `token` = ?", [$token]);
        }
    }

    // Baseline + status updates (actor unknown for public endpoint)
    if (function_exists('upsertUsersPasswordBaselineFromCurrent')) {
        upsertUsersPasswordBaselineFromCurrent($userId, null);
    }
    if (function_exists('upsertUsersPasswordStatus')) {
        upsertUsersPasswordStatus($userId, 'changed', null);
    }

    // Breadcrumbs for cancel UX
    $u = sqlQuery("SELECT username FROM users WHERE id = ? LIMIT 1", [$userId]);
    if (!empty($u['username'])) {
        $_SESSION['last_username'] = (string)$u['username'];
    }
    $_SESSION['last_user_id'] = $userId;

    redirectToChangePassword($site_id, [
        'step' => 'complete',
        'success' => 'Your account has been updated successfully!',
    ]);
}

// Fallback
redirectToChangePassword($site_id, [
    'step' => 'request',
    'error' => 'Invalid request.',
]);
