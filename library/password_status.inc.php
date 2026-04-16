<?php
// ─── EMRFlow Modifications ─────────────────────────────────────────────
// EMRFlow CUSTOM FILE
// Modified by: Facets Novum LLC (Darrell Henry)
// Purpose: Password management tables and helper functions for public password change system
// WHY: OpenEMR has no built-in token-based password reset infrastructure. This library
//      creates and manages the required tables (password_setup_tokens, users_password_baseline,
//      users_password_status, password_token_verify_log) and provides helpers for secure
//      token generation, verification, and anti-hammer protection.
// ──────────────────────────────────────────────────────────────────────

/**
 * /public_html/library/password_status.inc.php
 *
 * Single source of truth for ALL password-related tables + helpers.
 *
 * Tables:
 *  - password_setup_tokens: one-time password setup/reset tokens (stores sha256(token) only)
 *  - users_password_baseline: baseline snapshot of users_secure.password + last-seen snapshot
 *  - users_password_status: status flag (default|changed) + timestamps
 *  - password_token_verify_log: optional anti-hammer log for token verification attempts
 *
 * IMPORTANT:
 *  - NO output (no BOM, no whitespace before <?php)
 *  - Save as UTF-8 without BOM
 *
 * @package   OpenEMR
 * @license   https://github.com/openemr/openemr/blob/master/LICENSE GNU General Public License 3
 */

declare(strict_types=1);

// ------------------------------------------------------------
// Internal safety wrappers (never surface schema errors to UI)
// ------------------------------------------------------------

/**
 * Execute a schema operation but never allow it to bubble up to the UI.
 */
function pwdSchemaTry(callable $fn): bool
{
    try {
        $fn();
        return true;
    } catch (Throwable $e) {
        error_log("[PWD] schema error: " . $e->getMessage());
        return false;
    }
}

/**
 * True if a table exists in the current database.
 *
 * IMPORTANT:
 * - Avoid SHOW TABLES (your environment fails on placeholders/ESCAPE)
 * - Use INFORMATION_SCHEMA with placeholders (safe).
 */
function pwdTableExists(string $table): bool
{
    if ($table === '' || preg_match('/[^A-Za-z0-9_]/', $table)) {
        return false;
    }

    $row = sqlQuery(
        "SELECT 1 AS ok
           FROM INFORMATION_SCHEMA.TABLES
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME = ?
          LIMIT 1",
        [$table]
    );

    return !empty($row['ok']);
}

/**
 * True if a column exists on a table in the current database.
 * Uses INFORMATION_SCHEMA (no SHOW ... LIKE).
 */
function pwdColumnExists(string $table, string $column): bool
{
    if ($table === '' || $column === '') {
        return false;
    }
    if (preg_match('/[^A-Za-z0-9_]/', $table) || preg_match('/[^A-Za-z0-9_]/', $column)) {
        return false;
    }

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
 * Best-effort cleanup for tables that have created_at timestamp.
 */
function pwdCleanupByCreatedAt(string $table, int $olderThanDays): void
{
    $days = max(1, (int)$olderThanDays);
    if (!pwdTableExists($table)) {
        return;
    }
    if (!pwdColumnExists($table, 'created_at')) {
        return;
    }

    pwdSchemaTry(function () use ($table, $days) {
        // table name is validated to [A-Za-z0-9_]
        sqlStatement("DELETE FROM `$table` WHERE created_at < (NOW() - INTERVAL {$days} DAY)");
    });
}

/**
 * Initialize all password-related tables (call once per request is OK).
 */
function ensurePasswordTables(): void
{
    ensurePasswordSetupTokensTable();
    ensureUsersPasswordBaselineTable();
    ensureUsersPasswordStatusTable();
    ensureLegacyPasswordChangeTokensTable();
    // password_token_verify_log created lazily by shouldThrottlePasswordTokenVerify()
}

// ------------------------------------------------------------
// password_change_tokens (LEGACY raw tokens; backward compat)
// ------------------------------------------------------------

/**
 * Legacy table owned by OpenEMR.
 * Do NOT redefine schema if it already exists (varies by version).
 * If missing (rare), create a minimal compatible table.
 */
function ensureLegacyPasswordChangeTokensTable(): void
{
    if (pwdTableExists('password_change_tokens')) {
        return;
    }

    pwdSchemaTry(function () {
        sqlStatement(
            "CREATE TABLE IF NOT EXISTS `password_change_tokens` (
                `id` BIGINT(20) NOT NULL AUTO_INCREMENT PRIMARY KEY,
                `user_id` BIGINT(20) NOT NULL,
                `token` CHAR(64) NOT NULL UNIQUE,
                `expiry` DATETIME NOT NULL,
                `used` TINYINT(1) NOT NULL DEFAULT 0,
                `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX `idx_token` (`token`),
                INDEX `idx_user_id` (`user_id`),
                INDEX `idx_expiry` (`expiry`),
                INDEX `idx_used` (`used`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        );
    });
}

/**
 * Determine which boolean "used" column exists on password_change_tokens.
 * Common variants: used, consumed
 */
function pwdLegacyTokenUsedColumn(): ?string
{
    if (!pwdTableExists('password_change_tokens')) {
        return null;
    }
    if (pwdColumnExists('password_change_tokens', 'used')) {
        return 'used';
    }
    if (pwdColumnExists('password_change_tokens', 'consumed')) {
        return 'consumed';
    }
    return null;
}

/**
 * Determine which expiry datetime column exists on password_change_tokens.
 * Common variants: expiry, expires, expiration, expire_date (rare)
 */
function pwdLegacyTokenExpiryColumn(): ?string
{
    if (!pwdTableExists('password_change_tokens')) {
        return null;
    }
    foreach (['expiry', 'expires', 'expiration', 'expire_date', 'expire'] as $c) {
        if (pwdColumnExists('password_change_tokens', $c)) {
            return $c;
        }
    }
    return null;
}

/**
 * Create a legacy token (raw token stored).
 *
 * Inserts only columns that exist so we don't break across OpenEMR versions.
 */
function createLegacyPasswordChangeToken(int $userId, int $ttlSeconds = 1800): ?string
{
    ensureLegacyPasswordChangeTokensTable();

    $ttlSeconds = max(60, (int)$ttlSeconds);
    $rawToken   = bin2hex(random_bytes(32)); // 64 hex
    $expiryVal  = date('Y-m-d H:i:s', time() + $ttlSeconds);

    $usedCol   = pwdLegacyTokenUsedColumn();    // used|consumed|null
    $expiryCol = pwdLegacyTokenExpiryColumn();  // expiry|...|null

    // Build insert dynamically based on available columns
    $cols = ['user_id', 'token'];
    $vals = [$userId, $rawToken];

    if ($expiryCol !== null) {
        $cols[] = $expiryCol;
        $vals[] = $expiryVal;
    }

    if ($usedCol !== null) {
        $cols[] = $usedCol;
        $vals[] = 0;
    }

    $colSql = implode(', ', array_map(static fn($c) => "`{$c}`", $cols));
    $phSql  = implode(', ', array_fill(0, count($vals), '?'));

    $ok = pwdSchemaTry(function () use ($colSql, $phSql, $vals) {
        sqlStatement("INSERT INTO `password_change_tokens` ({$colSql}) VALUES ({$phSql})", $vals);
    });

    return $ok ? $rawToken : null;
}

/**
 * Fetch a valid legacy token row joined to users.
 * Adapts to used/consumed + expiry column variants.
 */
function fetchValidLegacyPasswordChangeToken(string $rawToken): ?array
{
    if ($rawToken === '' || strlen($rawToken) > 256) {
        return null;
    }

    ensureLegacyPasswordChangeTokensTable();

    $usedCol   = pwdLegacyTokenUsedColumn();
    $expiryCol = pwdLegacyTokenExpiryColumn();

    $where = ["t.token = ?"];
    $args  = [$rawToken];

    if ($usedCol !== null) {
        $where[] = "t.`{$usedCol}` = 0";
    }
    if ($expiryCol !== null) {
        $where[] = "t.`{$expiryCol}` > NOW()";
    }

    $sql =
        "SELECT t.*, u.username, u.google_signin_email
           FROM `password_change_tokens` t
           JOIN `users` u ON u.id = t.user_id
          WHERE " . implode(" AND ", $where) . "
          LIMIT 1";

    $row = sqlQuery($sql, $args);
    return $row ?: null;
}

/**
 * Mark a legacy token as used in a way that works across OpenEMR variants.
 * NEVER assumes used_at exists.
 */
function markLegacyPasswordChangeTokenUsed(string $rawToken): void
{
    if ($rawToken === '' || strlen($rawToken) > 256) {
        return;
    }

    ensureLegacyPasswordChangeTokensTable();

    $usedCol = pwdLegacyTokenUsedColumn();
    if ($usedCol === null) {
        return; // nothing we can safely update
    }

    pwdSchemaTry(function () use ($usedCol, $rawToken) {
        sqlStatement(
            "UPDATE `password_change_tokens`
                SET `{$usedCol}` = 1
              WHERE `token` = ?",
            [$rawToken]
        );
    });
}

// ------------------------------------------------------------
// password_setup_tokens (hashed-only tokens)
// ------------------------------------------------------------

function ensurePasswordSetupTokensTable(): void
{
    pwdSchemaTry(function () {
        sqlStatement(
            "CREATE TABLE IF NOT EXISTS `password_setup_tokens` (
                `id` BIGINT(20) NOT NULL AUTO_INCREMENT PRIMARY KEY,
                `user_id` BIGINT(20) NOT NULL,
                `token_hash` CHAR(64) NOT NULL UNIQUE,
                `expiry` DATETIME NOT NULL,
                `used` TINYINT(1) NOT NULL DEFAULT 0,
                `used_at` DATETIME NULL,
                `request_ip` VARCHAR(64) NULL,
                `user_agent` TEXT NULL,
                `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX `idx_token_hash` (`token_hash`),
                INDEX `idx_user_id` (`user_id`),
                INDEX `idx_expiry` (`expiry`),
                INDEX `idx_used` (`used`),
                INDEX `idx_ip_created` (`request_ip`, `created_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        );
    });
}

function cleanupPasswordSetupTokens(int $olderThanDays = 30): void
{
    ensurePasswordSetupTokensTable();
    $days = max(1, (int)$olderThanDays);

    pwdSchemaTry(function () use ($days) {
        sqlStatement(
            "DELETE FROM `password_setup_tokens`
              WHERE (used = 1 OR expiry < NOW())
                AND created_at < (NOW() - INTERVAL {$days} DAY)"
        );
    });
}

/**
 * Create a one-time setup/reset token (hashed-only storage).
 * Returns RAW token (hex) to be emailed.
 */
function createPasswordSetupToken(int $userId, int $ttlSeconds = 1800): ?string
{
    ensurePasswordSetupTokensTable();

    $ttlSeconds = max(60, (int)$ttlSeconds);

    $rawToken  = bin2hex(random_bytes(32)); // 64 hex
    $tokenHash = hash('sha256', $rawToken);
    $expiry    = date('Y-m-d H:i:s', time() + $ttlSeconds);

    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $ip = is_string($ip) ? substr($ip, 0, 64) : '';
    $ua = is_string($ua) ? substr($ua, 0, 500) : '';

    // Cleanup old tokens for this user (best-effort)
    pwdSchemaTry(function () use ($userId) {
        sqlStatement(
            "DELETE FROM `password_setup_tokens`
              WHERE user_id = ?
                AND (used = 1 OR expiry < NOW())",
            [$userId]
        );
    });

    $ok = pwdSchemaTry(function () use ($userId, $tokenHash, $expiry, $ip, $ua) {
        sqlStatement(
            "INSERT INTO `password_setup_tokens` (user_id, token_hash, expiry, used, request_ip, user_agent)
             VALUES (?, ?, ?, 0, ?, ?)",
            [$userId, $tokenHash, $expiry, $ip, $ua]
        );
    });

    if (!$ok) {
        error_log("[PWD] createPasswordSetupToken INSERT failed user_id={$userId}");
        return null;
    }

    $check = sqlQuery(
        "SELECT id FROM `password_setup_tokens` WHERE token_hash = ? LIMIT 1",
        [$tokenHash]
    );
    if (empty($check['id'])) {
        error_log("[PWD] createPasswordSetupToken INSERT verify failed user_id={$userId}");
        return null;
    }

    return $rawToken;
}

function fetchValidPasswordSetupToken(string $rawToken): ?array
{
    $len = strlen($rawToken);
    if ($len < 40 || $len > 256) {
        return null;
    }

    ensurePasswordSetupTokensTable();

    $tokenHash = hash('sha256', $rawToken);

    $row = sqlQuery(
        "SELECT t.*, u.username, u.google_signin_email
           FROM `password_setup_tokens` t
           JOIN `users` u ON u.id = t.user_id
          WHERE t.token_hash = ?
            AND t.used = 0
            AND t.expiry > NOW()
          LIMIT 1",
        [$tokenHash]
    );

    return $row ?: null;
}

function markPasswordSetupTokenUsed(string $rawToken): void
{
    $len = strlen($rawToken);
    if ($len < 40 || $len > 256) {
        return;
    }

    ensurePasswordSetupTokensTable();

    $tokenHash = hash('sha256', $rawToken);

    pwdSchemaTry(function () use ($tokenHash) {
        sqlStatement(
            "UPDATE `password_setup_tokens`
                SET used = 1,
                    used_at = NOW()
              WHERE token_hash = ?",
            [$tokenHash]
        );
    });
}

function rateLimitPasswordSetupRequest(string $ip, int $maxPerHour = 5): bool
{
    if ($ip === '') {
        return false;
    }

    ensurePasswordSetupTokensTable();

    $row = sqlQuery(
        "SELECT COUNT(*) AS cnt
           FROM `password_setup_tokens`
          WHERE request_ip = ?
            AND created_at > (NOW() - INTERVAL 1 HOUR)",
        [$ip]
    );

    return ((int)($row['cnt'] ?? 0) >= (int)$maxPerHour);
}

// ------------------------------------------------------------
// Optional: anti-hammer token verification throttling
// ------------------------------------------------------------

function shouldThrottlePasswordTokenVerify(string $ip, int $maxPer10Min = 60): bool
{
    if ($ip === '') {
        return false;
    }

    pwdSchemaTry(function () {
        sqlStatement(
            "CREATE TABLE IF NOT EXISTS `password_token_verify_log` (
                `id` BIGINT(20) NOT NULL AUTO_INCREMENT PRIMARY KEY,
                `request_ip` VARCHAR(64) NOT NULL,
                `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX `idx_ip_created` (`request_ip`, `created_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        );
    });

    $ok = pwdSchemaTry(function () use ($ip) {
        sqlStatement("INSERT INTO `password_token_verify_log` (`request_ip`) VALUES (?)", [$ip]);
    });

    if (!$ok) {
        return false; // don't lock people out if logging fails
    }

    $row = sqlQuery(
        "SELECT COUNT(*) AS cnt
           FROM `password_token_verify_log`
          WHERE request_ip = ?
            AND created_at > (NOW() - INTERVAL 10 MINUTE)",
        [$ip]
    );

    pwdCleanupByCreatedAt('password_token_verify_log', 7);

    return ((int)($row['cnt'] ?? 0) > (int)$maxPer10Min);
}

// ------------------------------------------------------------
// users_password_baseline (baseline snapshot + last-seen)
// ------------------------------------------------------------

function ensureUsersPasswordBaselineTable(): void
{
    pwdSchemaTry(function () {
        sqlStatement(
            "CREATE TABLE IF NOT EXISTS `users_password_baseline` (
                `user_id` BIGINT(20) NOT NULL PRIMARY KEY,
                `baseline_hash` VARCHAR(255) NOT NULL,
                `baseline_set_at` DATETIME NOT NULL,
                `baseline_set_by` BIGINT(20) NULL,
                `last_seen_hash` VARCHAR(255) NULL,
                `last_seen_at` DATETIME NULL,
                INDEX `idx_baseline_set_at` (`baseline_set_at`),
                INDEX `idx_baseline_set_by` (`baseline_set_by`),
                INDEX `idx_last_seen_at` (`last_seen_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        );
    });
}

function getUsersSecurePasswordHash(int $userId): ?string
{
    $row = sqlQuery("SELECT password FROM users_secure WHERE id = ?", [$userId]);
    if (empty($row) || empty($row['password'])) {
        return null;
    }
    return (string)$row['password'];
}

function upsertUsersPasswordBaselineFromCurrent(int $userId, ?int $actorUserId): void
{
    ensureUsersPasswordBaselineTable();

    $currentHash = getUsersSecurePasswordHash($userId);
    if ($currentHash === null || $currentHash === '') {
        return;
    }

    $exists = sqlQuery("SELECT user_id FROM users_password_baseline WHERE user_id = ?", [$userId]);

    if (!empty($exists)) {
        sqlStatement(
            "UPDATE users_password_baseline
                SET baseline_hash = ?,
                    baseline_set_at = NOW(),
                    baseline_set_by = ?,
                    last_seen_hash = ?,
                    last_seen_at = NOW()
              WHERE user_id = ?",
            [$currentHash, $actorUserId, $currentHash, $userId]
        );
    } else {
        sqlStatement(
            "INSERT INTO users_password_baseline
                (user_id, baseline_hash, baseline_set_at, baseline_set_by, last_seen_hash, last_seen_at)
             VALUES
                (?, ?, NOW(), ?, ?, NOW())",
            [$userId, $currentHash, $actorUserId, $currentHash]
        );
    }
}

function updateUsersPasswordBaselineLastSeen(int $userId): void
{
    ensureUsersPasswordBaselineTable();

    $currentHash = getUsersSecurePasswordHash($userId);
    if ($currentHash === null || $currentHash === '') {
        return;
    }

    $exists = sqlQuery("SELECT user_id FROM users_password_baseline WHERE user_id = ?", [$userId]);
    if (!empty($exists)) {
        sqlStatement(
            "UPDATE users_password_baseline
                SET last_seen_hash = ?,
                    last_seen_at = NOW()
              WHERE user_id = ?",
            [$currentHash, $userId]
        );
    }
}

function getUserPasswordBaselineMatchInfo(int $userId): array
{
    ensureUsersPasswordBaselineTable();

    $baseline = sqlQuery(
        "SELECT baseline_hash, baseline_set_at, baseline_set_by
           FROM users_password_baseline
          WHERE user_id = ?",
        [$userId]
    );

    $currentHash = getUsersSecurePasswordHash($userId);

    if (empty($baseline) || empty($baseline['baseline_hash']) || empty($currentHash)) {
        return [
            'has_baseline' => 0,
            'matches_baseline' => 0,
            'baseline_set_at' => null,
            'baseline_set_by' => null,
        ];
    }

    return [
        'has_baseline' => 1,
        'matches_baseline' => hash_equals((string)$baseline['baseline_hash'], (string)$currentHash) ? 1 : 0,
        'baseline_set_at' => $baseline['baseline_set_at'] ?? null,
        'baseline_set_by' => $baseline['baseline_set_by'] ?? null,
    ];
}

// ------------------------------------------------------------
// users_password_status (default/changed + timestamps)
// ------------------------------------------------------------

function ensureUsersPasswordStatusTable(): void
{
    pwdSchemaTry(function () {
        sqlStatement(
            "CREATE TABLE IF NOT EXISTS `users_password_status` (
                `user_id` BIGINT(20) NOT NULL PRIMARY KEY,
                `status` ENUM('default','changed') NOT NULL DEFAULT 'default',
                `default_set_at` DATETIME NULL,
                `default_set_by` BIGINT(20) NULL,
                `changed_at` DATETIME NULL,
                `changed_by` BIGINT(20) NULL,
                INDEX `idx_status` (`status`),
                INDEX `idx_changed_at` (`changed_at`),
                INDEX `idx_default_set_at` (`default_set_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        );
    });
}

function upsertUsersPasswordStatus(int $userId, string $status, ?int $actorUserId): void
{
    ensureUsersPasswordStatusTable();

    $status = ($status === 'default') ? 'default' : 'changed';
    $exists = sqlQuery("SELECT user_id FROM users_password_status WHERE user_id = ?", [$userId]);

    if (!empty($exists)) {
        if ($status === 'default') {
            sqlStatement(
                "UPDATE users_password_status
                    SET status='default',
                        default_set_at=NOW(),
                        default_set_by=?,
                        changed_at=NULL,
                        changed_by=NULL
                  WHERE user_id=?",
                [$actorUserId, $userId]
            );
        } else {
            sqlStatement(
                "UPDATE users_password_status
                    SET status='changed',
                        changed_at=NOW(),
                        changed_by=?
                  WHERE user_id=?",
                [$actorUserId, $userId]
            );
        }
    } else {
        if ($status === 'default') {
            sqlStatement(
                "INSERT INTO users_password_status (user_id, status, default_set_at, default_set_by)
                 VALUES (?, 'default', NOW(), ?)",
                [$userId, $actorUserId]
            );
        } else {
            sqlStatement(
                "INSERT INTO users_password_status (user_id, status, changed_at, changed_by)
                 VALUES (?, 'changed', NOW(), ?)",
                [$userId, $actorUserId]
            );
        }
    }
}

function derivePasswordStatusFromBaseline(int $userId): string
{
    $info = getUserPasswordBaselineMatchInfo($userId);
    if (empty($info['has_baseline'])) {
        return 'unknown';
    }
    return !empty($info['matches_baseline']) ? 'default' : 'changed';
}
