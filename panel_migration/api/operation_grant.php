<?php
declare(strict_types=1);

/* Buffer all incidental output from includes/runtime so the API emits JSON only. */
$__alvsia_grant_ob_level = ob_get_level();
ob_start();

/**
 * ALVSIA R4 protected-operation grant issuer.
 * The private key is read from ALVSIA_OPERATION_GRANT_PRIVATE_KEY or the
 * server-only operation_grant.pem beside this endpoint. Never commit the PEM.
 */
require_once __DIR__ . '/config.php';
@require_once __DIR__ . '/sec_lib.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');

function operation_grant_fail(int $status, string $message): void {
    global $__alvsia_grant_ob_level;
    while (ob_get_level() > $__alvsia_grant_ob_level) {
        ob_end_clean();
    }
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => false, 'error' => $message], JSON_UNESCAPED_SLASHES);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
    http_response_code(204);
    exit;
}
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST, OPTIONS');
    operation_grant_fail(405, 'POST required');
}

$rawBody = (string)file_get_contents('php://input');
$body = json_decode($rawBody, true);
if (!is_array($body) || json_last_error() !== JSON_ERROR_NONE) {
    operation_grant_fail(400, 'Invalid JSON');
}

$license = trim((string)($body['license'] ?? ''));
$hwid = strtolower(trim((string)($body['hwid'] ?? '')));
$sessionToken = trim((string)($body['session_token'] ?? ''));
$operationId = trim((string)($body['operation_id'] ?? ''));
$buildId = trim((string)($body['build_id'] ?? ''));

if ($license === '' ||
    !preg_match('/^[a-f0-9]{64}$/', $hwid) ||
    !preg_match('/^[a-fA-F0-9]{64}$/', $sessionToken) ||
    $buildId !== 'ALVSIA-20260923-V46') {
    operation_grant_fail(400, 'Missing or invalid grant request fields');
}

$allowedOperations = [
    'pak.unpack', 'pak.repack', 'pak.unpack_single', 'pak.repack_single',
    'pak.delete_entry', 'pak.delete_all', 'pak.diagnostics',
    'advanced.inject_any', 'advanced.inject_brplayer',
    'advanced.same_size_hashfix', 'advanced.zsdic_hashfix',
    'asset.unpack', 'obb.unpack', 'obb.repack',
    'lab.editor.auto_pak', 'lab.playerpawn.auto_pak',
];
if (!in_array($operationId, $allowedOperations, true)) {
    operation_grant_fail(403, 'Operation not grantable');
}

if (function_exists('alvsia_rate_limit_key') &&
    !alvsia_rate_limit_key($license . ':' . $hwid, 'operation_grant', 12, 60)) {
    operation_grant_fail(429, 'Grant rate limit exceeded');
}

/* Validate using the panel's established session contract. */
try {
    $sessionOk = false;
    if (function_exists('alvsia_session_ok')) {
        $sessionOk = alvsia_session_ok($license, $hwid, $sessionToken);
    }
    if (!$sessionOk && function_exists('session_validate')) {
        $session = session_validate($sessionToken, $hwid);
        if (is_array($session) &&
            isset($session['license_code']) &&
            hash_equals((string)$session['license_code'], $license)) {
            $sessionOk = true;
            if (function_exists('alvsia_session_put') && defined('SESSION_TTL')) {
                alvsia_session_put($license, $hwid, $sessionToken, SESSION_TTL);
            }
        }
    }
    if (!$sessionOk) {
        operation_grant_fail(401, 'Session invalid; re-login required');
    }

    /* Recheck the live DB session and key status when DB access is available. */
    try {
        $db = db();
        $stmt = $db->prepare('SELECT s.id, s.key_id, s.license_code, s.hwid,
            k.status, k.expires_at AS key_expires
            FROM vp_sessions s
            LEFT JOIN vp_license_keys k ON k.id = s.key_id
            WHERE s.token = ? AND s.revoked = 0 AND s.expires_at > UNIX_TIMESTAMP()
            LIMIT 1');
        if ($stmt) {
            $stmt->bind_param('s', $sessionToken);
            if ($stmt->execute()) {
                $row = $stmt->get_result()->fetch_assoc();
                if ($row) {
                    if ((string)$row['license_code'] !== $license ||
                        strtolower((string)$row['hwid']) !== $hwid) {
                        operation_grant_fail(401, 'Session/device binding mismatch');
                    }
                    if (strtolower((string)($row['status'] ?? '')) === 'blocked') {
                        operation_grant_fail(403, 'License blocked');
                    }
                    $expiry = (string)($row['key_expires'] ?? '');
                    if ($expiry !== '' && (($ts = strtotime($expiry)) === false || $ts < time())) {
                        operation_grant_fail(403, 'License expired');
                    }
                    $sid = (int)$row['id'];
                    $touch = $db->prepare('UPDATE vp_sessions SET last_seen = NOW() WHERE id = ?');
                    if ($touch) {
                        $touch->bind_param('i', $sid);
                        $touch->execute();
                        $touch->close();
                    }
                }
            }
            $stmt->close();
        }
    } catch (Throwable $dbError) {
        /* File-backed HMAC session validation remains authoritative fallback. */
    }
} catch (Throwable $e) {
    error_log('operation_grant: session validation failed (' . get_class($e) . ')');
    operation_grant_fail(503, 'Session validation failed');
}

/* Matches _alvsia_core_live_measurement() for ALVSIA_APK_SESSION=1. */
$measurement = hash('sha256', 'ALVSIA-APK-SESSION');
$now = time();
$fields = [
    'grant_id' => bin2hex(random_bytes(16)),
    'nonce' => rtrim(strtr(base64_encode(random_bytes(24)), '+/', '-_'), '='),
    'build_id' => 'ALVSIA-20260923-V46',
    'manifest_hash' => $measurement,
    'tool_hash' => $measurement,
    'device_id' => $hwid,
    'session_id' => $sessionToken,
    'operation_id' => $operationId,
    'issued_at' => gmdate('Y-m-d H:i:s', $now),
    /* 120 seconds issued; the verifier also enforces an absolute 180s maximum. */
    'expires_at' => gmdate('Y-m-d H:i:s', $now + 120),
];

$privatePem = getenv('ALVSIA_OPERATION_GRANT_PRIVATE_KEY');
if (!is_string($privatePem) || trim($privatePem) === '') {
    $keyPath = __DIR__ . '/operation_grant.pem';
    if (is_file($keyPath) && is_readable($keyPath)) {
        $privatePem = (string)file_get_contents($keyPath);
    }
}
if (!is_string($privatePem) || trim($privatePem) === '') {
    operation_grant_fail(503, 'Grant signing key is not configured on server');
}
$privatePem = str_replace('\\n', "\n", $privatePem);
$privateKey = openssl_pkey_get_private($privatePem);
if ($privateKey === false) {
    operation_grant_fail(503, 'Grant signing key is invalid');
}
$keyDetails = openssl_pkey_get_details($privateKey);
$expectedModulusB64u = '59rkifaSC8v07GndYOsL_D7H6W1VEnKnVlvLfxvtUgztjUYqKvea7AseAeAW59yqpiaQ7e1Nq3J-z9lfWUpJfETQFldk8F4g0ZBKdJLqzvw-Vw9be7Ky5x78B4Z9qYyN0vQinMIfhLLL2ctOeOGe01lYeEQ8m2y6v5OhTlY9wYRM_oKljG0h9HfKlbGuFLxGRCM-iK6fT33b2tzyxAO_bvsnHF-9IcHYdjyPgRVewZ_kWbAZ7FeabA8HtCqgizepjdlTtj6m8eufYodQw4a2kfe-r_0PMZhmnzOvzEeCQMxfnHwXAeQhTA9tB1GtO3eFJEAOCxVoq66sR8T3NuW6kw';
$expectedModulus = base64_decode(
    strtr($expectedModulusB64u, '-_', '+/') .
    str_repeat('=', (4 - strlen($expectedModulusB64u) % 4) % 4),
    true
);
if (!is_array($keyDetails) ||
    ($keyDetails['type'] ?? -1) !== OPENSSL_KEYTYPE_RSA ||
    !isset($keyDetails['rsa']['n'], $keyDetails['rsa']['e']) ||
    !is_string($expectedModulus) ||
    !hash_equals($expectedModulus, $keyDetails['rsa']['n']) ||
    !hash_equals("\x01\x00\x01", $keyDetails['rsa']['e'])) {
    openssl_pkey_free($privateKey);
    operation_grant_fail(503, 'Grant signing key does not match the app verifier');
}

$orderedKeys = [
    'grant_id', 'nonce', 'build_id', 'manifest_hash', 'tool_hash',
    'device_id', 'session_id', 'operation_id', 'issued_at', 'expires_at',
];
$canonical = "ALVSIA-R4\nkind=operation_grant";
foreach ($orderedKeys as $key) {
    $canonical .= "\n" . $key . '=' . $fields[$key];
}
$signature = '';
if (!openssl_sign($canonical, $signature, $privateKey, OPENSSL_ALGO_SHA256)) {
    openssl_pkey_free($privateKey);
    operation_grant_fail(503, 'Grant signing failed');
}
openssl_pkey_free($privateKey);

$fields['signature'] = [
    'alg' => 'RS256',
    'kid' => 'alvsia-r4-20260923',
    'value' => rtrim(strtr(base64_encode($signature), '+/', '-_'), '='),
];
while (ob_get_level() > $__alvsia_grant_ob_level) {
    ob_end_clean();
}
header('Content-Type: application/json; charset=utf-8');
echo json_encode(['ok' => true, 'grant' => $fields], JSON_UNESCAPED_SLASHES);
