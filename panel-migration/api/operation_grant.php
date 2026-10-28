<?php
declare(strict_types=1);

/**
 * ALVSIA PRO — RSA-signed operation grants for the new unaux panel.
 * Install as /api/operation_grant.php beside config.php and sec_lib.php.
 * Private key MUST be supplied through OPERATION_GRANT_PRIVATE_KEY_FILE
 * outside the webroot (or OPERATION_GRANT_PRIVATE_KEY environment variable).
 */
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/sec_lib.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, private');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('Access-Control-Allow-Headers: Content-Type, CF-Ray');
header('Access-Control-Allow-Methods: POST, OPTIONS');

function grant_reply(int $code, array $payload): void {
    http_response_code($code);
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
function grant_fail(string $message, int $code = 403): void {
    grant_reply($code, ['status' => 'error', 'msg' => $message]);
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') {
    http_response_code(204);
    exit;
}
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST, OPTIONS');
    grant_fail('Method not allowed', 405);
}
if (function_exists('alvsia_cf_ray_check') && !alvsia_cf_ray_check()) {
    grant_fail('Duplicate request', 429);
}

const GRANT_KID = 'alvsia-r4-20260923';
const GRANT_TTL = 180;
const GRANT_BUILD_ID = 'ALVSIA-20260923-V46';
const GRANT_MEASUREMENT = 'a2760b0984493be88bb9801091ee6c103b7a1f1690bd137d036fd88fa4dfa0f5';
const GRANT_ALLOWED = [
    'pak.unpack', 'pak.repack', 'pak.unpack_single', 'pak.repack_single',
    'pak.delete_entry', 'pak.delete_all', 'pak.diagnostics',
    'advanced.inject_any', 'advanced.inject_brplayer',
    'advanced.same_size_hashfix', 'advanced.zsdic_hashfix',
    'asset.unpack', 'obb.unpack', 'obb.repack',
    'lab.editor.auto_pak', 'lab.playerpawn.auto_pak'
];

$body = json_decode((string)file_get_contents('php://input'), true);
if (!is_array($body)) grant_fail('Bad request', 400);

$license = trim((string)($body['license'] ?? ''));
$hwid = strtolower(trim((string)($body['hwid'] ?? '')));
$token = strtolower(trim((string)($body['session_token'] ?? '')));
$sessionId = strtolower(trim((string)($body['session_id'] ?? '')));
$buildId = trim((string)($body['build_id'] ?? ''));
$manifestHash = strtolower(trim((string)($body['manifest_hash'] ?? '')));
$toolHash = strtolower(trim((string)($body['tool_hash'] ?? '')));
$opsInput = $body['operations'] ?? null;

if ($license === '' || strlen($license) > 128 ||
    !preg_match('/^[a-f0-9]{64}$/', $hwid) ||
    !preg_match('/^[a-f0-9]{64}$/', $token) ||
    !preg_match('/^[a-f0-9]{64}$/', $sessionId)) {
    grant_fail('Missing or invalid session fields', 400);
}
if (!hash_equals(hash('sha256', $token), $sessionId)) {
    grant_fail('Session binding mismatch', 403);
}
if (!hash_equals(GRANT_BUILD_ID, $buildId)) grant_fail('Build mismatch', 403);
if (!preg_match('/^[a-f0-9]{64}$/', $manifestHash) ||
    !preg_match('/^[a-f0-9]{64}$/', $toolHash) ||
    !hash_equals(GRANT_MEASUREMENT, $manifestHash) ||
    !hash_equals(GRANT_MEASUREMENT, $toolHash)) {
    grant_fail('Measurement mismatch', 403);
}
if (!is_array($opsInput) || count($opsInput) < 1 || count($opsInput) > 8) {
    grant_fail('Bad operations', 400);
}
$ops = [];
foreach ($opsInput as $op) {
    if (!is_string($op) || !in_array($op, GRANT_ALLOWED, true)) grant_fail('Operation not allowed', 403);
    $ops[] = $op;
}
$ops = array_values(array_unique($ops));
if (!$ops) grant_fail('Bad operations', 400);

$ip = function_exists('alvsia_client_ip') ? (string)alvsia_client_ip() : (string)($_SERVER['REMOTE_ADDR'] ?? '');
if (function_exists('is_ip_banned') && is_ip_banned($ip)) grant_fail('Access denied', 403);
if (function_exists('alvsia_hwid_banned') && alvsia_hwid_banned($hwid)) grant_fail('Device banned', 403);
if (function_exists('alvsia_rate_limit_key') && !alvsia_rate_limit_key($license, 'operation_grant', 20, 60)) {
    if (function_exists('alvsia_anomaly_hit')) alvsia_anomaly_hit('grant_rate_exceeded', $license, $hwid);
    grant_fail('Rate limited', 429);
}

/* Database is authoritative: never issue a grant when DB validation fails. */
try {
    $db = db();
    if (!($db instanceof mysqli)) throw new RuntimeException('DB unavailable');
    $stmt = $db->prepare(
        'SELECT s.id, s.license_code, s.hwid, s.expires_at AS session_expires,
                k.key_code, k.status AS license_status, k.expires_at AS key_expires
           FROM vp_sessions s
           INNER JOIN vp_license_keys k ON k.id = s.key_id
          WHERE s.token = ? AND s.revoked = 0 LIMIT 1'
    );
    if (!$stmt) throw new RuntimeException('DB prepare failed');
    $stmt->bind_param('s', $token);
    if (!$stmt->execute()) throw new RuntimeException('DB query failed');
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    if (!$row) grant_fail('Session invalid. Re-login required.', 401);
    if ((int)$row['session_expires'] <= time()) grant_fail('Session expired.', 401);
    if (!hash_equals((string)$row['license_code'], $license) ||
        !hash_equals((string)$row['key_code'], $license)) grant_fail('License mismatch', 403);
    if (!hash_equals(strtolower((string)$row['hwid']), $hwid)) grant_fail('Device mismatch', 403);
    if ((string)$row['license_status'] !== 'active') grant_fail('License blocked', 403);
    $expiry = trim((string)($row['key_expires'] ?? ''));
    if ($expiry !== '') {
        $expiryTs = strtotime($expiry);
        if ($expiryTs === false || $expiryTs <= time()) grant_fail('License expired', 403);
    }
    $touch = $db->prepare('UPDATE vp_sessions SET last_seen = NOW() WHERE id = ?');
    if (!$touch) throw new RuntimeException('Session touch failed');
    $sid = (int)$row['id'];
    $touch->bind_param('i', $sid);
    if (!$touch->execute()) throw new RuntimeException('Session touch failed');
    $touch->close();
} catch (Throwable $e) {
    error_log('[ALVSIA operation_grant] DB/session validation failed: ' . get_class($e));
    grant_fail('Authentication service unavailable', 503);
}

/* Load private signing key only from deployment environment, never from webroot/repo. */
$pem = null;
$envPem = getenv('OPERATION_GRANT_PRIVATE_KEY');
if (is_string($envPem) && strpos($envPem, '-----BEGIN') !== false) {
    $pem = str_replace('\\n', "\n", $envPem);
} else {
    $keyFile = getenv('OPERATION_GRANT_PRIVATE_KEY_FILE');
    if (is_string($keyFile) && $keyFile !== '' && is_readable($keyFile)) {
        $candidate = file_get_contents($keyFile);
        if (is_string($candidate) && strpos($candidate, '-----BEGIN') !== false) $pem = $candidate;
    }
    // Shared-host fallback: private directory adjacent to htdocs, never under webroot.
    if (!$pem) {
        $privateCandidate = dirname(__DIR__, 2) . '/private/operation_grant.pem';
        if (is_readable($privateCandidate)) {
            $candidate = file_get_contents($privateCandidate);
            if (is_string($candidate) && strpos($candidate, '-----BEGIN') !== false) $pem = $candidate;
        }
    }
}
if (!$pem) grant_fail('grant signer unavailable', 503);
$key = @openssl_pkey_get_private($pem);
if (!$key) grant_fail('grant signer unavailable', 503);

$fields = [
    'grant_id' => bin2hex(random_bytes(16)),
    'nonce' => bin2hex(random_bytes(16)),
    'build_id' => $buildId,
    'manifest_hash' => $manifestHash,
    'tool_hash' => $toolHash,
    'device_id' => $hwid,
    'session_id' => $sessionId,
    'operation_id' => implode(',', $ops),
    'issued_at' => gmdate('Y-m-d H:i:s', time() - 5),
    'expires_at' => gmdate('Y-m-d H:i:s', time() + GRANT_TTL)
];
$order = ['grant_id','nonce','build_id','manifest_hash','tool_hash','device_id','session_id','operation_id','issued_at','expires_at'];
$canonical = "ALVSIA-R4\nkind=operation_grant";
foreach ($order as $name) $canonical .= "\n" . $name . '=' . $fields[$name];
$signature = '';
if (!openssl_sign($canonical, $signature, $key, OPENSSL_ALGO_SHA256)) grant_fail('grant signing failed', 500);
$value = rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');
try {
    if (function_exists('log_activity')) log_activity(null, 'operation_grant', 'ops=' . implode(',', $ops));
} catch (Throwable $e) {
    // Logging failure does not invalidate the already-authorized grant.
}
grant_reply(200, ['status' => 'success', 'proof' => $fields + [
    'signature' => ['alg' => 'RS256', 'kid' => GRANT_KID, 'value' => $value]
]]);
