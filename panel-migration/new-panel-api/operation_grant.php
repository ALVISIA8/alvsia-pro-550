<?php
/**
 * ALVSIA PRO new-panel adapter: short-lived RSA operation grants.
 *
 * Deploy as /api/operation_grant.php on alvsiapanel.unaux.com.
 * The signing private key must be configured outside the web root:
 *   OPERATION_GRANT_PRIVATE_KEY (PEM with escaped newlines), or
 *   OPERATION_GRANT_PRIVATE_KEY_FILE (absolute path outside web root).
 * The public key embedded in app/src/main/python/alvsia_core.py MUST match it.
 * Missing/mismatched signer fails closed. TTL is hard-capped at 180 seconds.
 */
require_once __DIR__ . '/config.php';
if (is_file(__DIR__ . '/sec_lib.php')) require_once __DIR__ . '/sec_lib.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Content-Type');
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') { http_response_code(204); exit; }
function grant_fail(string $message, int $status = 403): void {
    http_response_code($status);
    echo json_encode(['status' => 'error', 'msg' => $message]);
    exit;
}
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') grant_fail('POST required', 405);
$body = json_decode(file_get_contents('php://input'), true);
if (!is_array($body)) grant_fail('Invalid JSON', 400);

$license = trim((string)($body['license'] ?? ''));
$hwid = strtolower(preg_replace('/[^a-fA-F0-9]/', '', (string)($body['hwid'] ?? '')));
$token = strtolower(preg_replace('/[^a-fA-F0-9]/', '', (string)($body['session_token'] ?? '')));
$sessionId = strtolower(preg_replace('/[^a-fA-F0-9]/', '', (string)($body['session_id'] ?? '')));
$buildId = trim((string)($body['build_id'] ?? ''));
$manifestHash = strtolower(trim((string)($body['manifest_hash'] ?? '')));
$toolHash = strtolower(trim((string)($body['tool_hash'] ?? '')));
$opsInput = $body['operations'] ?? [];
if ($license === '' || strlen($token) !== 64 || strlen($hwid) !== 64) grant_fail('Missing identity', 400);
if (!hash_equals(substr(hash('sha256', $token), 0, 32), $sessionId)) grant_fail('Session binding mismatch');
if ($buildId !== 'ALVSIA-20260923-V46') grant_fail('Build mismatch');
$measurement = hash('sha256', 'ALVSIA-APK-SESSION');
if (!hash_equals($measurement, $manifestHash) || !hash_equals($measurement, $toolHash)) grant_fail('Measurement mismatch');
$ops = is_array($opsInput) ? $opsInput : (isset($body['operation_id']) ? [$body['operation_id']] : []);
$allowed = [
 'pak.unpack','pak.repack','pak.unpack_single','pak.repack_single',
 'pak.delete_entry','pak.delete_all','pak.diagnostics',
 'advanced.inject_any','advanced.inject_brplayer','advanced.same_size_hashfix',
 'advanced.zsdic_hashfix','asset.unpack','obb.unpack','obb.repack',
 'lab.editor.auto_pak','lab.playerpawn.auto_pak'
];
$ops = array_values(array_unique(array_filter(array_map(fn($v) => trim((string)$v), $ops))));
if (!$ops || count($ops) > 8) grant_fail('Invalid operation list', 400);
foreach ($ops as $op) if (!in_array($op, $allowed, true)) grant_fail('Operation not allowed');

try {
    if (!function_exists('session_validate')) grant_fail('Session validator unavailable', 503);
    $session = session_validate($token, $hwid);
    if (!$session || !hash_equals((string)($session['license_code'] ?? ''), $license)) {
        grant_fail('Session invalid; login again', 401);
    }
    $keyId = (int)($session['key_id'] ?? 0);
    if ($keyId < 1) grant_fail('License record unavailable', 401);
    $q = db()->prepare('SELECT status, expires_at FROM vp_license_keys WHERE id = ? LIMIT 1');
    $q->bind_param('i', $keyId);
    $q->execute();
    $key = $q->get_result()->fetch_assoc();
    if (!$key) grant_fail('License unavailable', 401);
    if (in_array((string)($key['status'] ?? ''), ['blocked','banned'], true)) grant_fail('License blocked', 403);
    if (!empty($key['expires_at']) && strtotime((string)$key['expires_at']) < time()) grant_fail('License expired', 403);
} catch (Throwable $e) {
    grant_fail('Session validation failed', 503);
}

$pem = getenv('OPERATION_GRANT_PRIVATE_KEY');
if (is_string($pem) && strpos($pem, '-----BEGIN') !== false) {
    $pem = str_replace('\\n', "\n", $pem);
} else {
    $path = getenv('OPERATION_GRANT_PRIVATE_KEY_FILE');
    $pem = is_string($path) && $path !== '' && is_readable($path) ? file_get_contents($path) : '';
}
$pkey = is_string($pem) ? openssl_pkey_get_private($pem) : false;
if (!$pkey) grant_fail('Grant signer unavailable', 503);

$issued = time() - 5;
$expires = time() + 180;
$fields = [
 'grant_id' => bin2hex(random_bytes(16)),
 'nonce' => bin2hex(random_bytes(16)),
 'build_id' => $buildId,
 'manifest_hash' => $manifestHash,
 'tool_hash' => $toolHash,
 'device_id' => $hwid,
 'session_id' => $sessionId,
 'operation_id' => implode(',', $ops),
 'issued_at' => gmdate('Y-m-d H:i:s', $issued),
 'expires_at' => gmdate('Y-m-d H:i:s', $expires),
];
$message = "ALVSIA-R4\nkind=operation_grant";
foreach (['grant_id','nonce','build_id','manifest_hash','tool_hash','device_id','session_id','operation_id','issued_at','expires_at'] as $name) {
    $message .= "\n" . $name . '=' . $fields[$name];
}
$signature = '';
if (!openssl_sign($message, $signature, $pkey, OPENSSL_ALGO_SHA256)) grant_fail('Grant signing failed', 503);
$signature = rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');
echo json_encode([
 'status' => 'success',
 'proof' => array_merge($fields, ['signature' => ['alg' => 'RS256', 'kid' => 'alvsia-r4-20260923', 'value' => $signature]])
]);
