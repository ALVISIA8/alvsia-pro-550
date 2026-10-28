<?php
declare(strict_types=1);
/* ALVSIA PRO — Unaux JWT RS256 operation grant. Keep the login API unchanged. */
require_once __DIR__ . '/config.php';
@ini_set('display_errors','0'); error_reporting(0);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache'); header('X-Content-Type-Options: nosniff'); header('Referrer-Policy: no-referrer');
const ALVSIA_GRANT_KID='alvsia-unaux-rsa1';
const ALVSIA_GRANT_BUILD_ID='ALVSIA-UNaux-20261028-RSA1';
const ALVSIA_GRANT_ISSUER='https://alvsiapanel.unaux.com';
const ALVSIA_GRANT_AUDIENCE='com.alvsia.pro';
const ALVSIA_GRANT_TTL=180;
const ALVSIA_GRANT_PUBLIC_N_B64URL='p2G8SVBzL8Ic_aTg10HZcc35LJdw2Iv-rP0LyXyyKp-06Ju-_nOxTpDE9gpDoBegkXh7sj37qO94Fx-SZn3JDVdRzKMARzkRSevUX0wOGveXd6JzggcCDe70-P3QhHgPE91HM78QkGeBV0vSebOCLEVjP7l0MjmmBK_7zuK3FuPaMBZUBOi8CwGuW8lhjqbPwwiKM5tHKG5bd9-hWVZ6O-XBP_jiQSafnXX-3Gy_z6LuniDzK79CfxBoxQwJPOOxowHzeVvgcVSy7ubJO3ZzsATsi-JPYCyMtIOC7eKDHFourkFaOYd0i4r838nPAylbpL659vkP2DD3hd4SW5JStPIH20sShkpWsCglhGa0Hukt_kh-HrD9YMhRGdc0Ymc8dU6LnSU4KKb6wmk1LLhgtLC3NoTaM_Yx_3Z5iqrY9ELiLT6teSWlyEpJWOFPkPz39EoThQlDpWf0aO7syXoo3iAXJMUpWUli1qPCC94TSumUEAYwULv1m4_nbLO6WwNR';
function grant_reply($status,array $body) { http_response_code((int)$status); echo json_encode($body,JSON_UNESCAPED_SLASHES|JSON_INVALID_UTF8_SUBSTITUTE); exit; }
function grant_fail($status,$code) { grant_reply($status,['status'=>'error','code'=>$code]); }
function grant_b64url($s) { return rtrim(strtr(base64_encode($s),'+/','-_'),'='); }
function grant_operation_allowed($op) {
 return in_array($op,['pak_tools','obb_tools','skin_obb','lua_tools','file_scan','workspace','export_report','rebrand','so_analyzer','frida_tracer','xor_suite','decrypt_engine','string_recover','lua_inject','anti_re_audit','lua_protector','alvsia_private_tool','game_patch','apk_audit'],true);
}
function grant_audit($keyId,$operation,$requestId,$result) {
 try {
  $conn=db();
  $conn->query("CREATE TABLE IF NOT EXISTS vp_operation_grant_audit (
   id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
   key_id INT UNSIGNED NOT NULL DEFAULT 0,
   operation VARCHAR(64) NOT NULL,
   request_id VARCHAR(64) NOT NULL,
   result VARCHAR(24) NOT NULL,
   ip_hash CHAR(64) NOT NULL,
   created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
   PRIMARY KEY(id), KEY idx_key_created(key_id,created_at), KEY idx_request(request_id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
  $ip=(string)($_SERVER['REMOTE_ADDR']??''); $ipHash=hash('sha256',$ip);
  $stmt=$conn->prepare('INSERT INTO vp_operation_grant_audit (key_id,operation,request_id,result,ip_hash) VALUES (?,?,?,?,?)');
  if($stmt) { $stmt->bind_param('issss',$keyId,$operation,$requestId,$result,$ipHash); $stmt->execute(); }
 } catch(Throwable $e) { error_log('[ALVSIA grant audit] '.get_class($e)); }
}
function grant_rate_limit($action,$limit,$windowSeconds) {
 try {
  $conn=db(); $ip=substr((string)($_SERVER['REMOTE_ADDR']??'unknown'),0,64);
  $stmt=$conn->prepare('SELECT hits,window_start FROM vp_rate_limit WHERE ip_address=? AND action=? LIMIT 1');
  if(!$stmt) return false;
  $stmt->bind_param('ss',$ip,$action); if(!$stmt->execute()) return false;
  $row=$stmt->get_result()->fetch_assoc();
  if($row && (time()-strtotime((string)$row['window_start']))<$windowSeconds && (int)$row['hits'] >= $limit) return false;
  if($row && (time()-strtotime((string)$row['window_start']))<$windowSeconds) {
   $u=$conn->prepare('UPDATE vp_rate_limit SET hits=hits+1 WHERE ip_address=? AND action=?');
   if(!$u) return false; $u->bind_param('ss',$ip,$action); return $u->execute();
  }
  $u=$conn->prepare('INSERT INTO vp_rate_limit (ip_address,action,hits,window_start) VALUES (?, ?, 1, NOW()) ON DUPLICATE KEY UPDATE hits=1, window_start=NOW()');
  if(!$u) return false; $u->bind_param('ss',$ip,$action); return $u->execute();
 } catch(Throwable $e) { return false; }
}
if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { header('Allow: POST'); grant_fail(405,'method_not_allowed'); }
$type=strtolower(trim(explode(';',(string)($_SERVER['CONTENT_TYPE']??''))[0]));
if ($type!=='application/json') grant_fail(415,'json_required');
$len=(int)($_SERVER['CONTENT_LENGTH']??0); if($len>8192) grant_fail(413,'request_too_large');
$raw=file_get_contents('php://input',false,null,0,8193);
if(!is_string($raw)||$raw===''||strlen($raw)>8192) grant_fail(400,'invalid_body');
$body=json_decode($raw,true); if(!is_array($body)||json_last_error()!==JSON_ERROR_NONE) grant_fail(400,'invalid_json');
$token=strtolower(trim((string)($body['session_token']??'')));
$hwid=trim((string)($body['hwid']??'')); $build=trim((string)($body['build_id']??''));
$operation=strtolower(trim((string)($body['operation']??''))); $requestId=strtolower(trim((string)($body['request_id']??'')));
if(!preg_match('/^[a-f0-9]{64}$/',$token)) grant_fail(400,'invalid_session_token');
if($hwid===''||strlen($hwid)<8||strlen($hwid)>128) grant_fail(400,'invalid_hwid');
if(!hash_equals(ALVSIA_GRANT_BUILD_ID,$build)) grant_fail(403,'build_not_allowed');
if(!preg_match('/^[a-z0-9_]{2,64}$/',$operation)||!grant_operation_allowed($operation)) grant_fail(403,'operation_not_allowed');
if(!preg_match('/^[a-f0-9]{16,64}$/',$requestId)) grant_fail(400,'invalid_request_id');
if(!grant_rate_limit('operation_grant',30,60)) grant_fail(429,'rate_limited');
try {
 if(!function_exists('session_validate')||!function_exists('db')) grant_fail(503,'panel_auth_unavailable');
 $session=session_validate($token,$hwid); if(!$session) grant_fail(401,'session_invalid');
 $keyId=(int)($session['key_id']??0); $license=(string)($session['license_code']??'');
 if($keyId<1||$license==='') grant_fail(401,'session_binding_invalid');
 $conn=db(); $stmt=$conn->prepare('SELECT id,key_code,status,expires_at FROM vp_license_keys WHERE id=? AND key_code=? LIMIT 1');
 if(!$stmt) grant_fail(503,'license_check_unavailable');
 $stmt->bind_param('is',$keyId,$license); if(!$stmt->execute()) grant_fail(503,'license_check_unavailable');
 $keyRow=$stmt->get_result()->fetch_assoc();
 if(!$keyRow||(string)$keyRow['status']!=='active') grant_fail(403,'license_inactive');
 if(!empty($keyRow['expires_at'])&&strtotime((string)$keyRow['expires_at'])<=time()) grant_fail(403,'license_expired');
 try {
  $ban=$conn->prepare('SELECT id FROM vp_hwid WHERE key_id=? AND hwid=? AND is_banned=1 LIMIT 1');
  if(!$ban) grant_fail(503,'device_check_unavailable');
  $ban->bind_param('is',$keyId,$hwid); if(!$ban->execute()) grant_fail(503,'device_check_unavailable');
  if($ban->get_result()->fetch_assoc()) grant_fail(403,'device_banned');
 } catch(Throwable $e) { grant_fail(503,'device_check_unavailable'); }
 if(function_exists('is_ip_banned')) { $ip=function_exists('client_ip')?client_ip():($_SERVER['REMOTE_ADDR']??''); if(is_ip_banned($ip)) grant_fail(403,'access_denied'); }
 $privatePath=__DIR__.'/.private/operation_grant_private.pem';
 if(!is_file($privatePath)||!is_readable($privatePath)) grant_fail(503,'grant_signing_key_missing');
 $privatePem=file_get_contents($privatePath); $privateKey=$privatePem?openssl_pkey_get_private($privatePem):false;
 if($privateKey===false) grant_fail(503,'grant_signing_key_invalid');
 $details=openssl_pkey_get_details($privateKey);
 if(!$details||($details['type']??-1)!==OPENSSL_KEYTYPE_RSA||(int)($details['bits']??0)<3072) grant_fail(503,'grant_signing_key_weak');
 if(!isset($details['rsa']['n'])||!hash_equals(ALVSIA_GRANT_PUBLIC_N_B64URL,grant_b64url($details['rsa']['n']))) grant_fail(503,'grant_signing_key_mismatch');
 $now=time(); $payload=['iss'=>ALVSIA_GRANT_ISSUER,'aud'=>ALVSIA_GRANT_AUDIENCE,'sub'=>(string)$keyId,'kid'=>ALVSIA_GRANT_KID,'jti'=>bin2hex(random_bytes(16)),'iat'=>$now,'nbf'=>$now-2,'exp'=>$now+ALVSIA_GRANT_TTL,'ttl'=>ALVSIA_GRANT_TTL,'build_id'=>ALVSIA_GRANT_BUILD_ID,'operation'=>$operation,'request_id'=>$requestId,'session_hash'=>hash('sha256',$token),'hwid_hash'=>hash('sha256',$hwid),'license_hash'=>hash('sha256',$license)];
 $head=grant_b64url(json_encode(['typ'=>'JWT','alg'=>'RS256','kid'=>ALVSIA_GRANT_KID],JSON_UNESCAPED_SLASHES));
 $bodyPart=grant_b64url(json_encode($payload,JSON_UNESCAPED_SLASHES)); $input=$head.'.'.$bodyPart; $sig='';
 if(!openssl_sign($input,$sig,$privateKey,OPENSSL_ALGO_SHA256)) grant_fail(503,'grant_signing_failed');
 grant_audit($keyId,$operation,$requestId,'issued');
 grant_reply(200,['status'=>'ok','contract_version'=>1,'alg'=>'RS256','kid'=>ALVSIA_GRANT_KID,'grant_token'=>$input.'.'.grant_b64url($sig),'ttl'=>ALVSIA_GRANT_TTL,'server_time'=>$now,'expires_at'=>$now+ALVSIA_GRANT_TTL]);
} catch(Throwable $e) { error_log('[ALVSIA grant] service failure: '.get_class($e)); grant_fail(503,'grant_service_unavailable'); }
