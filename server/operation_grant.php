<?php
require_once __DIR__ . '/config.php';
header('Content-Type: application/json');
function grant_fail(string $m, int $code = 403): void { http_response_code($code); echo json_encode(['status'=>'error','msg'=>$m]); exit; }
if (($_SERVER['REQUEST_METHOD'] ?? 'POST') !== 'POST') grant_fail('POST only',405);
$body=json_decode(file_get_contents('php://input'),true); if(!is_array($body)) grant_fail('Invalid JSON',400);
$license=trim((string)($body['license']??'')); $hwid=substr(preg_replace('/[^a-zA-Z0-9_\-:]/','',(string)($body['hwid']??'')),0,128);
$session=preg_replace('/[^a-f0-9]/','',strtolower((string)($body['session_token']??''))); $build=trim((string)($body['build_id']??''));
$cert=strtolower(trim((string)($body['cert_sha256']??''))); $manifest=strtolower(trim((string)($body['manifest_hash']??''))); $tool=strtolower(trim((string)($body['tool_hash']??'')));
$operation=trim((string)($body['operation_id']??''));
if($license===''||strlen($hwid)<16||strlen($session)!==64) grant_fail('Missing authorization fields',400);
if($build!=='ALVSIA-20261006-R5.3'||$cert!=='99b33815c88a17abbcfe22be15250363f6dfc79c11ffc980e71b62b74b1f295c') grant_fail('Unsupported client build');
if(!preg_match('/^[a-f0-9]{64}$/',$manifest)||!preg_match('/^[a-f0-9]{64}$/',$tool)) grant_fail('Invalid measurement',400);
if($operation!=='tool.session') grant_fail('Operation denied');
if(function_exists('alvsia_hwid_banned')&&alvsia_hwid_banned($hwid)) grant_fail('Device banned');
$row=session_validate($session,$hwid); if(!$row||(string)$row['license_code']!==$license) grant_fail('Session invalid');
try{$q=db()->prepare('SELECT status, expires_at FROM vp_license_keys WHERE id=? LIMIT 1');$kid=(int)$row['key_id'];$q->bind_param('i',$kid);$q->execute();$key=$q->get_result()->fetch_assoc();if(!$key||in_array(($key['status']??''),['blocked','banned'],true))grant_fail('License denied');if(!empty($key['expires_at'])&&strtotime($key['expires_at'])<time())grant_fail('License expired');}catch(Throwable $e){grant_fail('License check failed',500);}
$privateFile=defined('ALVSIA_OPERATION_GRANT_PRIVATE_KEY_FILE')?ALVSIA_OPERATION_GRANT_PRIVATE_KEY_FILE:''; if($privateFile===''||!is_file($privateFile)||!is_readable($privateFile))grant_fail('Grant signer unavailable',503);
$private=@file_get_contents($privateFile);if($private===false||$private==='')grant_fail('Grant signer unavailable',503);$now=time();
$grant=['grant_id'=>bin2hex(random_bytes(16)),'nonce'=>bin2hex(random_bytes(16)),'build_id'=>$build,'manifest_hash'=>$manifest,'tool_hash'=>$tool,'device_id'=>$hwid,'session_id'=>$session,'operation_id'=>$operation,'issued_at'=>gmdate('Y-m-d H:i:s',$now),'expires_at'=>gmdate('Y-m-d H:i:s',$now+60)];
$lines=['ALVSIA-R4','kind=operation_grant'];foreach(['grant_id','nonce','build_id','manifest_hash','tool_hash','device_id','session_id','operation_id','issued_at','expires_at'] as $k)$lines[]=$k.'='.$grant[$k];$sig='';
if(!openssl_sign(implode("
",$lines),$sig,$private,OPENSSL_ALGO_SHA256))grant_fail('Grant signing failed',500);
$grant['signature']=['alg'=>'RS256','kid'=>'alvsia-op-20261006','value'=>rtrim(strtr(base64_encode($sig),'+/','-_'),'=')];
try{log_activity(null,'operation_grant','license='.substr($license,0,40).' hwid='.substr($hwid,0,32));}catch(Throwable $e){}
echo json_encode(['status'=>'ok','grant'=>$grant,'expires_at'=>$now+60]);
