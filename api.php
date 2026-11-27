<?php
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('X-Content-Type-Options: nosniff');
function out($ok,$msg,$code){http_response_code($code);echo json_encode(array('valid'=>$ok,'message'=>$msg));exit;}
$configFile=__DIR__.'/config.php';
if(!file_exists($configFile))out(false,'License server is not configured.',503);
$config=require $configFile;$db=$config['data_dir'].'/nexcora.sqlite';
if(!file_exists($config['data_dir'].'/installed.lock')||!file_exists($db))out(false,'License server is not ready.',503);
if($_SERVER['REQUEST_METHOD']!=='POST')out(false,'Request rejected.',405);
$type=strtolower($_SERVER['CONTENT_TYPE']??'');
if(strpos($type,'application/json')!==0)out(false,'Request rejected.',415);
$raw=file_get_contents('php://input');if($raw===false||strlen($raw)>2048)out(false,'Request rejected.',400);
$j=json_decode($raw,true);if(!is_array($j))out(false,'Request rejected.',400);
$key=strtoupper(trim((string)($j['license_key']??'')));
$device=trim((string)($j['device_id']??''));
if(!preg_match('/^NEXCORA-[A-F0-9]{6}-[A-F0-9]{6}-[A-F0-9]{6}$/',$key)||!preg_match('/^[A-Za-z0-9._:-]{8,128}$/',$device))out(false,'License verification failed.',403);
try {
 $pdo=new PDO('sqlite:'.$db);$pdo->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
 $stmt=$pdo->prepare('SELECT id,status,expires_at,device_hash FROM licenses WHERE key_hash=? LIMIT 1');
 $stmt->execute(array(hash('sha256',$key)));$row=$stmt->fetch(PDO::FETCH_ASSOC);
 if(!$row||$row['status']!=='active')out(false,'License verification failed.',403);
 if($row['expires_at']!==null&&(int)$row['expires_at']<time())out(false,'License has expired.',403);
 $dh=hash('sha256',$device);
 if($row['device_hash']!==null&&!hash_equals($row['device_hash'],$dh))out(false,'License is already registered to another device.',403);
 if($row['device_hash']===null){
   $upd=$pdo->prepare('UPDATE licenses SET device_hash=? WHERE id=? AND device_hash IS NULL');
   $upd->execute(array($dh,$row['id']));
   if($upd->rowCount()!==1)out(false,'Please try again.',409);
 }
 out(true,'License verified. Access granted.',200);
} catch(Exception $e){out(false,'Service temporarily unavailable.',503);}

