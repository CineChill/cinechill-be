<?php
function cors()
{
	// Allow from any origin
	if (isset($_SERVER['HTTP_ORIGIN'])) {
		// Decide if the origin in $_SERVER['HTTP_ORIGIN'] is one
		// you want to allow, and if so:
		header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
		header('Access-Control-Allow-Credentials: true');
		header('Access-Control-Max-Age: 86400');    // cache for 1 day
	}
	// Access-Control headers are received during OPTIONS requests
	if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
		if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD']))
			// may also be using PUT, PATCH, HEAD etc
			header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
		if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']))
			header("Access-Control-Allow-Headers: {$_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']}");
		// exit(0);
	}
	// echo "You have CORS!";
}
function str_replace_first($from, $to, $content)
{
	$from = '/' . preg_quote($from, '/') . '/';
	return preg_replace($from, $to, $content, 1);
}
function khong_dau($st)
{
	$vietChar 	= 'á|à|ả|ã|ạ|ă|ắ|ằ|ẳ|ẵ|ặ|â|ấ|ầ|ẩ|ẫ|ậ|é|è|ẻ|ẽ|ẹ|ê|ế|ề|ể|ễ|ệ|ó|ò|ỏ|õ|ọ|ơ|ớ|ờ|ở|ỡ|ợ|ô|ố|ồ|ổ|ỗ|ộ|ú|ù|ủ|ũ|ụ|ư|ứ|ừ|ử|ữ|ự|í|ì|ỉ|ĩ|ị|ý|ỳ|ỷ|ỹ|ỵ|đ|Á|À|Ả|Ã|Ạ|Ă|Ắ|Ằ|Ẳ|Ẵ|Ặ|Â|Ấ|Ầ|Ẩ|Ẫ|Ậ|É|È|Ẻ|Ẽ|Ẹ|Ê|Ế|Ề|Ể|Ễ|Ệ|Ó|Ò|Ỏ|Õ|Ọ|Ơ|Ớ|Ờ|Ở|Ỡ|Ợ|Ô|Ố|Ồ|Ổ|Ỗ|Ộ|Ú|Ù|Ủ|Ũ|Ụ|Ư|Ứ|Ừ|Ử|Ữ|Ự|Í|Ì|Ỉ|Ĩ|Ị|Ý|Ỳ|Ỷ|Ỹ|Ỵ|Đ';
	$engChar	= 'a|a|a|a|a|a|a|a|a|a|a|a|a|a|a|a|a|e|e|e|e|e|e|e|e|e|e|e|o|o|o|o|o|o|o|o|o|o|o|o|o|o|o|o|o|u|u|u|u|u|u|u|u|u|u|u|i|i|i|i|i|y|y|y|y|y|d|A|A|A|A|A|A|A|A|A|A|A|A|A|A|A|A|A|E|E|E|E|E|E|E|E|E|E|E|O|O|O|O|O|O|O|O|O|O|O|O|O|O|O|O|O|U|U|U|U|U|U|U|U|U|U|U|I|I|I|I|I|Y|Y|Y|Y|Y|D';
	$arrVietChar 	= explode("|", $vietChar);
	$arrEngChar		= explode("|", $engChar);
	$st = str_replace($arrVietChar, $arrEngChar, $st);
	$st = preg_replace("/[^0-9a-zA-Z- ]+/", '', $st);
	return $st;
}
function decode_id($id)
{
	$id = str_replace('/', '', $id);
	$id = str_replace_first('w', 5, $id);
	$id = str_replace_first('y', 4, $id);
	$id = str_replace_first('o', 3, $id);
	$id = str_replace_first('t', 2, $id);
	$id = str_replace_first('i', 1, $id);
	$id = hexdec($id);
	$id = $id - 123456;
	return strtolower($id);
}
function encode_id($id)
{
	$id = str_replace('/', '', $id);
	$id = dechex($id + 123456);
	$id = str_replace_first(1, 'i', $id);
	$id = str_replace_first(2, 't', $id);
	$id = str_replace_first(3, 'o', $id);
	$id = str_replace_first(4, 'y', $id);
	$id = str_replace_first(5, 'w', $id);
	return strtolower($id);
}
/**
 * Decrypt data from a CryptoJS json encoding string
 *
 * @param mixed $passphrase
 * @param mixed $jsonString
 * @return mixed
 */
function cryptoJsAesDecrypt($passphrase, $jsonString)
{
	$jsondata = json_decode($jsonString, true);
	$salt = hex2bin($jsondata["s"]);
	$ct = base64_decode($jsondata["ct"]);
	$iv  = hex2bin($jsondata["iv"]);
	$concatedPassphrase = $passphrase . $salt;
	$md5 = array();
	$md5[0] = md5($concatedPassphrase, true);
	$result = $md5[0];
	for ($i = 1; $i < 3; $i++) {
		$md5[$i] = md5($md5[$i - 1] . $concatedPassphrase, true);
		$result .= $md5[$i];
	}
	$key = substr($result, 0, 32);
	$data = openssl_decrypt($ct, 'aes-256-cbc', $key, true, $iv);
	return json_decode($data, true);
}
function cryptoJsAesEncrypt($passphrase, $value)
{
	$salt = openssl_random_pseudo_bytes(8);
	$salted = '';
	$dx = '';
	while (strlen($salted) < 48) {
		$dx = md5($dx . $passphrase . $salt, true);
		$salted .= $dx;
	}
	$key = substr($salted, 0, 32);
	$iv  = substr($salted, 32, 16);
	$encrypted_data = openssl_encrypt(json_encode($value), 'aes-256-cbc', $key, true, $iv);
	$data = array("ct" => base64_encode($encrypted_data), "iv" => bin2hex($iv), "s" => bin2hex($salt));
	return json_encode($data);
}
function openSslEncrypt($simple_string, $key)
{
	// Store the cipher method
	$ciphering = "AES-128-CTR";
	// Use OpenSSl Encryption method
	$iv_length = openssl_cipher_iv_length($ciphering);
	// Non-NULL Initialization Vector for encryption
	$encryption_iv = '12345678987654321';
	// Use openssl_encrypt() function to encrypt the data
	return openssl_encrypt($simple_string, $ciphering, $key, 0, $encryption_iv);
}
function openSslDecrypt($simple_string, $key)
{
	// Store the cipher method
	$ciphering = "AES-128-CTR";
	// Non-NULL Initialization Vector for decryption
	$decryption_iv = '12345678987654321';
	// Use openssl_decrypt() function to decrypt the data
	return openssl_decrypt($simple_string, $ciphering, $key, 0, $decryption_iv);
}
function XORCipher($data, $key)
{
	$dataLen = strlen($data);
	$keyLen = strlen($key);
	$output = $data;
	for ($i = 0; $i < $dataLen; ++$i) $output[$i] = $data[$i] ^ $key[$i % $keyLen];
	return $output;
}
function check_session($user_id, $token)
{
	try {
		$a = JWT::decode($token, SALT);
		// $a = json_decode($a, true);
		// return $a;
		if (time() < $a->exp && $a->user_id == $user_id) return array('error' => false, 'permission' => $a->permission, 'message' => 'Phiên hợp lệ!');
		else return array('error' => true, 'message' => 'Phiên không hợp lệ!');
	} catch (Exception $e) {
		return array('error' => true, 'message' => 'Phiên không hợp lệ!');
	}
}
function cURL($url, $arr = [])
{
	$curl = curl_init();
	// curl_setopt_array($curl, array(
	// 	CURLOPT_RETURNTRANSFER => 1,
	// 	CURLOPT_URL => $url,
	// 	CURLOPT_SSL_VERIFYPEER => false, //Bỏ kiểm SSL
	// 	CURLOPT_POST => 1,
	// 	CURLOPT_POSTFIELDS => http_build_query($arr)
	// ));
	curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($curl, CURLOPT_URL, $url);
	curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0);
	if (count($arr)) {
		curl_setopt($curl, CURLOPT_POST, 1);
		curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($arr));
	}
	$resp = curl_exec($curl);
	curl_close($curl);
	return $resp;
}
