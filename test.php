<?php
function str_replace_first($from, $to, $content)
{
	$from = '/' . preg_quote($from, '/') . '/';
	return preg_replace($from, $to, $content, 1);
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
function XORCipher($data, $key)
{
	$dataLen = strlen($data);
	$keyLen = strlen($key);
	$output = $data;
	for ($i = 0; $i < $dataLen; ++$i) $output[$i] = $data[$i] ^ $key[$i % $keyLen];
	return $output;
}
$a = 'Lorem Ipsum chỉ đơn giản là một đoạn văn bản giả, được dùng vào việc trình bày và dàn trang phục vụ cho in ấn. Lorem Ipsum đã được sử dụng như một văn bản chuẩn cho ngành công nghiệp in ấn từ những năm 1500, khi một họa sĩ vô danh ghép nhiều đoạn văn bản với nhau để tạo thành một bản mẫu văn bản. Đoạn văn bản này không những đã tồn tại năm thế kỉ, mà khi được áp dụng vào tin học văn phòng, nội dung của nó vẫn không hề bị thay đổi. Nó đã được phổ biến trong những năm 1960 nhờ việc bán những bản giấy Letraset in những đoạn Lorem Ipsum, và gần đây hơn, được sử dụng trong các ứng dụng dàn trang, như Aldus PageMaker.';
echo 'Độ dài chuỗi gốc: ' . strlen($a) . '<br> Với chuỗi gốc: ' . $a . '<br>----------<br>';
$b = XORCipher($a, '.... --- .- .--. .... .- - -- .. -. .... -.-. ... -.-. .... .- -');
echo 'Độ dài chuỗi đã mã hoá: ' . strlen($b) . '<br> Với chuỗi đã mã hoá: ' . $b . '<br>----------<br>';
$c = XORCipher($b, '.... --- .- .--. .... .- - -- .. -. .... -.-. ... -.-. .... .- -');
echo 'Độ dài chuỗi đã giải mã: ' . strlen($c) . '<br> Với chuỗi đã giải mã: ' . $c . '<br>----------<br>';

// $d = 'OAIYQkMLFg4sS2NYC11fVlVENVA1BA9dXkVcTzQNMxkBHR1nWBc4WhUhVHReUhZ4FWcbF1VBV1NBaG9iETctc3FweGgUan8aWl4IAVNPCG8TO1V+cUdXbgcbMSccfkhiVHRxTzM8P3Nzf1pjB2IjLyRjH1hXRSVbD0ZCVVlX';
// $d = XORCipher(base64_decode(str_replace('_', '/', $d)), 'Pvl2019!@#');
// echo 'Độ dài chuỗi đã giải mã: ' . strlen($d) . '<br> Với chuỗi đã giải mã: ' . $d . '<br>----------<br>';

?>
<!-- <html>

<head>
	<title>reCAPTCHA demo: Explicit render after an onload callback</title>
	<script>
		var onSubmit = function(token) {
			console.log('success!');
		};

		var onloadCallback = function() {
			grecaptcha.render('submit', {
				'sitekey': 'your_site_key',
				'callback': onSubmit
			});
		};

		function test() {
			grecaptcha.ready(function() {
				grecaptcha.execute('6LcBObsUAAAAAMN7ZGemdWy6fCmLW1KRNr8NVRS1', {
					action: 'submit'
				}).then(function(token) {
					console.log(token);
				});
			});
		}
	</script>
</head>

<body>
	<form action="?" method="POST">
		<input id='submit' type="submit" value="Submit">
	</form>
	<script src="https://www.google.com/recaptcha/api.js?render=6LcBObsUAAAAAMN7ZGemdWy6fCmLW1KRNr8NVRS1"></script>
</body>

</html> -->