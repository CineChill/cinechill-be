<?php
class JWT
{
	/**
	 * Decodes a JWT string into a PHP object.
	 *
	 * @param string      $jwt    The JWT
	 * @param string|null $key    The secret key
	 * @param bool        $verify Don't skip verification process 
	 *
	 * @return object      The JWT's payload as a PHP object
	 * @throws UnexpectedValueException Provided JWT was invalid
	 * @throws DomainException          Algorithm was not provided
	 * 
	 * @uses jsonDecode
	 * @uses urlsafeB64Decode
	 */
	public static function decode($jwt, $key = null, $verify = true)
	{
		$tks = explode('.', $jwt);
		if (count($tks) != 3) {
			throw new UnexpectedValueException('Wrong number of segments');
		}
		list($headb64, $bodyb64, $cryptob64) = $tks;
		if (null === ($header = JWT::jsonDecode(JWT::urlsafeB64Decode($headb64)))) {
			throw new UnexpectedValueException('Invalid segment encoding');
		}
		if (null === $payload = JWT::jsonDecode(JWT::urlsafeB64Decode($bodyb64))) {
			throw new UnexpectedValueException('Invalid segment encoding');
		}
		$sig = JWT::urlsafeB64Decode($cryptob64);
		if ($verify) {
			if (empty($header->alg)) {
				throw new DomainException('Empty algorithm');
			}
			if ($sig != JWT::sign("$headb64.$bodyb64", $key, $header->alg)) {
				throw new UnexpectedValueException('Signature verification failed');
			}
		}
		return $payload;
	}
	/**
	 * Converts and signs a PHP object or array into a JWT string.
	 *
	 * @param object|array $payload PHP object or array
	 * @param string       $key     The secret key
	 * @param string       $algo    The signing algorithm. Supported
	 *                              algorithms are 'HS256', 'HS384' and 'HS512'
	 *
	 * @return string      A signed JWT
	 * @uses jsonEncode
	 * @uses urlsafeB64Encode
	 */
	public static function encode($payload, $key, $algo = 'HS256')
	{
		$header = array('typ' => 'JWT', 'alg' => $algo);

		$segments = array();
		$segments[] = JWT::urlsafeB64Encode(JWT::jsonEncode($header));
		$segments[] = JWT::urlsafeB64Encode(JWT::jsonEncode($payload));
		$signing_input = implode('.', $segments);

		$signature = JWT::sign($signing_input, $key, $algo);
		$segments[] = JWT::urlsafeB64Encode($signature);

		return implode('.', $segments);
	}
	/**
	 * Sign a string with a given key and algorithm.
	 *
	 * @param string $msg    The message to sign
	 * @param string $key    The secret key
	 * @param string $method The signing algorithm. Supported
	 *                       algorithms are 'HS256', 'HS384' and 'HS512'
	 *
	 * @return string          An encrypted message
	 * @throws DomainException Unsupported algorithm was specified
	 */
	public static function sign($msg, $key, $method = 'HS256')
	{
		$methods = array(
			'HS256' => 'sha256',
			'HS384' => 'sha384',
			'HS512' => 'sha512',
		);
		if (empty($methods[$method])) {
			throw new DomainException('Algorithm not supported');
		}
		return hash_hmac($methods[$method], $msg, $key, true);
	}
	/**
	 * Decode a JSON string into a PHP object.
	 *
	 * @param string $input JSON string
	 *
	 * @return object          Object representation of JSON string
	 * @throws DomainException Provided string was invalid JSON
	 */
	public static function jsonDecode($input)
	{
		$obj = json_decode($input);
		if (function_exists('json_last_error') && $errno = json_last_error()) {
			JWT::_handleJsonError($errno);
		} else if ($obj === null && $input !== 'null') {
			throw new DomainException('Null result with non-null input');
		}
		return $obj;
	}
	/**
	 * Encode a PHP object into a JSON string.
	 *
	 * @param object|array $input A PHP object or array
	 *
	 * @return string          JSON representation of the PHP object or array
	 * @throws DomainException Provided object could not be encoded to valid JSON
	 */
	public static function jsonEncode($input)
	{
		$json = json_encode($input);
		if (function_exists('json_last_error') && $errno = json_last_error()) {
			JWT::_handleJsonError($errno);
		} else if ($json === 'null' && $input !== null) {
			throw new DomainException('Null result with non-null input');
		}
		return $json;
	}
	/**
	 * Decode a string with URL-safe Base64.
	 *
	 * @param string $input A Base64 encoded string
	 *
	 * @return string A decoded string
	 */
	public static function urlsafeB64Decode($input)
	{
		$remainder = strlen($input) % 4;
		if ($remainder) {
			$padlen = 4 - $remainder;
			$input .= str_repeat('=', $padlen);
		}
		return base64_decode(strtr($input, '-_', '+/'));
	}
	/**
	 * Encode a string with URL-safe Base64.
	 *
	 * @param string $input The string you want encoded
	 *
	 * @return string The base64 encode of what you passed in
	 */
	public static function urlsafeB64Encode($input)
	{
		return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
	}
	/**
	 * Helper method to create a JSON error.
	 *
	 * @param int $errno An error number from json_last_error()
	 *
	 * @return void
	 */
	private static function _handleJsonError($errno)
	{
		$messages = array(
			JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
			JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
			JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON'
		);
		throw new DomainException(
			isset($messages[$errno])
				? $messages[$errno]
				: 'Unknown JSON error: ' . $errno
		);
	}
}
class DB
{
	protected $conn;
	public function __construct($conn)
	{
		$this->conn = $conn;
	}
}
class API extends DB
{
	public function validUser($username)
	{
		$username = mysqli_escape_string($this->conn, $username);
		$a = mysqli_query($this->conn, "SELECT * FROM users WHERE (username = '$username' OR email = '$username')");
		if (mysqli_num_rows($a))
			while ($row = mysqli_fetch_assoc($a))
				$b = $row;
		else $b = false;
		mysqli_free_result($a);
		return $b;
	}
	public function encryptedPassword($password)
	{
		// return sha1(SALT . '|' . $password);
		return md5($password);
	}
	public function login($username, $password)
	{
		$username = mysqli_escape_string($this->conn, $username);
		$password = $this->encryptedPassword($password);
		$a = mysqli_query($this->conn, "SELECT * FROM users WHERE (username = '$username' OR email = '$username') AND `password`='$password'");
		if (mysqli_num_rows($a)) {
			// while ($row = mysqli_fetch_assoc($a))
			// 	$b = $row;
			$c = mysqli_fetch_assoc($a);
			unset($c['password']);
			$c['error'] = false;
			// var a = result[0]; delete a.password;
			// 		a.error = false;
			// 		a.token = jwt.sign({ user_id: a.user_id, exp: moment().unix() + time_vaild }, jwt_password);
			$c['token'] =  JWT::encode(['user_id' => $c['user_id'], 'permission' => $c['permission'], 'exp' => time() + 60 * 60 * 24 * 7], SALT);
			$b = $c;
		} else $b = ['error' => true, 'message' => 'Tài khoản đăng nhập không chính xác!'];
		return $b;
	}
	public function register($fullname, $username,  $email, $password, $rc_token)
	{
		$fullname = mysqli_escape_string($this->conn, $fullname);
		$username = mysqli_escape_string($this->conn, $username);
		$email = mysqli_escape_string($this->conn, $email);
		if (!preg_match('/^[A-Za-z][A-Za-z0-9]{5,14}$/', $username)) return ['error' => true, 'message' => 'Tên đăng nhập phải bắt đầu là chữ, có thể chứa số, giới hạn kí tự từ 6 đến 15!'];
		if (!filter_var($email, FILTER_VALIDATE_EMAIL)) return ['error' => true, 'message' => 'Email không hợp lệ!'];
		if (strlen($password) < 6) return ['error' => true, 'message' => 'Mật khẩu phải trên 6 kí tự!'];
		$a = $this->validUser($username);
		if ($a == false) {
			$captcha = json_decode(cURL('https://www.google.com/recaptcha/api/siteverify', ['secret' => RECAPTCHA_SECRET, 'response' => $rc_token]), true);
			if ($captcha['success'] == true && $captcha['action'] == 'signUp') {
				$password = $this->encryptedPassword($password);
				$time = time();
				$b = mysqli_query($this->conn, "INSERT INTO users (`fullname`, `username`, `email`, `password`, `date_joined`) VALUES ('$fullname', '$username', '$email', '$password', '$time')");
				if ($b) {
					$last_id = mysqli_insert_id($this->conn);
					return [
						'user_id' => $last_id,
						'fullname' => $fullname,
						'username' => $username,
						'email' => $email,
						'date_joined' => $time,
						'user_points' => 0,
						'permission' => 0,
						'token' => JWT::encode(['user_id' => $last_id, 'permission' => '0', 'exp' => time() + 60 * 60 * 24 * 7], SALT)
					];
				} else return ['error' => true, 'message' => 'Có lỗi xảy ra!'];
			} else return ['error' => true, 'message' => 'Lỗi xác thực bảo mật, vui lòng thử lại!'];
		} else return ['error' => true, 'message' => 'Tên đăng nhập hoặc email đã được sử dụng!'];
	}
	public function getUser($username)
	{
		return $this->validUser($username);
	}
	public function getUserByUserId($user_id)
	{
		$user_id = mysqli_escape_string($this->conn, $user_id);
		$a = mysqli_query($this->conn, "SELECT * FROM users WHERE user_id = '$user_id'");
		if (mysqli_num_rows($a))
			while ($row = mysqli_fetch_assoc($a)) {
				$b = $row;
				unset($b['password']);
				$b['error'] = false;
			}
		else $b = ['error' => true, 'message' => 'Thông tin người dùng không có!'];
		mysqli_free_result($a);
		return $b;
	}
	public function postPoints($user_id, $rc_token)
	{
		$captcha = json_decode(cURL('https://www.google.com/recaptcha/api/siteverify', ['secret' => RECAPTCHA_SECRET, 'response' => $rc_token]), true);
		if ($captcha['success'] == true && $captcha['action'] == 'points') {
			$user_id = mysqli_escape_string($this->conn, $user_id);
			mysqli_query($this->conn, "UPDATE `users` SET user_points = user_points + 1 WHERE user_id = $user_id");
			return ['error' => false, 'message' => true];
		} else return ['error' => true, 'message' => 'Lỗi xác thực bảo mật, vui lòng thử lại!'];
	}

	public function getFilms($country_id = '', $category_id = '', $year = '', $search = '', $q = '', $page = 1)
	{
		$country_id = mysqli_escape_string($this->conn, $country_id);
		$category_id = mysqli_escape_string($this->conn, $category_id);
		$year = mysqli_escape_string($this->conn, $year);
		$search = mysqli_escape_string($this->conn, $search);
		$q_ = 'WHERE film_hidden = 0';

		$q = explode(',', $q);
		// var_dump($q);
		if (in_array('film_theaters', $q)) $q_ .= ' AND film_theaters = 1';
		if (in_array('film_netflix', $q)) $q_ .= ' AND film_netflix = 1';

		if ($year != '') $q_ .= " AND film_release_year	= $year";

		if ($country_id != '') {
			$country = $this->getCountryByNameKd($country_id);
			if (count($country) > 0) {
				$country_id = $country[0]['country_id'];
				$country_name = $country[0]['country_name'];
				$q_ .= " AND find_in_set('$country_id', film_country)";
			} else return [];
		}
		if ($category_id != '') {
			$category = $this->getCategoryByNameKd($category_id);
			if (count($category) > 0) {
				$category_id = $category[0]['category_id'];
				$category_name = $category[0]['category_name'];
				$q_ .= " AND find_in_set('$category_id', film_categories)";
			} else return [];
		}
		if ($search != '') $q_ = "WHERE film_hidden = 0 AND (film_name LIKE '%$search%' OR film_name_en LIKE '%$search%')";

		$limit = DATA_PER_PAGE;
		$total = mysqli_query($this->conn, "SELECT COUNT(*) AS total_films FROM film $q_");
		$total = mysqli_fetch_assoc($total)['total_films'];
		if ($page < 1 || $page == '' || !is_numeric($page)) $page = 1;
		$limit = (($page - 1) * DATA_PER_PAGE) . ',' . DATA_PER_PAGE;
		$end_page =  ceil($total / DATA_PER_PAGE);
		$page_item = [];
		for ($i = 1; $i <= $end_page; $i++) if (abs($page - $i) <= 3 || $i == 1 || $i == $end_page) $page_item[] = $i;

		$a = mysqli_query($this->conn, "SELECT film_id, film_name, film_name_en, film_poster, film_duration, film_release_year, film_categories, film_rating, film_views, film_hidden FROM film $q_ ORDER BY film_id DESC LIMIT $limit");
		$b = [];
		if (mysqli_num_rows($a)) {
			while ($row = mysqli_fetch_assoc($a)) {
				$row['film_id'] = encode_id($row['film_id']);
				$row['film_name_kd'] = str_replace(' ', '-', strtolower(khong_dau($row['film_name'])));
				$film_categories = $this->getCategoryByIds($row['film_categories']);
				// var_dump($film_categories);
				$row['film_categories'] = implode(',', array_map(function ($entry) {
					return ($entry['category_name']);
				}, $film_categories));
				$row['film_categories_kd'] = implode(',', array_map(function ($entry) {
					return ($entry['category_name_kd']);
				}, $film_categories));
				$b[] = $row;
			}
			if ($country_id > 0) $b[0]['search_country'] = $country_name;
			if ($category_id > 0) $b[0]['search_category'] = $category_name;
			$b[0]['paging'] = $page_item;
		}
		return $b;
	}
	public function getFilm($film_id)
	{
		$film_id = mysqli_escape_string($this->conn, $film_id);
		if (!is_numeric($film_id)) $film_id = decode_id($film_id);
		$a = mysqli_query($this->conn, "SELECT * FROM film WHERE film_id = $film_id AND film_hidden = 0");
		if (mysqli_num_rows($a)) {
			$b = [mysqli_fetch_assoc($a)];
			$film_id = $b[0]['film_id'];
			$b[0]['film_id'] = encode_id($b[0]['film_id']);
			$b[0]['film_name_kd'] = str_replace(' ', '-', strtolower(khong_dau($b[0]['film_name'])));
			$film_country = $this->getCountryByIds($b[0]['film_country']);
			$film_categories = $this->getCategoryByIds($b[0]['film_categories']);
			$b[0]['film_country_id'] = $b[0]['film_country'];
			$b[0]['film_categories_id'] = $b[0]['film_categories'];
			$b[0]['film_country'] = implode(',', array_map(function ($entry) {
				return ($entry['country_name']);
			}, $film_country));
			$b[0]['film_categories'] = implode(',', array_map(function ($entry) {
				return ($entry['category_name']);
			}, $film_categories));
			$b[0]['film_country_kd'] = implode(',', array_map(function ($entry) {
				return ($entry['country_name_kd']);
			}, $film_country));
			$b[0]['film_categories_kd'] = implode(',', array_map(function ($entry) {
				return ($entry['category_name_kd']);
			}, $film_categories));
			$ep_first = $this->getEpFirst($film_id);
			if (count($ep_first) > 0) unset($ep_first[0]['film_id']);
			$b[0]['film_ep'] = $ep_first;
		} else $b = [];
		return $b;
	}
	public function getFilmsSitemap($limit = 100)
	{
		$a = mysqli_query($this->conn, "SELECT film_id, film_name FROM film WHERE film_hidden = 0 ORDER BY film_id DESC LIMIT $limit");
		$b = [];
		if (mysqli_num_rows($a)) {
			while ($row = mysqli_fetch_assoc($a)) {
				$row['film_id'] = encode_id($row['film_id']);
				$row['film_name_kd'] = str_replace(' ', '-', strtolower(khong_dau($row['film_name'])));
				$b[] = $row;
			}
		}
		return $b;
	}
	public function postFilm($film_name, $film_name_en, $film_director, $film_actors, $film_poster, $film_trailer, $film_content, $film_summary, $film_duration, $film_series, $film_ep_num, $film_theaters, $film_netflix, $film_release_year, $film_country, $film_categories)
	{
		$film_name = mysqli_escape_string($this->conn, $film_name);
		$film_name_en = mysqli_escape_string($this->conn, $film_name_en ?? '');
		$film_director = mysqli_escape_string($this->conn, $film_director ?? '');
		$film_actors = mysqli_escape_string($this->conn, $film_actors ?? '');
		$film_poster = mysqli_escape_string($this->conn, $film_poster ?? '');
		$film_trailer = mysqli_escape_string($this->conn, $film_trailer ?? '');
		$film_content = mysqli_escape_string($this->conn, $film_content ?? '');
		$film_summary = mysqli_escape_string($this->conn, $film_summary ?? '');
		$film_duration = mysqli_escape_string($this->conn, $film_duration ?? 0);
		$film_series = mysqli_escape_string($this->conn, $film_series ?? 0);
		$film_ep_num = mysqli_escape_string($this->conn, $film_ep_num ?? 0);
		$film_theaters = mysqli_escape_string($this->conn, $film_theaters ?? 0);
		$film_netflix = mysqli_escape_string($this->conn, $film_netflix ?? 0);
		$film_release_year = mysqli_escape_string($this->conn, $film_release_year ?? 0);
		$film_country = mysqli_escape_string($this->conn, $film_country ?? '');
		$film_categories = mysqli_escape_string($this->conn, $film_categories ?? '');
		$film_datetime = time();
		$a = "INSERT INTO `film` (`film_name`, `film_name_en`, `film_director`, `film_actors`, `film_poster`, `film_trailer`, `film_content`, `film_summary`, `film_duration`, `film_series`, `film_ep_num`, `film_theaters`, `film_netflix`, `film_release_year`, `film_country`, `film_categories`, `film_rating`, `film_datetime`)
							VALUES ('$film_name', '$film_name_en', '$film_director', '$film_actors', '$film_poster', '$film_trailer', '$film_content', '$film_summary', '$film_duration', '$film_series', '$film_ep_num', '$film_theaters', '$film_netflix', '$film_release_year', '$film_country', '$film_categories', '', '$film_datetime')";
		// var_dump($a);
		if (mysqli_query($this->conn, $a))
			return array('error' => false, 'film_id' => mysqli_insert_id($this->conn), 'message' => 'Thêm phim mới thành công!');
		else array('error' => true, 'message' => 'Có lỗi xảy ra!');
	}
	public function updateFilm($film_id, $film_name, $film_name_en, $film_director, $film_actors, $film_poster, $film_trailer, $film_content, $film_summary, $film_duration, $film_series, $film_ep_num, $film_theaters, $film_netflix, $film_release_year, $film_country, $film_categories)
	{
		$film_id = mysqli_escape_string($this->conn, $film_id);
		if (!is_numeric($film_id)) $film_id = decode_id($film_id);
		$film_name = mysqli_escape_string($this->conn, $film_name);
		$film_name_en = mysqli_escape_string($this->conn, $film_name_en ?? '');
		$film_director = mysqli_escape_string($this->conn, $film_director ?? '');
		$film_actors = mysqli_escape_string($this->conn, $film_actors ?? '');
		$film_poster = mysqli_escape_string($this->conn, $film_poster ?? '');
		$film_trailer = mysqli_escape_string($this->conn, $film_trailer ?? '');
		$film_content = mysqli_escape_string($this->conn, $film_content ?? '');
		$film_summary = mysqli_escape_string($this->conn, $film_summary ?? '');
		$film_duration = mysqli_escape_string($this->conn, $film_duration ?? 0);
		$film_series = mysqli_escape_string($this->conn, $film_series ?? 0);
		$film_ep_num = mysqli_escape_string($this->conn, $film_ep_num ?? 0);
		$film_theaters = mysqli_escape_string($this->conn, $film_theaters ?? 0);
		$film_netflix = mysqli_escape_string($this->conn, $film_netflix ?? 0);
		$film_release_year = mysqli_escape_string($this->conn, $film_release_year ?? 0);
		$film_country = mysqli_escape_string($this->conn, $film_country ?? '');
		$film_categories = mysqli_escape_string($this->conn, $film_categories ?? '');
		$a = "UPDATE `film` SET `film_name` = '$film_name', `film_name_en` = '$film_name_en', `film_director` = '$film_director', `film_actors` = '$film_actors', `film_poster` = '$film_poster', `film_trailer` = '$film_trailer', `film_content` = '$film_content', `film_summary` = '$film_summary',
								`film_duration` = '$film_duration', `film_series` = '$film_series', `film_ep_num` = '$film_ep_num', `film_theaters` = '$film_theaters', `film_netflix` = '$film_netflix', `film_release_year` = '$film_release_year', `film_country` = '$film_country', `film_categories` = '$film_categories' WHERE film_id = $film_id";
		if (mysqli_query($this->conn, $a))
			return array('error' => false, 'message' => 'Cập nhật phim thành công!');
		else array('error' => true, 'message' => 'Có lỗi xảy ra!');
	}
	public function getEpFirst($film_id)
	{
		$film_id = mysqli_escape_string($this->conn, $film_id);
		if (!is_numeric($film_id)) $film_id = decode_id($film_id);
		$a = mysqli_query($this->conn, "SELECT * FROM `ep` LEFT JOIN `server` USING(server_id) WHERE film_id = $film_id ORDER BY ep_id ASC LIMIT 1");
		if (mysqli_num_rows($a)) {
			$b = [mysqli_fetch_assoc($a)];
			$b[0]['ep_id'] = encode_id($b[0]['ep_id']);
		} else $b = [];
		return $b;
	}
	public function getEpByFilmId($film_id, $server_id = 0)
	{
		$film_id = mysqli_escape_string($this->conn, $film_id);
		$server_id = mysqli_escape_string($this->conn, $server_id);
		if (!is_numeric($film_id)) $film_id = decode_id($film_id);
		$q_sv = '';
		if ($server_id > 0 && is_numeric($server_id)) $q_sv = "AND server_id = $server_id";
		$a = mysqli_query($this->conn, "SELECT * FROM `ep` LEFT JOIN `server` USING(server_id) WHERE film_id = $film_id $q_sv");
		$b = [];
		if (mysqli_num_rows($a))
			while ($row = mysqli_fetch_assoc($a)) {
				if ($row['server_id'] == 1) $row['ep_url'] =  '/hls/' . $row['ep_id'];
				$b[] = $row;
			}
		$arr = array();
		foreach ($b as $key => $item) {
			unset($item['film_id']);
			$item['ep_id'] = encode_id($item['ep_id']);
			$arr['server_' . $item['server_id']][] = $item;
		}
		$b = $arr;
		return $b;
	}
	public function getEpByEpId($ep_id)
	{
		$ep_id = mysqli_escape_string($this->conn, $ep_id);
		if (!is_numeric($ep_id)) $ep_id = decode_id($ep_id);
		$a = mysqli_query($this->conn, "SELECT * FROM `ep` LEFT JOIN `server` USING(server_id) WHERE ep_id = $ep_id");
		if (mysqli_num_rows($a)) {
			$b = [mysqli_fetch_assoc($a)];
			$b[0]['film_id'] = encode_id($b[0]['film_id']);
			$b[0]['ep_id'] = encode_id($b[0]['ep_id']);
		} else $b = [];
		return $b;
	}
	public function postEp($film_id, $ep_name, $ep_url)
	{
		$film_id = mysqli_escape_string($this->conn, $film_id);
		$ep_name = mysqli_escape_string($this->conn, $ep_name);
		$ep_url = mysqli_escape_string($this->conn, $ep_url);
		if (!is_numeric($film_id)) $film_id = decode_id($film_id);
		$film = $this->getFilm($film_id);
		$servers = $this->getServers();
		$server_id = 0;
		foreach ($servers as $k => $v) if (strpos($ep_url, $v['server_identification']) !== false) $server_id = $v['server_id'];
		if (count($film) > 0 && (int)$server_id > 0) {
			$ep = $this->getEpByFilmId($film_id, $server_id);
			if (($film[0]['film_series'] + 0) == 0 && count($ep) > 0) {
				$ep_id = $ep['server_' . $server_id][0]['ep_id'];
				if (!is_numeric($ep_id)) $ep_id = decode_id($ep_id);
				// if (mysqli_query($this->conn, "UPDATE `ep` SET ep_name = '$ep_name', ep_url = '$ep_url' WHERE ep_id = $ep_id"))
				// 	return array('error' => false, 'message' => 'Cập nhật thành công!');
				// else return array('error' => true, 'message' => 'Có lỗi xảy ra!');
				return $this->updateEpByEpId($ep_id, $ep_name, $ep_url);
			} else {
				if (mysqli_query($this->conn, "INSERT INTO `ep` (`film_id`, `ep_name`, `ep_url`, `server_id`) VALUES ('$film_id', '$ep_name', '$ep_url', '$server_id')"))
					return array('error' => false, 'ep_id' => mysqli_insert_id($this->conn), 'message' => 'Thêm tập phim mới thành công!');
				else return array('error' => true, 'message' => 'Có lỗi xảy ra!');
			}
		} else return array('error' => true, 'message' => 'ID phim không tồn tại hoặc liên kết chưa được nhận diện!');
	}
	public function updateEpByEpId($ep_id, $ep_name, $ep_url)
	{
		$ep_id = mysqli_escape_string($this->conn, $ep_id);
		$ep_name = mysqli_escape_string($this->conn, $ep_name);
		$ep_url = mysqli_escape_string($this->conn, $ep_url);
		if (!is_numeric($ep_id)) $ep_id = decode_id($ep_id);
		$ep = $this->getEpByEpId($ep_id);
		$servers = $this->getServers();
		$server_id = 0;
		// foreach ($servers as $k => $v) if (strpos($ep_url, $v['server_identification']) !== false) $server_id = $v['server_id'];
		foreach ($servers as $k => $v) if (preg_match('/(' . str_replace('.', '\.', $v['server_identification']) . ')/gi', $ep_url)) $server_id = $v['server_id'];
		if (count($ep) > 0 && (int)$server_id > 0)
			if (mysqli_query($this->conn, "UPDATE `ep` SET ep_name = '$ep_name', ep_url = '$ep_url', server_id = $server_id WHERE ep_id = $ep_id"))
				return array('error' => false, 'message' => 'Cập nhật thành công!');
			else array('error' => true, 'message' => 'Có lỗi xảy ra!');
		else array('error' => true, 'message' => 'ID episode không tồn tại hoặc liên kết chưa được nhận diện!');
	}
	public function getESV($ep_id, $type = '')
	{
		$ep_id = mysqli_escape_string($this->conn, $ep_id);
		$type = mysqli_escape_string($this->conn, $type);
		if (!is_numeric($ep_id)) $ep_id = decode_id($ep_id);
		$a = mysqli_query($this->conn, "SELECT * FROM `ep_server_vip` WHERE `ep_id` = $ep_id");
		if (mysqli_num_rows($a)) {
			$b = mysqli_fetch_assoc($a);
			// $b[0]['ep_id'] = encode_id($b[0]['ep_id']);
			if ($type == 'index.m3u8') {
				$b = $b['esv_index_edit'];
				foreach (preg_split("/((\r?\n)|(\r\n?))/", $b) as $line) {
					if (strpos($line, 'http') !== false) $b = str_replace($line, 'https://cdn-c1.cinechill.xyz/proxy/' . str_replace(['+', '/'], ['-', '_'], base64_encode(XORCipher($line, SALT))), $b);
				}
			} else if (strpos($type, 'subtitle_') !== false) {
				$lang = explode('_', str_replace('.vtt', '', $type))[1];
				$esv_subtitles = json_decode($b['esv_subtitles'], true);
				// var_dump($b['esv_subtitles'], $esv_subtitles);
				if ($esv_subtitles != null && $esv_subtitles[$lang]) return cURL($esv_subtitles[$lang]);
				else return 'WEBVTT';
			} else
				$b = array([
					'esv_thumbnails' => '/hls/' . encode_id($b['ep_id']) . '/thumbnails.vtt',
					'esv_subtitles' => '/hls/' . encode_id($b['ep_id'])  . '/subtitles.vtt',
					'esv_index' => cryptoJsAesEncrypt('3f5962638b7179a0fda7c48ee7aed718', $b['esv_index_edit']) //'/hls/' . $b['ep_id'] . '/index.m3u8'
				]);
		} else $b = '[]';
		return $b;
	}
	public function postView($film_id)
	{
		$film_id = mysqli_escape_string($this->conn, $film_id);
		if (!is_numeric($film_id)) $film_id = decode_id($film_id);
		$tv_date = time();
		mysqli_query($this->conn, "UPDATE `film` SET film_views = film_views + 1 WHERE film_id = $film_id");
		mysqli_query($this->conn, "INSERT INTO `top_views` (`film_id`, `tv_date`) VALUES ($film_id, '$tv_date')");
	}
	public function deleteEp($ep_id)
	{
		if (!is_numeric($ep_id)) $ep_id = decode_id($ep_id);
		$a = mysqli_query($this->conn, "DELETE FROM `ep` WHERE ep_id = $ep_id");
		if ($a)
			return ['error' => false, 'message' => 'Xoá tập phim thành công!'];
		else return ['error' => true, 'Có lỗi xảy ra!'];
	}
	public function getYears()
	{
		$a = mysqli_query($this->conn, "SELECT DISTINCT film_release_year FROM `film` ORDER BY film_release_year DESC");
		$b = [];
		if (mysqli_num_rows($a))
			while ($row = mysqli_fetch_assoc($a))
				$b[] = $row;
		return $b;
	}
	public function getServers()
	{
		$a = mysqli_query($this->conn, "SELECT * FROM `server`");
		$b = [];
		if (mysqli_num_rows($a))
			while ($row = mysqli_fetch_assoc($a))
				$b[] = $row;
		return $b;
	}
	public function getCountries()
	{
		$a = mysqli_query($this->conn, "SELECT * FROM `country`");
		$b = [];
		if (mysqli_num_rows($a))
			while ($row = mysqli_fetch_assoc($a))
				$b[] = $row;
		return $b;
	}
	public function getCountryByIds($ids)
	{
		if ($ids != '') {
			$ids = mysqli_escape_string($this->conn, $ids);
			$a = mysqli_query($this->conn, "SELECT * FROM country WHERE country_id IN($ids)");
			$b = [];
			if (mysqli_num_rows($a))
				while ($row = mysqli_fetch_assoc($a))
					$b[] = $row;
		} else $b = [];
		return $b;
	}
	public function getCountryByNameKd($country_name_kd)
	{
		$country_name_kd = mysqli_escape_string($this->conn, $country_name_kd);
		$a = mysqli_query($this->conn, "SELECT * FROM `country` WHERE country_name_kd = '$country_name_kd'");
		if (mysqli_num_rows($a))
			$b = [mysqli_fetch_assoc($a)];
		else $b = [];
		return $b;
	}

	public function getCategories()
	{
		$a = mysqli_query($this->conn, "SELECT * FROM `category`");
		$b = [];
		if (mysqli_num_rows($a))
			while ($row = mysqli_fetch_assoc($a))
				$b[] = $row;
		return $b;
	}
	public function getCategoryByIds($ids)
	{
		if ($ids != '') {
			$ids = mysqli_escape_string($this->conn, $ids);
			$a = mysqli_query($this->conn, "SELECT * FROM category WHERE category_id IN($ids)");
			$b = [];
			if (mysqli_num_rows($a))
				while ($row = mysqli_fetch_assoc($a))
					$b[] = $row;
		} else $b = [];
		return $b;
	}
	public function getCategoryByNameKd($category_name_kd)
	{
		$category_name_kd = mysqli_escape_string($this->conn, $category_name_kd);
		$a = mysqli_query($this->conn, "SELECT * FROM `category` WHERE category_name_kd = '$category_name_kd'");
		if (mysqli_num_rows($a))
			$b = [mysqli_fetch_assoc($a)];
		else $b = [];
		return $b;
	}
	public function topViews($limit = 10)
	{
		$a = mysqli_query($this->conn, "SELECT film_id, COUNT(film_id) AS views FROM top_views WHERE tv_date >= UNIX_TIMESTAMP(DATE_SUB(CURDATE(), INTERVAL 1 DAY)) GROUP BY film_id ORDER BY views DESC LIMIT $limit");
		$b = [];
		if (mysqli_num_rows($a))
			while ($row = mysqli_fetch_assoc($a)) {
				$c = $this->getFilm($row['film_id']);
				if (count($c))
					$b[] = $c[0];
				// $b[] = $row;
			}
		return $b;
	}
	public function statistics()
	{
		$a = mysqli_query($this->conn, "SELECT (SELECT COUNT(film_id) FROM film) AS total_films, (SELECT COUNT(country_id) FROM country) AS total_countries, (SELECT COUNT(category_id) FROM category) AS total_categories, (SELECT COUNT(user_id) FROM users) AS total_users;");
		$b = mysqli_query($this->conn, "SELECT C.country_id, C.country_name, C.country_name_kd, CASE WHEN SUM(F.film_id) IS NULL THEN 0 ELSE COUNT(C.country_id) END AS country_total_films FROM country C LEFT OUTER JOIN film F ON find_in_set(C.country_id, F.film_country) GROUP BY C.country_id");
		$c = mysqli_query($this->conn, "SELECT C.category_id, C.category_name, C.category_name_kd, CASE WHEN SUM(F.film_id) IS NULL THEN 0 ELSE COUNT(C.category_id) END AS category_total_films FROM category C LEFT OUTER JOIN film F ON find_in_set(C.category_id, F.film_categories) GROUP BY C.category_id");
		$a_ = [];
		$b_ = [];
		$c_ = [];
		while ($row = mysqli_fetch_assoc($a))
			$a_ = $row;
		while ($row = mysqli_fetch_assoc($b))
			$b_[] = $row;
		while ($row = mysqli_fetch_assoc($c))
			$c_[] = $row;
		return array_merge($a_, ['countries' => $b_, 'categories' => $c_]);
	}
	public function getReports()
	{
		$a = mysqli_query($this->conn, "SELECT * FROM reports");
		$b = [];
		if (mysqli_num_rows($a))
			while ($row = mysqli_fetch_assoc($a))
				$b[] = $row;
		return $b;
	}
	public function postReport($report_content, $rc_token)
	{
		$report_content = mysqli_escape_string($this->conn, $report_content);
		$captcha = json_decode(cURL('https://www.google.com/recaptcha/api/siteverify', ['secret' => RECAPTCHA_SECRET, 'response' => $rc_token]), true);
		if ($captcha['success'] == true && $captcha['action'] == 'reports') {
			$time = time();
			$b = mysqli_query($this->conn, "INSERT INTO reports (`report_content`, `report_date`) VALUES ('$report_content', '$time')");
			if ($b) {
				return ['error' => false, 'message' => 'Gửi góp ý/báo cáo thành công!'];
			} else return ['error' => true, 'message' => 'Có lỗi xảy ra!'];
		} else return ['error' => true, 'message' => 'Lỗi xác thực bảo mật, vui lòng thử lại!'];
	}
	public function getNews()
	{
		$a = mysqli_query($this->conn, "SELECT * FROM news");
		$b = [];
		if (mysqli_num_rows($a))
			while ($row = mysqli_fetch_assoc($a)) {
				$row['news_title_kd'] = str_replace(' ', '-', strtolower(khong_dau($row['news_title'])));
				$b[] = $row;
			}
		return $b;
	}
	public function getNewsById($news_id)
	{
		$news_id = mysqli_escape_string($this->conn, $news_id);
		$a = mysqli_query($this->conn, "SELECT * FROM news WHERE news_id = '$news_id'");
		$b = [];
		if (mysqli_num_rows($a)) {
			$b = [mysqli_fetch_assoc($a)];
			$b['news_title_kd'] = str_replace(' ', '-', strtolower(khong_dau($b['news_title'])));
		}
		return $b;
	}
	public function postNews($news_title, $news_category, $news_content, $news_thumbnail)
	{
		$news_title = mysqli_escape_string($this->conn, $news_title);
		$news_category = mysqli_escape_string($this->conn, $news_category);
		$news_content = mysqli_escape_string($this->conn, $news_content);
		$news_thumbnail = mysqli_escape_string($this->conn, $news_thumbnail);
		$news_date = time();
		$b = mysqli_query($this->conn, "INSERT INTO news (`news_title`, `news_category`, `news_content`, `news_thumbnail`, `news_date`) VALUES ('$news_title', '$news_category', '$news_content', '$news_thumbnail', '$news_date')");
		if ($b)
			return ['error' => false, 'message' => 'Thêm news thành công!'];
		else return ['error' => true, 'message' => 'Có lỗi xảy ra!'];
	}
	public function updateNews($news_id, $news_title, $news_category, $news_content, $news_thumbnail)
	{
		$news_id = mysqli_escape_string($this->conn, $news_id);
		if (!is_numeric($news_id)) $news_id = decode_id($news_id);
		$news_title = mysqli_escape_string($this->conn, $news_title);
		$news_category = mysqli_escape_string($this->conn, $news_category);
		$news_content = mysqli_escape_string($this->conn, $news_content);
		$news_thumbnail = mysqli_escape_string($this->conn, $news_thumbnail);
		if (mysqli_query($this->conn, "UPDATE `news` SET news_title = '$news_title', news_category = '$news_category', news_content = '$news_content', news_thumbnail = '$news_thumbnail' WHERE news_id = $news_id")) {
			return ['error' => false, 'message' => 'Cập nhật news thành công!'];
		} else return ['error' => true, 'message' => 'Có lỗi xảy ra!'];
	}
}
