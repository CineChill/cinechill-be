<?php
// var_dump($_REQUEST);
// var_dump($_SERVER['REQUEST_METHOD']);
// var_dump($_POST['asd']);
header('Content-Type: text/plain; charset=UTF-8');
include 'config.php';

cors();

$p = explode('/', $_GET['url']);
// var_dump($p);
$method = $_SERVER['REQUEST_METHOD'];
$method_ = strtoupper($_GET['method']);
// var_dump($method, $method_);
$a = new API($conn);
$b = [];
switch ($p[0]) {
	case 'encode_id':
		if (is_numeric($p[1])) exit(encode_id($p[1]));
		break;
	case 'decode_id':
		if (!is_numeric($p[1])) exit(decode_id($p[1]));
		break;
	case 'countries':
		if ($method == 'GET')
			$b = $a->getCountries();
		break;
	case 'categories':
		if ($method == 'GET')
			$b = $a->getCategories();
		break;
	case 'films':
		if ($method == 'GET')
			$b = $a->getFilms($_GET['country'], $_GET['category'], $_GET['year'], $_GET['search'], $_GET['q'], $_GET['page']);
		break;
	case 'film':
		if ($p[1]) {
			if ($p[2] == 'episodes') {
				if ($method == 'GET')
					$b = $a->getEpByFilmId($p[1]);
				else if ($method == 'POST')
					if (!empty($_POST['ep_name']) && !empty($_POST['ep_url'])) {
						$b = check_session($_REQUEST['user_id'], $_REQUEST['token']);
						if ($b['error'] == false)
							$b = $a->postEp($p[1], $_POST['ep_name'], $_POST['ep_url']);
					} else $b = array('error' => true, 'message' => 'Thông tin yêu cầu bị thiếu!');
			} else if ($p[2] == 'views') {
				if ($method == 'POST') $b = $a->postView($p[1]);
			} else if ($p[2] == '' || $p[2] == NULL) {
				if ($method == 'GET')
					$b = $a->getFilm($p[1]);
				else if ($method == 'POST' && $method_ == 'PUT')
					if (!empty($_POST['film_name'])) {
						$b = check_session($_REQUEST['user_id'], $_REQUEST['token']);
						if ($b['error'] == false)
							$b = $a->updateFilm($p[1], $_POST['film_name'], $_POST['film_name_en'], $_POST['film_director'], $_POST['film_actors'], $_POST['film_poster'], $_POST['film_trailer'], $_POST['film_content'], $_POST['film_summary'], $_POST['film_duration'], $_POST['film_series'], $_POST['film_ep_num'], $_POST['film_theaters'], $_POST['film_netflix'], $_POST['film_release_year'], ($_POST['film_country'] ? implode(',', $_POST['film_country']) : ''), ($_POST['film_categories'] ? implode(',', $_POST['film_categories']) : ''));
					} else $b = array('error' => true, 'message' => 'Thông tin yêu cầu bị thiếu!');
			}
		} else if ($method == 'POST')
			if (!empty($_POST['film_name'])) {
				$b = check_session($_REQUEST['user_id'], $_REQUEST['token']);
				if ($b['error'] == false)
					$b = $a->postFilm($_POST['film_name'], $_POST['film_name_en'], $_POST['film_director'], $_POST['film_actors'], $_POST['film_poster'], $_POST['film_trailer'], $_POST['film_content'], $_POST['film_summary'], $_POST['film_duration'], $_POST['film_series'], $_POST['film_ep_num'], $_POST['film_theaters'], $_POST['film_netflix'], $_POST['film_release_year'], ($_POST['film_country'] ? implode(',', $_POST['film_country']) : ''), ($_POST['film_categories'] ? implode(',', $_POST['film_categories']) : ''));
			} else $b = array('error' => true, 'message' => 'Thông tin yêu cầu bị thiếu!');
		break;
	case 'ep':
		if ($p[1]) {
			if ($method == 'GET')
				$b = $a->getEpByEpId($p[1]);
			else if ($method == 'POST' && $method_ == 'PUT')
				if (!empty($_POST['ep_name']) && !empty($_POST['ep_url'])) {
					$b = check_session($_REQUEST['user_id'], $_REQUEST['token']);
					if ($b['error'] == false)
						$b = $a->updateEpByEpId($p[1], $_POST['ep_name'], $_POST['ep_url']);
				} else $b = array('error' => true, 'message' => 'Thông tin yêu cầu bị thiếu !');
		}
		break;
	case 'years':
		$b = $a->getYears();
		break;
	case 'signIn':
		if ($method == 'POST')
			if (!empty($_POST['username'] || $_POST['email']) && !empty($_POST['password']))
				$b = $a->login(($_POST['username'] ?? $_POST['email']), $_POST['password']);
			else $b = array('error' => true, 'message' => 'Thông tin yêu cầu bị thiếu!');
		break;
	case 'signUp':
		if ($method == 'POST')
			if (!empty($_POST['fullname']) && !empty($_POST['username']) && !empty($_POST['email']) && !empty($_POST['password']) && !empty($_POST['rc_token']))
				$b = $a->register($_POST['fullname'], $_POST['username'], $_POST['email'], $_POST['password'], $_POST['rc_token']);
			else $b = array('error' => true, 'message' => 'Thông tin yêu cầu bị thiếu!');
		break;
	case 'checkSession':
		if ($method == 'POST')
			if (!empty($_POST['user_id']) && !empty($_POST['token']))
				$b = check_session($_POST['user_id'], $_POST['token']);
			else $b = array('error' => true, 'message' => 'Thông tin yêu cầu bị thiếu!');
		break;
	case 'user':
		if ($p[1])
			if ($method == 'GET') $b = $a->getUserByUserId($p[1]);
			else if ($method == 'POST' && $p[2] == 'points') $b = $a->postPoints($p[1], $_REQUEST['rc_token']);
		break;
	case 'hls':
		if ($p[1]) {
			if ($p[2] == 'index.m3u8' || strpos($p[2], 'subtitle_') !== false) exit($a->getESV($p[1], $p[2]));
			else $b = $a->getESV($p[1]);
		}
		break;
	case 'proxy':
		if ($p[1]) {
			header('Cache-Control: max-age=600');
			$url = XORCipher(base64_decode(str_replace(['-', '_'], ['+', '/'], $p[1])), SALT);
			// echo ($p[1] . "\n" . $url);
			// exit();
			$timestamp = time();
			$tsstring = gmdate('D, d M Y H:i:s ', $timestamp) . 'GMT';
			$etag = md5($url);

			$if_modified_since = isset($_SERVER['HTTP_IF_MODIFIED_SINCE']) ? $_SERVER['HTTP_IF_MODIFIED_SINCE'] : false;
			$if_none_match = isset($_SERVER['HTTP_IF_NONE_MATCH']) ? $_SERVER['HTTP_IF_NONE_MATCH'] : false;
			if ((($if_none_match && $if_none_match == $etag) || (!$if_none_match)) &&
				($if_modified_since && $if_modified_since == $tsstring)
			) {
				header('HTTP/1.1 304 Not Modified');
				exit();
			} else {
				header("Last-Modified: $tsstring");
				header("ETag: \"{$etag}\"");
			}
			# Check if the client already has the requested item
			// if (isset($_SERVER['HTTP_IF_MODIFIED_SINCE']) or isset($_SERVER['HTTP_IF_NONE_MATCH'])) {
			// 	header('HTTP/1.1 304 Not Modified');
			// 	exit;
			// }
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($ch, CURLOPT_HEADER, true);
			curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
			// curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 4);
			curl_setopt($ch, CURLOPT_BUFFERSIZE, 12800);
			curl_setopt($ch, CURLOPT_NOPROGRESS, false);
			curl_setopt($ch, CURLOPT_PROGRESSFUNCTION, function ($DownloadSize, $Downloaded, $UploadSize, $Uploaded) {
				return ($Downloaded > (1024 * 1024 * 20)) ? 1 : 0;
			}); # max 4096kb đổi thành max 20mb
			$response = curl_exec($ch);
			$header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
			curl_close($ch);
			$header_blocks =  array_filter(preg_split('#\n\s*\n#Uis', substr($response, 0, $header_size)));
			$header_array = explode("\n", $header_blocks[array_key_last($header_blocks)]);
			$body = substr($response, $header_size);
			$headers = [];
			foreach ($header_array as $header_value) {
				$header_pieces = explode(': ', $header_value);
				if (count($header_pieces) == 2) {
					$headers[strtolower($header_pieces[0])] = trim($header_pieces[1]);
				}
			}
			if (array_key_exists('content-type', $headers)) {
				$ct = $headers['content-type'];
				if (preg_match('#image/png|image/.*icon|image/jpe?g|image/gif#', strtolower($ct)) !== 1) {
					header('HTTP/1.1 404 Not Found');
					exit;
				}
				header('Content-Type: ' . $ct);
			} else {
				header('HTTP/1.1 404 Not Found');
				exit;
			}
			if (array_key_exists('content-length', $headers))
				header('Content-Length: ' . $headers['content-length']);
			if (array_key_exists('Expires', $headers))
				header('Expires: ' . $headers['expires']);
			if (array_key_exists('Cache-Control', $headers))
				header('Cache-Control: ' . $headers['cache-control']);
			if (array_key_exists('Last-Modified', $headers))
				header('Last-Modified: ' . $headers['last-modified']);
			// header('Last-Modified: ' . gmdate('D, d M Y H:i:s \G\M\T', $time + 600));
			echo $body;
			exit;
		}
		break;
	case 'top_views':
		$b = $a->topViews();
		break;
	case 'statistics':
		$b = $a->statistics();
		break;
	case 'sitemap.xml':
		$xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n
<urlset xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://www.sitemaps.org/schemas/sitemap/0.9 http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd\" xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n
	<url>\n
		<loc>https://cinechill.xyz</loc>\n
		<changefreq>hourly</changefreq>\n
		<priority>1.0</priority>\n
	</url>\n";
		$b = $a->getFilmsSitemap();
		for ($i = 0; $i < count($b); $i++) {
			$url_phim = 'https://cinechill.xyz/phim/' . $b[$i]['film_name_kd'] . '-' . $b[$i]['film_id'];
			$xml	.=	"	<url>\n
		<loc>$url_phim</loc>\n
		<changefreq>monthly</changefreq>\n
		<priority>0.2</priority>\n
	</url>\n";
		}
		$xml .= "</urlset>";
		echo $xml;
		exit;
		break;
	case 'reports':
		if ($method == 'POST')
			if (!empty($_POST['report_content']) && !empty($_POST['rc_token']))
				$b = $a->postReport($_POST['report_content'], $_POST['rc_token']);
			else $b = array('error' => true, 'message' => 'Thông tin yêu cầu bị thiếu!');
		else $b = $a->getReports();
		break;
	case 'news':
		if ($method == 'GET')
			if (!empty($p[1]))
				$b = $a->getNewsById($p[1]);
			else $b = $a->getNews();
		else if ($method == 'POST') {
			$b = check_session($_REQUEST['user_id'], $_REQUEST['token']);
			if ($b['error'] == false)
				if (!empty($_POST['news_title']) && !empty($_POST['news_category']) && !empty($_POST['news_content']))
					if ($method_ == 'PUT')
						$b = $a->updateNews($p[1], $_POST['news_title'], $_POST['news_category'], $_POST['news_content'], $_POST['news_thumbnail']);
					else
						$b = $a->postNews($_POST['news_title'], $_POST['news_category'], $_POST['news_content'], $_POST['news_thumbnail']);
				else $b = array('error' => true, 'message' => 'Thông tin yêu cầu bị thiếu!');
		}
		break;
	default:
		$b = [];
		break;
}
echo json_encode($b);
