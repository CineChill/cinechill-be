<?php
// error_reporting(E_ALL & ~E_NOTICE);
// error_reporting(0);
date_default_timezone_set('Asia/Ho_Chi_Minh');

$conn = mysqli_connect('localhost', 'root', '', 'phim_lau') or die('Không thể kết nối tới database');
mysqli_set_charset($conn, "utf8");
define('SALT', 'Pvl2019!@#'); // SALT để trộn
define('DATA_PER_PAGE', 21); // Số dữ liệu hiển thị trên mỗi trang
define('RECAPTCHA_SECRET', '6Lf_gEQcAAAAANa-aqB7mAC_OIGef2oPFHc3-hag'); // Secret key của reCAPTCHA

require_once('function.php');
require_once('class.php');
