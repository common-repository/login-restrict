<?php
/*
* Constants
*/

/* Different ways to get remote address: direct & behind proxy */
define('LMT_LOGIN_DIR_ADD', 'REMOTE_ADDR');
define('LMT_LOGIN_PROXY_ADD', 'HTTP_X_FORWARDED_FOR');

/* Notify value checked against these in limit_login_sanitize_variables() */
define('LMT_LOGIN_LOCK_NOTIFY_ALLOWED', 'log,email');
?>