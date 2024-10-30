<?php


/*
 * Functions start here
 */
/* Get options and setup filters & actions */
function login_lmt_setup() {
	load_plugin_textdomain('login-lmt-attempts', false
			       , dirname(plugin_basename(__FILE__)));

	login_lmt_setup_options();

	/* Filters and actions */
	add_action('wp_login_failed', 'login_lmt_failed');
	if (login_lmt_option('cookies')) {
		login_lmt_handle_cookies();
		add_action('auth_cookie_bad_username', 'login_lmt_failed_cookie');

		global $wp_version;

		if (version_compare($wp_version, '3.0', '>=')) {
			add_action('auth_cookie_bad_hash', 'login_lmt_failed_cookie_hash');
			add_action('auth_cookie_valid', 'login_lmt_valid_cookie', 10, 2);
		} else {
			add_action('auth_cookie_bad_hash', 'login_lmt_failed_cookie');
		}
	}
	add_filter('wp_authenticate_user', 'login_lmt_wp_authenticate_user', 99999, 2);
	add_filter('shake_error_codes', 'login_lmt_failure_shake');
	add_action('login_head', 'login_lmt_add_error_message');
	add_action('login_errors', 'login_lmt_fixup_error_messages');
	add_action('admin_menu', 'login_lmt_admin_menu');

	/*
	 * This action should really be changed to the 'authenticate' filter as
	 * it will probably be deprecated. That is however only available in
	 * later versions of WP.
	 */
	add_action('wp_authenticate', 'login_lmt_track_credentials', 10, 2);
}


/* Get current option value */
function login_lmt_option($option_name) {
	global $login_lmt_opts;

	if (isset($login_lmt_opts[$option_name])) {
		return $login_lmt_opts[$option_name];
	} else {
		return null;
	}
}


/* Get correct remote address */
function login_lmt_get_address($type_name = '') {
	$type = $type_name;
	if (empty($type)) {
		$type = login_lmt_option('client_type');
	}

	if (isset($_SERVER[$type])) {
		return $_SERVER[$type];
	}

	/*
	 * Not found. Did we get proxy type from option?
	 * If so, try to fall back to direct address.
	 */
	if ( empty($type_name) && $type == LMT_LOGIN_PROXY_ADD
		 && isset($_SERVER[LMT_LOGIN_DIR_ADD])) {

		/*
		 * NOTE: Even though we fall back to direct address -- meaning you
		 * can get a mostly working plugin when set to PROXY mode while in
		 * fact directly connected to Internet it is not safe!
		 *
		 * Client can itself send HTTP_X_FORWARDED_FOR header fooling us
		 * regarding which IP should be banned.
		 */

		return $_SERVER[LMT_LOGIN_DIR_ADD];
	}

	return '';
}


/*
 * Check if IP is whitelisted.
 *
 * This function allow external ip whitelisting using a filter. Note that it can
 * be called multiple times during the login process.
 *
 * Note that retries and statistics are still counted and notifications
 * done as usual for whitelisted ips , but no block is done.
 *
 * Example:
 * function my_ip_whitelist($allow, $ip) {
 * 	return ($ip == 'my-ip') ? true : $allow;
 * }
 * add_filter('login_lmt_whitelist_ip', 'my_ip_whitelist', 10, 2);
 */
function is_login_lmt_ip_whitelisted($ip = null) {
	if (is_null($ip)) {
		$ip = login_lmt_get_address();
	}
	$whitelisted = apply_filters('login_lmt_whitelist_ip', false, $ip);

	return ($whitelisted === true);
}


/* Check if it is ok to login */
function is_login_lmt_ok() {
	$ip = login_lmt_get_address();

	/* Check external whitelist filter */
	if (is_login_lmt_ip_whitelisted($ip)) {
		return true;
	}

	/* block active? */
	$blocks = get_option('login_lmt_blocks');
	return (!is_array($blocks) || !isset($blocks[$ip]) || time() >= $blocks[$ip]);
}


/* Filter: allow login attempt? (called from wp_authenticate()) */
function login_lmt_wp_authenticate_user($user, $password) {
	if (is_wp_error($user) || is_login_lmt_ok() ) {
		return $user;
	}

	global $lmt_login_error_shown;
	$lmt_login_error_shown = true;

	$error = new WP_Error();
	// This error should be the same as in "shake it" filter below
	$error->add('too_many_retries', login_lmt_error_msg());
	return $error;
}


/* Filter: add this failure to login page "Shake it!" */
function login_lmt_failure_shake($error_codes) {
	$error_codes[] = 'too_many_retries';
	return $error_codes;
}


/*
 * Must be called in plugin_loaded (really early) to make sure we do not allow
 * auth cookies while locked out.
 */
function login_lmt_handle_cookies() {
	if (is_login_lmt_ok()) {
		return;
	}

	login_lmt_clear_auth_cookie();
}


/*
 * Action: failed cookie login hash
 *
 * Make sure same invalid cookie doesn't get counted more than once.
 *
 * Requires WordPress version 3.0.0, previous versions use login_lmt_failed_cookie()
 */
function login_lmt_failed_cookie_hash($cookie_elements) {
	login_lmt_clear_auth_cookie();

	/*
	 * Under some conditions an invalid auth cookie will be used multiple
	 * times, which results in multiple failed attempts from that one
	 * cookie.
	 *
	 * Unfortunately I've not been able to replicate this consistently and
	 * thus have not been able to make sure what the exact cause is.
	 *
	 * Probably it is because a reload of for example the admin dashboard
	 * might result in multiple requests from the browser before the invalid
	 * cookie can be cleard.
	 *
	 * Handle this by only counting the first attempt when the exact same
	 * cookie is attempted for a user.
	 */

	extract($cookie_elements, EXTR_OVERWRITE);

	// Check if cookie is for a valid user
	$user = get_userdatabylogin($username);
	if (!$user) {
		// "shouldn't happen" for this action
		login_lmt_failed($username);
		return;
	}

	$previous_cookie = get_user_meta($user->ID, 'login_lmt_previous_cookie', true);
	if ($previous_cookie && $previous_cookie == $cookie_elements) {
		// Identical cookies, ignore this attempt
		return;
	}

	// Store cookie
	if ($previous_cookie)
		update_user_meta($user->ID, 'login_lmt_previous_cookie', $cookie_elements);
	else
		add_user_meta($user->ID, 'login_lmt_previous_cookie', $cookie_elements, true);

	login_lmt_failed($username);
}


/*
 * Action: successful cookie login
 *
 * Clear any stored user_meta.
 *
 * Requires WordPress version 3.0.0, not used in previous versions
 */
function login_lmt_valid_cookie($cookie_elements, $user) {
	/*
	 * As all meta values get cached on user load this should not require
	 * any extra work for the common case of no stored value.
	 */

	if (get_user_meta($user->ID, 'login_lmt_previous_cookie')) {
		delete_user_meta($user->ID, 'login_lmt_previous_cookie');
	}
}


/* Action: failed cookie login (calls login_lmt_failed()) */
function login_lmt_failed_cookie($cookie_elements) {
	login_lmt_clear_auth_cookie();

	/*
	 * Invalid username gets counted every time.
	 */

	login_lmt_failed($cookie_elements['username']);
}


/* Make sure auth cookie really get cleared (for this session too) */
function login_lmt_clear_auth_cookie() {
	wp_clear_auth_cookie();

	if (!empty($_COOKIE[AUTH_COOKIE])) {
		$_COOKIE[AUTH_COOKIE] = '';
	}
	if (!empty($_COOKIE[SECURE_AUTH_COOKIE])) {
		$_COOKIE[SECURE_AUTH_COOKIE] = '';
	}
	if (!empty($_COOKIE[LOGGED_IN_COOKIE])) {
		$_COOKIE[LOGGED_IN_COOKIE] = '';
	}
}

/*
 * Action when login attempt failed
 *
 * Increase nr of retries (if necessary). Reset valid value. Setup
 * block if nr of retries are above threshold. And more!
 *
 * A note on external whitelist: retries and statistics are still counted and
 * notifications done as usual, but no block is done.
 */
function login_lmt_failed($username) {
	$ip = login_lmt_get_address();

	/* if currently locked-out, do not add to retries */
	$blocks = get_option('login_lmt_blocks');
	if (!is_array($blocks)) {
		$blocks = array();
	}
	if(isset($blocks[$ip]) && time() < $blocks[$ip]) {
		return;
	}

	/* Get the arrays with retries and retries-valid information */
	$retries = get_option('login_lmt_retries');
	$valid = get_option('login_lmt_retries_valid');
	if (!is_array($retries)) {
		$retries = array();
		add_option('login_lmt_retries', $retries, '', 'no');
	}
	if (!is_array($valid)) {
		$valid = array();
		add_option('login_lmt_retries_valid', $valid, '', 'no');
	}

	/* Check validity and add one to retries */
	if (isset($retries[$ip]) && isset($valid[$ip]) && time() < $valid[$ip]) {
		$retries[$ip] ++;
	} else {
		$retries[$ip] = 1;
	}
	$valid[$ip] = time() + login_lmt_option('valid_duration');

	/* block? */
	if($retries[$ip] % login_lmt_option('allowed_retries') != 0) {
		/*
		 * Not block (yet!)
		 * Do housecleaning (which also saves retry/valid values).
		 */
		login_lmt_cleanup($retries, null, $valid);
		return;
	}

	/* block! */

	$whitelisted = is_login_lmt_ip_whitelisted($ip);

	$retries_long = login_lmt_option('allowed_retries')
		* login_lmt_option('allowed_blocks');

	/*
	 * Note that retries and statistics are still counted and notifications
	 * done as usual for whitelisted ips , but no block is done.
	 */
	if ($whitelisted) {
		if ($retries[$ip] >= $retries_long) {
			unset($retries[$ip]);
			unset($valid[$ip]);
		}
	} else {
		global $lmt_login_just_block;
		$lmt_login_just_block = true;

		/* setup block, reset retries as needed */
		if ($retries[$ip] >= $retries_long) {
			/* long block */
			$blocks[$ip] = time() + login_lmt_option('long_duration');
			unset($retries[$ip]);
			unset($valid[$ip]);
		} else {
			/* normal block */
			$blocks[$ip] = time() + login_lmt_option('lock_after_duration');
		}
	}

	/* do housecleaning and save values */
	login_lmt_cleanup($retries, $blocks, $valid);

	/* do any notification */
	login_lmt_notify($username);

	/* increase statistics */
	$total = get_option('login_lmt_blocks_total');
	if ($total === false || !is_numeric($total)) {
		add_option('login_lmt_blocks_total', 1, '', 'no');
	} else {
		update_option('login_lmt_blocks_total', $total + 1);
	}
}


/* Clean up old blocks and retries, and save supplied arrays */
function login_lmt_cleanup($retries = null, $blocks = null, $valid = null) {
	$now = time();
	$blocks = !is_null($blocks) ? $blocks : get_option('login_lmt_blocks');

	/* remove old blocks */
	if (is_array($blocks)) {
		foreach ($blocks as $ip => $block) {
			if ($block < $now) {
				unset($blocks[$ip]);
			}
		}
		update_option('login_lmt_blocks', $blocks);
	}

	/* remove retries that are no longer valid */
	$valid = !is_null($valid) ? $valid : get_option('login_lmt_retries_valid');
	$retries = !is_null($retries) ? $retries : get_option('login_lmt_retries');
	if (!is_array($valid) || !is_array($retries)) {
		return;
	}

	foreach ($valid as $ip => $block) {
		if ($block < $now) {
			unset($valid[$ip]);
			unset($retries[$ip]);
		}
	}

	/* go through retries directly, if for some reason they've gone out of sync */
	foreach ($retries as $ip => $retry) {
		if (!isset($valid[$ip])) {
			unset($retries[$ip]);
		}
	}

	update_option('login_lmt_retries', $retries);
	update_option('login_lmt_retries_valid', $valid);
}


/* Is this WP Multisite? */
function is_login_lmt_multisite() {
	return function_exists('get_site_option') && function_exists('is_multisite') && is_multisite();
}


/* Email notification of block to admin (if configured) */
function login_lmt_notify_email($user) {
	$ip = login_lmt_get_address();
	$whitelisted = is_login_lmt_ip_whitelisted($ip);

	$retries = get_option('login_lmt_retries');
	if (!is_array($retries)) {
		$retries = array();
	}

	/* check if we are at the right nr to do notification */
	if ( isset($retries[$ip])
		 && ( ($retries[$ip] / login_lmt_option('allowed_retries'))
			  % login_lmt_option('notify_email_after') ) != 0 ) {
		return;
	}

	/* Format message. First current block duration */
	if (!isset($retries[$ip])) {
		/* longer block */
		$count = login_lmt_option('allowed_retries')
			* login_lmt_option('allowed_blocks');
		$blocks = login_lmt_option('allowed_blocks');
		$time = round(login_lmt_option('long_duration') / 3600);
		$when = sprintf(_n('%d hour', '%d hours', $time, 'login-lmt-attempts'), $time);
	} else {
		/* normal block */
		$count = $retries[$ip];
		$blocks = floor($count / login_lmt_option('allowed_retries'));
		$time = round(login_lmt_option('lock_after_duration') / 60);
		$when = sprintf(_n('%d minute', '%d minutes', $time, 'login-lmt-attempts'), $time);
	}

	$blogname = is_login_lmt_multisite() ? get_site_option('site_name') : get_option('blogname');

	if ($whitelisted) {
		$subject = sprintf(__("[%s] Failed login attempts from whitelisted IP"
				      , 'login-lmt-attempts')
				   , $blogname);
	} else {
		$subject = sprintf(__("[%s] Too many failed login attempts"
				      , 'login-lmt-attempts')
				   , $blogname);
	}

	$message = sprintf(__("%d failed login attempts (%d block(s)) from IP: %s"
			      , 'login-lmt-attempts') . "\r\n\r\n"
			   , $count, $blocks, $ip);
	if ($user != '') {
		$message .= sprintf(__("Last user attempted: %s", 'login-lmt-attempts')
				    . "\r\n\r\n" , $user);
	}
	if ($whitelisted) {
		$message .= __("IP was NOT blocked because of external whitelist.", 'login-lmt-attempts');
	} else {
		$message .= sprintf(__("IP was blocked for %s", 'login-lmt-attempts'), $when);
	}

	$admin_email = is_login_lmt_multisite() ? get_site_option('admin_email') : get_option('admin_email');

	@wp_mail($admin_email, $subject, $message);
}


/* Logging of block (if configured) */
function login_lmt_notify_log($user) {
	$log = $option = get_option('login_lmt_logged');
	if (!is_array($log)) {
		$log = array();
	}
	$ip = login_lmt_get_address();

	/* can be written much simpler, if you do not mind php warnings */
	if (isset($log[$ip])) {
		if (isset($log[$ip][$user])) {
			$log[$ip][$user]++;
		} else {
			$log[$ip][$user] = 1;
		}
	} else {
		$log[$ip] = array($user => 1);
	}

	if ($option === false) {
		add_option('login_lmt_logged', $log, '', 'no'); /* no autoload */
	} else {
		update_option('login_lmt_logged', $log);
	}
}


/* Handle notification in event of block */
function login_lmt_notify($user) {
	$args = explode(',', login_lmt_option('lock_after_notify'));

	if (empty($args)) {
		return;
	}

	foreach ($args as $mode) {
		switch (trim($mode)) {
		case 'email':
			login_lmt_notify_email($user);
			break;
		case 'log':
			login_lmt_notify_log($user);
			break;
		}
	}
}


/* Construct informative error message */
function login_lmt_error_msg() {
	$ip = login_lmt_get_address();
	$blocks = get_option('login_lmt_blocks');

	$msg = __('<strong>ERROR</strong>: Too many failed login attempts.', 'login-lmt-attempts') . ' ';

	if (!is_array($blocks) || !isset($blocks[$ip]) || time() >= $blocks[$ip]) {
		/* Huh? No timeout active? */
		$msg .=  __('Please try again later.', 'login-lmt-attempts');
		return $msg;
	}

	$when = ceil(($blocks[$ip] - time()) / 60);
	if ($when > 60) {
		$when = ceil($when / 60);
		$msg .= sprintf(_n('Please try again in %d hour.', 'Please try again in %d hours.', $when, 'login-lmt-attempts'), $when);
	} else {
		$msg .= sprintf(_n('Please try again in %d minute.', 'Please try again in %d minutes.', $when, 'login-lmt-attempts'), $when);
	}

	return $msg;
}


/* Construct retries remaining message */
function login_lmt_retries_remaining_msg() {
	$ip = login_lmt_get_address();
	$retries = get_option('login_lmt_retries');
	$valid = get_option('login_lmt_retries_valid');

	/* Should we show retries remaining? */

	if (!is_array($retries) || !is_array($valid)) {
		/* no retries at all */
		return '';
	}
	if (!isset($retries[$ip]) || !isset($valid[$ip]) || time() > $valid[$ip]) {
		/* no: no valid retries */
		return '';
	}
	if (($retries[$ip] % login_lmt_option('allowed_retries')) == 0 ) {
		/* no: already been locked out for these retries */
		return '';
	}

	$remaining = max((login_lmt_option('allowed_retries') - ($retries[$ip] % login_lmt_option('allowed_retries'))), 0);
	return sprintf(_n("<strong>%d</strong> attempt remaining.", "<strong>%d</strong> attempts remaining.", $remaining, 'login-lmt-attempts'), $remaining);
}


/* Return current (error) message to show, if any */
function login_lmt_get_message() {
	/* Check external whitelist */
	if (is_login_lmt_ip_whitelisted()) {
		return '';
	}

	/* Is block in effect? */
	if (!is_login_lmt_ok()) {
		return login_lmt_error_msg();
	}

	return login_lmt_retries_remaining_msg();
}


/* Should we show errors and messages on this page? */
function should_login_lmt_show_msg() {
	if (isset($_GET['key'])) {
		/* reset password */
		return false;
	}

	$action = isset($_REQUEST['action']) ? sanitize_text_field($_REQUEST['action']) : '';

	return ( $action != 'lostpassword' && $action != 'retrievepassword'
			 && $action != 'resetpass' && $action != 'rp'
			 && $action != 'register' );
}


/* Fix up the error message before showing it */
function login_lmt_fixup_error_messages($content) {
	global $lmt_login_just_block, $lmt_login_nonempty_credentials, $lmt_login_error_shown;

	if (!should_login_lmt_show_msg()) {
		return $content;
	}

	/*
	 * During block we do not want to show any other error messages (like
	 * unknown user or empty password).
	 */
	if (!is_login_lmt_ok() && !$lmt_login_just_block) {
		return login_lmt_error_msg();
	}

	/*
	 * We want to filter the messages 'Invalid username' and
	 * 'Invalid password' as that is an information leak regarding user
	 * account names (prior to WP 2.9?).
	 *
	 * Also, if more than one error message, put an extra <br /> tag between
	 * them.
	 */
	$msgs = explode("<br />\n", $content);

	if (strlen(end($msgs)) == 0) {
		/* remove last entry empty string */
		array_pop($msgs);
	}

	$count = count($msgs);
	$my_warn_count = $lmt_login_error_shown ? 1 : 0;

	if ($lmt_login_nonempty_credentials && $count > $my_warn_count) {
		/* Replace error message, including ours if necessary */
		$content = __('<strong>ERROR</strong>: Incorrect username or password.', 'login-lmt-attempts') . "<br />\n";
		if ($lmt_login_error_shown) {
			$content .= "<br />\n" . login_lmt_get_message() . "<br />\n";
		}
		return $content;
	} elseif ($count <= 1) {
		return $content;
	}

	$new = '';
	while ($count-- > 0) {
		$new .= array_shift($msgs) . "<br />\n";
		if ($count > 0) {
			$new .= "<br />\n";
		}
	}

	return $new;
}


/* Add a message to login page when necessary */
function login_lmt_add_error_message() {
	global $error, $lmt_login_error_shown;

	if (!should_login_lmt_show_msg() || $lmt_login_error_shown) {
		return;
	}

	$msg = login_lmt_get_message();

	if ($msg != '') {
		$lmt_login_error_shown = true;
		$error .= $msg;
	}

	return;
}


/* Keep track of if user or password are empty, to filter errors correctly */
function login_lmt_track_credentials($user, $password) {
	global $lmt_login_nonempty_credentials;

	$lmt_login_nonempty_credentials = (!empty($user) && !empty($password));
}


/*
 * Admin stuff
 */

/* Make a guess if we are behind a proxy or not */
function login_lmt_guess_proxy() {
	return isset($_SERVER[LMT_LOGIN_PROXY_ADD])
		? LMT_LOGIN_PROXY_ADD : LMT_LOGIN_DIR_ADD;
}


/* Only change var if option exists */
function login_lmt_get_option($option, $var_name) {
	$a = get_option($option);

	if ($a !== false) {
		global $login_lmt_opts;

		$login_lmt_opts[$var_name] = $a;
	}
}


/* Setup global variables from options */
function login_lmt_setup_options() {
	login_lmt_get_option('login_lmt_client_type', 'client_type');
	login_lmt_get_option('login_lmt_allowed_retries', 'allowed_retries');
	login_lmt_get_option('login_lmt_lock_after_duration', 'lock_after_duration');
	login_lmt_get_option('login_lmt_valid_duration', 'valid_duration');
	login_lmt_get_option('login_lmt_cookies', 'cookies');
	login_lmt_get_option('login_lmt_lock_after_notify', 'lock_after_notify');
	login_lmt_get_option('login_lmt_allowed_blocks', 'allowed_blocks');
	login_lmt_get_option('login_lmt_long_duration', 'long_duration');
	login_lmt_get_option('login_lmt_notify_email_after', 'notify_email_after');

	login_lmt_sanitize_variables();
}


/* Update options in db from global variables */
function login_lmt_update_options() {
	update_option('login_lmt_client_type', login_lmt_option('client_type'));
	update_option('login_lmt_allowed_retries', login_lmt_option('allowed_retries'));
	update_option('login_lmt_lock_after_duration', login_lmt_option('lock_after_duration'));
	update_option('login_lmt_allowed_blocks', login_lmt_option('allowed_blocks'));
	update_option('login_lmt_long_duration', login_lmt_option('long_duration'));
	update_option('login_lmt_valid_duration', login_lmt_option('valid_duration'));
	update_option('login_lmt_lock_after_notify', login_lmt_option('lock_after_notify'));
	update_option('login_lmt_notify_email_after', login_lmt_option('notify_email_after'));
	update_option('login_lmt_cookies', login_lmt_option('cookies') ? '1' : '0');
}


/* Make sure the variables make sense -- simple integer */
function login_lmt_sanitize_simple_int($var_name) {
	global $login_lmt_opts;

	$login_lmt_opts[$var_name] = max(1, intval(login_lmt_option($var_name)));
}


/* Make sure the variables make sense */
function login_lmt_sanitize_variables() {
	global $login_lmt_opts;

	login_lmt_sanitize_simple_int('allowed_retries');
	login_lmt_sanitize_simple_int('lock_after_duration');
	login_lmt_sanitize_simple_int('valid_duration');
	login_lmt_sanitize_simple_int('allowed_blocks');
	login_lmt_sanitize_simple_int('long_duration');

	$login_lmt_opts['cookies'] = !!login_lmt_option('cookies');

	$notify_email_after = max(1, intval(login_lmt_option('notify_email_after')));
	$login_lmt_opts['notify_email_after'] = min(login_lmt_option('allowed_blocks'), $notify_email_after);

	$args = explode(',', login_lmt_option('lock_after_notify'));
	$args_allowed = explode(',', LMT_LOGIN_LOCK_NOTIFY_ALLOWED);
	$new_args = array();
	foreach ($args as $a) {
		if (in_array($a, $args_allowed)) {
			$new_args[] = $a;
		}
	}
	$login_lmt_opts['lock_after_notify'] = implode(',', $new_args);

	if ( login_lmt_option('client_type') != LMT_LOGIN_DIR_ADD
		 && login_lmt_option('client_type') != LMT_LOGIN_PROXY_ADD ) {
		$login_lmt_opts['client_type'] = LMT_LOGIN_DIR_ADD;
	}
}


/* Add admin options page */
function login_lmt_admin_menu() {
	global $wp_version;

	// Modern WP?
	if (version_compare($wp_version, '3.0', '>=')) {
	    add_options_page('Login Restrict', 'Login Restrict', 'manage_options', 'login-lmt-attempts', 'login_lmt_option_page');
	    return;
	}

	// Older WPMU?
	if (function_exists("get_current_site")) {
	    add_submenu_page('wpmu-admin.php', 'Login Restrict', 'Login Restrict', 9, 'login-lmt-attempts', 'login_lmt_option_page');
	    return;
	}

	// Older WP
	add_options_page('Login Restrict', 'Login Restrict', 9, 'login-lmt-attempts', 'login_lmt_option_page');
}


/* Show log on admin page */
function login_lmt_show_log($log) {
	if (!is_array($log) || count($log) == 0) {
		return;
	}

	echo('<tr><th scope="col">' . _x("IP", "Internet address", 'login-lmt-attempts') . '</th><th scope="col">' . __('Tried to log in as', 'login-lmt-attempts') . '</th></tr>');
	foreach ($log as $ip => $arr) {
		echo('<tr><td class="limit-login-ip">' . $ip . '</td><td class="limit-login-max">');
		$first = true;
		foreach($arr as $user => $count) {
			$count_desc = sprintf(_n('%d block', '%d blocks', $count, 'login-lmt-attempts'), $count);
			if (!$first) {
				echo(', ' . $user . ' (' .  $count_desc . ')');
			} else {
				echo($user . ' (' .  $count_desc . ')');
			}
			$first = false;
		}
		echo('</td></tr>');
	}
}

/* Actual admin page */
function login_lmt_option_page()	{
	login_lmt_cleanup();

	if (!current_user_can('manage_options')) {
		wp_die('Sorry, but you do not have permissions to change settings.');
	}

	/* Make sure post was from this page */
	if (count($_POST) > 0) {

		check_admin_referer('login-lmt-attempts-options');
        if(wp_verify_nonce(sanitize_text_field($_POST['_wpnonce']),'login-lmt-attempts-options') != 1)
        {
            echo "<br>The link you followed has expired.";
            exit;
        }
        current_user_can('administrator');
	}

	/* Should we clear log? */
	if (isset($_POST['clear_log'])) {
		delete_option('login_lmt_logged');
		echo '<div id="message" class="updated fade"><p>'
			. __('Cleared IP log', 'login-lmt-attempts')
			. '</p></div>';
	}

	/* Should we reset counter? */
	if (isset($_POST['reset_total'])) {
		update_option('login_lmt_blocks_total', 0);
		echo '<div id="message" class="updated fade"><p>'
			. __('Reset block count', 'login-lmt-attempts')
			. '</p></div>';
	}

	/* Should we restore current blocks? */
	if (isset($_POST['reset_current'])) {
		update_option('login_lmt_blocks', array());
		echo '<div id="message" class="updated fade"><p>'
			. __('Cleared current blocks', 'login-lmt-attempts')
			. '</p></div>';
	}

	/* Should we update options? */
	if (isset($_POST['update_options'])) {
		global $login_lmt_opts;


		$login_lmt_opts['client_type'] = sanitize_text_field($_POST['client_type']);
		$login_lmt_opts['allowed_retries'] = sanitize_text_field((int)$_POST['allowed_retries']);
		$login_lmt_opts['lock_after_duration'] = sanitize_text_field((int)$_POST['lock_after_duration']) * 60;
		$login_lmt_opts['valid_duration'] = sanitize_text_field((int)$_POST['valid_duration']) * 3600;
		$login_lmt_opts['allowed_blocks'] = sanitize_text_field((int)$_POST['allowed_blocks']);
		$login_lmt_opts['long_duration'] = sanitize_text_field((int)$_POST['long_duration']) * 3600;
		$login_lmt_opts['notify_email_after'] = sanitize_text_field($_POST['email_after']);
		$login_lmt_opts['cookies'] = (isset($_POST['cookies']) && $_POST['cookies'] == '1');


		$v = array();
		if (isset($_POST['lock_after_notify_log'])) {
			$v[] = 'log';
		}
		if (isset($_POST['lock_after_notify_email'])) {
			$v[] = 'email';
		}
		$login_lmt_opts['lock_after_notify'] = implode(',', $v);

		login_lmt_sanitize_variables();
		login_lmt_update_options();
		echo '<div id="message" class="updated fade"><p>'
			. __('Options changed', 'login-lmt-attempts')
			. '</p></div>';
	}

	$blocks_total = get_option('login_lmt_blocks_total', 0);
	$blocks = get_option('login_lmt_blocks');
	$blocks_now = is_array($blocks) ? count($blocks) : 0;

	$cookies_yes = login_lmt_option('cookies') ? ' checked ' : '';
	$cookies_no = login_lmt_option('cookies') ? '' : ' checked ';

	$client_type = login_lmt_option('client_type');
	$client_type_direct = $client_type == LMT_LOGIN_DIR_ADD ? ' checked ' : '';
	$client_type_proxy = $client_type == LMT_LOGIN_PROXY_ADD ? ' checked ' : '';

	$client_type_guess = login_lmt_guess_proxy();

	if ($client_type_guess == LMT_LOGIN_DIR_ADD) {
		$client_type_message = sprintf(__('It appears the site is reached directly (from your IP: %s)','login-lmt-attempts'), login_lmt_get_address(LMT_LOGIN_DIR_ADD));
	} else {
		$client_type_message = sprintf(__('It appears the site is reached through a proxy server (proxy IP: %s, your IP: %s)','login-lmt-attempts'), login_lmt_get_address(LMT_LOGIN_DIR_ADD), login_lmt_get_address(LMT_LOGIN_PROXY_ADD));
	}
	$client_type_message .= '<br />';

	$client_type_warning = '';
	if ($client_type != $client_type_guess) {
		$faq = 'http://wordpress.org/extend/plugins/login-lmt-attempts/faq/';

		$client_type_warning = '<br /><br />' . sprintf(__('<strong>Current setting appears to be invalid</strong>. Please make sure it is correct. Further information can be found <a href="%s" title="FAQ">here</a>','login-lmt-attempts'), $faq);
	}

	$v = explode(',', login_lmt_option('lock_after_notify'));
	$log_checked = in_array('log', $v) ? ' checked ' : '';
	$email_checked = in_array('email', $v) ? ' checked ' : '';
	?>
	<div class="wrap">
	  <h2><?php echo __('Login Limit Settings','login-lmt-attempts'); ?></h2>
	  <h3><?php echo __('Statistics','login-lmt-attempts'); ?></h3>
	  <form action="options-general.php?page=login-lmt-attempts" method="post">
		<?php wp_nonce_field('login-lmt-attempts-options'); ?>
	    <table class="form-table">
		  <tr>
			<th scope="row" valign="top"><?php echo __('Total blocks','login-lmt-attempts'); ?></th>
			<td>
			  <?php if ($blocks_total > 0) { ?>
			  <input name="reset_total" value="<?php echo __('Reset Counter','login-lmt-attempts'); ?>" type="submit" />
			  <?php echo sprintf(_n('%d block since last reset', '%d blocks since last reset', $blocks_total, 'login-lmt-attempts'), $blocks_total); ?>
			  <?php } else { echo __('No blocks yet','login-lmt-attempts'); } ?>
			</td>
		  </tr>
		  <?php if ($blocks_now > 0) { ?>
		  <tr>
			<th scope="row" valign="top"><?php echo __('Active blocks','login-lmt-attempts'); ?></th>
			<td>
			  <input name="reset_current" value="<?php echo __('Restore blocks','login-lmt-attempts'); ?>" type="submit" />
			  <?php echo sprintf(__('%d IP is currently blocked from trying to log in','login-lmt-attempts'), $blocks_now); ?>
			</td>
		  </tr>
		  <?php } ?>
		</table>
	  </form>
	  <h3><?php echo __('Options','login-lmt-attempts'); ?></h3>
	  <form action="options-general.php?page=login-lmt-attempts" method="post">
		<?php wp_nonce_field('login-lmt-attempts-options'); ?>
	    <table class="form-table">
		  <tr>
			<th scope="row" valign="top"><?php echo __('blocks','login-lmt-attempts'); ?></th>
			<td>
			  <input type="number" step="any" min="1" size="3" maxlength="4" value="<?php echo(login_lmt_option('allowed_retries')); ?>" name="allowed_retries" /> <?php echo __('allowed attempts','login-lmt-attempts'); ?> <br />
			  <input type="number" step="any" min="1" size="3" maxlength="4" value="<?php echo(login_lmt_option('lock_after_duration')/60); ?>" name="lock_after_duration" /> <?php echo __('minutes block','login-lmt-attempts'); ?> <br />
			  <input type="number" step="any" min="1" size="3" maxlength="4" value="<?php echo(login_lmt_option('allowed_blocks')); ?>" name="allowed_blocks" /> <?php echo __('block time increase upto to','login-lmt-attempts'); ?> <input type="text" size="3" maxlength="4" value="<?php echo(login_lmt_option('long_duration')/3600); ?>" name="long_duration" /> <?php echo __('hours','login-lmt-attempts'); ?> <br />
			  <input type="number" step="any" min="1" size="3" maxlength="4" value="<?php echo(login_lmt_option('valid_duration')/3600); ?>" name="valid_duration" /> <?php echo __('hours until attempts are reset','login-lmt-attempts'); ?>
			</td>
		  </tr>
            <input type="hidden" name="client_type"
                <?php echo $client_type_direct; ?> value="<?php echo LMT_LOGIN_DIR_ADD; ?>" />


            <input type="hidden" name="cookies" <?php echo $cookies_yes; ?> value="1" />
		  <tr>
			<th scope="row" valign="top"><?php echo __('Notify on block','login-lmt-attempts'); ?></th>
			<td>
			  <input type="checkbox" name="lock_after_notify_log" <?php echo $log_checked; ?> value="log" /> <?php echo __('Log IP','login-lmt-attempts'); ?><br />
			  <input type="checkbox" name="lock_after_notify_email" <?php echo $email_checked; ?> value="email" /> <?php echo __('Email to admin after','login-lmt-attempts'); ?> <input type="number" min="1" size="3" maxlength="4" value="<?php echo(login_lmt_option('notify_email_after')); ?>" name="email_after" /> <?php echo __('blocks','login-lmt-attempts'); ?>
			</td>
		  </tr>
		</table>
		<p class="submit">
		  <input name="update_options" value="<?php echo __('Change Options','login-lmt-attempts'); ?>" type="submit" />
		</p>
	  </form>
	  <?php
		$log = get_option('login_lmt_logged');

		if (is_array($log) && count($log) > 0) {
	  ?>
	  <h3><?php echo __('block log','login-lmt-attempts'); ?></h3>
	  <form action="options-general.php?page=login-lmt-attempts" method="post">
		<?php wp_nonce_field('login-lmt-attempts-options'); ?>
		<input type="hidden" value="true" name="clear_log" />
		<p class="submit">
		  <input name="submit" value="<?php echo __('Clear Log','login-lmt-attempts'); ?>" type="submit" />
		</p>
	  </form>
	  <style type="text/css" media="screen">
		.limit-login-log th {
			font-weight: bold;
		}
		.limit-login-log td, .limit-login-log th {
			padding: 1px 5px 1px 5px;
		}
		td.limit-login-ip {
			font-family:  "Courier New", Courier, monospace;
			vertical-align: top;
		}
		td.limit-login-max {
			width: 100%;
		}
	  </style>
	  <div class="limit-login-log">
		<table class="form-table">
		  <?php login_lmt_show_log($log); ?>
		</table>
	  </div>
	  <?php
		} /* if showing $log */
	  ?>

	</div>
	<?php
}
?>