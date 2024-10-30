<?php
/*
* Variables
*
* Assignments are for default value -- change on admin page.
*/

$login_lmt_opts =
array(
/* Are we behind a proxy? */
'client_type' => LMT_LOGIN_DIR_ADD

/* Lock out after this many tries */
, 'allowed_retries' => 5

/* Lock the user for 30 minute */
, 'lock_after_duration' => 1800

/* block for long time after this many locks */
, 'allowed_lockouts' => 5

/* block for this many seconds */
, 'long_duration' => 86400 // 24 hours

/* Reset failed attempts after this many seconds */
, 'valid_duration' => 43200 // 12 hours

/* Also limit malformed/forged cookies? */
, 'cookies' => true

/* Notify on restiction. Values: '', 'log', 'email', 'log,email' */
, 'lock_after_notify' => 'log'

/* If notify by email, do so after this number of blocks */
, 'notify_email_after' => 4
);

$lmt_login_error_shown = false;
$lmt_login_just_block = false;
$lmt_login_nonempty_credentials = false;

?>
