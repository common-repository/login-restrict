<?php
/*
  Plugin Name: Login Restrict
  Description: For security, it will lock account after number of login attempts.
  Author: Skynet Technologies
  Author URI: https://www.skynetindia.info
  Text Domain: login-limit
  Version: 1.0
  Copyright 2019 - 2019 Skynet Technologies
  Licenced under the GNU GPL:

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

include_once("constant.php");
include_once("variables.php");

/*
 * Startup
 */

add_action('plugins_loaded', 'login_lmt_setup', 99999);
include_once("all-functions.php");


?>