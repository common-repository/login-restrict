=== Login Restrict ===
Contributors: Wordpress.org
Donate link: https://skynetindia.info
Tags: login, security, authentication
Requires PHP: 5.6
Requires at least: 3.0.1
Tested up to: 5.2.2
Stable tag: 1.0
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

For security, it will lock account after number of login attempts.

== Description ==

By default WordPress allows unlimited login attempts through the login page but this will lock account after number of login attempts

Features

* Limit the number of login attempts
* Informs user about remaining attempts or block time on login page
* Optional logging, optional email notification
* Handles server behind reverse proxy
* It is possible to whitelist IPs using a filter.

Plugin uses standard actions and filters only.

== Installation ==

1. Download and extract plugin files to a wp-content/plugin directory.
2. Activate the plugin through the WordPress admin interface.
3. Customize the settings on the options page, if desired. If your server is located behind a reverse proxy make sure to change this setting.



== Frequently Asked Questions ==

= Why not reset failed attempts on a successful login? =

This is very much by design. Otherwise you could brute force the "admin" password by logging in as your own user every 4th attempt.

= What is this option about site connection and reverse proxy? =

A reverse proxy is a server in between the site and the Internet (perhaps handling caching or load-balancing). This makes getting the correct client IP to block slightly more complicated.

The option default to NOT being behind a proxy -- which should be by far the common case.

= How do I know if my site is behind a reverse proxy? =

You probably are not or you would know. We show a pretty good guess on the option page. Set the option using this unless you are sure you know better.

= Can I whitelist my IP so I don't get block? =

First please consider if you really need this. Generally speaking it is not a good idea to have exceptions to your security policies.

That said, there is now a filter which allows you to do it: "login_lmt_whitelist_ip".

Example:
function my_ip_whitelist($allow, $ip) {
	 return ($ip == 'my-ip') ? true : $allow;
}
add_filter('login_lmt_whitelist_ip', 'my_ip_whitelist', 10, 2);

Note that we still do notification and logging as usual. This is meant to allow you to be aware of any suspicious activity from whitelisted IPs.

= I locked myself out testing this thing, what do I do? =

Either wait, or:

If you know how to edit / add to PHP files you can use the IP whitelist functionality described above. You should then use the "Restore Lockouts" button on the plugin settings page and remove the whitelist function again.

If you have ftp / ssh access to the site rename the file "wp-content/plugins/login-limit/login-limit.php" to deactivate the plugin.

If you have access to the database (for example through phpMyAdmin) you can clear the login_lmt_blocks option in the wordpress options table. In a default setup this would work: "UPDATE wp_options SET option_value = '' WHERE option_name = 'login_lmt_blocks'"

== Screenshots ==

1. screenshot-1.png
2. screenshot-2.png
3. screenshot-3.png

== Changelog ==

= 1.0 =
* Initial version

== Upgrade Notice ==
=No Upgrade details=