<?php
defined( 'WPINC' ) || exit;


function dologin_update_1_4_1() {
	global $wpdb;
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- one-time schema migration on the plugin's own custom table; table name is a hardcoded internal identifier.
	$wpdb->query( 'ALTER TABLE `' . $wpdb->prefix . "dologin_pswdless` ADD COLUMN `src` varchar(255) NOT NULL DEFAULT '' AFTER `hash`" );
}
