<?php
defined( 'WPINC' ) || exit;


function dologin_update_1_4_1() {
	global $wpdb;
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- one-time schema migration on the plugin's own custom table; table name is a hardcoded internal identifier.
	$wpdb->query( 'ALTER TABLE `' . $wpdb->prefix . "dologin_pswdless` ADD COLUMN `src` varchar(255) NOT NULL DEFAULT '' AFTER `hash`" );
}

function dologin_update_4_0_0() {
	\dologin\Data::cls()->tb_create( 'site' );
}

function dologin_update_4_5_0() {
	global $wpdb;

	// SMS login is legacy and no longer participates in DoLogin authentication.
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared -- one-time schema migration on the plugin's own legacy table.
	$wpdb->query( 'DROP TABLE IF EXISTS `' . $wpdb->prefix . 'dologin_sms`' );

	delete_option( 'dologin.sms' );
	delete_option( 'dologin.sms_force' );
}

function dologin_update_4_6_0() {
	delete_option( 'dologin.kl_sso_app_tag' );
	delete_option( 'dologin.kl_sso_app_hash' );
	delete_option( 'dologin.kl_sso_api_base' );
	delete_option( 'dologin.kl_sso_ws_url' );
}

/**
 * Protect legacy bearer tokens and recoverable authentication secrets at rest.
 */
function dologin_update_4_7_4() {
	$data = \dologin\Data::cls();
	$data->tables_create();

	dologin_migrate_token_hashes( $data->tb( 'pswdless' ), 'passwordless-login' );
	dologin_migrate_token_hashes( $data->tb( 'site' ), 'site-connection' );
	dologin_migrate_twofa_secrets();

	$site_sk = (string) \dologin\Conf::val( '_sk' );
	if ( $site_sk && ! \dologin\Secret::is_sealed( $site_sk ) ) {
		$sealed = \dologin\Secret::seal( 'site-easy-login-signing-key', $site_sk );
		if ( $sealed ) {
			\dologin\Conf::update( '_sk', $sealed );
		}
	}
}

/**
 * Remove the obsolete force-mode activation-owner marker.
 */
function dologin_update_4_7_5() {
	\dologin\Conf::delete( '_kl_sso_force_uid' );
}

/**
 * Replace raw token values with purpose-bound HMAC verifiers.
 */
function dologin_migrate_token_hashes( $table, $purpose ) {
	global $wpdb;

	$last_id = 0;
	do {
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery -- one-time migration of a hardcoded internal table; the cursor is prepared.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT id, hash FROM `$table` WHERE id > %d AND hash <> '' ORDER BY id ASC LIMIT 500", $last_id ) );
		if ( ! is_array( $rows ) ) {
			return false;
		}
		foreach ( $rows as $row ) {
			$last_id = (int) $row->id;
			$stored  = (string) $row->hash;
			if ( \dologin\Secret::is_token_hash( $stored ) ) {
				continue;
			}
			$hash = \dologin\Secret::token_hash( $purpose, $stored );
			if ( ! $hash ) {
				continue;
			}
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery -- one-time migration of a hardcoded internal table; all values are prepared and the old value is compared atomically.
			$wpdb->query( $wpdb->prepare( "UPDATE `$table` SET hash = %s WHERE id = %d AND hash = %s", $hash, $last_id, $stored ) );
		}
	} while ( 500 === count( $rows ) );

	return true;
}

/**
 * Encrypt existing TOTP shared secrets in bounded batches.
 */
function dologin_migrate_twofa_secrets() {
	global $wpdb;

	$last_id = 0;
	do {
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery -- one-time migration of WordPress user metadata; the key and cursor are prepared.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT umeta_id, meta_value FROM `$wpdb->usermeta` WHERE umeta_id > %d AND meta_key = %s ORDER BY umeta_id ASC LIMIT 500", $last_id, '2fa' ) );
		if ( ! is_array( $rows ) ) {
			return false;
		}
		foreach ( $rows as $row ) {
			$last_id = (int) $row->umeta_id;
			$stored  = (string) $row->meta_value;
			if ( ! $stored || \dologin\Secret::is_sealed( $stored ) ) {
				continue;
			}
			$sealed = \dologin\Secret::seal( 'totp-user-secret', $stored );
			if ( ! $sealed ) {
				continue;
			}
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery -- one-time usermeta migration; all values are prepared and the old value is compared atomically.
			$wpdb->query( $wpdb->prepare( "UPDATE `$wpdb->usermeta` SET meta_value = %s WHERE umeta_id = %d AND meta_value = %s", $sealed, $last_id, $stored ) );
		}
	} while ( 500 === count( $rows ) );

	return true;
}
