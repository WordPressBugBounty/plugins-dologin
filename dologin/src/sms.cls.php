<?php
/**
 * SMS class
 *
 * @since 1.3
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

class SMS extends Instance {

	private $_dry_run = false;

	/**
	 * GUI notice when no phone set.
	 */
	public function gui_notice() {
		$current_user_phone = $this->current_user_phone();
		if ( ! $current_user_phone && Conf::val( 'sms' ) && Conf::val( 'sms_force' ) ) {
			GUI::error( DOLOGIN_LOGO . __( 'You need to setup your Dologin Phone number before enabling this setting to avoid yourself being blocked from next time login.', 'dologin' ) . ' <a href="profile.php">' . __( 'Click here to set your Dologin Security phone number', 'dologin' ) . '</a>' );
		}
	}

	/**
	 * Return current usre's phone number
	 *
	 * @since 1.3
	 */
	public function current_user_phone() {
		$uid   = get_current_user_id();
		$phone = get_user_meta( $uid, 'phone_number', true );
		return $phone;
	}

	/**
	 * Check if is dry run (dry run = before sending sms) or not
	 *
	 * @since  1.6
	 */
	public static function is_dry_run() {
		return self::cls()->_dry_run;
	}

	/**
	 * Verify SMS after u+p authenticated
	 *
	 * @since  1.3
	 *
	 * @param mixed  $user     WP_User or WP_Error from earlier authenticate filters.
	 * @param string $username Submitted username.
	 * @param string $password Submitted password.
	 * @return mixed
	 */
	public function authenticate( $user, $username, $password ) {
		global $wpdb;

		defined( 'debug' ) && debug( 'auth' );

		if ( $this->_dry_run ) {
			defined( 'debug' ) && debug( 'bypassed due to dryrun' );
			return $user;
		}

		if ( empty( $username ) || empty( $password ) ) {
			defined( 'debug' ) && debug( 'bypassed due to lack of u/p' );
			return $user;
		}

		if ( is_wp_error( $user ) ) {
			defined( 'debug' ) && debug( 'bypassed due to is_wp_error already' );
			return $user;
		}

		// If sms is optional and the user doesn't have phone set, bypass.
		$phone = get_user_meta( $user->ID, 'phone_number', true );
		if ( ! $phone ) {
			defined( 'debug' ) && debug( 'no phone number set' );
			if ( ! Conf::val( 'sms_force' ) ) {
				defined( 'debug' ) && debug( 'bypassed due to no force_sms check' );
				return $user;
			}
		}

		$error = new \WP_Error();

		// Validate dynamic code.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( empty( $_POST['dologin-two_factor_code'] ) ) {
			$error->add( 'dynamic_code_missing', Lang::msg( 'dynamic_code_missing' ) );
			define( 'DOLOGIN_ERR', true );
			defined( 'debug' ) && debug( '❌ sms missing' );
			return $error;
		}

		$tb_sms = $this->cls( 'Data' )->tb( 'sms' );

		$q = "SELECT id, code FROM $tb_sms WHERE user_id = %d AND used = 0";
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$tb_sms is a hardcoded internal table name; user_id is prepared.
		$row = $wpdb->get_row( $wpdb->prepare( $q, array( $user->ID ) ) );

		if ( $row && $row->id ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$tb_sms is a hardcoded internal table name; id is prepared.
			$wpdb->query( $wpdb->prepare( "UPDATE $tb_sms SET used = 1 WHERE id = %d", array( $row->id ) ) );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$submitted_code = sanitize_text_field( wp_unslash( $_POST['dologin-two_factor_code'] ) );
		if ( ! $row || ! $row->code || ! hash_equals( (string) $row->code, (string) $submitted_code ) ) {
			$error->add( 'dynamic_code_wrong', Lang::msg( 'dynamic_code_wrong' ) );
			define( 'DOLOGIN_ERR', true );
			defined( 'debug' ) && debug( '❌ sms wrong' );
			return $error;
		}

		defined( 'debug' ) && debug( '✅ auth successfully' );

		return $user;
	}

	/**
	 * Send test SMS
	 *
	 * @since  1.3
	 */
	public function test_send() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( empty( $_POST['phone'] ) ) {
			return REST::err( Lang::msg( 'not_phone_set_curr' ) );
		}

		// Check interval.
		if ( time() - get_option( 'dologin_test' ) < 60 ) {
			return REST::err( Lang::msg( 'try_after', 60 ) );
		}

		update_option( 'dologin_test', time() );

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$phone = sanitize_text_field( wp_unslash( $_POST['phone'] ) );

		// Send.
		try {
			$res = $this->_api( $phone, array( 'type' => 'test' ) );
		} catch ( \Exception $ex ) {
			return REST::err( $ex->getMessage() );
		}

		return REST::ok( array( 'info' => 'Sent to ***' . substr( $phone, -4 ) . ' at ' . gmdate( 'm/d/Y H:i:s', time() + get_option( 'gmt_offset' ) * 60 * 60 ) ) );
	}

	/**
	 * Send SMS
	 *
	 * @since  1.3
	 */
	public function send() {
		global $wpdb;

		if ( ! Conf::val( 'sms' ) ) {
			return REST::ok( array( 'bypassed' => 1 ) );
		}

		$field_u = 'log';
		$field_p = 'pwd';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( isset( $_POST['woocommerce-login-nonce'] ) ) {
			$field_u = 'username';
			$field_p = 'password';
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( empty( $_POST[ $field_u ] ) || empty( $_POST[ $field_p ] ) ) {
			return REST::err( Lang::msg( 'empty_u_p' ) );
		}

		// Verify u & p first.
		$this->_dry_run = true;
		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$user           = wp_authenticate( $_POST[ $field_u ], $_POST[ $field_p ] );
		$this->_dry_run = false;
		if ( is_wp_error( $user ) ) {
			return REST::err( $user->get_error_message() );
		}

		// Search if the user has number set in phone.
		$phone = get_user_meta( $user->ID, 'phone_number', true );

		if ( ! $phone ) {
			if ( ! Conf::val( 'sms_force' ) ) {
				defined( 'debug' ) && debug( 'bypassed due to no phone set' );
				return REST::ok( array( 'bypassed' => 1 ) );
			}
			return REST::err( Lang::msg( 'not_phone_set_user' ) );
		}

		// Throttle real SMS sending per user to prevent SMS flooding / toll fraud abuse.
		$throttle_key = 'dologin_sms_' . $user->ID;
		if ( get_transient( $throttle_key ) ) {
			return REST::err( Lang::msg( 'try_after', 60 ) );
		}
		set_transient( $throttle_key, time(), 60 );

		// Generate dynamic code.
		$code    = s::rrand( 4, 1 );
		$rid     = s::rrand( 2, 1 );
		$ip_info = ip::geo();
		$info    = sprintf(
			/* translators: 1: the dynamic login code, 2: a short tag id. */
			__( 'Dynamic Code:%1$s.(Tag:%2$s) From: ', 'dologin' ),
			$code,
			$rid
		) . $ip_info['country'] . '-' . $ip_info['city'] . '.';
		$data = array(
			'type' => 'login',
			'lang' => get_locale(),
			'code' => $code,
			'tag'  => $rid,
		);

		$tb_sms = $this->cls( 'Data' )->tb( 'sms' );

		// Expire old ones.
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$tb_sms is a hardcoded internal table name; user_id is prepared.
		$wpdb->query( $wpdb->prepare( "UPDATE $tb_sms SET used = -1 WHERE user_id = %d AND used = 0", array( $user->ID ) ) );

		// Save to db.
		$s = array(
			'user_id'  => $user->ID,
			'sms'      => $info,
			'code'     => $code,
			'used'     => 0,
			'dateline' => time(),
		);
		$q = 'INSERT INTO ' . $tb_sms . ' ( ' . implode( ',', array_keys( $s ) ) . ' ) VALUES ( ' . implode( ',', array_fill( 0, count( $s ), '%s' ) ) . ' )';
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$tb_sms is a hardcoded internal table name; values are prepared.
		$wpdb->query( $wpdb->prepare( $q, $s ) );
		$id = $wpdb->insert_id;

		// Send.
		try {
			$res = $this->_api( $phone, $data );
		} catch ( \Exception $ex ) {
			return REST::err( $ex->getMessage() );
		}

		// Update log.
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$tb_sms is a hardcoded internal table name; id is prepared.
		$wpdb->query( $wpdb->prepare( "UPDATE $tb_sms SET res = %s WHERE id = %d", array( $res, $id ) ) );

		$res_json = json_decode( $res, true );

		// Expected response.
		if ( ! empty( $res_json['_res'] ) && 'ok' === $res_json['_res'] ) {
			return REST::ok( array( 'info' => "Tag:$rid. Sent to ***" . substr( $phone, -4 ) . '.' ) );
		}

		if ( ! empty( $res_json['_msg'] ) ) {
			return REST::err( $res_json['_msg'] );
		}

		return REST::err( 'Unknown error' );
	}

	/**
	 * Call API to send msg
	 *
	 * @since  1.5
	 */
	private function _api( $phone, $data ) {
		// Send.
		$url  = 'https://doapi.us/text?format=json';
		$data = array(
			'app'    => 'dologin',
			'domain' => home_url(),
			'ip'     => ip::me(),
			'phone'  => $phone,
			'data'   => wp_json_encode( $data ),
		);

		$res = wp_remote_post(
			$url,
			array(
				'body'      => $data,
				'timeout'   => 15,
				'sslverify' => true,
			)
		);

		if ( is_wp_error( $res ) ) {
			$error_message = $res->get_error_message();
			throw new \Exception( esc_html( $error_message ) );
		}

		return $res['body'];
	}
}
