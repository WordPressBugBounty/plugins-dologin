<?php
/**
 * 2FA class
 *
 * @since 3.5
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

class TwoFA extends Instance {

	private $_dry_run = false;

	/**
	 * Register replay-marker lifecycle cleanup.
	 */
	public function init() {
		add_action( 'added_user_meta', array( $this, 'clear_replay_marker_for_meta' ), 10, 3 );
		add_action( 'deleted_user_meta', array( $this, 'clear_replay_marker_for_meta' ), 10, 3 );
		add_action( 'deleted_user', array( $this, 'delete_replay_markers' ), 10, 1 );
		add_action( 'remove_user_from_blog', array( $this, 'delete_replay_marker' ), 10, 1 );
	}

	/**
	 * Delete replay state when a user's TOTP secret changes.
	 */
	public function clear_replay_marker_for_meta( $meta_ids, $user_id, $meta_key ) {
		if ( '2fa' === $meta_key ) {
			$this->delete_replay_markers( $user_id );
		}
	}

	/**
	 * Delete one user's replay markers from every site where they are a member.
	 */
	public function delete_replay_markers( $user_id ) {
		$user_id = (int) $user_id;
		if ( $user_id < 1 ) {
			return;
		}
		$this->delete_replay_marker( $user_id );
		if ( ! is_multisite() || ! function_exists( 'get_blogs_of_user' ) ) {
			return;
		}

		$current_blog_id = (int) get_current_blog_id();
		foreach ( (array) get_blogs_of_user( $user_id ) as $blog ) {
			$blog_id = is_object( $blog ) && isset( $blog->userblog_id ) ? (int) $blog->userblog_id : 0;
			if ( $blog_id < 1 || $current_blog_id === $blog_id ) {
				continue;
			}
			switch_to_blog( $blog_id );
			$this->delete_replay_marker( $user_id );
			restore_current_blog();
		}
	}

	/**
	 * Delete one user's replay marker from the current site.
	 */
	public function delete_replay_marker( $user_id ) {
		$user_id = (int) $user_id;
		if ( $user_id > 0 ) {
			delete_option( self::replay_option_name( $user_id ) );
		}
	}

	/**
	 * Maybe save user 2fa status
	 *
	 * @since 3.5
	 */
	public function maybe_save_2fa() {
		if ( empty( $_POST['dologin-2fa-code'] ) || ! is_string( $_POST['dologin-2fa-code'] ) ) {
			return;
		}
		if ( empty( $_POST['dologin-2fa-secret'] ) || ! is_string( $_POST['dologin-2fa-secret'] ) ) {
			return;
		}
		check_admin_referer( 'dologin-set2fa' );

		$secret = sanitize_text_field( wp_unslash( $_POST['dologin-2fa-secret'] ) );
		$code   = sanitize_text_field( wp_unslash( $_POST['dologin-2fa-code'] ) );

		$lib = new lib\Two_FA_Lib();
		if ( ! $lib->verifyCode( $secret, $code, 1 ) ) {
			GUI::error( __( 'Code verification failed!', 'dologin' ) );
			return;
		}

		// Set user's 2FA secret
		if ( $this->current_status() ) {
			GUI::error( __( 'You have set your 2FA secret before!', 'dologin' ) );
			return;
		}

		$uid = get_current_user_id();
		$sealed = Secret::seal( 'totp-user-secret', $secret );
		if ( ! $sealed || false === update_user_meta( $uid, '2fa', $sealed ) ) {
			GUI::error( __( 'Failed to encrypt the 2FA secret. The secret was not saved.', 'dologin' ) );
			return;
		}

		GUI::succeed( __( 'Congratulations! Your 2FA is successfully enabled!', 'dologin' ) );

		wp_safe_redirect( wp_get_referer() ? wp_get_referer() : admin_url() );
		exit;
	}

	/**
	 * Show GUI notice if missing 2fa in user profile
	 *
	 * @since 3.5
	 */
	public function gui_notice() {
		$current_user_2fa = $this->current_status();
		if ( ! $current_user_2fa && Conf::val( '2fa' ) ) {
			$installer = new Installer();
			if ( ! $installer->dash_notifier_is_plugin_active( 'doqrcode' ) ) {
				$install_link = Util::build_url( Router::ACTION_INSTALLER, Installer::TYPE_INSTALL_3RD, false, null, array( 'plugin' => 'doqrcode' ) );
				$desc         = __( 'You need to install the following plugin to enable 2FA', 'dologin' ) . ': <a href="' . esc_url( $install_link ) . '">WordPress QR Code generator (click to install)</a>';
				GUI::error( '<h2>' . DOLOGIN_LOGO . __( 'Dologin Notice', 'dologin' ) . '</h2>' . $desc );
				return;
			}

			$lib    = new lib\Two_FA_Lib();
			$secret = $lib->createSecret();
			$qrcode = do_shortcode( "[qrcode size='8' margin='3']" . $lib->getQRCodeGoogleUrl( get_bloginfo( 'name' ), $secret ) . '[/qrcode]' );
			$form   = '<form action="' . esc_url( menu_page_url( 'dologin', false ) ) . '" method="post"><input type="hidden" name="dologin-2fa-secret" value="' . esc_attr( $secret ) . '" />'
					. wp_nonce_field( 'dologin-set2fa', '_wpnonce', true, false )
					. esc_html__( 'Code', 'dologin' )
					. ': <input type="text" name="dologin-2fa-code" />'
					. get_submit_button( __( 'Enable 2FA', 'dologin' ) )
					. '</form>';

			$desc = __( 'Please scan this barcode w/ your phone 2FA app (e.g. KeyLockr or Google Authenticator) and type the code in 2FA app below.', 'dologin' );
			if ( Conf::val( '2fa_force' ) ) {
				$desc .= '<br/><span style="color:red;">' . __( 'You need to setup your 2FA before enabling this setting to avoid yourself being blocked from next time login.', 'dologin' ) . '</span>';
			}

			GUI::error( '<h2>' . DOLOGIN_LOGO . __( 'Dologin Notice', 'dologin' ) . '</h2>' . $desc . '<br />' . $qrcode . $form );
		}
	}

	/**
	 * Return current usre's 2fa status
	 *
	 * @since 3.5
	 */
	public function current_status() {
		$uid  = get_current_user_id();
		$code = get_user_meta( $uid, '2fa', true );
		return (bool) $code;
	}

	/**
	 * Check if is dry run or not
	 *
	 * @since  3.5
	 */
	public static function is_dry_run() {
		return self::cls()->_dry_run;
	}

	/**
	 * Verify code after u+p authenticated
	 *
	 * @since  3.5
	 *
	 * @param mixed  $user     WP_User or WP_Error from earlier authenticate filters.
	 * @param string $username Submitted username.
	 * @param string $password Submitted password.
	 * @return mixed
	 */
	public function authenticate( $user, $username, $password ) {
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

		// If 2fa is optional and the user doesn't have phone set, bypass.
		$code = $this->user_secret( $user->ID );
		if ( null === $code ) {
			defined( 'debug' ) && debug( 'no 2fa set' );
			if ( ! Conf::val( '2fa_force' ) ) {
				defined( 'debug' ) && debug( 'bypassed due to no force_2fa check' );
				return $user;
			}

			$error = new \WP_Error();
			$error->add( 'not_2fa_set_user', Lang::msg( 'not_2fa_set_user' ) );
			! defined( 'DOLOGIN_ERR' ) && define( 'DOLOGIN_ERR', true );
			return $error;
		}
		if ( false === $code ) {
			$error = new \WP_Error();
			$error->add( 'twofa_secret_unavailable', __( 'The stored 2FA secret cannot be decrypted. Restore the WordPress authentication salts or reset this user\'s 2FA secret.', 'dologin' ) );
			! defined( 'DOLOGIN_ERR' ) && define( 'DOLOGIN_ERR', true );
			return $error;
		}

		$error = new \WP_Error();

		// Validate dynamic code.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( empty( $_POST['dologin-two_factor_code'] ) || ! is_string( $_POST['dologin-two_factor_code'] ) ) {
			$error->add( 'dynamic_code_missing', Lang::msg( 'dynamic_code_missing' ) );
			! defined( 'DOLOGIN_ERR' ) && define( 'DOLOGIN_ERR', true );
			defined( 'debug' ) && debug( '❌ 2fa missing' );
			return $error;
		}

		$lib = new lib\Two_FA_Lib();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$submitted_code = sanitize_text_field( wp_unslash( $_POST['dologin-two_factor_code'] ) );
		$matched_slice  = $lib->findValidTimeSlice( $code, $submitted_code, 1 );
		if ( false === $matched_slice ) {
			$error->add( 'dynamic_code_wrong', Lang::msg( 'dynamic_code_wrong' ) );
			! defined( 'DOLOGIN_ERR' ) && define( 'DOLOGIN_ERR', true );
			defined( 'debug' ) && debug( '❌ 2fa wrong' );
			return $error;
		}

		// Remember the secret fingerprint and latest time slice to prevent TOTP replay within the valid window.
		$fingerprint = hash( 'sha256', (string) $code );
		if ( ! $this->consume_time_slice( $user->ID, $fingerprint, $matched_slice ) ) {
			$error->add( 'dynamic_code_wrong', Lang::msg( 'dynamic_code_wrong' ) );
			! defined( 'DOLOGIN_ERR' ) && define( 'DOLOGIN_ERR', true );
			defined( 'debug' ) && debug( '❌ 2fa replayed' );
			return $error;
		}

		defined( 'debug' ) && debug( '✅ auth successfully' );

		return $user;
	}

	/**
	 * Atomically consume a TOTP time slice with an option-value compare-and-swap.
	 */
	private function consume_time_slice( $user_id, $fingerprint, $time_slice ) {
		global $wpdb;

		$option_name = self::replay_option_name( $user_id );
		$new_value   = $fingerprint . ':' . (int) $time_slice;
		for ( $attempt = 0; $attempt < 2; $attempt++ ) {
			$current = (string) get_option( $option_name, '' );
			$parts   = explode( ':', $current, 2 );
			if ( 2 === count( $parts ) && hash_equals( $fingerprint, $parts[0] ) && (int) $time_slice <= (int) $parts[1] ) {
				return false;
			}
			if ( '' === $current ) {
				if ( add_option( $option_name, $new_value, '', false ) ) {
					return true;
				}
				wp_cache_delete( $option_name, 'options' );
				continue;
			}

			$q = "UPDATE `$wpdb->options` SET option_value = %s WHERE option_name = %s AND option_value = %s";
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery -- Per-user replay markers require an atomic compare-and-swap.
			$updated = $wpdb->query( $wpdb->prepare( $q, $new_value, $option_name, $current ) );
			wp_cache_delete( $option_name, 'options' );
			if ( 1 === $updated ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Build one user's current-site replay option name.
	 */
	private static function replay_option_name( $user_id ) {
		return 'dologin.2fa.last.' . (int) $user_id;
	}

	/**
	 * Read and, when necessary, migrate one user's encrypted TOTP secret.
	 *
	 * @return string|null|false Plain secret, null when missing, or false when unavailable.
	 */
	private function user_secret( $user_id ) {
		$stored = get_user_meta( (int) $user_id, '2fa', true );
		if ( ! is_string( $stored ) || '' === $stored ) {
			return null;
		}
		if ( Secret::is_sealed( $stored ) ) {
			$plain = Secret::open( 'totp-user-secret', $stored );
			return is_string( $plain ) && '' !== $plain ? $plain : false;
		}

		$sealed = Secret::seal( 'totp-user-secret', $stored );
		if ( ! $sealed || false === update_user_meta( (int) $user_id, '2fa', $sealed, $stored ) ) {
			$latest = get_user_meta( (int) $user_id, '2fa', true );
			if ( is_string( $latest ) && Secret::is_sealed( $latest ) ) {
				$plain = Secret::open( 'totp-user-secret', $latest );
				return is_string( $plain ) && '' !== $plain ? $plain : false;
			}
			return false;
		}
		return $stored;
	}

	/**
	 * Check if has enabled 2fa or not
	 *
	 * @since  3.5
	 */
	public function check() {
		if ( ! Conf::val( '2fa' ) ) {
			return REST::ok( array( 'bypassed' => 1 ) );
		}

		if ( $this->cls( 'Auth' )->is_ip_denied() ) {
			return REST::err( __( 'This IP is not allowed to login.', 'dologin' ) );
		}
		if ( $this->cls( 'Auth' )->is_rate_limited() ) {
			return REST::err( Lang::msg( 'max_retries_hit' ) );
		}

		$field_u = 'log';
		$field_p = 'pwd';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( isset( $_POST['woocommerce-login-nonce'] ) ) {
			$field_u = 'username';
			$field_p = 'password';
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( empty( $_POST[ $field_u ] ) || ! is_string( $_POST[ $field_u ] ) || empty( $_POST[ $field_p ] ) || ! is_string( $_POST[ $field_p ] ) ) {
			return REST::err( Lang::msg( 'empty_u_p' ) );
		}

		// Password contents must not be sanitized, but WordPress-added slashes must be removed.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$username = wp_unslash( $_POST[ $field_u ] );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$password = wp_unslash( $_POST[ $field_p ] );

		// Verify u & p first.
		$this->_dry_run = true;
		$user           = wp_authenticate( $username, $password );
		$this->_dry_run = false;
		if ( is_wp_error( $user ) ) {
			if ( $this->is_credential_error( $user ) ) {
				// wp_authenticate() already fired wp_login_failed, so do not count it again.
				return REST::err( Lang::msg( 'auth_failed' ) );
			}
			return REST::err( $user->get_error_message() );
		}

		// Search if the user has enabled 2fa or not.
		$twofa = $this->user_secret( $user->ID );

		if ( null === $twofa ) {
			if ( ! Conf::val( '2fa_force' ) ) {
				defined( 'debug' ) && debug( 'bypassed due to no 2fa set' );
				return REST::ok( array( 'bypassed' => 1 ) );
			}
			return REST::err( Lang::msg( 'not_2fa_set_user' ) );
		}
		if ( false === $twofa ) {
			return REST::err( __( 'The stored 2FA secret cannot be decrypted. Restore the WordPress authentication salts or reset this user\'s 2FA secret.', 'dologin' ) );
		}

		return REST::ok( array( 'info' => __( 'Please provide the code from your 2FA app', 'dologin' ) ) );
	}

	/**
	 * Whether a wp_authenticate() error should be counted as a login failure.
	 */
	private function is_credential_error( $error ) {
		$credential_codes = array(
			'incorrect_password',
			'invalid_email',
			'invalid_username',
		);
		foreach ( $credential_codes as $code ) {
			if ( $error->get_error_message( $code ) ) {
				return true;
			}
		}
		return false;
	}
}
