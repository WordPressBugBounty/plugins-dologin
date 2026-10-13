<?php
/**
 * Captcha class
 *
 * @since 1.6
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

class Captcha extends Instance {

	/** Saving local verification must not strand users on an insecure login origin. */
	public static function local_supported() {
		foreach ( array( site_url(), home_url(), wp_login_url() ) as $url ) {
			$host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
			$loopback = 'localhost' === $host || '[::1]' === $host || ( filter_var( $host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) && 0 === strpos( $host, '127.' ) );
			// Frontend login forms need a secure origin too; a loopback site must
			// not exempt an unrelated custom login or home URL from this check.
			if ( ! $loopback && ( ! is_ssl() || 'https' !== wp_parse_url( $url, PHP_URL_SCHEME ) ) ) { return false; }
		}
		return true;
	}
	/** Preserve the existing enabled flag and keys across provider selection. */
	public static function method() {
		if ( ! Conf::val( 'cf' ) ) {
			return 'off';
		}
		return Conf::val( 'captcha_method' ) ? Conf::val( 'captcha_method' ) : 'turnstile';
	}

	public static function enabled( $context = 'login' ) {
		if ( 'off' === self::method() ) {
			return false;
		}
		if ( 'login' === $context ) {
			return ! KLSso::force_enabled();
		}
		return ( 'register' === $context && Conf::val( 'recapt_register' ) ) || ( 'reset' === $context && Conf::val( 'recapt_forget' ) );
	}

	/**
	 * Display the selected verification provider.
	 *
	 * @since  1.6
	 */
	public function show( $context = 'login' ) {
		if ( 'turnstile' !== self::method() ) {
			Captcha_UI::widget( self::method(), $context );
			return;
		}
		// Cloudflare Turnstile must load its api.js from Cloudflare's domain; it cannot be self-hosted.
		// phpcs:ignore PluginCheck.CodeAnalysis.EnqueuedResourceOffloading.OffloadedContent
		wp_register_script( 'dologin_cf_api', 'https://challenges.cloudflare.com/turnstile/v0/api.js', array(), Core::VER, true );
		wp_enqueue_script( 'dologin_cf_api' );

		echo '<div class="cf-turnstile" data-sitekey="' . esc_attr( Conf::val( 'cf_pub_key' ) ) . '"></div>';
	}

	/**
	 * Validate the selected provider before the protected form action.
	 *
	 * @since  1.6
	 */
	public function authenticate( $context = 'login', $username = '', $password = '' ) {
		if ( in_array( self::method(), array( 'pow', 'sequence', 'puzzle' ), true ) ) {
			$this->cls( 'Captcha_Local' )->authenticate( $context, $username, $password );
			return;
		}
		// This runs on the public login form / REST 2-step and is authenticated by the Turnstile token itself, not a WP nonce.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( empty( $_POST['cf-turnstile-response'] ) || ! is_string( $_POST['cf-turnstile-response'] ) ) {
			throw new \Exception( 'captcha_missing' );
		}

		// Check if stored token matches, then bypass.
		if ( $this->_validate_token() ) {
			defined( 'debug' ) && debug( '✅ bypassed, token matched' );
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$cf_response = sanitize_text_field( wp_unslash( $_POST['cf-turnstile-response'] ) );
		$this->verify_turnstile( $cf_response );
		$this->_store_token();
	}

	/** Shared server check; previews never create a login continuation. */
	public function verify_turnstile( $cf_response ) {
		if ( ! is_string( $cf_response ) || '' === $cf_response || strlen( $cf_response ) > 2048 ) {
			throw new \Exception( 'captcha_missing' );
		}

		// phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- Cloudflare Turnstile verification endpoint; required by the captcha feature and cannot be self-hosted.
		$url  = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
		$data = array(
			'secret'   => Conf::val( 'cf_priv_key' ),
			'response' => $cf_response,
			'remoteip' => IP::me(),
		);

		$res = wp_safe_remote_post(
			$url,
			array(
				'body'                => $data,
				'timeout'             => 10,
				'redirection'         => 0,
				'limit_response_size' => 32768,
				'sslverify'           => true,
			)
		);

		if ( is_wp_error( $res ) ) {
			defined( 'debug' ) && debug( '❌ Turnstile transport error: ' . $res->get_error_message() );
			throw new \Exception( 'captcha_transport_error' );
		}

		if ( 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
			defined( 'debug' ) && debug( '❌ Turnstile service HTTP status: ' . (int) wp_remote_retrieve_response_code( $res ) );
			throw new \Exception( 'captcha_service_error' );
		}

		$res = json_decode( wp_remote_retrieve_body( $res ), true );
		defined( 'debug' ) && debug( 'Turnstile verification response:', $res );

		if ( empty( $res['success'] ) ) {
			$err_code = ! empty( $res['error-codes'][0] ) && is_string( $res['error-codes'][0] ) ? sanitize_key( $res['error-codes'][0] ) : 'error';
			$err_code = $err_code ? $err_code : 'error';

			throw new \Exception( $err_code );
		}

		defined( 'debug' ) && debug( '✅ passed' );
	}

	/** The REST route also enforces capability and WordPress REST nonce checks. */
	public function demo_turnstile( $request ) {
		nocache_headers();
		if ( ! current_user_can( apply_filters( 'dologin_admin_menu_access', 'manage_options' ) ) ) {
			return REST::err( __( 'You cannot preview verification settings.', 'dologin' ) );
		}
		try {
			$this->verify_turnstile( $request->get_param( 'response' ) );
			return REST::ok( array( 'message' => __( 'Passed: Cloudflare confirmed this response on the server.', 'dologin' ) ) );
		} catch ( \Exception $ex ) {
			return REST::err( Lang::text( $ex->getMessage() ) );
		}
	}

	/**
	 * Store token for 2nd step verification use
	 *
	 * @since 4.2
	 */
	private function _store_token() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotValidated
		$response   = sanitize_text_field( wp_unslash( $_POST['cf-turnstile-response'] ) );
		$expiration = 5 * MINUTE_IN_SECONDS;
		set_transient( $this->_generate_token_tag( $response ), true, $expiration );
	}

	/**
	 * Generate the token tag to use in storage
	 *
	 * @since 4.2
	 */
	private function _generate_token_tag( $response ) {
		$tag = IP::me();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! empty( $_POST['log'] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$tag = sanitize_text_field( wp_unslash( $_POST['log'] ) );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! empty( $_POST['user_login'] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$tag = sanitize_text_field( wp_unslash( $_POST['user_login'] ) );
		}
		return 'dologin_tmp_data_' . hash( 'sha256', $tag . '|' . IP::me() . '|' . (string) $response );
	}

	/**
	 * One time token validation and delete
	 *
	 * @since 4.2
	 */
	private function _validate_token() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotValidated
		$response      = sanitize_text_field( wp_unslash( $_POST['cf-turnstile-response'] ) );
		$transient_key = $this->_generate_token_tag( $response );
		$stored_token  = get_transient( $transient_key );

		if ( true === $stored_token || '1' === $stored_token ) {
			delete_transient( $transient_key );
			return true;
		}

		return false;
	}
}
