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

	/**
	 * Display Cloudflare Turnstile
	 *
	 * @since  1.6
	 */
	public function show() {
		// Cloudflare Turnstile must load its api.js from Cloudflare's domain; it cannot be self-hosted.
		// phpcs:ignore PluginCheck.CodeAnalysis.EnqueuedResourceOffloading.OffloadedContent
		wp_register_script( 'dologin_cf_api', 'https://challenges.cloudflare.com/turnstile/v0/api.js', array(), Core::VER, true );
		wp_enqueue_script( 'dologin_cf_api' );

		echo '<div class="cf-turnstile" data-sitekey="' . esc_attr( Conf::val( 'cf_pub_key' ) ) . '"></div>';
	}

	/**
	 * Validate Cloudflare Turnstile
	 *
	 * @since  1.6
	 */
	public function authenticate() {
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

		// Mark this session as trusted, to prevent duplicate check when submitting 2FA.
		$this->_store_token();

		defined( 'debug' ) && debug( '✅ passed' );
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
