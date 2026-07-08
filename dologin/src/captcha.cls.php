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
	 * Display recaptcha
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
	 * Validate recaptcha
	 *
	 * @since  1.6
	 */
	public function authenticate() {
		// This runs on the public login form / REST 2-step and is authenticated by the Turnstile token itself, not a WP nonce.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( empty( $_POST['cf-turnstile-response'] ) ) {
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

		$res = json_decode( $res['body'], true );
		defined( 'debug' ) && debug( '2fa challenge res:', $res );

		if ( empty( $res['success'] ) ) {
			$err_code = ! empty( $res['error-codes'][0] ) ? $res['error-codes'][0] : 'error';

			throw new \Exception( esc_html( $err_code ) );
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
		$token      = md5( sanitize_text_field( wp_unslash( $_POST['cf-turnstile-response'] ) ) . IP::me() );
		$expiration = 5 * MINUTE_IN_SECONDS;
		set_transient( $this->_generate_token_tag(), $token, $expiration );
	}

	/**
	 * Generate the token tag to use in storage
	 *
	 * @since 4.2
	 */
	private function _generate_token_tag() {
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
		return 'dologin_tmp_data_' . md5( $tag );
	}

	/**
	 * One time token validation and delete
	 *
	 * @since 4.2
	 */
	private function _validate_token() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotValidated
		$token         = md5( sanitize_text_field( wp_unslash( $_POST['cf-turnstile-response'] ) ) . IP::me() );
		$transient_key = $this->_generate_token_tag();
		$stored_token  = get_transient( $transient_key );

		if ( $stored_token === $token ) {
			delete_transient( $transient_key );
			return true;
		}

		return false;
	}
}
