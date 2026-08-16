<?php
/**
 * Language class
 *
 * @since 1.0
 */
namespace dologin;

defined( 'WPINC' ) || exit;

class Lang extends Instance {
	/**
	 * Init hook
	 *
	 * @since  1.4.7
	 */
	public function init() {
		add_action( 'plugins_loaded', array( $this, 'plugins_loaded' ) );
	}

	/**
	 * Plugin loaded hooks
	 *
	 * @since 1.4.7
	 */
	public function plugins_loaded() {
		// phpcs:ignore PluginCheck.CodeAnalysis.DiscouragedFunctions.load_plugin_textdomainFound -- kept for backward compatibility with WordPress < 4.6 (plugin supports WP 4.0).
		load_plugin_textdomain( 'dologin', false, 'dologin/lang/' );
	}

	/**
	 * Format the translated remaining-attempts message around one replacement.
	 */
	private static function _remaining_attempts( $replacement ) {
		/* translators: %s: number of remaining login attempts. */
		return sprintf( __( '%s attempt(s) remaining.', 'dologin' ), $replacement );
	}

	/**
	 * Return the localized text for a message tag.
	 */
	public static function text( $tag, $num = null ) {
		switch ( $tag ) {
			case 'not_2fa_set_user':
				$msg = __( 'No 2FA set under this user profile.', 'dologin' );
				break;

			case 'empty_u_p':
				$msg = __( 'Empty username/password.', 'dologin' );
				break;

			case 'auth_failed':
				$msg = __( 'Invalid username/password.', 'dologin' );
				break;

			case 'not_in_whitelist':
				$msg = __( 'Your IP is not in the whitelist.', 'dologin' );
				break;

			case 'in_blacklist':
				$msg = __( 'Your IP is in the blacklist.', 'dologin' );
				break;

			case 'max_retries_hit':
				$msg = __( 'Too many failed login attempts. Please try later.', 'dologin' );
				break;

			case 'under_protected':
				$msg = __( 'ON', 'dologin' );
				break;

			case 'max_retries':
				$msg = self::_remaining_attempts( (int) $num );
				break;

			case 'dynamic_code_missing':
				$msg = __( 'Dynamic code is required.', 'dologin' );
				break;

			case 'dynamic_code_wrong':
				$msg = __( 'Dynamic code is not correct.', 'dologin' );
				break;

			case 'captcha_missing':
				$msg = __( 'Please complete the Cloudflare Turnstile verification.', 'dologin' );
				break;

			// @see https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
			case 'missing-input-response':
				$msg = __( 'The response parameter is missing.', 'dologin' );
				break;

			case 'invalid-input-response':
				$msg = __( 'The response parameter is invalid or malformed.', 'dologin' );
				break;

			case 'missing-input-secret':
				$msg = __( 'The secret parameter is missing.', 'dologin' );
				break;

			case 'invalid-input-secret':
				$msg = __( 'The secret parameter is invalid or malformed.', 'dologin' );
				break;

			case 'bad-request':
				$msg = __( 'The request is invalid or malformed.', 'dologin' );
				break;

			case 'timeout-or-duplicate':
				$msg = __( 'The response is no longer valid: either is too old or has been used previously.', 'dologin' );
				break;

			case 'captcha_transport_error':
			case 'captcha_service_error':
			case 'error':
			case 'internal-error':
				$msg = __( 'Cloudflare Turnstile verification is temporarily unavailable. Please try again.', 'dologin' );
				break;

			case 'dologin_kl_sso_required':
				$msg = __( 'KeyLockr SSO is required to log in to this site.', 'dologin' );
				break;

			case 'dologin_ip_denied':
				$msg = __( 'Login is not allowed from your IP address.', 'dologin' );
				break;

			case 'dologin_rate_limited':
				$msg = __( 'Too many failed login attempts. Please try again later.', 'dologin' );
				break;

			case 'dologin_link_invalid':
			case 'dologin_invalid_root_record':
				$msg = __( 'This login link is invalid.', 'dologin' );
				break;

			case 'dologin_link_used':
				$msg = __( 'This login link has already been used or disabled.', 'dologin' );
				break;

			case 'dologin_link_expired':
				$msg = __( 'This login link has expired.', 'dologin' );
				break;

			case 'dologin_sodium_unavailable':
				$msg = __( 'Secure login is temporarily unavailable. Please contact the site administrator.', 'dologin' );
				break;

			case 'dologin_token_generation_failed':
				$msg = __( 'Unable to create a secure login token. Please try again.', 'dologin' );
				break;

			case 'dologin_invalid_token_record':
			case 'dologin_site_token_invalid':
				$msg = __( 'This site connection token is invalid.', 'dologin' );
				break;

			case 'dologin_site_token_missing':
				$msg = __( 'Enter a child-site connection token.', 'dologin' );
				break;

			case 'dologin_site_connection_failed':
				$msg = __( 'Unable to connect to the child site. Check the connection token and try again.', 'dologin' );
				break;

			case 'dologin_site_clock_mismatch':
				$msg = __( 'The root and child site clocks are too far apart to complete the connection.', 'dologin' );
				break;

			case 'dologin_site_same_url':
				$msg = __( 'A site cannot connect to itself.', 'dologin' );
				break;

			case 'dologin_site_already_connected':
				$msg = __( 'This root site is already connected for the selected user.', 'dologin' );
				break;

			case 'dologin_token_expired':
				$msg = __( 'This site connection token has expired.', 'dologin' );
				break;

			case 'dologin_token_used':
				$msg = __( 'This site connection token has already been used.', 'dologin' );
				break;

			default:
				$msg = __( 'Unable to complete this request. Please try again.', 'dologin' );
				break;
		}

		return $msg;
	}

	public static function msg( $tag, $num = null ) {
		$msg = 'max_retries' === $tag
			? self::_remaining_attempts( '<strong>' . (int) $num . '</strong>' )
			: self::text( $tag, $num );

		return '<strong>' . __( 'DoLogin Security', 'dologin' ) . '</strong>: ' . $msg;
	}
}
