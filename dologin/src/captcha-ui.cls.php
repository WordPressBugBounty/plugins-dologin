<?php
/**
 * Shared local verification controls and localized browser configuration.
 *
 * @package dologin
 */
namespace dologin;

defined( 'WPINC' ) || exit;

class Captcha_UI {
	public static function methods() {
		return array(
			'off' => __( 'Off', 'dologin' ),
			'pow' => __( 'Local PoW', 'dologin' ),
			'sequence' => __( 'Ordered clicks + PoW', 'dologin' ),
			'puzzle' => __( 'Slider puzzle + PoW', 'dologin' ),
			'turnstile' => __( 'Cloudflare Turnstile', 'dologin' ),
		);
	}

	public static function enqueue( $demo = false ) {
		wp_enqueue_style( 'dologin-captcha', DOLOGIN_PLUGIN_URL . 'assets/captcha.css', array(), Core::VER );
		wp_enqueue_script( 'dologin-captcha', DOLOGIN_PLUGIN_URL . 'assets/captcha.js', array(), Core::VER, true );
		wp_localize_script( 'dologin-captcha', 'dologin_captcha', array(
			'url' => get_rest_url( null, 'dologin/v1/captcha/' ),
			'worker' => DOLOGIN_PLUGIN_URL . 'assets/captcha-worker.js?ver=' . Core::VER,
			'nonce' => $demo ? wp_create_nonce( 'wp_rest' ) : '',
			'sitekey' => $demo ? Conf::val( 'cf_pub_key' ) : '',
			'has_keys' => $demo && Conf::val( 'cf_pub_key' ) && Conf::val( 'cf_priv_key' ),
			'i18n' => array(
				'working' => __( 'Computing proof on this device…', 'dologin' ),
				'loading' => __( 'Loading challenge…', 'dologin' ),
				'checking' => __( 'Checking on the server…', 'dologin' ),
				'passed' => __( 'Verification passed.', 'dologin' ),
				'failed' => __( 'Could not complete verification. Start a new challenge and try again.', 'dologin' ),
				'unsupported' => __( 'Local verification needs HTTPS, JavaScript, Web Workers and Web Crypto in a modern browser.', 'dologin' ),
				'expired' => __( 'Verification expired. Please try again.', 'dologin' ),
				'required' => __( 'Complete verification before submitting.', 'dologin' ),
				'order' => __( 'Select these patterns in order:', 'dologin' ),
				'point' => __( 'Click the image, or use arrow keys to move and Enter or Space to mark a point. Backspace undoes the last point before submission. Green rings record clicks, not correct answers.', 'dologin' ),
				// translators: 1: recorded points, 2: required points.
				'points' => __( 'Recorded %1$d of %2$d points.', 'dologin' ),
				'patterns' => __( 'Find the three requested patterns in this image.', 'dologin' ),
				'drag' => __( 'Drag to fill the gap and release to verify. With a keyboard, adjust with arrow keys, then press Enter.', 'dologin' ),
				'position' => __( 'Puzzle piece position', 'dologin' ),
				'work_target' => __( 'SHA-256 · 16 zero bits · ~65,536 hashes on average', 'dologin' ),
				// translators: 1: hashes computed, 2: elapsed milliseconds, 3: hashes per second.
				'work_stats' => __( '%1$s hashes · %2$s ms · %3$s hashes/s', 'dologin' ),
				'work_wait' => __( 'Starting local computation…', 'dologin' ),
				'picture' => __( 'Landscape with a missing puzzle piece', 'dologin' ),
				'off' => __( 'Verification is off. Choose a method to try it.', 'dologin' ),
				'keys' => __( 'Save both Turnstile keys first. The preview uses the saved keys.', 'dologin' ),
				'cloudflare' => __( 'Complete the Turnstile challenge below.', 'dologin' ),
				// translators: %s: elapsed milliseconds measured by the browser.
				'elapsed' => __( 'Elapsed: %s ms', 'dologin' ),
			),
		) );
	}

	/** The same widget runs publicly and in the isolated admin preview. */
	public static function widget( $method, $context, $demo = false ) {
		self::enqueue( $demo );
		?>
		<div class="dologin-captcha" data-method="<?php echo esc_attr( $method ); ?>" data-context="<?php echo esc_attr( $context ); ?>" data-demo="<?php echo $demo ? '1' : '0'; ?>">
			<button class="dologin-captcha-refresh" type="button" aria-label="<?php esc_attr_e( 'Refresh challenge', 'dologin' ); ?>" title="<?php esc_attr_e( 'Refresh challenge', 'dologin' ); ?>"><svg aria-hidden="true" viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 7v5h-5M4 17v-5h5M19 11a7 7 0 0 0-12-4L4 10m16 4-3 3a7 7 0 0 1-12-4"/></svg></button>
			<p class="dologin-captcha-status" role="status" aria-live="polite"><?php esc_html_e( 'Ready to verify.', 'dologin' ); ?></p>
			<div class="dologin-captcha-stage"></div>
			<?php if ( ! $demo ) : ?>
				<input type="hidden" name="dologin-captcha-ticket" value="" />
			<?php endif; ?>
			<noscript><?php esc_html_e( 'JavaScript is required for verification.', 'dologin' ); ?></noscript>
		</div>
		<?php
	}
}
