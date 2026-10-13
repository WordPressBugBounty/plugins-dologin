<?php
/** Verification method settings and isolated interactive preview. @package dologin */
namespace dologin;
defined( 'WPINC' ) || exit;
$dologin_captcha_method = Captcha::method();
?>
<h3 class="dologin-title-short"><?php esc_html_e( 'Bot Protection', 'dologin' ); ?></h3>
<table class="wp-list-table striped dologin-table dologin-captcha-settings">
	<tbody><tr>
		<th scope="row"><?php esc_html_e( 'Verification method', 'dologin' ); ?></th>
		<td>
		<fieldset class="dologin-captcha-methods">
			<legend class="screen-reader-text"><?php esc_html_e( 'Verification method', 'dologin' ); ?></legend>
			<div class="dologin-switch">
			<?php foreach ( Captcha_UI::methods() as $dologin_method => $dologin_label ) : ?>
				<input type="radio" id="captcha-method-<?php echo esc_attr( $dologin_method ); ?>" name="captcha_method" value="<?php echo esc_attr( $dologin_method ); ?>" <?php checked( $dologin_captcha_method, $dologin_method ); ?> /><label for="captcha-method-<?php echo esc_attr( $dologin_method ); ?>"><?php echo esc_html( $dologin_label ); ?></label>
			<?php endforeach; ?>
			</div>
		</fieldset>
	<div class="dologin-captcha-layout">
	<div class="dologin-captcha-options">
		<div class="dologin-desc" data-captcha-desc="off" <?php echo 'off' !== $dologin_captcha_method ? 'hidden' : ''; ?>>
			<p><?php esc_html_e( 'No bot-verification challenge is added. Login attempt limits and account authentication remain separate settings.', 'dologin' ); ?></p>
		</div>
		<div class="dologin-desc" data-captcha-desc="local" <?php echo ! in_array( $dologin_captcha_method, array( 'pow', 'sequence', 'puzzle' ), true ) ? 'hidden' : ''; ?>>
			<p><strong><?php esc_html_e( 'No service account, API keys or third-party requests.', 'dologin' ); ?></strong></p>
			<p><?php esc_html_e( 'The server issues a random challenge valid for five minutes. A Web Worker on the visitor’s device searches for a number whose SHA-256 hash, combined with that challenge, begins with 16 zero bits. This takes about 65,536 hashes on average; your server verifies the proof with one hash. Computation runs away from the page’s main thread and stops when the challenge is cancelled or its time limit is reached.', 'dologin' ); ?></p>
			<p><?php esc_html_e( 'The server binds the challenge to the request’s IP address and browser user agent, checks the answer, and issues a short-lived, single-use form ticket. A 2FA login can continue once with the same credentials. Preview challenges cannot authorize a login. Temporary records are bounded and expire after five minutes.', 'dologin' ); ?></p>
			<p><?php esc_html_e( 'PoW raises the cost of automated requests; it does not prove that a visitor is human and is not cryptocurrency mining. Faster hardware can still automate it. Keep login attempt limits enabled. It needs HTTPS and a modern JavaScript browser and may take longer or use more battery on slower devices. It does not replace passwords or 2FA.', 'dologin' ); ?></p>
		</div>
		<div class="dologin-desc" data-captcha-desc="sequence" <?php echo 'sequence' !== $dologin_captcha_method ? 'hidden' : ''; ?>>
			<p><?php esc_html_e( 'Click the three sample shapes in order anywhere on the image. Each click adds a green ring to record its position, including incorrect clicks; no answer is checked until the third click submits all three coordinates with PoW. Shapes have random positions, rotations and colors over a colored background. Match shapes, not colors. Keyboard users can move a free cursor with arrow keys (Shift for larger steps) and mark with Enter or Space.', 'dologin' ); ?></p>
			<p><?php esc_html_e( 'Only PNG pixels are sent to the browser; target positions and acceptance areas stay on the server. Color and distortion add visual variation but cannot guarantee resistance to image recognition or bots. Both image modes require PHP GD with PNG support. Choose Local PoW if GD or visual interaction is unavailable; no weaker fallback is applied automatically.', 'dologin' ); ?></p>
		</div>
		<div class="dologin-desc" data-captcha-desc="puzzle" <?php echo 'puzzle' !== $dologin_captcha_method ? 'hidden' : ''; ?>>
			<p><?php esc_html_e( 'Drag the large slider handle to fill the gap, then release to verify automatically. Keyboard users can adjust with arrow keys and press Enter to verify. The server accepts an alignment within four image pixels and also checks PoW. PHP GD with PNG support is required. Image matching can be automated; choose Local PoW if GD or visual interaction is unavailable.', 'dologin' ); ?></p>
		</div>
		<div class="dologin-desc" data-captcha-desc="turnstile" <?php echo 'turnstile' !== $dologin_captcha_method ? 'hidden' : ''; ?>>
			<p><?php esc_html_e( 'Cloudflare evaluates the browser and returns a token that this server verifies with Cloudflare. This method needs both keys and makes third-party network requests. Trying the preview consumes a test response without logging you in.', 'dologin' ); ?></p>
			<p><label><?php esc_html_e( 'Site Key', 'dologin' ); ?><br /><?php $dologin_gui->build_input( 'cf_pub_key', '' ); ?></label></p>
			<p><label><?php esc_html_e( 'Secret Key', 'dologin' ); ?><br /><?php $dologin_gui->build_input( 'cf_priv_key', '' ); ?></label></p>
			<?php // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- Optional Turnstile credentials are issued by Cloudflare; this dashboard cannot be self-hosted. ?>
			<p><a href="https://dash.cloudflare.com/?to=/:account/turnstile" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Get Turnstile keys', 'dologin' ); ?></a></p>
		</div>
	</div>
	<aside class="dologin-captcha-preview" aria-label="<?php esc_attr_e( 'Interactive verification preview', 'dologin' ); ?>">
		<h4><?php esc_html_e( 'Try it here', 'dologin' ); ?></h4>
		<p><?php esc_html_e( 'See the challenge and its actual server result before saving.', 'dologin' ); ?></p>
		<?php Captcha_UI::widget( $dologin_captcha_method, 'demo', true ); ?>
	</aside>
	</div>
		</td>
	</tr><tr>
		<th scope="row"><?php esc_html_e( 'Registration', 'dologin' ); ?></th>
		<td><?php $dologin_gui->build_switch( 'recapt_register' ); ?></td>
	</tr><tr>
		<th scope="row"><?php esc_html_e( 'Lost password', 'dologin' ); ?></th>
		<td><?php $dologin_gui->build_switch( 'recapt_forget' ); ?>
			<div class="dologin-desc"><?php esc_html_e( 'Login is protected whenever a method is enabled. Applies to WordPress forms and WooCommerce login. Forced KeyLockr SSO keeps its own login flow. Changes take effect after saving.', 'dologin' ); ?></div>
		</td>
	</tr></tbody>
</table>
