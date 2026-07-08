<?php
/**
 * Site easy-login confirmation page.
 *
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

// Prevent the secret login token in the URL from leaking to third parties via the Referer header.
if ( ! headers_sent() ) {
	header( 'Referrer-Policy: no-referrer' );
}
?>
<div style="max-width:520px;margin:60px auto;padding:24px;border:1px solid #ddd;border-radius:8px;font-family:sans-serif;text-align:center;">
	<h2><?php esc_html_e( 'DoLogin Easy Login Notice', 'dologin' ); ?></h2>
	<p><?php esc_html_e( 'You will login as the following user', 'dologin' ); ?>:</p>
	<p style="font-size:1.2em;color:#2a9d2a;"><?php echo esc_html( $user_info->user_login ); ?></p>
	<p><?php esc_html_e( 'to the site:', 'dologin' ); ?></p>
	<p style="font-size:1.2em;color:#2a9d2a;"><?php echo esc_url( site_url() ); ?></p>
	<form method="post" style="margin-top:24px;">
		<input type="hidden" name="confirmed" value="1">
		<button type="submit" style="padding:10px 24px;font-size:1em;background:#2a9d2a;color:#fff;border:none;border-radius:4px;cursor:pointer;"><?php esc_html_e( 'Click here to login', 'dologin' ); ?></button>
	</form>
</div>
