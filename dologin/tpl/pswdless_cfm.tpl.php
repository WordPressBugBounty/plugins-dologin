<?php
/**
 * Passwordless login confirmation page.
 *
 * Rendered standalone: the caller requires this file and exits, so nothing else emits markup.
 * The document skeleton and inline styles therefore live here; no stylesheet is enqueued on this request.
 *
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

nocache_headers();

// Prevent the secret login token in the URL from leaking to third parties via the Referer header.
if ( ! headers_sent() ) {
	header( 'Referrer-Policy: no-referrer' );
}
?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
	<meta charset="<?php bloginfo( 'charset' ); ?>" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<meta name="robots" content="noindex,nofollow" />
	<title><?php esc_html_e( 'DoLogin Notice', 'dologin' ); ?></title>
</head>
<body style="margin:0;background:#f0f0f1;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen-Sans,Ubuntu,Cantarell,'Helvetica Neue',sans-serif;color:#1d2327;">
<main style="max-width:520px;margin:60px auto;padding:24px;background:#fff;border:1px solid #dcdcde;border-radius:8px;text-align:center;">
	<h1 style="margin:0 0 16px;font-size:1.3em;"><?php esc_html_e( 'DoLogin Notice', 'dologin' ); ?></h1>
	<p style="margin:0 0 4px;"><?php esc_html_e( 'You will login as the following user', 'dologin' ); ?>:</p>
	<p style="margin:0;font-size:1.2em;font-weight:600;color:#1a7f37;"><?php echo esc_html( $username ); ?></p>
	<?php if ( $row->onetime ) : ?>
		<p style="margin:16px 0 0;color:#8a5700;"><?php esc_html_e( 'Note: this is a one time usage link.', 'dologin' ); ?></p>
	<?php endif; ?>
	<form method="post" style="margin-top:24px;">
		<?php wp_nonce_field( $confirm_nonce_action, 'dologin_confirm_nonce' ); ?>
		<input type="hidden" name="confirmed" value="1">
		<button type="submit" style="padding:10px 24px;font-size:1em;background:#1a7f37;color:#fff;border:none;border-radius:4px;cursor:pointer;"><?php esc_html_e( 'Click here to login', 'dologin' ); ?></button>
	</form>
</main>
</body>
</html>
