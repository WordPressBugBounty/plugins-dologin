<?php
/**
 * Standalone error page for public token endpoints.
 *
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

// Secret-bearing token URLs must not leak through referrers.
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
	<title><?php esc_html_e( 'DoLogin Security', 'dologin' ); ?></title>
</head>
<body style="margin:0;background:#f0f0f1;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen-Sans,Ubuntu,Cantarell,'Helvetica Neue',sans-serif;color:#1d2327;">
<main style="max-width:520px;margin:60px auto;padding:24px;background:#fff;border:1px solid #dcdcde;border-radius:8px;text-align:center;">
	<h1 style="margin:0 0 16px;font-size:1.3em;"><?php esc_html_e( 'DoLogin Security', 'dologin' ); ?></h1>
	<p style="margin:0;line-height:1.5;color:#b32d2e;"><?php echo esc_html( $message ); ?></p>
	<p style="margin:20px 0 0;"><a href="<?php echo esc_url( wp_login_url() ); ?>" style="color:#2271b1;text-decoration:underline;"><?php esc_html_e( 'Go to the login page', 'dologin' ); ?></a></p>
</main>
</body>
</html>
