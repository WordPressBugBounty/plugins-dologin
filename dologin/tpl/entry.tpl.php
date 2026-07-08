<?php
/**
 * Main settings page wrapper template.
 *
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

$dologin_menu_list = array(
	'site'     => __( 'Site Connections', 'dologin' ),
	'setting'  => __( 'Settings', 'dologin' ),
	'pswdless' => __( 'Passwordless Login', 'dologin' ),
	'log'      => __( 'Login Attempts Log', 'dologin' ),
);
?>
<div class="wrap dologin-settings">
	<h1 class="dologin-h1">
		<?php esc_html_e( 'DoLogin Security', 'dologin' ); ?>
	</h1>
	<span class="dologin-desc">
		v<?php echo esc_html( Core::VER ); ?>
	</span>
	<hr class="wp-header-end">
</div>

<div class="dologin-wrap">
	<h2 class="dologin-header nav-tab-wrapper">
	<?php
	$dologin_i = 1;
	foreach ( $dologin_menu_list as $dologin_tab => $dologin_val ) {
		echo "<a class='dologin-tab nav-tab' href='#" . esc_attr( $dologin_tab ) . "' data-dologin-tab='" . esc_attr( $dologin_tab ) . "'";
		if ( $dologin_i <= 9 ) {
			echo " dologin-accesskey='" . (int) $dologin_i . "'";
		}
		echo '>' . esc_html( $dologin_val ) . '</a>';
		++$dologin_i;
	}
	?>
	</h2>

	<div class="dologin-body">
	<?php
	// Include all tab templates up front for faster switching.
	foreach ( $dologin_menu_list as $dologin_tab => $dologin_val ) {
		echo "<div data-dologin-layout='" . esc_attr( $dologin_tab ) . "'>";
		require DOLOGIN_DIR . 'tpl/' . $dologin_tab . '.tpl.php';
		echo '</div>';
	}
	?>
	</div>

</div>

<h2 style="margin: 30px;">
	<a href="https://wordpress.org/support/plugin/dologin/reviews/?rate=5#new-post" target="_blank"><?php esc_html_e( 'Rate Us!', 'dologin' ); ?>
		<span class="wporg-ratings rating-stars" style="text-decoration: none;">
			<span class="dashicons dashicons-star-filled" style="color:#ffb900 !important;"></span><span class="dashicons dashicons-star-filled" style="color:#ffb900 !important;"></span><span class="dashicons dashicons-star-filled" style="color:#ffb900 !important;"></span><span class="dashicons dashicons-star-filled" style="color:#ffb900 !important;"></span><span class="dashicons dashicons-star-filled" style="color:#ffb900 !important;"></span>
		</span>
	</a>
</h2>
