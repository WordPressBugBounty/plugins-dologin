<?php
/**
 * Core class
 *
 * @since 1.0
 */
namespace dologin;

defined( 'WPINC' ) || exit;

class Core extends Instance {
	const VER = DOLOGIN_V;

	/**
	 * Init
	 *
	 * @since  1.0
	 * @access protected
	 */
	protected function __construct() {
		defined( 'debug' ) && debug2( 'init' );

		$this->cls( 'Conf' )->init();

		if ( is_admin() ) {
			$this->cls( 'Admin' )->init();
		}

		$this->cls( 'Auth' )->init();

		$this->cls( 'GUI' )->init();

		$this->cls( 'REST' )->init();

		$this->cls( 'Util' )->init();

		$this->cls( 'Router' )->init();

		$this->cls( 'Pswdless' )->init();

		$this->cls( 'Site' )->init();

		$this->cls( 'KLSso' )->init();

		register_activation_hook( DOLOGIN_DIR . 'dologin.php', __NAMESPACE__ . '\Util::activate' );
		register_deactivation_hook( DOLOGIN_DIR . 'dologin.php', __NAMESPACE__ . '\Util::deactivate' );
		register_uninstall_hook( DOLOGIN_DIR . 'dologin.php', __NAMESPACE__ . '\Util::uninstall' );

		add_action( 'wp_initialize_site', __NAMESPACE__ . '\Util::new_site', 10, 1 );
		add_action( 'wpmu_new_blog', __NAMESPACE__ . '\Util::new_site', 10, 1 );

		$this->cls( 'Lang' )->init();
	}
}
