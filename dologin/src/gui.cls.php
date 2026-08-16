<?php
/**
 * GUI class
 *
 * @since 1.0
 */
namespace dologin;

defined( 'WPINC' ) || exit;

class GUI extends Instance {
	const DB_MSG        = 'dologin.msg';
	const NOTICE_BLUE   = 'notice notice-info';
	const NOTICE_GREEN  = 'notice notice-success';
	const NOTICE_RED    = 'notice notice-error';
	const NOTICE_YELLOW = 'notice notice-warning';

	/**
	 * Init
	 *
	 * @since  1.3
	 * @access public
	 */
	public function init() {
		add_action( 'login_message', array( $this, 'login_message' ) );
		add_filter( 'login_body_class', array( $this, 'login_body_class' ), 10, 2 );
		add_filter( 'body_class', array( $this, 'frontend_body_class' ) );
		add_action( 'wp_enqueue_scripts', array( $this, 'frontend_enqueue_styles' ) );
		add_filter( 'lost_password_html_link', array( $this, 'lost_password_html_link' ), PHP_INT_MAX );
		add_filter( 'login_link_separator', array( $this, 'login_link_separator' ), PHP_INT_MAX );

		add_action( 'login_enqueue_scripts', array( $this, 'login_enqueue_scripts' ) );

		// Inject Cloudflare Turnstile into the registration form.
		add_action( 'register_form', array( $this, 'register_form' ) );

		add_action( 'lostpassword_form', array( $this, 'lostpassword_form' ) );

		// Append js and set ajax url
		add_action( 'login_form', array( $this, 'login_form' ) );

		add_action( 'woocommerce_login_form', array( $this, 'login_enqueue_scripts' ) );
		add_action( 'woocommerce_login_form', array( $this, 'login_form' ) );
	}

	/**
	 * Mark forced-SSO login screens for immediate password-reset link hiding.
	 *
	 * @since 4.8.1
	 */
	public function login_body_class( $classes, $action ) {
		if ( 'login' === $action && KLSso::force_enabled() ) {
			$classes[] = 'dologin-kl-force-login';
		}

		return $classes;
	}

	/**
	 * Mark frontend forced-SSO screens for non-JavaScript password-form hiding.
	 *
	 * @since 4.9.5
	 */
	public function frontend_body_class( $classes ) {
		if ( KLSso::force_enabled() ) {
			$classes[] = 'dologin-kl-force-login';
		}

		return $classes;
	}

	/**
	 * Load forced-login styles in the frontend head before WooCommerce renders.
	 *
	 * @since 5.0.1
	 */
	public function frontend_enqueue_styles() {
		if ( KLSso::force_enabled() ) {
			wp_enqueue_style( 'dologin-kl-force', DOLOGIN_PLUGIN_URL . 'assets/force-login.css', array(), Core::VER, 'all' );
		}
	}

	/**
	 * Drop the core lost-password link server-side while forced SSO is active (WP 6.1+).
	 *
	 * @since 4.8.1
	 */
	public function lost_password_html_link( $link ) {
		return KLSso::force_enabled() ? '' : $link;
	}

	/**
	 * Drop the nav separator that would otherwise dangle after the removed lost-password link.
	 *
	 * @since 4.8.1
	 */
	public function login_link_separator( $separator ) {
		return KLSso::force_enabled() ? '' : $separator;
	}

	/**
	 * Enqueue js
	 *
	 * @since  1.3
	 * @access public
	 */
	public function login_enqueue_scripts() {
		$this->enqueue_style();

		if ( Conf::val( '2fa' ) && ! KLSso::force_enabled() ) {
			wp_register_script( 'dologin', DOLOGIN_PLUGIN_URL . 'assets/login.js', array( 'jquery' ), Core::VER, false );

			$localize_data              = array();
			$localize_data['login_url'] = get_rest_url( null, 'dologin/v1/2fa' );
			wp_localize_script( 'dologin', 'dologin', $localize_data );

			wp_enqueue_script( 'dologin' );
		}

		if ( KLSso::enabled() || KLSso::force_enabled() ) {
			$this->enqueue_klsso_script( 'login' );
		}
	}

	/**
	 * Load style
	 *
	 * @since 1.3
	 */
	public function enqueue_style() {
		wp_enqueue_style( 'dologin', DOLOGIN_PLUGIN_URL . 'assets/login.css', array(), Core::VER, 'all' );
		wp_enqueue_style( 'dologin-kl-sso', DOLOGIN_PLUGIN_URL . 'assets/kl-sso.css', array( 'dologin' ), Core::VER, 'all' );
	}

	/**
	 * Load css/js for admin
	 *
	 * @since 2.0
	 */
	public function enqueue_admin( $hook ) {
		$page = '';
		if ( ! empty( $_GET['page'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- reading current admin page slug only, no state change.
			$page = sanitize_text_field( wp_unslash( $_GET['page'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- reading current admin page slug only, no state change.
		}

		$is_dologin_page = $page && 0 === strpos( $page, 'dologin' );
		$is_users_page   = 'users.php' === $hook;
		$is_profile_page = 'profile.php' === $hook;
		if ( ! $is_dologin_page && ! $is_users_page && ! $is_profile_page ) {
			return;
		}
		$this->enqueue_style();
		wp_enqueue_style( 'dologin-components', DOLOGIN_PLUGIN_URL . 'assets/login-components.css', array( 'dologin' ), Core::VER, 'all' );

		if ( $is_dologin_page || $is_users_page ) {
			wp_register_script( 'dologin_admin', DOLOGIN_PLUGIN_URL . 'assets/admin.js', array( 'jquery' ), Core::VER, false );

			$localize_data                       = array();
			$localize_data['url_myip']          = get_rest_url( null, 'dologin/v1/myip' );
			$localize_data['url_kl_reset_keys'] = get_rest_url( null, 'dologin/v1/kl_sso/reset_keys' );
			$localize_data['nonce']             = wp_create_nonce( 'wp_rest' );
			$localize_data['ip_lookup_progress'] = __( 'Looking up this IP address...', 'dologin' );
			$localize_data['ip_lookup_failed']   = __( 'Failed to look up this IP address.', 'dologin' );
			$localize_data['clear_log_confirm']   = __( 'Clear login-attempt records older than one month? This action cannot be undone.', 'dologin' );
			$localize_data['reset_keys_confirm'] = __( 'Reset the KeyLockr site keys? As the service owner, you must update Service key in the SSO Keys block in MyDeveloper before scanning again. Future scans will create a new KeyLockr connection, and linked accounts must then pass Verify Connection or a successful SSO login. Existing KeyLockr connection records are not removed.', 'dologin' );
			$localize_data['resetting_keys']     = __( 'Resetting KeyLockr site keys...', 'dologin' );
			$localize_data['reset_keys_failed']  = __( 'Failed to reset KeyLockr site keys.', 'dologin' );
			$localize_data['copy_public_key']     = __( 'Copy Public Key', 'dologin' );
			$localize_data['copied']             = __( 'Copied!', 'dologin' );
			$localize_data['copy_failed']         = __( 'Copy failed. Select and copy manually.', 'dologin' );
			wp_localize_script( 'dologin_admin', 'dologin_admin', $localize_data );

			wp_enqueue_script( 'dologin_admin' );
		}

		if ( KLSso::configured() && ( $is_dologin_page || $is_profile_page ) ) {
			$this->enqueue_klsso_script( 'bind' );
		}
	}

	/**
	 * Load KeyLockr SSO QR client.
	 */
	public function enqueue_klsso_script( $mode ) {
		wp_register_script( 'dologin_qrcode', DOLOGIN_PLUGIN_URL . 'qilu/npm/qrcode-generator/qrcode.js', array(), Core::VER, true );
		wp_register_script( 'dologin_kl_sso', DOLOGIN_PLUGIN_URL . 'assets/kl-sso.js', array( 'jquery', 'dologin_qrcode' ), Core::VER, true );

		wp_localize_script(
			'dologin_kl_sso',
			'dologin_kl_sso',
			array(
				'mode'             => $mode,
				'force'            => KLSso::force_enabled(),
				'url_start'        => get_rest_url( null, 'dologin/v1/kl_sso/start' ),
				'url_frame'        => get_rest_url( null, 'dologin/v1/kl_sso/frame' ),
				'url_unbind'       => get_rest_url( null, 'dologin/v1/kl_sso/unbind' ),
				'lostpassword_url' => wp_lostpassword_url(),
				'nonce'            => wp_create_nonce( 'wp_rest' ),
				'i18n'             => array(
					'connecting' => __( 'Connecting to KeyLockr...', 'dologin' ),
					'new_qr'     => __( 'Get New QR', 'dologin' ),
					'failed'     => __( 'KeyLockr SSO failed.', 'dologin' ),
					'done'       => __( 'KeyLockr SSO verified.', 'dologin' ),
					'unlink'     => __( 'Unlink KeyLockr SSO from this WordPress account?', 'dologin' ),
				),
			)
		);

		wp_enqueue_script( 'dologin_qrcode' );
		wp_enqueue_script( 'dologin_kl_sso' );
	}

	/**
	 * Display login form
	 *
	 * @since  1.3
	 * @access public
	 */
	public function login_form() {
		if ( Conf::val( '2fa' ) && ! KLSso::force_enabled() ) {
			echo '	<p id="dologin-process">
						Dologin Security:
						<span id="dologin-process-msg"></span>
					</p>
					<p id="dologin-dynamic_code">
						<label for="dologin-two_factor_code">' . esc_html__( 'Dynamic Code', 'dologin' ) . '</label>
						<br /><input type="text" name="dologin-two_factor_code" id="dologin-two_factor_code" autocomplete="off" />
					</p>
				';
		}

		$this->cls( 'KLSso' )->login_form();

		if ( Conf::val( 'cf' ) && ! KLSso::force_enabled() ) {
			$this->cls( 'Captcha' )->show();
		}
	}

	/**
	 * Inject register form
	 *
	 * @since  1.9
	 * @access public
	 */
	public function register_form() {
		if ( Conf::val( 'cf' ) && Conf::val( 'recapt_register' ) ) {
			$this->cls( 'Captcha' )->show();
		}
	}

	/**
	 * Inject lost password form
	 *
	 * @since  1.9
	 * @access public
	 */
	public function lostpassword_form() {
		if ( Conf::val( 'cf' ) && Conf::val( 'recapt_forget' ) ) {
			$this->cls( 'Captcha' )->show();
		}
	}

	/**
	 * Login default display messages
	 *
	 * @since  1.1
	 * @access public
	 */
	public function login_message( $msg ) {
		if ( defined( 'DOLOGIN_ERR' ) ) {
			return;
		}

		$msg .= '<div class="success">' . Lang::msg( 'under_protected' ) . '<img src="' . DOLOGIN_PLUGIN_URL . 'assets/shield.svg" class="dologin-shield"></div>';

		return $msg;
	}

	/**
	 * Register this setting to save
	 *
	 * @since  2.0
	 * @access public
	 */
	public function enroll( $id ) {
		echo '<input type="hidden" name="_settings-enroll[]" value="' . esc_attr( $id ) . '" />';
	}

	/**
	 * Build a textarea
	 *
	 * @since 2.0
	 * @access public
	 */
	public function build_textarea( $id, $cols = false, $val = null ) {
		if ( $val === null ) {
			$val = Conf::val( $id );

			if ( is_array( $val ) ) {
				$val = implode( "\n", $val );
			}
		}

		if ( ! $cols ) {
			$cols = 80;
		}

		$this->enroll( $id );

		echo "<textarea name='" . esc_attr( $id ) . "' rows='9' cols='" . esc_attr( $cols ) . "'>" . esc_textarea( $val ) . '</textarea>';
	}

	/**
	 * Build a text input field
	 *
	 * @since 2.0
	 * @access public
	 */
	public function build_input( $id, $cls = null, $val = null, $type = 'text' ) {
		if ( $val === null ) {
			$val = Conf::val( $id );
		}

		$label_id = preg_replace( '|\W|', '', $id );

		if ( $type == 'text' ) {
			$cls = "regular-text $cls";
		}

		$this->enroll( $id );

		echo "<input type='" . esc_attr( $type ) . "' class='" . esc_attr( $cls ) . "' name='" . esc_attr( $id ) . "' value='" . esc_textarea( $val ) . "' id='input_" . esc_attr( $label_id ) . "' /> ";
	}

	/**
	 * Build a switch div html snippet
	 *
	 * @since 1.2
	 * @access public
	 */
	public function build_switch( $id, $title_list = false ) {
		$this->enroll( $id );

		echo '<div class="dologin-switch">';

		if ( ! $title_list ) {
			$title_list = array(
				__( 'OFF', 'dologin' ),
				__( 'ON', 'dologin' ),
			);
		}

		foreach ( $title_list as $k => $v ) {
			$this->_build_radio( $id, $k, $v );
		}

		echo '</div>';
	}

	/**
	 * Build a radio input html codes and output
	 *
	 * @since 1.2
	 * @access private
	 */
	private function _build_radio( $id, $val, $txt ) {
		$id_attr = 'input_radio_' . preg_replace( '|\W|', '', $id ) . '_' . $val;

		if ( ! is_string( Conf::$_default_options[ $id ] ) ) {
			$checked = (int) Conf::val( $id, true ) === (int) $val ? ' checked ' : '';
		} else {
			$checked = Conf::val( $id, true ) === $val ? ' checked ' : '';
		}

		echo "<input type='radio' autocomplete='off' name='" . esc_attr( $id ) . "' id='" . esc_attr( $id_attr ) . "' value='" . esc_attr( $val ) . "' " . esc_attr( $checked ) . " /> <label for='" . esc_attr( $id_attr ) . "'>" . esc_html( $txt ) . '</label>';
	}

	/**
	 * Builds a single msg.
	 *
	 * @access private
	 */
	private static function _build_msg( $color, $str ) {
		return '<div class="' . $color . ' is-dismissible"><p>' . $str . '</p></div>';
	}

	/**
	 * Display info notice
	 *
	 * @access public
	 */
	public static function info( $msg, $echo = false ) {
		self::_add_notice( self::NOTICE_BLUE, $msg, $echo );
	}

	/**
	 * Display note notice
	 *
	 * @access public
	 */
	public static function note( $msg, $echo = false ) {
		self::_add_notice( self::NOTICE_YELLOW, $msg, $echo );
	}

	/**
	 * Display success notice
	 *
	 * @access public
	 */
	public static function succeed( $msg, $echo = false ) {
		self::_add_notice( self::NOTICE_GREEN, $msg, $echo );
	}

	/**
	 * Display error notice
	 *
	 * @access public
	 */
	public static function error( $msg, $echo = false ) {
		self::_add_notice( self::NOTICE_RED, $msg, $echo );
	}

	/**
	 * Render a standalone localized error page for a public token endpoint.
	 *
	 * The caller remains responsible for terminating the request after rendering.
	 */
	public static function error_page( $tag, $status_code = 400 ) {
		status_header( (int) $status_code );
		nocache_headers();

		$message = Lang::text( $tag );
		require DOLOGIN_DIR . 'tpl/error.tpl.php';
	}

	/**
	 * Adds a notice to display on the admin page
	 *
	 * @access private
	 */
	private static function _add_notice( $color, $msg, $echo = false ) {
		// Bypass adding for CLI or cron
		if ( defined( 'DOING_CRON' ) ) {
			// WP CLI will show the info directly
			if ( defined( 'WP_CLI' ) && WP_CLI ) {
				$msg = wp_strip_all_tags( $msg );
				if ( $color == self::NOTICE_RED ) {
					\WP_CLI::error( $msg );
				} else {
					\WP_CLI::success( $msg );
				}
			}
			return;
		}

		if ( $echo ) {
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- trusted plugin-generated admin notice markup.
			echo self::_build_msg( $color, $msg );
			return;
		}

		$messages = get_option( self::DB_MSG );

		if ( is_array( $msg ) ) {
			foreach ( $msg as $str ) {
				$messages[] = self::_build_msg( $color, $str );
			}
		} else {
			$messages[] = self::_build_msg( $color, $msg );
		}
		update_option( self::DB_MSG, $messages );
	}

	/**
	 * Display admin msg
	 *
	 * @access public
	 */
	public function display_msg() {
		$this->cls( 'TwoFA' )->gui_notice();

		// One time msg
		$messages = get_option( self::DB_MSG );
		if ( is_array( $messages ) ) {
			$messages = array_unique( $messages );

			$added_thickbox = false;
			foreach ( $messages as $msg ) {
				// Added for popup links
				if ( strpos( $msg, 'TB_iframe' ) && ! $added_thickbox ) {
					add_thickbox();
					$added_thickbox = true;
				}
				// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- trusted plugin-generated admin notice markup (may contain the 2FA setup form).
				echo $msg;
			}
		}
		delete_option( self::DB_MSG );
	}
}
