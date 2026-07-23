<?php
/**
 * Admin class
 *
 * @since 1.0
 */
namespace dologin;

defined( 'WPINC' ) || exit;

class Admin extends Instance {
	/**
	 * Init admin
	 *
	 * @since  1.0
	 * @access public
	 */
	public function init() {
		add_action( 'admin_menu', array( $this, 'admin_menu' ) );
		add_filter( 'plugin_action_links_dologin/dologin.php', array( $this, 'add_plugin_links' ) );
		add_action( 'admin_init', array( $this, 'admin_init' ) );

		add_action( 'admin_enqueue_scripts', array( $this->cls( 'GUI' ), 'enqueue_admin' ) );

		add_action( 'wp_dashboard_setup', array( $this, 'dashboard_widget' ) );
	}

	/**
	 * Register a dashboard widget
	 */
	public function dashboard_widget() {
		wp_add_dashboard_widget( 'dologin', __( 'DoLogin Security Overview', 'dologin' ), array( $this, 'widget_overview' ) );
	}

	/**
	 * Overview widget
	 */
	public function widget_overview() {
		require_once DOLOGIN_DIR . 'tpl/widget.tpl.php';
	}

	/**
	 * Admin setting page
	 *
	 * @since  1.0
	 * @access public
	 */
	public function admin_menu() {
		add_options_page( 'DoLogin Security', 'DoLogin Security', apply_filters( 'dologin_admin_menu_access', 'manage_options' ), 'dologin', array( $this, 'setting_page' ) );

		$this->cls( 'TwoFA' )->maybe_save_2fa();
	}

	/**
	 * admin_init
	 *
	 * @since  1.2.2
	 * @access public
	 */
	public function admin_init() {
		if ( get_transient( 'dologin_activation_redirect' ) ) {
			delete_transient( 'dologin_activation_redirect' );
			if ( ! is_network_admin() && ! isset( $_GET['activate-multi'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- reading WordPress core activation flag, no state change.
				wp_safe_redirect( menu_page_url( 'dologin', 0 ) );
			}
		}

		// Hide authentication fields that are managed only by dedicated flows.
		add_filter( 'user_contactmethods', array( $this, 'user_contactmethods' ), 10, 1 );
		add_filter( 'manage_users_columns', array( $this, 'manage_users_columns' ) );
		add_filter( 'manage_users_custom_column', array( $this, 'manage_users_custom_column' ), 10, 3 );

		add_action( 'admin_notices', array( $this->cls( 'GUI' ), 'display_msg' ) );
	}

	/**
	 * Remove authentication fields that cannot be edited on the standard profile page.
	 *
	 * @since  1.3
	 */
	public function user_contactmethods( $contactmethods ) {
		// The 2FA secret is managed only by its enrollment flow and must not appear in standard profile fields.
		unset( $contactmethods['2fa'] );
		return $contactmethods;
	}

	public function manage_users_columns( $column ) {
		if ( ! array_key_exists( 'dologin_operations', $column ) ) {
			$column['dologin_operations'] = __( 'Dologin Operations', 'dologin' );
		}
		if ( ! array_key_exists( '2fa', $column ) ) {
			$column['2fa'] = __( 'Dologin 2FA', 'dologin' );
		}
		return $column;
	}

	public function manage_users_custom_column( $val, $column_name, $user_id ) {
		if ( 'dologin_operations' === $column_name ) {
			$val = '<div class="dologin"><a href="' . esc_url( Util::build_url( Router::ACTION_SITE, Site::TYPE_GEN_TOKEN, false, null, array( 'uid' => $user_id ) ) ) . '" class="button dologin-btn-tiny dologin-btn-success dologin-mb10">' . esc_html__( 'Create Site Token', 'dologin' ) . '</a>';
			$val .= ' <a href="' . esc_url( Util::build_url( Router::ACTION_PSWD, Pswdless::TYPE_GEN, false, null, array( 'uid' => $user_id ) ) ) . '" class="button dologin-btn-primary dologin-btn-tiny">' . esc_html__( 'Generate Login Link', 'dologin' ) . '</a></div>';

			return $val;
		}

		if ( $column_name == '2fa' ) {
			$val = get_the_author_meta( '2fa', $user_id );
			$val = $val ? 'Enabled' : '-';
		}

		return $val;
	}

	/**
	 * Plugin link
	 *
	 * @since  1.1
	 * @access public
	 */
	public function add_plugin_links( $links ) {
		$links[] = '<a href="' . menu_page_url( 'dologin', 0 ) . '">' . __( 'Settings', 'dologin' ) . '</a>';

		return $links;
	}

	/**
	 * Display and save options
	 *
	 * @since  1.0
	 * @access public
	 */
	public function setting_page() {
		$this->cls( 'Data' )->tables_create();

		if ( ! empty( $_POST ) ) {
			check_admin_referer( 'dologin' );

			$raw_data = self::cleanup_text( $_POST );
			$force_was_enabled = (bool) Conf::val( 'kl_sso_force' );

			// Save options
			$list = array();

			foreach ( $this->cls( 'Conf' )->get_options() as $id => $v ) {
				if ( substr( $id, 0, 1 ) === '_' ) {
					continue;
				}

				$list[ $id ] = ! empty( $raw_data[ $id ] ) ? $raw_data[ $id ] : false;
			}

			// Special handler for list
			$list['whitelist'] = $this->_sanitize_list( $raw_data['whitelist'] );
			$list['blacklist'] = $this->_sanitize_list( $raw_data['blacklist'] );

			$save_errors = array();
			if ( ! empty( $list['kl_sso'] ) ) {
				$requirements = KLSso::requirements();
				if ( empty( $list['kl_sso_svc_id'] ) ) {
					$requirements[] = __( 'KeyLockr App Tag is required.', 'dologin' );
				}
				if ( ! empty( $requirements ) ) {
					$list['kl_sso'] = false;
					$save_errors[]  = __( 'KeyLockr SSO was not enabled.', 'dologin' ) . ' ' . implode( ' ', $requirements );
				}
			}
			if ( ! $force_was_enabled && ! empty( $list['kl_sso_force'] ) && ( empty( $list['kl_sso'] ) || ! KLSso::force_ready( $list['kl_sso_svc_id'] ) ) ) {
				$list['kl_sso_force'] = false;
				$save_errors[]         = __( 'Force KeyLockr SSO was not enabled. Link and verify the current administrator with the saved App Tag and site keys first.', 'dologin' );
			}

			foreach ( $list as $id => $v ) {
				Conf::update( $id, $v );
			}

			if ( $save_errors ) {
				GUI::error( implode( '<br />', array_map( 'esc_html', $save_errors ) ), true );
			} else {
				GUI::succeed( __( 'Options saved successfully!', 'dologin' ), true );
			}

			wp_safe_redirect( menu_page_url( 'dologin', false ) );
			exit;
		}

		require_once DOLOGIN_DIR . 'tpl/entry.tpl.php';
	}

	/**
	 * Clean up the input string of any extra slashes/spaces.
	 *
	 * @access public
	 */
	public static function cleanup_text( $input ) {
		if ( is_array( $input ) ) {
			return array_map( __CLASS__ . '::cleanup_text', $input );
		}

		return stripslashes( trim( $input ) );
	}

	/**
	 * Sanitize list
	 *
	 * @since  1.0
	 * @access public
	 */
	private function _sanitize_list( $list ) {
		if ( ! is_array( $list ) ) {
			$list = explode( "\n", trim( $list ) );
		}

		foreach ( $list as $k => $v ) {
			$list[ $k ] = implode( ', ', array_map( 'trim', explode( ',', $v ) ) );
		}

		return array_filter( $list );
	}

	/**
	 * Display pswdless
	 *
	 * @since  1.4
	 * @access public
	 */
	public function pswdless_log() {
		global $wpdb;

		$list = $wpdb->get_results( 'SELECT * FROM ' . $this->cls( 'Data' )->tb( 'pswdless' ) . ' ORDER BY id DESC' ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery -- table name is a hardcoded internal identifier.
		foreach ( $list as $k => $v ) {
			$user_info            = get_userdata( $v->user_id );
			$list[ $k ]->username = $user_info ? $user_info->user_login : __( 'Deleted user', 'dologin' );
		}

		return $list;
	}

	/**
	 * Display child sites
	 *
	 * @since  4.0
	 * @access public
	 */
	public function sites() {
		global $wpdb;

		$list = $wpdb->get_results( 'SELECT * FROM ' . $this->cls( 'Data' )->tb( 'site' ) . ' ORDER BY id DESC' ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery -- table name is a hardcoded internal identifier.
		foreach ( $list as $k => $v ) {
			$user_info            = get_userdata( $v->user_id );
			$list[ $k ]->username = $user_info ? $user_info->user_login : __( 'Deleted user', 'dologin' );
			$roles                = array();
			$easy_login           = '';
			if ( $v->is_child && $user_info ) {
				$roles = $user_info->roles;
			} else {
				$easy_login = Util::build_url( Router::ACTION_SITE, Site::TYPE_EASY_LOGIN, false, null, array( 'dologin_id' => $v->id ) );
			}
			$list[ $k ]->roles      = $roles;
			$list[ $k ]->easy_login = $easy_login;
			$list[ $k ]->_lock_link = Util::build_url( Router::ACTION_SITE, Pswdless::TYPE_LOCK, false, null, array( 'dologin_id' => $v->id ) );
			$list[ $k ]->_del_link  = Util::build_url( Router::ACTION_SITE, Pswdless::TYPE_DEL, false, null, array( 'dologin_id' => $v->id ) );
			$list[ $k ]->_valid     = time() - $v->dateline <= 3600;
		}

		return $list;
	}

}
