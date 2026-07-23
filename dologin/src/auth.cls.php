<?php

/**
 * Login Auth class
 *
 * @since 1.0
 */

namespace dologin;

defined( 'WPINC' ) || exit;

class Auth extends Instance {

	const TYPE_CLEAR_LOG = 'clear_log';

	private $_tb;
	private $__data;
	private $_application_password_user_id;

	protected function __construct() {
		$this->__data = $this->cls( 'Data' );
		$this->_tb    = $this->__data->tb( 'failure' );
	}

	/**
	 * Init
	 *
	 * @since  1.0
	 * @access public
	 */
	public function init() {
		add_action( 'login_head', array( $this, 'login_head' ) );
		add_filter( 'authenticate', array( $this, 'authenticate' ), 2, 3 );
		add_filter( 'authenticate', array( $this, 'enforce_klsso' ), PHP_INT_MAX, 3 );
		add_action( 'application_password_did_authenticate', array( $this, 'allow_application_password' ), 10, 1 );
		// Recaptcha validation
		add_filter( 'registration_errors', array( $this, 'registration_errors' ) );
		add_filter( 'lostpassword_errors', array( $this, 'lostpassword_errors' ) );

		if ( Conf::val( '2fa' ) && ! KLSso::force_enabled() ) {
			add_filter( 'authenticate', array( $this->cls( 'TwoFA' ), 'authenticate' ), 30, 3 ); // Need to be after WP auth check
		}

		add_action( 'wp_login_failed', array( $this, 'wp_login_failed' ) );

		// XMLRPC
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			add_action( 'init', array( $this, 'check_xmlrpc' ) );
		}

		// Add notices for XMLRPC request
		add_filter( 'xmlrpc_login_error', array( $this, 'xmlrpc_error_msg' ) );
	}

	/**
	 * Check recaptcha for register
	 *
	 * @since 1.9
	 * @access public
	 */
	public function registration_errors( $errors ) {
		if ( Conf::val( 'cf' ) && Conf::val( 'recapt_register' ) ) {
			try {
				$this->cls( 'Captcha' )->authenticate(); // Need to be before WP auth check
			} catch ( \Exception $ex ) {
				$err_code = $ex->getMessage();
				defined( 'debug' ) && debug( '❌ reCAPTCHA error: ' . $err_code );

				$errors->add( 'captcha_err', Lang::msg( $err_code ) );
			}
		}

		return $errors;
	}

	/**
	 * Check recaptcha for lost password request
	 *
	 * @since 1.9
	 * @access public
	 */
	public function lostpassword_errors( $errors ) {
		if ( Conf::val( 'cf' ) && Conf::val( 'recapt_forget' ) ) {
			try {
				$this->cls( 'Captcha' )->authenticate(); // Need to be before WP auth check
			} catch ( \Exception $ex ) {
				$err_code = $ex->getMessage();
				defined( 'debug' ) && debug( '❌ reCAPTCHA error: ' . $err_code );

				$errors->add( 'captcha_err', Lang::msg( $err_code ) );
			}
		}

		return $errors;
	}

	/**
	 * Login page display messages
	 *
	 * @since  1.0
	 * @access public
	 */
	public function login_head() {
		global $error;

		if ( defined( 'DOLOGIN_ERR' ) ) {
			return;
		}

		// check whitelist
		if ( ! $this->try_whitelist() ) {
			// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- appending to the WP login $error global by design.
			$error .= Lang::msg( 'not_in_whitelist' );
			return;
		}

		// check blacklist
		if ( $this->try_blacklist() ) {
			// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- appending to the WP login $error global by design.
			$error .= Lang::msg( 'in_blacklist' );
			return;
		}

		// Check if has login error
		$err_msg = $this->_has_login_err( true );
		if ( $err_msg ) {
			// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- appending to the WP login $error global by design.
			$error .= $err_msg;
			return;
		}
	}

	/**
	 * Check if has login error limit
	 *
	 * @since  1.0
	 * @access private
	 */
	private function _has_login_err( $msg_only = false, $duration_rate = false, $retry_rate = false ) {
		global $wpdb;

		$ip = IP::me();
		if ( Conf::val( 'gdpr' ) ) {
			$ip = md5( $ip );
		}

		$duration = intval( Conf::val( 'duration' ) ) * 60;
		if ( $duration_rate ) {
			$duration *= $duration_rate;
		}

		$q = "SELECT COUNT(*) FROM `$this->_tb` WHERE ip = %s AND dateline > %s";
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; values are prepared.
		$err_count = $wpdb->get_var( $wpdb->prepare( $q, array( $ip, time() - $duration ) ) );

		if ( ! $err_count ) {
			return false;
		}

		$max_retries = Conf::val( 'max_retries' );
		if ( $retry_rate ) {
			$max_retries *= $retry_rate;
		}

		// Block visit
		if ( $err_count < $max_retries ) {
			if ( $msg_only ) {
				return Lang::msg( 'max_retries', $max_retries - $err_count );
			}
			return false;
		}

		// Can try but has failure
		return Lang::msg( 'max_retries_hit' );
	}

	/**
	 * Public check: is the current visitor IP currently over the failure limit?
	 * Reused by tokenized login endpoints (passwordless / site easy-login) that bypass the wp-login flow.
	 *
	 * @since  4.4
	 * @access public
	 */
	public function is_rate_limited() {
		return (bool) $this->_has_login_err();
	}

	/**
	 * Public check for tokenized/passwordless login flows that bypass wp-login authenticate filters.
	 *
	 * @since  4.5
	 * @access public
	 */
	public function is_ip_denied() {
		return ! $this->try_whitelist() || $this->try_blacklist();
	}

	/**
	 * Authenticate
	 *
	 * @since  1.0
	 * @access public
	 */
	public function authenticate( $user, $username, $password ) {
		if ( empty( $username ) || empty( $password ) ) {
			defined( 'debug' ) && debug( 'lack_of_u/p' );
			return $user;
		}

		if ( is_wp_error( $user ) ) {
			defined( 'debug' ) && debug( 'error already' );
			return $user;
		}

		$error = new \WP_Error();

		if ( ! $this->try_whitelist() ) {
			defined( 'debug' ) && debug( '❌ not_in_whitelist' );
			$error->add( 'not_in_whitelist', Lang::msg( 'not_in_whitelist' ) );
			! defined( 'DOLOGIN_ERR' ) && define( 'DOLOGIN_ERR', true );
		}

		if ( $this->try_blacklist() ) {
			defined( 'debug' ) && debug( '❌ in_blacklist' );
			$error->add( 'in_blacklist', Lang::msg( 'in_blacklist' ) );
			! defined( 'DOLOGIN_ERR' ) && define( 'DOLOGIN_ERR', true );
		}

		if ( ! defined( 'DOLOGIN_ERR' ) ) {
			$err_msg = $this->_has_login_err();
			if ( $err_msg ) {
				defined( 'debug' ) && debug( '❌ _has_login_err' );
				$error->add( 'in_blacklist', $err_msg );
				! defined( 'DOLOGIN_ERR' ) && define( 'DOLOGIN_ERR', true );
			}
		}

		// reCAPTCHA validate. Skip XML-RPC: machine clients cannot solve a captcha, and XML-RPC is already covered by the IP limiter + white/blacklist via check_xmlrpc().
		if ( ! defined( 'DOLOGIN_ERR' ) && Conf::val( 'cf' ) && ! ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) ) {
			try {
				$this->cls( 'Captcha' )->authenticate(); // Need to be before WP auth check
			} catch ( \Exception $ex ) {
				$err_code = $ex->getMessage();
				defined( 'debug' ) && debug( '❌ reCAPTCHA error: ' . $err_code );

				$error->add( 'captcha_err', Lang::msg( $err_code ) );
				! defined( 'DOLOGIN_ERR' ) && define( 'DOLOGIN_ERR', true );
			}
		}

		if ( defined( 'DOLOGIN_ERR' ) ) {
			// bypass verifying user info
			remove_filter( 'authenticate', 'wp_authenticate_username_password', 20 );
			remove_filter( 'authenticate', 'wp_authenticate_email_password', 20 );
			return $error;
		}

		defined( 'debug' ) && debug( '✅ passed' );

		return $user;
	}

	/**
	 * Enforce QR-only login after other authentication providers run.
	 *
	 * @since 4.6.5
	 */
	public function enforce_klsso( $user, $username, $password ) {
		if ( ! KLSso::force_enabled() ) {
			return $user;
		}
		if ( $user instanceof \WP_User && (int) $user->ID === (int) $this->_application_password_user_id ) {
			return $user;
		}

		$error = new \WP_Error();
		$error->add( 'kl_sso_required', __( 'KeyLockr SSO login is required.', 'dologin' ) );
		return $error;
	}

	/**
	 * Record the user authenticated by a WordPress Application Password for this request.
	 *
	 * @since 4.6.5
	 */
	public function allow_application_password( $user ) {
		if ( $user instanceof \WP_User ) {
			$this->_application_password_user_id = (int) $user->ID;
		}
	}

	/**
	 * Block XMLRPC if bad
	 *
	 * @since  1.2
	 * @access public
	 */
	public function check_xmlrpc() {
		if ( is_user_logged_in() ) {
			return;
		}

		if ( ! $this->try_whitelist() || $this->try_blacklist() || $this->_has_login_err() ) {
			header( 'HTTP/1.0 403 Forbidden' );
			exit;
		}
	}

	/**
	 * Valiadte XMLRPC
	 *
	 * @since  1.2
	 * @access public
	 */
	public function xmlrpc_error_msg( $err ) {
		if ( ! class_exists( 'IXR_Error' ) ) {
			return $err;
		}

		if ( ! $this->try_whitelist() ) {
			return new \IXR_Error( 403, Lang::msg( 'not_in_whitelist' ) );
		}

		if ( $this->try_blacklist() ) {
			return new \IXR_Error( 403, Lang::msg( 'in_blacklist' ) );
		}

		$err_msg = $this->_has_login_err();
		if ( $err_msg ) {
			return new \IXR_Error( 403, $err_msg );
		}

		return $err;
	}

	/**
	 * Log login failure
	 *
	 * @since  1.0
	 * @access public
	 */
	public function wp_login_failed( $user ) {
		global $wpdb;

		$ip = IP::me();

		// Do not trigger external GeoIP requests after the record limit is reached.
		if ( $this->_has_login_err( false, 10 ) ) {
			return;
		}

		// Parse Geo info
		$ip_geo_list = IP::geo( $ip );
		unset( $ip_geo_list['ip'] );
		$ip_geo = array();
		foreach ( $ip_geo_list as $k => $v ) {
			$ip_geo[] = $k . ':' . $v;
		}
		$ip_geo = implode( ', ', $ip_geo );

		// GDPR compliance
		if ( Conf::val( 'gdpr' ) ) {
			$ip = md5( $ip );
		}

		// Parse gateway
		$gateway = 'WP Login';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( isset( $_POST['woocommerce-login-nonce'] ) ) {
			$gateway = 'WooCommerce';
		} elseif ( isset( $GLOBALS['wp_xmlrpc_server'] ) && is_object( $GLOBALS['wp_xmlrpc_server'] ) ) {
			$gateway = 'XMLRPC';
		}

		$q = "INSERT INTO `$this->_tb` SET ip = %s, ip_geo = %s, username = %s, gateway = %s, dateline = %s";
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; values are prepared.
		$wpdb->query( $wpdb->prepare( $q, array( $ip, $ip_geo, $user, $gateway, time() ) ) );
	}

	/**
	 * Display log
	 *
	 * @since  2.7
	 * @access public
	 */
	public function history_list( $limit, $offset = false ) {
		global $wpdb;

		if ( $offset === false ) {
			$total  = $this->count_list();
			$offset = Util::pagination( $total, $limit, true );
		}

		$q = "SELECT * FROM `$this->_tb` ORDER BY id DESC LIMIT %d, %d";
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; values are prepared.
		return $wpdb->get_results( $wpdb->prepare( $q, $offset, $limit ) );
	}

	/**
	 * Count the log list
	 */
	public function count_list() {
		global $wpdb;

		if ( ! $this->__data->tb_exist( 'failure' ) ) {
			return false;
		}

		$q = "SELECT COUNT(*) FROM `$this->_tb`";
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; no user input.
		return $wpdb->get_var( $q );
	}

	/**
	 * Delete old log
	 */
	public function _clear_log() {
		global $wpdb;

		$q = "DELETE FROM `$this->_tb` WHERE dateline < %d";
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; value is prepared.
		$count = $wpdb->query( $wpdb->prepare( $q, time() - 86400 * 30 ) );

		GUI::succeed(
			sprintf(
				/* translators: %d: number of cleared records. */
				__( 'Cleared %d record(s) successfully!', 'dologin' ),
				$count
			)
		);
	}

	/**
	 * Validate if hit whitelist
	 *
	 * @since  1.0
	 * @access public
	 */
	private function try_whitelist() {
		$list = Conf::val( 'whitelist' );
		if ( ! $list ) {
			return true;
		}

		if ( $this->cls( 'IP' )->maybe_hit_rule( $list ) ) {
			return 'hit';
		}

		return false;
	}

	/**
	 * Validate if hit blacklist
	 *
	 * @since  1.0
	 * @access public
	 */
	private function try_blacklist() {
		$list = Conf::val( 'blacklist' );
		if ( ! $list ) {
			return false;
		}

		if ( $this->cls( 'IP' )->maybe_hit_rule( $list ) ) {
			return 'hit';
		}

		return false;
	}

	/**
	 * Handler
	 *
	 * @since  2.7
	 */
	public function handler() {
		$type = Router::verify_type();

		switch ( $type ) {
			case self::TYPE_CLEAR_LOG:
				$this->_clear_log();
				break;

			default:
				break;
		}
	}
}
