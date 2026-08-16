<?php
/**
 * Password less class
 *
 * @since 1.4
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

class Pswdless extends Instance {

	const TYPE_GEN            = 'gen';
	const TYPE_LOCK           = 'lock';
	const TYPE_DEL            = 'del';
	const TYPE_TOGGLE_ONETIME = 'toggle_onetime';
	const TYPE_EXPIRE_7       = 'expire_7';

	private $_tb;

	protected function __construct() {
		$this->_tb = $this->cls( 'Data' )->tb( 'pswdless' );
	}

	/**
	 * Init
	 *
	 * @since  1.4
	 */
	public function init() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! empty( $_GET['dologin'] ) ) {
			add_action( 'init', array( $this, 'try_login' ) );
		}
	}

	/**
	 * Login
	 *
	 * @since  1.4
	 */
	public function try_login() {
		global $wpdb;

		$username = 'N/A';
		if ( KLSso::force_enabled() ) {
			$this->_error_page( 'dologin_kl_sso_required', 403 );
		}

		// This endpoint bypasses wp-login and must apply the same IP rules and failure limits.
		if ( $this->cls( 'Auth' )->is_ip_denied() ) {
			$this->_error_page( 'dologin_ip_denied', 403 );
		}
		if ( $this->cls( 'Auth' )->is_rate_limited() ) {
			$this->_error_page( 'dologin_rate_limited', 429 );
		}

		// Magic-link endpoint authenticated by the secret token in the URL, not a nonce.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$raw_token = isset( $_GET['dologin'] ) && is_string( $_GET['dologin'] ) ? sanitize_text_field( wp_unslash( $_GET['dologin'] ) ) : '';
		$info      = explode( '.', $raw_token );
		if ( 2 !== count( $info ) || empty( $info[0] ) || empty( $info[1] ) ) {
			return $this->_failed_login( $username );
		}

		$pid = (int) $info[0];
		if ( $pid <= 0 ) {
			return $this->_failed_login( $username );
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; id is prepared.
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `$this->_tb` WHERE id = %d", $pid ) );
		if ( $row ) {
			$user_info = get_userdata( $row->user_id );
			if ( $user_info ) {
				$username = $user_info->user_login;
			}
		}

		if ( ! $row || ! $user_info || ! Secret::verify_token( 'passwordless-login', (string) $info[1], (string) $row->hash ) ) {
			return $this->_failed_login( $username );
		}

		if ( $row->active != 1 ) {
			$this->_error_page( 'dologin_link_used', 410 );
		}

		if ( $row->expired_at < time() ) {
			$this->_error_page( 'dologin_link_expired', 410 );
		}

		$confirm_nonce_action = 'dologin_pswdless_confirm_' . hash( 'sha256', $raw_token );

		// Show login confirm page.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( empty( $_POST['confirmed'] ) ) {
			require_once DOLOGIN_DIR . 'tpl/pswdless_cfm.tpl.php';
			exit;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$confirm_nonce = empty( $_POST['dologin_confirm_nonce'] ) || ! is_string( $_POST['dologin_confirm_nonce'] ) ? '' : sanitize_text_field( wp_unslash( $_POST['dologin_confirm_nonce'] ) );
		if ( ! wp_verify_nonce( $confirm_nonce, $confirm_nonce_action ) ) {
			return $this->_failed_login( $username );
		}

		// Can login, update record first.
		$q = "UPDATE `$this->_tb` SET last_used_at = %d, count = count + 1";
		if ( $row->onetime ) {
			$q .= ', active = 0 ';
		}
		$q .= ' WHERE id = %d AND active = 1';
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; values are prepared.
		$updated = $wpdb->query( $wpdb->prepare( $q, array( time(), $pid ) ) );
		if ( 1 !== $updated ) {
			$this->_error_page( 'dologin_link_used', 410 );
		}

		// Login.
		wp_set_current_user( $user_info->ID );
		wp_set_auth_cookie( $user_info->ID, false );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- firing the WordPress core hook on programmatic login.
		do_action( 'wp_login', $user_info->user_login, $user_info );

		nocache_headers();

		Router::redirect( admin_url() );
	}

	/**
	 * Note failed login
	 *
	 * @since  1.4
	 */
	private function _failed_login( $username ) {
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- firing the WordPress core hook.
		do_action( 'wp_login_failed', $username );
		$this->_error_page( 'dologin_link_invalid', 403 );
	}

	/**
	 * Complete a rejected public token request with a localized page.
	 */
	private function _error_page( $tag, $status_code ) {
		GUI::error_page( $tag, $status_code );
		exit;
	}

	/**
	 * Expiration set
	 *
	 * @since  1.4
	 */
	private function _expire_link() {
		global $wpdb;

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$pid = empty( $_GET['dologin_id'] ) ? 0 : (int) $_GET['dologin_id'];
		if ( $pid <= 0 ) {
			return;
		}

		$q = "UPDATE `$this->_tb` SET expired_at = GREATEST( expired_at, %d ) + 86400 * 7 WHERE id = %d";
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; values are prepared.
		$wpdb->query( $wpdb->prepare( $q, time(), $pid ) );
	}

	/**
	 * Switch one time
	 *
	 * @since  1.4
	 */
	private function _onetime_link() {
		global $wpdb;

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$pid = empty( $_GET['dologin_id'] ) ? 0 : (int) $_GET['dologin_id'];
		if ( $pid <= 0 ) {
			return;
		}

		$q = "UPDATE `$this->_tb` SET onetime = ( onetime + 1 ) % 2 WHERE id = %d";
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; id is prepared.
		$wpdb->query( $wpdb->prepare( $q, $pid ) );
	}

	/**
	 * Lock
	 *
	 * @since  1.4
	 */
	private function _lock_link() {
		global $wpdb;

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$pid = empty( $_GET['dologin_id'] ) ? 0 : (int) $_GET['dologin_id'];
		if ( $pid <= 0 ) {
			return;
		}

		$q = "UPDATE `$this->_tb` SET active = ( active + 1 ) % 2 WHERE id = %d";
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; id is prepared.
		$wpdb->query( $wpdb->prepare( $q, $pid ) );
	}

	/**
	 * Delete
	 *
	 * @since  1.4.1
	 */
	public function del_link( $pid = false ) {
		global $wpdb;

		if ( ! $pid ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( empty( $_GET['dologin_id'] ) ) {
				return;
			}

			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$pid = (int) $_GET['dologin_id'];
		}

		$pid = (int) $pid;
		if ( $pid <= 0 ) {
			return;
		}

		$q = "DELETE FROM `$this->_tb` WHERE id = %d";
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; id is prepared.
		$wpdb->query( $wpdb->prepare( $q, $pid ) );
	}

	/**
	 * Generate link
	 *
	 * @since  1.4
	 * @access public
	 */
	public function gen_link( $src, $uid, $return_url = false ) {
		global $wpdb;

		$this->cls( 'Data' )->tb_create( 'pswdless' );

		$uid = (int) $uid;
		$user_info = $uid > 0 ? get_userdata( $uid ) : false;
		if ( ! $user_info ) {
			if ( $return_url ) {
				return 'Invalid User ID';
			}
			Router::redirect( admin_url( 'options-general.php?page=dologin' ) );
		}

		$token = s::rrand( 32 );
		$hash  = Secret::token_hash( 'passwordless-login', $token );
		if ( ! $hash ) {
			if ( $return_url ) {
				return false;
			}
			wp_die( esc_html__( 'Failed to protect the passwordless login token.', 'dologin' ) );
		}

		$q = "INSERT INTO `$this->_tb` SET user_id = %d, hash = %s, dateline = %d, onetime = 1, active = 1, src = %s, expired_at = %d";
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; values are prepared.
		$inserted = $wpdb->query( $wpdb->prepare( $q, array( $uid, $hash, time(), $src, time() + 86400 * 7 ) ) );
		$id = $wpdb->insert_id;
		if ( 1 !== $inserted || $id <= 0 ) {
			if ( $return_url ) {
				return false;
			}
			wp_die( esc_html__( 'Failed to save the passwordless login link.', 'dologin' ) );
		}

		$link = admin_url( '?dologin=' . $id . '.' . $token );
		if ( $return_url ) {
			return $link;
		}

		$this->show_generated_link( $link );
	}

	/**
	 * Display a newly generated bearer link once without persisting its raw token.
	 */
	private function show_generated_link( $link ) {
		$back = admin_url( 'options-general.php?page=dologin#pswdless' );
		$message = '<p>' . esc_html__( 'Copy this passwordless login link now. For database-leak protection, its secret token is not stored and cannot be shown again.', 'dologin' ) . '</p>'
			. '<p><code style="display:block;overflow-wrap:anywhere;padding:12px;">' . esc_html( $link ) . '</code></p>'
			. '<p><a class="button button-primary" href="' . esc_url( $back ) . '">' . esc_html__( 'Continue to Passwordless Links', 'dologin' ) . '</a></p>';
		wp_die( $message, esc_html__( 'Passwordless Link Created', 'dologin' ), array( 'response' => 200 ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- every dynamic value in the assembled admin-only message is escaped above.
	}

	/**
	 * Handler
	 *
	 * @since  1.4
	 */
	public function handler() {
		$type = Router::verify_type();

		switch ( $type ) {
			case self::TYPE_GEN:
				// phpcs:ignore WordPress.Security.NonceVerification.Recommended
				if ( ! empty( $_GET['uid'] ) ) {
					$user = wp_get_current_user();
					// phpcs:ignore WordPress.Security.NonceVerification.Recommended
					$this->gen_link( $user->display_name, (int) $_GET['uid'] );
				}
				break;

			case self::TYPE_LOCK:
				$this->_lock_link();
				break;

			case self::TYPE_DEL:
				$this->del_link();
				break;

			case self::TYPE_TOGGLE_ONETIME:
				$this->_onetime_link();
				break;

			case self::TYPE_EXPIRE_7:
				$this->_expire_link();
				break;

			default:
				break;
		}
	}
}
