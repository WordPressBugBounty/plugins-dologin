<?php
/**
 * Child Site one click connection class
 *
 * @since 4.0
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

class Site extends Instance {

	const TYPE_GEN_TOKEN     = 'gen_token';
	const TYPE_CONNECT       = 'connect_site';
	const TYPE_AUTH          = 'auth';
	const TYPE_EASY_LOGIN    = 'easy_login'; // Login to child site
	const TYPE_LOCK          = 'lock';
	const TYPE_DEL           = 'del';
	const QS_NAME_ROOT_AUTH  = 'dologin_root_auth';
	const QS_NAME_EASY_LOGIN = 'dologin_easy_login';

	private $_tb;

	protected function __construct() {
		$this->_tb = $this->cls( 'Data' )->tb( 'site' );
	}

	/**
	 * Init
	 *
	 * @since  4.0
	 */
	public function init() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing
		if ( ! empty( $_GET[ self::QS_NAME_ROOT_AUTH ] ) && ! empty( $_POST['pk'] ) ) {
			defined( 'debug' ) && debug( 'knock knock, site connection in' );
			add_action( 'init', array( $this, 'connect_auth_init' ) );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! empty( $_GET[ self::QS_NAME_EASY_LOGIN ] ) ) {
			defined( 'debug' ) && debug( 'knock knock, easy login comes' );
			add_action( 'init', array( $this, 'try_easy_login' ) );
		}
	}

	/**
	 * Easy login to child site init and jump
	 *
	 * @since  4.0
	 */
	private function _easy_login() {
		global $wpdb;

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$pid = empty( $_GET['dologin_id'] ) ? 0 : (int) $_GET['dologin_id'];
		if ( $pid <= 0 ) {
			return;
		}
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; id is prepared.
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `$this->_tb` WHERE id = %d", $pid ) );
		if ( ! $row ) {
			exit( 'Invalid record' );
		}

		$data = implode(
			',',
			array(
				$row->user_id,
				Conf::val( '_pk' ),
				$this->_pack_b64sign( time() ),
			)
		);
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- benign base64 encoding of the easy-login token payload.
		$url = $row->url . '?' . self::QS_NAME_EASY_LOGIN . '=' . base64_encode( $data );
		defined( 'debug' ) && debug( 'Easy login to child site w/ token: ' . $url );
		// phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- intentional cross-site redirect to the connected child site.
		wp_redirect( $url );
		exit();
	}

	/**
	 * Allow a connection from a root site
	 *
	 * @since  4.0
	 */
	public function try_easy_login() {
		global $wpdb;

		$username = 'N/A';

		// This tokenized endpoint bypasses wp-login, so enforce the per-IP failure limit here too.
		if ( $this->cls( 'Auth' )->is_rate_limited() ) {
			exit( 'dologin_rate_limited' );
		}

		// Magic-link endpoint authenticated by the signed token, not a nonce.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$raw_token = isset( $_GET[ self::QS_NAME_EASY_LOGIN ] ) ? sanitize_text_field( wp_unslash( $_GET[ self::QS_NAME_EASY_LOGIN ] ) ) : '';
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- benign base64 decoding of the easy-login token payload.
		$info = explode( ',', base64_decode( $raw_token ) );
		if ( empty( $info[0] ) || empty( $info[1] ) || empty( $info[2] ) ) {
			defined( 'debug' ) && debug( 'dologin easy login token failed to decode' );
			return $this->_failed_login( $username );
		}

		$uid = (int) $info[0];
		$pk  = $info[1];

		// Validate root site record FIRST; the public key must match a stored, trusted connection.
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; values are prepared.
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `$this->_tb` WHERE user_id=%d AND pk=%s", $uid, $pk ) );
		if ( ! $row ) {
			defined( 'debug' ) && debug( 'dologin easy login no record found for uid: ' . $uid . ', pk: ' . $pk );
			return $this->_failed_login( $username );
		}
		if ( $row->active != 1 || $row->is_child != 1 ) {
			exit( 'dologin_invalid_root_record' );
		}

		// Verify the signature against the STORED public key, never the one supplied in the request.
		$ts = $this->_unpack_b64sign( $info[2], $row->pk );
		if ( ! $ts ) {
			defined( 'debug' ) && debug( 'dologin easy login token invalid' );
			return $this->_failed_login( $username );
		}
		if ( $ts < time() - 3600 ) { // Token should not be older than 1 hour
			defined( 'debug' ) && debug( 'dologin easy login token expired. Got ts: ' . $ts . ', current: ' . time() );
			return $this->_failed_login( $username );
		}
		// Check if last used timestamp is the current one to prevent replay attacks.
		if ( $row->last_used_at && (string) $row->last_used_at === (string) $ts ) {
			defined( 'debug' ) && debug( 'dologin easy login already used' . $ts );
			exit( 'dologin_link_used' );
		}

		$user_info = get_userdata( $uid );
		defined( 'debug' ) && debug( 'dologin easy login passed, uid: ' . $uid . ', username: ' . $user_info->user_login );

		// Show login confirm page.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( empty( $_POST['confirmed'] ) ) {
			require_once DOLOGIN_DIR . 'tpl/easylogin_cfm.tpl.php';
			exit;
		}

		// Can login, update record first.
		$q = "UPDATE `$this->_tb` SET last_used_at=%d, count=count+1 WHERE id=%d";
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; values are prepared.
		$wpdb->query( $wpdb->prepare( $q, array( $ts, $row->id ) ) );

		// Login.
		wp_set_auth_cookie( $user_info->ID, false );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- firing the WordPress core hook on programmatic login.
		do_action( 'wp_login', $user_info->user_login, $user_info );

		nocache_headers();

		Router::redirect( admin_url() );
	}

	/**
	 * Note failed login
	 *
	 * @since  4.0
	 */
	private function _failed_login( $username ) {
		defined( 'debug' ) && debug( 'Failed to auth as user: ', $username );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- firing the WordPress core hook.
		do_action( 'wp_login_failed', $username );
	}

	/**
	 * Lock
	 *
	 * @since  4.0
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
	 * @since  4.0
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
	 * Generate a new connection token
	 *
	 * @since  4.0
	 * @access public
	 */
	public function gen_token( $uid, $return_url = false ) {
		global $wpdb;

		$this->cls( 'Data' )->tb_create( 'site' );

		$uid = (int) $uid;
		if ( $uid <= 0 ) {
			if ( $return_url ) {
				return 'Invalid User ID';
			}
			Router::redirect( admin_url( 'options-general.php?page=dologin' ) );
		}

		$user_info = get_userdata( $uid );
		$hash      = s::rrand( 32 );

		$q = "INSERT INTO `$this->_tb` SET user_id = %d, user_name = %s, hash = %s, dateline = %d, active=1,is_child=1";
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; values are prepared.
		$wpdb->query( $wpdb->prepare( $q, array( $uid, $user_info->user_login, $hash, time() ) ) );
		$id = $wpdb->insert_id;

		if ( $return_url ) {
			return admin_url( '?dologin=' . $id . '.' . $hash );
		}

		Router::redirect( admin_url( 'options-general.php?page=dologin' ) );
	}

	/**
	 * Init PK/SK
	 *
	 * @since 4.0
	 */
	private function _init_pksk() {
		if ( Conf::val( '_pk' ) && Conf::val( '_sk' ) ) {
			return false;
		}

		defined( 'debug' ) && debug( 'Generate new PK/SK' );

		$keypair = sodium_crypto_sign_keypair();
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- benign base64 encoding of an ed25519 public key.
		$pk = base64_encode( sodium_crypto_sign_publickey( $keypair ) );
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- benign base64 encoding of an ed25519 secret key.
		$sk = base64_encode( sodium_crypto_sign_secretkey( $keypair ) );
		Conf::update( '_pk', $pk );
		Conf::update( '_sk', $sk );
		return true;
	}

	/**
	 * Sign a msg w/ SK
	 *
	 * @since  4.0
	 * @access public
	 */
	private function _pack_b64sign( $msg ) {
		$pk = Conf::val( '_pk' );
		$sk = Conf::val( '_sk' );
		if ( ! $pk || ! $sk ) {
			return false;
		}
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- benign base64 decoding of the stored ed25519 secret key.
		$sign = sodium_crypto_sign( (string) $msg, base64_decode( $sk ) );
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- benign base64 encoding of the signature.
		return base64_encode( $sign );
	}

	/**
	 * Verify a signed msg w/ PK
	 *
	 * @since  4.0
	 * @access public
	 */
	private function _unpack_b64sign( $msg, $pk ) {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- benign base64 decoding of the signed message and public key.
		return sodium_crypto_sign_open( base64_decode( $msg ), base64_decode( $pk ) );
	}

	/**
	 * Connect a new child site w/ token
	 *
	 * @since  4.0
	 * @access public
	 */
	public function connect_site() {
		global $wpdb;
		$this->cls( 'Data' )->tb_create( 'site' );

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( empty( $_POST['token'] ) ) {
			exit( 'Missing token' );
		}

		defined( 'debug' ) && debug( 'connection to child' );

		// Generate pk/sk pair if not yet.
		$this->_init_pksk();

		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- admin-gated action; benign base64 decode of the connection URL token.
		$token_link = base64_decode( sanitize_text_field( wp_unslash( $_POST['token'] ) ) );
		// Block SSRF to internal/invalid hosts (defense in depth even though this path is manage_options-gated).
		if ( ! wp_http_validate_url( $token_link ) ) {
			exit( 'Invalid token URL' );
		}
		defined( 'debug' ) && debug( 'connection to child token link:', $token_link );
		// Post to the child site w/ pk.
		$pk   = Conf::val( '_pk' );
		$ts   = time();
		$resp = wp_remote_post(
			$token_link,
			array(
				'body'      => array(
					'pk'         => $pk,
					'site_url'   => site_url(),
					'site_title' => get_bloginfo( 'name' ),
					'sign'       => $this->_pack_b64sign( $ts ),
				),
				'timeout'   => 15,
				'sslverify' => true,
			)
		);

		if ( is_wp_error( $resp ) ) {
			$error_message = $resp->get_error_message();
			throw new \Exception( esc_html( $error_message ) );
		}

		$res = json_decode( $resp['body'], true );
		defined( 'debug' ) && debug( 'child connection res:', $res );
		if ( empty( $res['status'] ) || $res['status'] != 'ok' || empty( $res['child_title'] ) || empty( $res['child_url'] ) ) {
			exit( esc_html( 'Invalid child site response: ' . $resp['body'] ) );
		}

		$q = "INSERT INTO `$this->_tb` SET title=%s, url=%s, pk=%s, is_child=0, user_id=%d, user_name=%s, dateline=%d, active=1";
		// phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery -- $this->_tb is a hardcoded internal table name; values are prepared.
		$wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- $this->_tb is a hardcoded internal table name; values are prepared.
				$q,
				array(
					$res['child_title'],
					$res['child_url'],
					'-',
					$res['child_user_id'],
					$res['child_user_name'],
					time(),
				)
			)
		);
	}

	/**
	 * Auth a connection setup from a root site
	 *
	 * @since  4.0
	 */
	public function connect_auth_init() {
		global $wpdb;

		$username = 'N/A';

		// This tokenized endpoint bypasses wp-login, so enforce the per-IP failure limit here too.
		if ( $this->cls( 'Auth' )->is_rate_limited() ) {
			exit( 'dologin_rate_limited' );
		}

		defined( 'debug' ) && debug( 'Root site connection in' );
		// Server-to-server handshake authenticated by the signed token, not a nonce.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$raw_token = isset( $_GET[ self::QS_NAME_ROOT_AUTH ] ) ? sanitize_text_field( wp_unslash( $_GET[ self::QS_NAME_ROOT_AUTH ] ) ) : '';
		$info      = explode( '.', $raw_token );
		if ( empty( $info[0] ) || empty( $info[1] ) ) {
			return $this->_failed_login( $username );
		}

		$pid = (int) $info[0];
		if ( $pid <= 0 ) {
			return $this->_failed_login( $username );
		}

		// Verify reord.
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; id is prepared.
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `$this->_tb` WHERE id = %d", $pid ) );
		if ( ! $row ) {
			return $this->_failed_login( $username );
		}
		$user_info = get_userdata( $row->user_id );
		$username  = $user_info->user_login;
		if ( $row->hash !== $info[1] ) {
			return $this->_failed_login( $username );
		}
		if ( $row->active != 1 || $row->is_child != 1 || $row->pk ) {
			defined( 'debug' ) && debug( 'Invalid token record' );
			exit( 'dologin_invalid_token_record' );
		}

		if ( time() - $row->dateline > 3600 ) {
			defined( 'debug' ) && debug( 'Token expired' );
			exit( 'dologin_token_expired' );
		}

		// Verify root site info.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$root_url = isset( $_POST['site_url'] ) ? sanitize_text_field( wp_unslash( $_POST['site_url'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$root_title = isset( $_POST['site_title'] ) ? sanitize_text_field( wp_unslash( $_POST['site_title'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$root_pk = isset( $_POST['pk'] ) ? sanitize_text_field( wp_unslash( $_POST['pk'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$sign = isset( $_POST['sign'] ) ? sanitize_text_field( wp_unslash( $_POST['sign'] ) ) : '';
		if ( ! $root_url || ! $root_title || ! $root_pk || ! $sign ) {
			defined( 'debug' ) && debug( 'Invalid dologin connect root data' );
			exit( 'Invalid dologin connect root data' );
		}
		$signed_ts = $this->_unpack_b64sign( $sign, $root_pk );
		if ( ! $signed_ts || $signed_ts < time() - 3600 ) { // Root site clock shouldn't diff more than 1 hour w/ child
			defined( 'debug' ) && debug( 'dologin connect root clock should not diff w/ child more than 1 hour' );
			exit( 'dologin: Failed to validate timestamp. Root site clock should not diff w/ child more than 1 hour' );
		}
		if ( $root_url == site_url() ) {
			defined( 'debug' ) && debug( 'dologin connect root site url same as child' );
			exit( 'dologin connect root site url same as child' );
		}
		// Only one record allowed per root site pk per user_id.
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; values are prepared.
		$exists = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM `$this->_tb` WHERE pk = %s AND user_id = %d", $root_pk, $row->user_id ) );
		if ( $exists > 0 ) {
			defined( 'debug' ) && debug( 'dologin connect root site pk already exists for user' );
			exit( 'dologin connect root site pk already exists for user' );
		}

		// Can login, update record first.
		$q = "UPDATE `$this->_tb` SET title=%s,url=%s,pk=%s WHERE id = %d";
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; values are prepared.
		$wpdb->query( $wpdb->prepare( $q, array( $root_title, $root_url, $root_pk, $pid ) ) );

		nocache_headers();

		exit(
			wp_json_encode(
				array(
					'status'          => 'ok',
					'child_title'     => get_bloginfo( 'name' ),
					'child_url'       => admin_url(),
					'child_user_id'   => $row->user_id,
					'child_user_name' => $username,
				)
			)
		);
	}

	/**
	 * Handler
	 *
	 * @since  1.4
	 */
	public function handler() {
		$type = Router::verify_type();

		switch ( $type ) {
			case self::TYPE_GEN_TOKEN:
				// phpcs:ignore WordPress.Security.NonceVerification.Recommended
				$this->gen_token( isset( $_GET['uid'] ) ? (int) $_GET['uid'] : 0 );
				break;

			case self::TYPE_CONNECT:
				$this->connect_site();
				break;

			case self::TYPE_EASY_LOGIN:
				$this->_easy_login();
				break;

			case self::TYPE_LOCK:
				$this->_lock_link();
				break;

			case self::TYPE_DEL:
				$this->del_link();
				break;

			default:
				break;
		}
	}
}
