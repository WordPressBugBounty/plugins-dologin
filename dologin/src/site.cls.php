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
	 * Check cryptographic requirements for site connections.
	 *
	 * @since 4.6.5
	 */
	private function _sodium_ready() {
		return KLSso::sodium_ready()
			&& function_exists( 'sodium_crypto_sign' )
			&& function_exists( 'sodium_crypto_sign_open' );
	}

	/**
	 * Easy login to child site init and jump
	 *
	 * @since  4.0
	 */
	private function _easy_login() {
		global $wpdb;
		if ( ! $this->_sodium_ready() ) {
			return $this->_admin_error( 'dologin_sodium_unavailable' );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$pid = empty( $_GET['dologin_id'] ) ? 0 : (int) $_GET['dologin_id'];
		if ( $pid <= 0 ) {
			return;
		}
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; id is prepared.
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `$this->_tb` WHERE id = %d", $pid ) );
		if ( ! $row || 1 !== (int) $row->active || 0 !== (int) $row->is_child || ! wp_http_validate_url( $row->url ) ) {
			return $this->_admin_error( 'dologin_site_token_invalid' );
		}

		$audience = $this->_easy_login_audience( $row->url );
		try {
			$jti = bin2hex( random_bytes( 16 ) );
		} catch ( \Exception $ex ) {
			return $this->_admin_error( 'dologin_token_generation_failed' );
		}
		$claims = array(
			'v'   => 2,
			'uid' => (int) $row->user_id,
			'pk'  => (string) Conf::val( '_pk' ),
			'aud' => $audience,
			'iat' => time(),
			'jti' => $jti,
		);
		$claims_json = $this->_easy_login_claims_json( $claims );
		$signature   = $claims_json ? $this->_pack_b64sign( $claims_json ) : false;
		if ( ! $audience || ! $claims_json || ! $signature ) {
			return $this->_admin_error( 'dologin_token_generation_failed' );
		}
		$data = wp_json_encode(
			array(
				'claims' => $claims,
				'sig'    => $signature,
			)
		);
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- benign base64 encoding of the easy-login token payload.
		$url = add_query_arg( self::QS_NAME_EASY_LOGIN, base64_encode( $data ), $row->url );
		defined( 'debug' ) && debug( 'Easy login token generated for child site.' );
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

		// This endpoint bypasses wp-login and must apply the same IP rules and failure limits.
		if ( $this->cls( 'Auth' )->is_ip_denied() ) {
			$this->_error_page( 'dologin_ip_denied', 403 );
		}
		if ( $this->cls( 'Auth' )->is_rate_limited() ) {
			$this->_error_page( 'dologin_rate_limited', 429 );
		}
		if ( ! $this->_sodium_ready() ) {
			$this->_error_page( 'dologin_sodium_unavailable', 503 );
		}

		// Magic-link endpoint authenticated by the signed token, not a nonce.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$raw_token = isset( $_GET[ self::QS_NAME_EASY_LOGIN ] ) && is_string( $_GET[ self::QS_NAME_EASY_LOGIN ] ) ? sanitize_text_field( wp_unslash( $_GET[ self::QS_NAME_EASY_LOGIN ] ) ) : '';
		if ( KLSso::force_enabled() ) {
			$this->_error_page( 'dologin_kl_sso_required', 403 );
		}
		$token = $this->_decode_easy_login_token( $raw_token );
		if ( ! $token ) {
			defined( 'debug' ) && debug( 'dologin easy login token failed to decode' );
			return $this->_failed_login( $username );
		}

		$claims = $token['claims'];
		$uid    = $claims['uid'];
		$pk     = $claims['pk'];

		// Validate root site record FIRST; the public key must match a stored, trusted connection.
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; values are prepared.
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `$this->_tb` WHERE user_id=%d AND pk=%s", $uid, $pk ) );
		if ( ! $row ) {
			defined( 'debug' ) && debug( 'dologin easy login no record found for uid: ' . $uid . ', pk: ' . $pk );
			return $this->_failed_login( $username );
		}
		if ( $row->active != 1 || $row->is_child != 1 ) {
			$this->_error_page( 'dologin_invalid_root_record', 403 );
		}

		// Verify the complete assertion against the stored public key, never a request-only key.
		$signed_claims = $this->_unpack_b64sign( $token['sig'], $row->pk );
		if ( ! is_string( $signed_claims ) || ! hash_equals( $token['claims_json'], $signed_claims ) ) {
			defined( 'debug' ) && debug( 'dologin easy login token invalid' );
			return $this->_failed_login( $username );
		}
		$audience = $this->_easy_login_audience( admin_url() );
		if ( ! $audience || ! hash_equals( $audience, $claims['aud'] ) ) {
			defined( 'debug' ) && debug( 'dologin easy login token audience mismatch' );
			return $this->_failed_login( $username );
		}
		$ts  = $claims['iat'];
		$now = time();
		if ( $ts < $now - 3600 || $ts > $now + 300 ) { // Tokens cannot be older than one hour or materially in the future.
			defined( 'debug' ) && debug( 'dologin easy login token expired. Got ts: ' . $ts . ', current: ' . $now );
			return $this->_failed_login( $username );
		}
		// Only a token newer than every previously consumed token may proceed.
		if ( (int) $row->last_used_at >= $ts ) {
			defined( 'debug' ) && debug( 'dologin easy login already used' . $ts );
			$this->_error_page( 'dologin_link_used', 410 );
		}

		$user_info = get_userdata( $uid );
		if ( ! $user_info ) {
			return $this->_failed_login( $username );
		}
		$username = $user_info->user_login;
		defined( 'debug' ) && debug( 'dologin easy login passed, uid: ' . $uid . ', username: ' . $user_info->user_login );

		$confirm_nonce_action = 'dologin_easy_login_confirm_' . hash( 'sha256', $raw_token );

		// Show login confirm page.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( empty( $_POST['confirmed'] ) ) {
			require_once DOLOGIN_DIR . 'tpl/easylogin_cfm.tpl.php';
			exit;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$confirm_nonce = empty( $_POST['dologin_confirm_nonce'] ) || ! is_string( $_POST['dologin_confirm_nonce'] ) ? '' : sanitize_text_field( wp_unslash( $_POST['dologin_confirm_nonce'] ) );
		if ( ! wp_verify_nonce( $confirm_nonce, $confirm_nonce_action ) ) {
			return $this->_failed_login( $username );
		}

		// Can login, update record first.
		$q = "UPDATE `$this->_tb` SET last_used_at=%d, count=count+1 WHERE id=%d AND active=1 AND last_used_at<%d";
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; values are prepared.
		$updated = $wpdb->query( $wpdb->prepare( $q, array( $ts, $row->id, $ts ) ) );
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
	 * Build the canonical easy-login assertion string.
	 */
	private function _easy_login_claims_json( $claims ) {
		if ( ! is_array( $claims ) ) {
			return false;
		}
		$required = array( 'v', 'uid', 'pk', 'aud', 'iat', 'jti' );
		$keys     = array_keys( $claims );
		sort( $keys, SORT_STRING );
		$sorted_required = $required;
		sort( $sorted_required, SORT_STRING );
		if ( $keys !== $sorted_required
			|| ! is_int( $claims['v'] ) || 2 !== $claims['v']
			|| ! is_int( $claims['uid'] ) || $claims['uid'] <= 0
			|| ! is_string( $claims['pk'] ) || '' === $claims['pk']
			|| ! is_string( $claims['aud'] ) || '' === $claims['aud']
			|| ! is_int( $claims['iat'] ) || $claims['iat'] <= 0
			|| ! is_string( $claims['jti'] ) || ! preg_match( '/^[a-f0-9]{32}$/D', $claims['jti'] ) ) {
			return false;
		}

		return wp_json_encode(
			array(
				'v'   => 2,
				'uid' => $claims['uid'],
				'pk'  => $claims['pk'],
				'aud' => $claims['aud'],
				'iat' => $claims['iat'],
				'jti' => $claims['jti'],
			)
		);
	}

	/**
	 * Decode and strictly validate a versioned easy-login token.
	 */
	private function _decode_easy_login_token( $raw_token ) {
		if ( ! is_string( $raw_token ) || '' === $raw_token || strlen( $raw_token ) > 16384 ) {
			return false;
		}
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- benign base64 decoding of the easy-login token payload.
		$decoded = base64_decode( $raw_token, true );
		$token   = false === $decoded ? null : json_decode( $decoded, true );
		if ( ! is_array( $token ) || array( 'claims', 'sig' ) !== array_keys( $token ) || ! is_array( $token['claims'] ) || ! is_string( $token['sig'] ) || '' === $token['sig'] ) {
			return false;
		}
		$claims_json = $this->_easy_login_claims_json( $token['claims'] );
		if ( ! $claims_json ) {
			return false;
		}
		$token['claims_json'] = $claims_json;
		return $token;
	}

	/**
	 * Normalize the target admin URL used as the signed token audience.
	 */
	private function _easy_login_audience( $url ) {
		$url = is_string( $url ) ? esc_url_raw( $url ) : '';
		if ( ! $url || ! wp_http_validate_url( $url ) ) {
			return '';
		}
		$parts = wp_parse_url( $url );
		if ( ! is_array( $parts ) || empty( $parts['scheme'] ) || empty( $parts['host'] ) || isset( $parts['user'] ) || isset( $parts['pass'] ) ) {
			return '';
		}
		$scheme = strtolower( $parts['scheme'] );
		if ( ! in_array( $scheme, array( 'http', 'https' ), true ) ) {
			return '';
		}
		$host = strtolower( $parts['host'] );
		$port = isset( $parts['port'] ) ? ':' . (int) $parts['port'] : '';
		$path = isset( $parts['path'] ) ? '/' . trim( $parts['path'], '/' ) . '/' : '/';
		return $scheme . '://' . $host . $port . $path;
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
	 * Queue a localized error for a nonce- and capability-gated admin action.
	 */
	private function _admin_error( $tag ) {
		GUI::error( Lang::msg( $tag ) );
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
		if ( ! $this->_sodium_ready() ) {
			if ( $return_url ) {
				return 'Sodium cryptography support is required';
			}
			GUI::error( __( 'Sodium cryptography support is required.', 'dologin' ) );
			Router::redirect( admin_url( 'options-general.php?page=dologin' ) );
		}

		$this->cls( 'Data' )->tb_create( 'site' );

		$uid       = (int) $uid;
		$user_info = $uid > 0 ? get_userdata( $uid ) : false;
		if ( ! $user_info ) {
			if ( $return_url ) {
				return 'Invalid User ID';
			}
			Router::redirect( admin_url( 'options-general.php?page=dologin' ) );
		}

		$token = s::rrand( 32 );
		$hash  = Secret::token_hash( 'site-connection', $token );
		if ( ! $hash ) {
			if ( $return_url ) {
				return false;
			}
			wp_die( esc_html__( 'Failed to protect the site connection token.', 'dologin' ) );
		}

		$q = "INSERT INTO `$this->_tb` SET user_id = %d, user_name = %s, hash = %s, dateline = %d, active=1,is_child=1";
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; values are prepared.
		$inserted = $wpdb->query( $wpdb->prepare( $q, array( $uid, $user_info->user_login, $hash, time() ) ) );
		$id = $wpdb->insert_id;
		if ( 1 !== $inserted || $id <= 0 ) {
			if ( $return_url ) {
				return false;
			}
			wp_die( esc_html__( 'Failed to save the site connection token.', 'dologin' ) );
		}

		$link = admin_url( '?' . self::QS_NAME_ROOT_AUTH . '=' . $id . '.' . $token );
		if ( $return_url ) {
			return $link;
		}

		$this->show_generated_connection_token( base64_encode( $link ) );
	}

	/**
	 * Display a newly generated connection token once without storing its raw secret.
	 */
	private function show_generated_connection_token( $token ) {
		$back = admin_url( 'options-general.php?page=dologin' );
		$message = '<p>' . esc_html__( 'Copy this child-site connection token now. For database-leak protection, its secret value is not stored and cannot be shown again.', 'dologin' ) . '</p>'
			. '<p><code style="display:block;overflow-wrap:anywhere;padding:12px;">' . esc_html( $token ) . '</code></p>'
			. '<p><a class="button button-primary" href="' . esc_url( $back ) . '">' . esc_html__( 'Continue to Site Connections', 'dologin' ) . '</a></p>';
		wp_die( $message, esc_html__( 'Site Connection Token Created', 'dologin' ), array( 'response' => 200 ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- every dynamic value in the assembled admin-only message is escaped above.
	}

	/**
	 * Init PK/SK
	 *
	 * @since 4.0
	 */
	private function _init_pksk() {
		if ( ! $this->_sodium_ready() ) {
			return false;
		}
		if ( Conf::val( '_pk' ) && Conf::val( '_sk' ) ) {
			return false;
		}

		defined( 'debug' ) && debug( 'Generate new PK/SK' );

		$keypair = sodium_crypto_sign_keypair();
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- benign base64 encoding of an ed25519 public key.
		$pk = base64_encode( sodium_crypto_sign_publickey( $keypair ) );
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- benign base64 encoding of an ed25519 secret key.
		$sk     = base64_encode( sodium_crypto_sign_secretkey( $keypair ) );
		$sealed = Secret::seal( 'site-easy-login-signing-key', $sk );
		if ( ! $sealed ) {
			return false;
		}
		Conf::update( '_pk', $pk );
		Conf::update( '_sk', $sealed );
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
		$stored_sk = Conf::val( '_sk' );
		if ( ! $pk || ! $stored_sk || ! $this->_sodium_ready() ) {
			return false;
		}
		if ( Secret::is_sealed( $stored_sk ) ) {
			$sk = Secret::open( 'site-easy-login-signing-key', $stored_sk );
		} else {
			$sk     = (string) $stored_sk;
			$sealed = Secret::seal( 'site-easy-login-signing-key', $sk );
			if ( ! $sealed ) {
				return false;
			}
			Conf::update( '_sk', $sealed );
		}
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- benign base64 decoding of the stored ed25519 secret key.
		$secret_key = base64_decode( $sk, true );
		if ( false === $secret_key || strlen( $secret_key ) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES ) {
			return false;
		}
		$sign = sodium_crypto_sign( (string) $msg, $secret_key );
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
		$signed     = base64_decode( $msg, true );
		$public_key = base64_decode( $pk, true );
		if ( ! $this->_sodium_ready() || false === $signed || false === $public_key || strlen( $public_key ) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES ) {
			return false;
		}
		return sodium_crypto_sign_open( $signed, $public_key );
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
		if ( ! $this->_sodium_ready() ) {
			return $this->_admin_error( 'dologin_sodium_unavailable' );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( empty( $_POST['token'] ) ) {
			return $this->_admin_error( 'dologin_site_token_missing' );
		}

		defined( 'debug' ) && debug( 'connection to child' );

		// Generate pk/sk pair if not yet.
		$this->_init_pksk();

		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- admin-gated action; benign base64 decode of the connection URL token.
		$token_link = is_string( $_POST['token'] ) ? base64_decode( sanitize_text_field( wp_unslash( $_POST['token'] ) ), true ) : false;
		// Block SSRF to internal/invalid hosts (defense in depth even though this path is manage_options-gated).
		if ( ! wp_http_validate_url( $token_link ) ) {
			return $this->_admin_error( 'dologin_site_token_invalid' );
		}
		defined( 'debug' ) && debug( 'Validated child site connection token URL.' );
		// Post to the child site w/ pk.
		$pk   = Conf::val( '_pk' );
		$ts   = time();
		$resp = wp_safe_remote_post(
			$token_link,
			array(
				'body'                => array(
					'pk'         => $pk,
					'site_url'   => site_url(),
					'site_title' => get_bloginfo( 'name' ),
					'sign'       => $this->_pack_b64sign( $ts ),
				),
				'timeout'             => 15,
				'redirection'         => 2,
				'limit_response_size' => 65536,
				'sslverify'           => true,
			)
		);

		if ( is_wp_error( $resp ) ) {
			$error_message = $resp->get_error_message();
			defined( 'debug' ) && debug( 'Child site connection request failed:', $error_message );
			return $this->_admin_error( 'dologin_site_connection_failed' );
		}

		$response_code = (int) wp_remote_retrieve_response_code( $resp );
		if ( $response_code < 200 || $response_code >= 300 ) {
			defined( 'debug' ) && debug( 'Child site connection returned HTTP status:', $response_code );
			return $this->_admin_error( 'dologin_site_connection_failed' );
		}

		$res = json_decode( wp_remote_retrieve_body( $resp ), true );
		if ( empty( $res['status'] ) || 'ok' !== $res['status'] || empty( $res['child_title'] ) || ! is_scalar( $res['child_title'] ) || empty( $res['child_url'] ) || ! is_scalar( $res['child_url'] ) || ! isset( $res['child_user_id'], $res['child_user_name'] ) || ! is_scalar( $res['child_user_id'] ) || ! is_scalar( $res['child_user_name'] ) ) {
			defined( 'debug' ) && debug( 'Child site connection response failed schema validation.' );
			return $this->_admin_error( 'dologin_site_connection_failed' );
		}
		$child_url = esc_url_raw( $res['child_url'] );
		if ( ! wp_http_validate_url( $child_url ) ) {
			return $this->_admin_error( 'dologin_site_connection_failed' );
		}

		$q = "INSERT INTO `$this->_tb` SET title=%s, url=%s, pk=%s, is_child=0, user_id=%d, user_name=%s, dateline=%d, active=1";
		// phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery -- $this->_tb is a hardcoded internal table name; values are prepared.
		$wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- $this->_tb is a hardcoded internal table name; values are prepared.
				$q,
				array(
					sanitize_text_field( $res['child_title'] ),
					$child_url,
					'-',
					(int) $res['child_user_id'],
					sanitize_text_field( $res['child_user_name'] ),
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

		// This public handshake endpoint must apply the same IP rules and failure limits.
		if ( $this->cls( 'Auth' )->is_ip_denied() ) {
			$this->_error_page( 'dologin_ip_denied', 403 );
		}
		if ( $this->cls( 'Auth' )->is_rate_limited() ) {
			$this->_error_page( 'dologin_rate_limited', 429 );
		}
		if ( ! $this->_sodium_ready() ) {
			$this->_error_page( 'dologin_sodium_unavailable', 503 );
		}

		defined( 'debug' ) && debug( 'Root site connection in' );
		// Server-to-server handshake authenticated by the signed token, not a nonce.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$raw_token = isset( $_GET[ self::QS_NAME_ROOT_AUTH ] ) && is_string( $_GET[ self::QS_NAME_ROOT_AUTH ] ) ? sanitize_text_field( wp_unslash( $_GET[ self::QS_NAME_ROOT_AUTH ] ) ) : '';
		$info      = explode( '.', $raw_token );
		if ( 2 !== count( $info ) || empty( $info[0] ) || empty( $info[1] ) ) {
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
		if ( ! $user_info ) {
			return $this->_failed_login( $username );
		}
		$username = $user_info->user_login;
		if ( ! Secret::verify_token( 'site-connection', (string) $info[1], (string) $row->hash ) ) {
			return $this->_failed_login( $username );
		}
		if ( $row->active != 1 || $row->is_child != 1 || $row->pk ) {
			defined( 'debug' ) && debug( 'Invalid token record' );
			$this->_error_page( 'dologin_invalid_token_record', 403 );
		}

		if ( time() - $row->dateline > 3600 ) {
			defined( 'debug' ) && debug( 'Token expired' );
			$this->_error_page( 'dologin_token_expired', 410 );
		}

		// Verify root site info.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$root_url = isset( $_POST['site_url'] ) && is_string( $_POST['site_url'] ) ? esc_url_raw( wp_unslash( $_POST['site_url'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$root_title = isset( $_POST['site_title'] ) && is_string( $_POST['site_title'] ) ? sanitize_text_field( wp_unslash( $_POST['site_title'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$root_pk = isset( $_POST['pk'] ) && is_string( $_POST['pk'] ) ? sanitize_text_field( wp_unslash( $_POST['pk'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$sign = isset( $_POST['sign'] ) && is_string( $_POST['sign'] ) ? sanitize_text_field( wp_unslash( $_POST['sign'] ) ) : '';
		$root_scheme = wp_parse_url( $root_url, PHP_URL_SCHEME );
		if ( ! $root_url || ! in_array( $root_scheme, array( 'http', 'https' ), true ) || ! $root_title || ! $root_pk || ! $sign ) {
			defined( 'debug' ) && debug( 'Invalid dologin connect root data' );
			$this->_error_page( 'dologin_site_token_invalid', 403 );
		}
		$signed_ts = $this->_unpack_b64sign( $sign, $root_pk );
		if ( ! is_string( $signed_ts ) || ! preg_match( '/^[0-9]+$/D', $signed_ts ) || (int) $signed_ts < time() - 3600 || (int) $signed_ts > time() + 300 ) { // Root and child site clocks cannot be materially out of sync.
			defined( 'debug' ) && debug( 'dologin connect root clock should not diff w/ child more than 1 hour' );
			$this->_error_page( 'dologin_site_clock_mismatch', 403 );
		}
		if ( $root_url == site_url() ) {
			defined( 'debug' ) && debug( 'dologin connect root site url same as child' );
			$this->_error_page( 'dologin_site_same_url', 409 );
		}
		// Only one record allowed per root site pk per user_id.
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; values are prepared.
		$exists = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM `$this->_tb` WHERE pk = %s AND user_id = %d", $root_pk, $row->user_id ) );
		if ( $exists > 0 ) {
			defined( 'debug' ) && debug( 'dologin connect root site pk already exists for user' );
			$this->_error_page( 'dologin_site_already_connected', 409 );
		}

		// Can login, update record first.
		$q = "UPDATE `$this->_tb` SET title=%s,url=%s,pk=%s WHERE id = %d AND pk = '' AND active = 1";
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery --$this->_tb is a hardcoded internal table name; values are prepared.
		$updated = $wpdb->query( $wpdb->prepare( $q, array( $root_title, $root_url, $root_pk, $pid ) ) );
		if ( 1 !== $updated ) {
			$this->_error_page( 'dologin_token_used', 410 );
		}

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
