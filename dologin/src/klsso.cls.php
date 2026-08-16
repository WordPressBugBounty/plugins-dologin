<?php
/**
 * KeyLockr SSO integration.
 *
 * @since 4.5
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

class KLSso extends Instance {
	use KLSso_Keys;
	use KLSso_Protocol;
	use KLSso_Repair;
	use KLSso_State;
	use KLSso_UI;

	const META_SAFE_ID             = 'dologin_kl_safe_id';
	const META_NICKNAME            = 'dologin_kl_nickname';
	const META_APP_HASH            = 'dologin_kl_app_hash';
	const META_SITE_KEY_FP         = 'dologin_kl_site_key_fingerprint';
	const META_APP_TAG             = 'dologin_kl_app_tag';
	const TRANSIENT_PREFIX         = 'dologin_kl_sso_';
	const CLOCK_CACHE              = 'dologin_kl_sso_clock_ok';
	const SERVER_KEYS_CACHE        = 'dologin_kl_sso_server_keys';
	const SITE_KEYS_OPTION         = 'dologin.kl_sso_site_keys';
	const SESSION_TTL              = 600;
	const START_WINDOW             = 60;
	const START_LIMIT              = 6;
	const FRAME_LIMIT              = 64;
	const FRAME_MAX_BYTES          = 65536;
	const FRAME_IP_LIMIT           = 120;
	const CLOCK_PAST_LIMIT         = 600;
	const CLOCK_FUTURE_LIMIT       = 180;
	const REPAIR_REQUIRED_CODE     = 4702;
	const APP_AUTH_TERMINAL_CODE   = 4703;
	const AUTH_DENIED_CODE         = 4704;
	const LOGIN_IDENTITY_CODE      = 4705;
	const APPDATA_CAS_RETRY_LIMIT = 1;
	const API_BASE                 = 'https://api.keylockr.app/v3';
	const WS_URL                   = 'wss://api.keylockr.app/v3/ws';
	const WWW_URL                  = 'https://keylockr.app';
	const DEVELOPER_ADD_URL        = 'https://my.keylockr.app/developer_sso_add';
	const QR_SCHEME_TEMPLATE       = 'keylockr://sso?tmp_id=%s';

	/**
	 * Register hooks.
	 */
	public function init() {
		add_action( 'show_user_profile', array( $this, 'profile_form' ) );
	}

	/**
	 * Is SSO configured enough to show login/bind widgets.
	 */
	public static function enabled() {
		return (bool) Conf::val( 'kl_sso' ) && self::app_tag();
	}

	/**
	 * Whether the saved policy restricts interactive login to KeyLockr QR.
	 */
	public static function force_enabled() {
		return (bool) Conf::val( 'kl_sso_force' );
	}

	/**
	 * Is service configuration present.
	 */
	public static function configured() {
		return (bool) self::app_tag();
	}

	/**
	 * Runtime requirements for KeyLockr SSO.
	 */
	public static function requirements() {
		$errors = array();
		if ( ! self::sodium_ready() ) {
			$errors[] = __( 'Sodium cryptography support is required.', 'dologin' );
		}
		if ( ! file_exists( DOLOGIN_DIR . 'qilu/npm/qrcode-generator/qrcode.js' ) ) {
			$errors[] = __( 'Bundled QR code generator is missing.', 'dologin' );
		}
		return $errors;
	}

	/**
	 * Return the effective KeyLockr app_tag.
	 *
	 * Keep the existing setting key to avoid a local migration, but never send its value as svc_id.
	 */
	public static function app_tag() {
		return trim( (string) Conf::val( 'kl_sso_svc_id' ) );
	}

	/**
	 * API base URL.
	 */
	public static function api_base() {
		return self::API_BASE;
	}

	/**
	 * WebSocket URL.
	 */
	public static function ws_url() {
		return self::WS_URL;
	}

	/**
	 * Build the current AppData handshake payload.
	 */
	private function handshake_body( $sign_pk, $enc_pk, $name, $app_tag = '' ) {
		$app_tag = $app_tag ? $app_tag : self::app_tag();
		return KLSso_MsgPack::pack(
			array(
				'app_data' => true,
				'app_tag'  => $app_tag,
				'enc_pk'   => KLSso_MsgPack::bin( $enc_pk ),
				'name'     => $name,
				'sign_pk'  => KLSso_MsgPack::bin( $sign_pk ),
			)
		);
	}

	/**
	 * Per-user appdata hash. Generated once and stored in user meta.
	 */
	private static function user_app_hash( $uid ) {
		$uid = (int) $uid;
		if ( $uid <= 0 ) {
			return '';
		}

		$hash = trim( (string) get_user_meta( $uid, self::META_APP_HASH, true ) );
		if ( $hash ) {
			return $hash;
		}

		$hash = hash_hmac( 'sha256', 'dologin-kl-user|' . home_url() . '|' . $uid, wp_salt( 'auth' ) );
		update_user_meta( $uid, self::META_APP_HASH, $hash );
		return $hash;
	}

	/**
	 * Current user's bind status for settings UI.
	 */
	public static function current_user_status() {
		$uid = get_current_user_id();
		if ( ! $uid ) {
			return array(
				'bound' => false,
			);
		}

		$safe_id     = get_user_meta( $uid, self::META_SAFE_ID, true );
		$app_tag     = trim( (string) get_user_meta( $uid, self::META_APP_TAG, true ) );
		$current_tag = self::app_tag();
		return array(
			'bound'           => (bool) $safe_id,
			'key_current'     => (bool) $safe_id && self::binding_uses_current_connection( $uid ),
			'app_tag_changed' => (bool) $safe_id && '' !== $app_tag && '' !== $current_tag && ! hash_equals( $current_tag, $app_tag ),
			'safe_id'         => $safe_id,
			'nickname'        => get_user_meta( $uid, self::META_NICKNAME, true ),
		);
	}

	/**
	 * Whether this user's binding has been verified with the current KeyLockr connection identity.
	 */
	private static function binding_uses_current_connection( $uid ) {
		$fingerprint = trim( (string) get_user_meta( (int) $uid, self::META_SITE_KEY_FP, true ) );
		$app_tag     = trim( (string) get_user_meta( (int) $uid, self::META_APP_TAG, true ) );
		$current_tag = self::app_tag();
		return '' !== $fingerprint
			&& '' !== $app_tag
			&& '' !== $current_tag
			&& hash_equals( $current_tag, $app_tag )
			&& self::site_key_fingerprint_matches( $fingerprint );
	}

	/**
	 * Whether the current administrator has a complete binding for force-mode activation.
	 */
	public static function force_ready( $app_tag = '' ) {
		$uid        = get_current_user_id();
		$app_tag    = trim( (string) $app_tag );
		$capability = apply_filters( 'dologin_admin_menu_access', 'manage_options' );
		if ( ! $uid || ! $app_tag || ! get_userdata( $uid ) || ! user_can( $uid, $capability ) ) {
			return false;
		}
		$safe_id     = trim( (string) get_user_meta( $uid, self::META_SAFE_ID, true ) );
		$app_hash    = trim( (string) get_user_meta( $uid, self::META_APP_HASH, true ) );
		$stored_tag  = trim( (string) get_user_meta( $uid, self::META_APP_TAG, true ) );
		$fingerprint = trim( (string) get_user_meta( $uid, self::META_SITE_KEY_FP, true ) );
		return '' !== $safe_id
			&& '' !== $app_hash
			&& '' !== $stored_tag
			&& '' !== $fingerprint
			&& hash_equals( $app_tag, $stored_tag )
			&& self::site_key_fingerprint_matches( $fingerprint );
	}

	/**
	 * Unlink KeyLockr from the current WordPress user.
	 *
	 * @since 4.6.5
	 */
	public function unbind() {
		$uid = get_current_user_id();
		if ( ! $uid ) {
			return REST::err( __( 'You need to login before unlinking KeyLockr SSO.', 'dologin' ) );
		}
		if ( self::force_enabled() ) {
			return REST::err( __( 'Disable Force KeyLockr SSO before unlinking this account.', 'dologin' ) );
		}

		$meta_keys = array(
			self::META_SAFE_ID,
			self::META_NICKNAME,
			self::META_APP_HASH,
			self::META_SITE_KEY_FP,
			self::META_APP_TAG,
			'dologin_kl_sso_client_id',
			'dologin_kl_bound_at',
		);
		foreach ( $meta_keys as $meta_key ) {
			delete_user_meta( $uid, $meta_key );
		}

		return REST::ok(
			array(
				'status'  => 'done',
				'message' => __( 'KeyLockr SSO unlinked successfully.', 'dologin' ),
			)
		);
	}

	/**
	 * Start a KeyLockr SSO session.
	 */
	public function start( $request ) {
		$raw_mode = $request->get_param( 'mode' );
		$mode     = is_string( $raw_mode ) ? sanitize_key( $raw_mode ) : '';
		if ( ! in_array( $mode, array( 'login', 'bind', 'verify', 'repair' ), true ) ) {
			return REST::err( __( 'Invalid KeyLockr SSO mode.', 'dologin' ) );
		}

		if ( 'login' === $mode && ! self::enabled() ) {
			return REST::err( __( 'KeyLockr SSO is not configured.', 'dologin' ) );
		}

		if ( in_array( $mode, array( 'bind', 'verify', 'repair' ), true ) && ! self::configured() ) {
			return REST::err( __( 'KeyLockr App Tag is not configured.', 'dologin' ) );
		}

		$requirements = self::requirements();
		if ( $requirements ) {
			return REST::err( implode( ' ', $requirements ) );
		}

		if ( in_array( $mode, array( 'bind', 'verify', 'repair' ), true ) && ! is_user_logged_in() ) {
			return REST::err( 'verify' === $mode
				? __( 'You need to login before verifying the KeyLockr connection.', 'dologin' )
				: __( 'You need to login before linking KeyLockr SSO.', 'dologin' ) );
		}

		if ( in_array( $mode, array( 'verify', 'repair' ), true ) && empty( self::current_user_status()['bound'] ) ) {
			return REST::err( __( 'Link this WordPress account with KeyLockr SSO before verifying the connection.', 'dologin' ) );
		}

		if ( 'login' === $mode ) {
			if ( $this->cls( 'Auth' )->is_ip_denied() ) {
				return REST::err( __( 'This IP is not allowed to login.', 'dologin' ) );
			}
			if ( $this->cls( 'Auth' )->is_rate_limited() ) {
				return REST::err( Lang::msg( 'max_retries_hit' ) );
			}
		}

		if ( $this->start_rate_limited() ) {
			return REST::err( __( 'Too many KeyLockr SSO session requests. Please try later.', 'dologin' ) );
		}

		$clock = $this->check_server_clock();
		if ( is_wp_error( $clock ) ) {
			return REST::err( $clock->get_error_message() );
		}

		$keys = $this->server_keys();
		if ( is_wp_error( $keys ) ) {
			return REST::err( $keys->get_error_message() );
		}

		try {
			$state_id = bin2hex( random_bytes( 16 ) );
		} catch ( \Exception $ex ) {
			return REST::err( __( 'Failed to create KeyLockr SSO session.', 'dologin' ) );
		}

		$site_keys = self::site_keys();
		if ( is_wp_error( $site_keys ) ) {
			return REST::err( $site_keys->get_error_message() );
		}
		$sign_kp = $site_keys['sign_kp'];
		$box_kp  = $site_keys['box_kp'];
		$sign_pk = sodium_crypto_sign_publickey( $sign_kp );
		$sign_sk = sodium_crypto_sign_secretkey( $sign_kp );
		$enc_pk  = sodium_crypto_box_publickey( $box_kp );
		$enc_sk  = sodium_crypto_box_secretkey( $box_kp );

		$app_tag = self::app_tag();
		$body    = $this->handshake_body( $sign_pk, $enc_pk, get_bloginfo( 'name' ) . ' DoLogin', $app_tag );

		$res = wp_safe_remote_post(
			self::api_base() . '/handshake',
			array(
				'timeout'             => 15,
				'redirection'         => 0,
				'limit_response_size' => self::FRAME_MAX_BYTES,
				'sslverify'           => true,
				'headers' => array(
					'Accept'       => 'application/octet-stream',
					'Content-Type' => 'application/octet-stream',
				),
				'body'    => $body,
			)
		);
		if ( is_wp_error( $res ) ) {
			return REST::err( $res->get_error_message() );
		}
		if ( (int) wp_remote_retrieve_response_code( $res ) < 200 || (int) wp_remote_retrieve_response_code( $res ) >= 300 ) {
			return REST::err( __( 'KeyLockr handshake returned an invalid response status.', 'dologin' ) );
		}

		try {
			$decoded = KLSso_MsgPack::unpack( wp_remote_retrieve_body( $res ) );
		} catch ( \Exception $ex ) {
			return REST::err( __( 'Failed to decode KeyLockr handshake response.', 'dologin' ) );
		}
		if ( ! is_array( $decoded ) || ! isset( $decoded['_res'] ) || 'ok' !== $decoded['_res'] ) {
			return REST::err( is_array( $decoded ) ? $this->handshake_error_message( $decoded ) : __( 'KeyLockr handshake failed.', 'dologin' ) );
		}

		$tmp_id = isset( $decoded['tmp_id'] ) && is_string( $decoded['tmp_id'] ) ? $decoded['tmp_id'] : '';
		if ( ! $this->valid_tmp_id( $tmp_id ) ) {
			return REST::err( __( 'KeyLockr handshake did not return tmp_id.', 'dologin' ) );
		}

		$state = array(
			'mode'                 => $mode,
			'phase'                => 'tmp_auth',
			'user_id'              => get_current_user_id(),
			'id'                   => 'tmp.' . $tmp_id,
			'tmp_id'               => $tmp_id,
			'app_tag'              => $app_tag,
			'site_key_fingerprint' => self::site_key_fingerprint_from_keys( $site_keys ),
			'sign_sk'              => base64_encode( $sign_sk ),
			'enc_sk'               => base64_encode( $enc_sk ),
			'server_enc_pk'        => base64_encode( $keys['enc_pk'] ),
			'server_sign_pk'       => base64_encode( $keys['sign_pk'] ),
		);
		if ( ! $this->save_state( $state_id, $state ) ) {
			return REST::err( __( 'Failed to store KeyLockr SSO session.', 'dologin' ) );
		}

		return REST::ok(
			array(
				'state'  => $state_id,
				'qr'     => sprintf( self::QR_SCHEME_TEMPLATE, rawurlencode( $tmp_id ) ),
				'ws_url' => $this->ws_url_for( 'tmp.' . $tmp_id, $sign_sk ),
			)
		);
	}

	/**
	 * Process a KeyLockr WebSocket frame forwarded by the browser.
	 */
	public function frame( $request ) {
		$raw_state = $request->get_param( 'state' );
		$raw_frame = $request->get_param( 'frame' );
		$state_id  = is_string( $raw_state ) ? sanitize_text_field( $raw_state ) : '';
		$frame     = is_string( $raw_frame ) ? $raw_frame : '';
		if ( $this->request_rate_limited( 'frame', self::FRAME_IP_LIMIT, self::START_WINDOW ) ) {
			return REST::err( __( 'Too many KeyLockr SSO frame requests. Please try later.', 'dologin' ) );
		}
		if ( ! preg_match( '/^[a-f0-9]{32}$/', $state_id ) ) {
			return REST::err( __( 'KeyLockr SSO session expired.', 'dologin' ) );
		}
		$lock_owner = $this->acquire_state_lock( $state_id );
		if ( ! $lock_owner ) {
			return REST::err( __( 'KeyLockr SSO session is busy. Please retry.', 'dologin' ) );
		}

		try {
			return $this->process_frame( $state_id, $frame );
		} finally {
			$this->release_state_lock( $state_id, $lock_owner );
		}
	}

	/**
	 * Process one forwarded frame while holding the state lock.
	 */
	private function process_frame( $state_id, $frame ) {
		$state = $this->load_state( $state_id );
		if ( ! $state ) {
			return REST::err( __( 'KeyLockr SSO session expired.', 'dologin' ) );
		}
		if ( empty( $state['site_key_fingerprint'] ) || ! self::site_key_fingerprint_matches( $state['site_key_fingerprint'] ) ) {
			$this->delete_state( $state_id );
			return REST::err( __( 'KeyLockr site keys changed. Start a new session.', 'dologin' ) );
		}
		if ( empty( $state['app_tag'] ) || ! hash_equals( self::app_tag(), (string) $state['app_tag'] ) ) {
			$this->delete_state( $state_id );
			return REST::err( __( 'KeyLockr App Tag changed. Start a new session.', 'dologin' ) );
		}

		if ( isset( $state['mode'] )
			&& in_array( $state['mode'], array( 'bind', 'verify', 'repair' ), true )
			&& (int) get_current_user_id() !== (int) $state['user_id'] ) {
			return REST::err( __( 'KeyLockr SSO account session does not match current user.', 'dologin' ) );
		}
		$state['frame_count'] = isset( $state['frame_count'] ) ? (int) $state['frame_count'] + 1 : 1;
		if ( $state['frame_count'] > self::FRAME_LIMIT || strlen( $frame ) > ( self::FRAME_MAX_BYTES * 2 ) ) {
			$this->delete_state( $state_id );
			return REST::err( __( 'KeyLockr SSO frame limit exceeded.', 'dologin' ) );
		}

		$bytes = base64_decode( $frame, true );
		if ( false === $bytes || strlen( $bytes ) > self::FRAME_MAX_BYTES ) {
			if ( ! $this->save_state( $state_id, $state ) ) {
				$this->delete_state( $state_id );
			}
			return REST::err( __( 'Invalid KeyLockr SSO frame.', 'dologin' ) );
		}
		if ( ! $this->remember_frame( $state, $bytes ) ) {
			if ( ! $this->save_state( $state_id, $state ) ) {
				$this->delete_state( $state_id );
			}
			return REST::err( __( 'KeyLockr SSO frame was already processed.', 'dologin' ) );
		}

		try {
			list( $action, $body ) = $this->open_kps( $state, $bytes );
			$res                  = $this->handle_kps_action( $state, $action, $body );
		} catch ( \Exception $ex ) {
			if ( $this->is_terminal_kps_error( $ex ) ) {
				$this->delete_state( $state_id );
			} elseif ( ! $this->save_state( $state_id, $state ) ) {
				$this->delete_state( $state_id );
				return REST::err( __( 'Failed to store KeyLockr SSO session.', 'dologin' ) );
			}
			$this->fail_login_if_needed( $state, $ex );
			$error = REST::err( $ex->getMessage() );
			if ( self::REPAIR_REQUIRED_CODE === $ex->getCode() && isset( $state['mode'] ) && 'verify' === $state['mode'] ) {
				$error['repair'] = true;
			}
			return $error;
		} catch ( \Throwable $ex ) {
			if ( ! $this->save_state( $state_id, $state ) ) {
				$this->delete_state( $state_id );
				return REST::err( __( 'Failed to store KeyLockr SSO session.', 'dologin' ) );
			}
			return REST::err( __( 'Invalid KeyLockr SSO frame.', 'dologin' ) );
		}

		if ( ! empty( $res['_delete_state'] ) ) {
			$this->delete_state( $state_id );
			unset( $res['_delete_state'] );
		} elseif ( ! $this->save_state( $state_id, $state ) ) {
			$this->delete_state( $state_id );
			return REST::err( __( 'Failed to store KeyLockr SSO session.', 'dologin' ) );
		}
		return REST::ok( $res );
	}

	/**
	 * Handle decrypted KPS actions.
	 */
	private function handle_kps_action( &$state, $action, $body ) {
		if ( ! is_array( $body ) ) {
			throw new \Exception( __( 'Invalid KeyLockr SSO response.', 'dologin' ) );
		}
		$this->assert_kps_action_phase( $state, $action );

		if ( ! isset( $body['_res'] ) || 'ok' !== $body['_res'] ) {
			$code = isset( $body['code'] ) && is_scalar( $body['code'] ) ? sanitize_text_field( (string) $body['code'] ) : 'unknown_error';
			if ( isset( $body['_res'] ) && 'err' === $body['_res'] ) {
				if ( 'app_auth_result' === $action && $this->authorization_denied_code( $code ) ) {
					throw $this->app_auth_terminal_error( sprintf( __( 'KeyLockr authorization failed: %s', 'dologin' ), $code ), true );
				}
				if ( 'app_file_not_found' === $code ) {
					throw $this->appdata_disabled_error();
				}
				if ( $this->appdata_write_mode( $state ) && 'app_set_data' === $action && 'file_ver_conflict' === $code ) {
					$res            = $this->retry_appdata_write( $state );
					$state['phase'] = 'app_read';
					return $res;
				}
				if ( $this->appdata_write_mode( $state ) && in_array( $action, array( 'app_set_data', 'app_get_data' ), true ) ) {
					throw $this->appdata_verification_error();
				}
				throw new \Exception( sprintf( __( 'KeyLockr returned an error: %s', 'dologin' ), $code ) );
			}
			throw new \Exception( __( 'Invalid KeyLockr SSO response.', 'dologin' ) );
		}

		if ( 'connected' === $action ) {
			if ( ! isset( $body['status'] ) || 'ok' !== $body['status'] ) {
				throw new \Exception( __( 'Invalid KeyLockr SSO response.', 'dologin' ) );
			}
			return array(
				'status'  => 'connected',
				'message' => __( 'Connected to KeyLockr. Waiting for authorization...', 'dologin' ),
			);
		}

		if ( 'app_auth_result' === $action ) {
			$tmp_id = isset( $body['tmp_id'] ) && is_string( $body['tmp_id'] ) ? $body['tmp_id'] : '';
			if ( empty( $state['tmp_id'] ) || '' === $tmp_id || ! hash_equals( $state['tmp_id'], $tmp_id ) ) {
				throw $this->app_auth_terminal_error( __( 'KeyLockr authorization did not match this login request.', 'dologin' ) );
			}

			$status = isset( $body['status'] ) && is_string( $body['status'] ) ? $body['status'] : '';
			if ( 'error' === $status ) {
				$code = isset( $body['code'] ) && is_string( $body['code'] ) ? trim( $body['code'] ) : '';
				if ( '' === $code ) {
					throw $this->app_auth_terminal_error( __( 'KeyLockr returned an invalid authorization error.', 'dologin' ) );
				}
				if ( 'app_auth_result_too_large' === $code ) {
					throw $this->app_auth_terminal_error( __( 'KeyLockr authorization result was too large. Reduce the service payload and scan again.', 'dologin' ) );
				}
				throw $this->app_auth_terminal_error(
					sprintf( __( 'KeyLockr authorization failed: %s', 'dologin' ), sanitize_text_field( $code ) ),
					$this->authorization_denied_code( $code )
				);
			}
			if ( 'done' !== $status ) {
				throw $this->app_auth_terminal_error( __( 'Invalid KeyLockr SSO response.', 'dologin' ) );
			}

			$app_id  = isset( $body['app_id'] ) && is_string( $body['app_id'] ) ? $body['app_id'] : '';
			$safe_id = isset( $body['safe_id'] ) && is_string( $body['safe_id'] ) ? $body['safe_id'] : '';
			if ( ! $this->valid_identity_id( $app_id ) || ! $this->valid_identity_id( $safe_id ) ) {
				throw $this->app_auth_terminal_error( __( 'KeyLockr did not return SSO identity.', 'dologin' ) );
			}
			$capabilities = $this->response_capabilities( $body );
			if ( false === $capabilities ) {
				throw $this->app_auth_terminal_error( __( 'Invalid KeyLockr SSO response.', 'dologin' ) );
			}
			sort( $capabilities, SORT_STRING );
			if ( array( 'app_data', 'sso' ) !== $capabilities ) {
				throw $this->app_auth_terminal_error( __( 'KeyLockr returned unexpected SSO capabilities.', 'dologin' ) );
			}

			try {
				$data_ver = $this->appdata_version( $body );
			} catch ( \Exception $ex ) {
				throw $this->app_auth_terminal_error( $ex->getMessage() );
			}
			if ( array_key_exists( 'data_deferred', $body ) && true !== $body['data_deferred'] ) {
				throw $this->app_auth_terminal_error( __( 'KeyLockr returned an invalid deferred app data flag.', 'dologin' ) );
			}
			$data_deferred = isset( $body['data_deferred'] ) && true === $body['data_deferred'];
			if ( $data_deferred && ( array_key_exists( 'data_plain', $body ) || array_key_exists( 'data_encrypted', $body ) ) ) {
				throw $this->app_auth_terminal_error( __( 'KeyLockr returned app data fields with a deferred result.', 'dologin' ) );
			}
			if ( ! $data_deferred && array_key_exists( 'data_encrypted', $body )
				&& ! is_string( $body['data_encrypted'] )
				&& ! ( $body['data_encrypted'] instanceof KLSso_MsgPack_Bin ) ) {
				throw $this->app_auth_terminal_error( __( 'KeyLockr returned invalid encrypted app data.', 'dologin' ) );
			}

			if ( ! isset( $body['data_filekey'] )
				|| ( ! is_string( $body['data_filekey'] ) && ! ( $body['data_filekey'] instanceof KLSso_MsgPack_Bin ) ) ) {
				throw $this->app_auth_terminal_error( __( 'KeyLockr did not return the direct app data filekey required by this site.', 'dologin' ) );
			}
			$packed_file_key = $this->bin_value( $body['data_filekey'] );
			if ( '' === $packed_file_key ) {
				throw $this->app_auth_terminal_error( __( 'KeyLockr did not return the direct app data filekey required by this site.', 'dologin' ) );
			}
			try {
				$file_key = $this->load_file_key( $state, $body );
			} catch ( \Exception $ex ) {
				throw $this->app_auth_terminal_error( $ex->getMessage() );
			}

			$state['app_id']       = $app_id;
			$state['safe_id']      = $safe_id;
			$state['data_ver']     = $data_ver;
			$state['data_filekey'] = base64_encode( $packed_file_key );
			$state['verified']     = true;
			$state['nickname']     = isset( $body['user_nickname'] ) && is_string( $body['user_nickname'] )
				? sanitize_text_field( $body['user_nickname'] )
				: '';
			$state['id']           = 'app.' . $app_id;
			$state['phase']        = 'app_read';

			try {
				if ( $this->appdata_write_mode( $state ) && empty( $state['appdata_written'] ) ) {
					$res            = $this->write_appdata( $state, $file_key );
					$state['phase'] = 'app_write';
					$res['status']   = 'reconnect';
					$res['ws_url']   = $this->ws_url_for( $state['id'], base64_decode( $state['sign_sk'] ) );
					return $res;
				}
				if ( ! $data_deferred && array_key_exists( 'data_encrypted', $body ) ) {
					$data_enc = $this->bin_value( $body['data_encrypted'] );
					return $this->process_appdata( $state, $data_enc, $file_key );
				}
			} finally {
				$this->clear_file_key( $file_key );
			}

			return array(
				'status'  => 'reconnect',
				'ws_url'  => $this->ws_url_for( $state['id'], base64_decode( $state['sign_sk'] ) ),
				'send'    => base64_encode( $this->seal_kps( $state, 'app_get_data', array() ) ),
				'message' => __( 'Reading KeyLockr app data...', 'dologin' ),
			);
		}

		if ( 'app_get_data' === $action ) {
			if ( empty( $state['data_filekey'] ) ) {
				throw new \Exception( __( 'KeyLockr app data filekey is missing.', 'dologin' ) );
			}
			$packed_file_key = base64_decode( $state['data_filekey'], true );
			if ( false === $packed_file_key ) {
				throw new \Exception( __( 'Invalid KeyLockr app data filekey.', 'dologin' ) );
			}
			$file_key_body = array(
				'data_filekey' => KLSso_MsgPack::bin( $packed_file_key ),
			);
			$file_key = $this->load_file_key( $state, $file_key_body );
			$data_enc = $this->bin_value( isset( $body['data_encrypted'] ) ? $body['data_encrypted'] : '' );
			$state['data_ver'] = $this->appdata_version( $body );
			try {
				if ( $this->appdata_write_mode( $state ) && ! empty( $state['appdata_retry_pending'] ) ) {
					unset( $state['appdata_retry_pending'] );
					$res            = $this->write_appdata( $state, $file_key );
					$state['phase'] = 'app_write';
					return $res;
				}
				return $this->process_appdata( $state, $data_enc, $file_key );
			} finally {
				$this->clear_file_key( $file_key );
			}
		}

		if ( 'app_set_data' === $action ) {
			$file_id_ok = isset( $body['file_id'] ) && is_string( $body['file_id'] ) && '' !== trim( $body['file_id'] );
			$new_ver    = $this->appdata_version( $body );
			if ( ! $this->appdata_write_mode( $state ) || empty( $state['data_filekey'] ) || empty( $state['app_hash'] ) || empty( $state['data_ver'] ) || ! $file_id_ok || hash_equals( $state['data_ver'], $new_ver ) ) {
				throw $this->appdata_verification_error();
			}
			$state['appdata_written'] = true;
			$state['data_ver']        = $new_ver;
			$state['phase']           = 'app_read';
			return array(
				'status'  => 'send',
				'send'    => base64_encode( $this->seal_kps( $state, 'app_get_data', array() ) ),
				'message' => __( 'KeyLockr app data saved. Reading it back for verification...', 'dologin' ),
			);
		}

		if ( 'ping' === $action ) {
			return array(
				'status' => 'send',
				'send'   => base64_encode( $this->seal_kps( $state, 'pong', array() ) ),
			);
		}

		throw new \Exception( __( 'Unexpected KeyLockr SSO message.', 'dologin' ) );
	}

	/**
	 * Decrypt and verify the AppData hash, or write it during binding and repair.
	 */
	private function process_appdata( &$state, $data_enc, $file_key ) {
		if ( ! $file_key ) {
			throw new \Exception( __( 'KeyLockr app data key is missing.', 'dologin' ) );
		}

		$data = null;
		if ( $data_enc ) {
			try {
				$plain = $this->decrypt_appdata( $data_enc, $file_key );
				if ( false === $plain ) {
					throw new \Exception( __( 'Failed to decrypt KeyLockr app data.', 'dologin' ) );
				}
				$data = KLSso_MsgPack::unpack( $plain );
			} catch ( \Exception $ex ) {
				if ( $this->appdata_write_mode( $state ) ) {
					throw $this->appdata_verification_error();
				}
				throw $ex;
			}
		}

		if ( $this->appdata_write_mode( $state ) ) {
			$expected_hash = self::user_app_hash( $state['user_id'] );
			if ( ! is_array( $data ) || ! isset( $data['hash'] ) || ! is_scalar( $data['hash'] ) || ! hash_equals( $expected_hash, (string) $data['hash'] ) ) {
				throw $this->appdata_verification_error();
			}
			$state['app_hash']    = (string) $data['hash'];
			$state['app_hash_ok'] = true;
			return $this->complete_verified_session( $state );
		}

		if ( ! is_array( $data ) || ! isset( $data['hash'] ) || ! is_scalar( $data['hash'] ) ) {
			if ( 'verify' === $state['mode'] ) {
				throw $this->repair_required_error();
			}
			throw $this->login_identity_error( __( 'Please link this WordPress account with KeyLockr SSO first.', 'dologin' ) );
		}
		$state['app_hash'] = (string) $data['hash'];
		return $this->complete_verified_session( $state );
	}

	/**
	 * Write KeyLockr verification data for the current WordPress user.
	 */
	private function write_appdata( &$state, $file_key ) {
		if ( isset( $state['mode'] ) && 'repair' === $state['mode'] ) {
			$this->validate_repair_state( $state );
		} else {
			$this->validate_bind_state( $state );
		}
		if ( empty( $state['data_ver'] ) ) {
			throw $this->appdata_verification_error();
		}
		$state['app_hash']        = self::user_app_hash( $state['user_id'] );
		$state['app_hash_ok']     = false;
		$state['appdata_written'] = false;
		$payload                  = KLSso_MsgPack::pack(
			array(
				'hash' => $state['app_hash'],
				'site' => home_url(),
				'ts'   => time(),
				'v'    => 1,
			)
		);
		$enc = $this->encrypt_appdata( $payload, $file_key );

		return array(
			'status'  => 'send',
			'send'    => base64_encode(
				$this->seal_kps(
					$state,
					'app_set_data',
					array(
						'data_enc__' => 0,
						'ver'        => $state['data_ver'],
					),
					array( $enc )
				)
			),
			'message' => __( 'Writing KeyLockr app data verification hash...', 'dologin' ),
		);
	}

	/**
	 * Confirm that the KeyLockr account may be linked to the current WordPress user.
	 */
	private function validate_bind_state( $state ) {
		if ( empty( $state['verified'] ) || empty( $state['safe_id'] ) || empty( $state['app_id'] ) ) {
			throw new \Exception( __( 'KeyLockr SSO identity is not verified.', 'dologin' ) );
		}
		$uid = (int) $state['user_id'];
		if ( ! $uid || ! get_userdata( $uid ) ) {
			throw new \Exception( __( 'WordPress user is not available for KeyLockr binding.', 'dologin' ) );
		}

		$existing = get_users(
			array(
				'meta_key'    => self::META_SAFE_ID, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- rare binding operation.
				'meta_value'  => $state['safe_id'], // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value -- rare binding operation.
				'fields'      => 'ID',
				'number'      => 2,
				'count_total' => false,
			)
		);
		foreach ( $existing as $existing_uid ) {
			if ( (int) $existing_uid !== $uid ) {
				throw new \Exception( __( 'This KeyLockr account is already linked to another WordPress user.', 'dologin' ) );
			}
		}
		return $uid;
	}

	/**
	 * Complete a verified bind, repair, test, or login session.
	 */
	private function complete_verified_session( &$state ) {
		if ( empty( $state['verified'] ) ) {
			throw new \Exception( __( 'KeyLockr SSO identity is not verified.', 'dologin' ) );
		}
		if ( empty( $state['site_key_fingerprint'] ) || ! self::site_key_fingerprint_matches( $state['site_key_fingerprint'] ) ) {
			throw new \Exception( __( 'KeyLockr site keys changed. Start a new session.', 'dologin' ) );
		}
		if ( empty( $state['app_tag'] ) || ! hash_equals( self::app_tag(), (string) $state['app_tag'] ) ) {
			throw new \Exception( __( 'KeyLockr App Tag changed. Start a new session.', 'dologin' ) );
		}

		if ( in_array( $state['mode'], array( 'login', 'verify' ), true ) && empty( $state['app_hash'] ) ) {
			throw new \Exception( __( 'KeyLockr app data hash is not verified.', 'dologin' ) );
		}
		if ( $this->appdata_write_mode( $state ) && empty( $state['app_hash_ok'] ) ) {
			throw new \Exception( __( 'KeyLockr app data read-back is not verified.', 'dologin' ) );
		}

		if ( 'verify' === $state['mode'] ) {
			$uid           = (int) $state['user_id'];
			$safe_id       = trim( (string) get_user_meta( $uid, self::META_SAFE_ID, true ) );
			$expected_hash = trim( (string) get_user_meta( $uid, self::META_APP_HASH, true ) );
			if ( ! $uid || ! get_userdata( $uid ) || ! $safe_id
				|| empty( $state['safe_id'] )
				|| ! hash_equals( $safe_id, (string) $state['safe_id'] ) ) {
				throw new \Exception( __( 'KeyLockr SSO verification does not match this WordPress account.', 'dologin' ) );
			}
			if ( ! $expected_hash || ! hash_equals( $expected_hash, (string) $state['app_hash'] ) ) {
				throw $this->repair_required_error( true );
			}
			$state['app_hash_ok'] = true;
			update_user_meta( $uid, self::META_SITE_KEY_FP, $state['site_key_fingerprint'] );
			update_user_meta( $uid, self::META_APP_TAG, $state['app_tag'] );
			return array(
				'status'        => 'done',
				'_delete_state' => true,
				'message'       => __( 'KeyLockr SSO verification succeeded.', 'dologin' ),
				'reload'        => false,
			);
		}

		if ( 'login' === $state['mode'] && ( $this->cls( 'Auth' )->is_ip_denied() || $this->cls( 'Auth' )->is_rate_limited() ) ) {
			throw new \Exception( __( 'This IP is not allowed to login.', 'dologin' ) );
		}

		if ( 'repair' === $state['mode'] ) {
			return $this->complete_repair_session( $state );
		}

		if ( 'bind' === $state['mode'] ) {
			$uid = $this->validate_bind_state( $state );

			update_user_meta( $uid, self::META_SAFE_ID, $state['safe_id'] );
			update_user_meta( $uid, self::META_NICKNAME, $state['nickname'] );
			update_user_meta( $uid, self::META_SITE_KEY_FP, $state['site_key_fingerprint'] );
			update_user_meta( $uid, self::META_APP_TAG, $state['app_tag'] );

			return array(
				'status'        => 'done',
				'_delete_state' => true,
				'message'       => __( 'KeyLockr SSO linked successfully.', 'dologin' ),
			);
		}

		$users = get_users(
			array(
				'meta_key'    => self::META_SAFE_ID, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- SSO login lookup.
				'meta_value'  => $state['safe_id'], // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value -- SSO login lookup.
				'fields'      => 'all',
				'number'      => 2,
				'count_total' => false,
			)
		);
		if ( 1 !== count( $users ) ) {
			throw $this->login_identity_error( __( 'The KeyLockr account link is missing or ambiguous.', 'dologin' ) );
		}

		$user = $users[0];
		$expected_hash = get_user_meta( $user->ID, self::META_APP_HASH, true );
		if ( ! $expected_hash || empty( $state['app_hash'] ) || ! hash_equals( (string) $expected_hash, (string) $state['app_hash'] ) ) {
			throw $this->login_identity_error( __( 'KeyLockr app data hash does not match this WordPress account.', 'dologin' ) );
		}
		$state['app_hash_ok'] = true;
		update_user_meta( $user->ID, self::META_SITE_KEY_FP, $state['site_key_fingerprint'] );
		update_user_meta( $user->ID, self::META_APP_TAG, $state['app_tag'] );

		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, false, is_ssl() );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- firing WordPress core login hook.
		do_action( 'wp_login', $user->user_login, $user );

		return array(
			'status'        => 'done',
			'_delete_state' => true,
			'message'       => __( 'Logged in with KeyLockr SSO.', 'dologin' ),
			'redirect'      => apply_filters( 'login_redirect', admin_url(), '', $user ),
		);
	}

	/**
	 * Is libsodium available.
	 */
	public static function sodium_ready() {
		return function_exists( 'sodium_crypto_box_keypair' )
			&& function_exists( 'sodium_crypto_box' )
			&& function_exists( 'sodium_crypto_box_open' )
			&& function_exists( 'sodium_crypto_box_keypair_from_secretkey_and_publickey' )
			&& function_exists( 'sodium_crypto_secretbox' )
			&& function_exists( 'sodium_crypto_secretbox_open' )
			&& function_exists( 'sodium_crypto_sign_keypair' )
			&& function_exists( 'sodium_crypto_sign' )
			&& function_exists( 'sodium_crypto_sign_open' );
	}

	/**
	 * Extract binary bytes from MsgPack bin wrapper.
	 */
	private function bin_value( $value ) {
		return $value instanceof KLSso_MsgPack_Bin ? $value->bytes : (string) $value;
	}

	/**
	 * URL-safe base64 without padding.
	 */
	private function base64url_encode( $data ) {
		return rtrim( strtr( base64_encode( $data ), '+/', '-_' ), '=' );
	}

	/**
	 * Count failed SSO login attempts when appropriate.
	 */
	private function fail_login_if_needed( $state, $exception ) {
		$code = $exception instanceof \Exception ? $exception->getCode() : 0;
		if ( is_array( $state )
			&& isset( $state['mode'] )
			&& 'login' === $state['mode']
			&& in_array( $code, array( self::AUTH_DENIED_CODE, self::LOGIN_IDENTITY_CODE ), true ) ) {
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- firing WordPress core failure hook.
			do_action( 'wp_login_failed', 'keylockr_sso' );
		}
	}

	/**
	 * Whether a classified protocol error has ended this short-lived session.
	 */
	private function is_terminal_kps_error( $exception ) {
		return $exception instanceof \Exception
			&& in_array(
				$exception->getCode(),
				array( self::APP_AUTH_TERMINAL_CODE, self::AUTH_DENIED_CODE, self::LOGIN_IDENTITY_CODE ),
				true
			);
	}
}
