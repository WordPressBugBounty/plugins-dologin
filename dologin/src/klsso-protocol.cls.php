<?php
/**
 * KeyLockr SSO protocol and cryptographic helpers.
 *
 * @since 4.6.5
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

trait KLSso_Protocol {
	/**
	 * Decode the file key returned by KeyLockr app_req_filekey.
	 */
	private function load_file_key( $state, $body ) {
		$packed = $this->bin_value( isset( $body['data_filekey'] ) ? $body['data_filekey'] : '' );
		if ( ! $packed ) {
			throw new \Exception( __( 'KeyLockr did not return app data filekey.', 'dologin' ) );
		}

		$data = KLSso_MsgPack::unpack( $packed );
		if ( ! is_array( $data ) || ! isset( $data['encFileKey'], $data['nonceForKey'], $data['nonceForData'], $data['apEncPk'] ) ) {
			throw new \Exception( __( 'Invalid KeyLockr app data filekey.', 'dologin' ) );
		}
		$enc_file_key   = $this->bin_value( $data['encFileKey'] );
		$nonce_for_key  = $this->bin_value( $data['nonceForKey'] );
		$nonce_for_data = $this->bin_value( $data['nonceForData'] );
		$sender_pk      = $this->bin_value( $data['apEncPk'] );

		if ( strlen( $enc_file_key ) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES + SODIUM_CRYPTO_BOX_MACBYTES
			|| strlen( $nonce_for_key ) !== SODIUM_CRYPTO_BOX_NONCEBYTES
			|| strlen( $nonce_for_data ) !== SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
			throw new \Exception( __( 'Invalid KeyLockr app data filekey.', 'dologin' ) );
		}
		if ( strlen( $sender_pk ) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES ) {
			throw new \Exception( __( 'KeyLockr app data filekey is missing sender public key.', 'dologin' ) );
		}

		$enc_sk = empty( $state['enc_sk'] ) ? false : base64_decode( $state['enc_sk'], true );
		if ( false === $enc_sk || strlen( $enc_sk ) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES ) {
			throw new \Exception( __( 'Invalid KeyLockr SSO session key.', 'dologin' ) );
		}
		$keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey( $enc_sk, $sender_pk );
		$key     = sodium_crypto_box_open( $enc_file_key, $nonce_for_key, $keypair );
		if ( false === $key || strlen( $key ) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES ) {
			throw new \Exception( __( 'Failed to decrypt KeyLockr app data filekey.', 'dologin' ) );
		}

		return $key;
	}

	/**
	 * Decrypt nonce-prefixed AppData.
	 */
	private function decrypt_appdata( $data_enc, $file_key ) {
		if ( strlen( $data_enc ) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES ) {
			return false;
		}
		$nonce = substr( $data_enc, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		return sodium_crypto_secretbox_open( substr( $data_enc, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ), $nonce, $file_key );
	}

	/**
	 * Encrypt AppData with a fresh nonce prefixed to the secretbox ciphertext.
	 */
	private function encrypt_appdata( $plain, $file_key ) {
		$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		return $nonce . sodium_crypto_secretbox( $plain, $nonce, $file_key );
	}

	/**
	 * Best-effort clear the raw file key after a request.
	 */
	private function clear_file_key( &$file_key ) {
		if ( $file_key && function_exists( 'sodium_memzero' ) ) {
			sodium_memzero( $file_key );
		}
		$file_key = '';
	}

	/**
	 * Build an AppData read-back verification error.
	 */
	private function appdata_verification_error() {
		return new \Exception( __( 'KeyLockr app data write could not be verified. Unlock KeyLockr on your phone and try linking again.', 'dologin' ) );
	}

	/**
	 * Build an error for exhausted AppData version-conflict retries.
	 */
	private function appdata_conflict_error() {
		return new \Exception( __( 'KeyLockr app data changed repeatedly while linking. Please scan again.', 'dologin' ) );
	}

	/**
	 * Build an error for a service without App Data Storage.
	 */
	private function appdata_disabled_error() {
		return new \Exception( __( 'KeyLockr app data was not found. This usually means App Data Storage is disabled for this service. Open KeyLockr Developer, edit this App Tag, enable App Data Storage, and scan again.', 'dologin' ) );
	}

	/**
	 * Read the current AppData CAS version.
	 */
	private function appdata_version( $body ) {
		if ( ! isset( $body['ver'] ) || ! is_string( $body['ver'] ) || ! preg_match( '/^[0-9]+$/', $body['ver'] ) ) {
			throw new \Exception( __( 'KeyLockr returned an invalid app data version.', 'dologin' ) );
		}
		return $body['ver'];
	}

	/**
	 * Convert current handshake error codes into actionable messages.
	 */
	private function handshake_error_message( $body ) {
		$code = isset( $body['code'] ) && is_scalar( $body['code'] ) ? sanitize_text_field( (string) $body['code'] ) : 'unknown_error';
		if ( 'sso_data_not_approved' === $code ) {
			return __( 'KeyLockr App Data Storage is not approved for this App Tag. Enable it in KeyLockr Developer and try again.', 'dologin' );
		}
		if ( in_array( $code, array( 'app_tag_invalid', 'sso_service_invalid' ), true ) ) {
			return __( 'KeyLockr could not resolve this App Tag. Check the effective App Tag in KeyLockr Developer and try again.', 'dologin' );
		}
		return sprintf( __( 'KeyLockr handshake failed: %s', 'dologin' ), $code );
	}

	/**
	 * Parse and validate capabilities from the authorization result.
	 */
	private function response_capabilities( $body ) {
		if ( ! isset( $body['capabilities'] ) || ! is_array( $body['capabilities'] ) ) {
			return false;
		}
		$capabilities = array();
		foreach ( $body['capabilities'] as $capability ) {
			if ( ! is_string( $capability ) || '' === $capability ) {
				return false;
			}
			$capabilities[] = $capability;
		}
		return $capabilities;
	}

	/**
	 * Read the latest version after an AppData CAS conflict and retry once.
	 */
	private function retry_appdata_write( &$state ) {
		if ( empty( $state['data_filekey'] ) ) {
			throw $this->appdata_verification_error();
		}
		$retry_count = isset( $state['appdata_cas_retries'] ) ? (int) $state['appdata_cas_retries'] : 0;
		if ( $retry_count >= self::APPDATA_CAS_RETRY_LIMIT ) {
			throw $this->appdata_conflict_error();
		}
		$state['appdata_cas_retries']  = $retry_count + 1;
		$state['appdata_retry_pending'] = true;
		return array(
			'status'  => 'send',
			'send'    => base64_encode( $this->seal_kps( $state, 'app_get_data', array() ) ),
			'message' => __( 'KeyLockr app data changed while linking. Reading the latest version before retrying...', 'dologin' ),
		);
	}

	/**
	 * Call the backend app_verify endpoint to verify identity.
	 */
	private function app_verify( $state ) {
		$res = wp_safe_remote_post(
			self::api_base() . '/app_verify',
			array(
				'timeout'             => 15,
				'redirection'         => 0,
				'limit_response_size' => self::FRAME_MAX_BYTES,
				'sslverify'           => true,
				'headers' => array(
					'Accept'       => 'application/json',
					'Content-Type' => 'application/json',
				),
				'body'    => wp_json_encode(
					array(
						'app_tag' => $state['app_tag'],
						'app_id'  => $state['app_id'],
						'safe_id' => $state['safe_id'],
						'sign_pk' => $state['sign_pk'],
					)
				),
			)
		);
		if ( is_wp_error( $res ) ) {
			return $res;
		}
		if ( (int) wp_remote_retrieve_response_code( $res ) < 200 || (int) wp_remote_retrieve_response_code( $res ) >= 300 ) {
			return new \WP_Error( 'dologin_kl_sso_verify_status', __( 'KeyLockr app_verify returned an invalid response status.', 'dologin' ) );
		}

		$body = json_decode( wp_remote_retrieve_body( $res ), true );
		if ( ! is_array( $body ) ) {
			return new \WP_Error( 'dologin_kl_sso_verify_decode', __( 'Failed to decode KeyLockr app_verify response.', 'dologin' ) );
		}
		if ( ! isset( $body['_res'] ) || 'ok' !== $body['_res'] ) {
			$code = isset( $body['code'] ) && is_scalar( $body['code'] ) ? sanitize_text_field( (string) $body['code'] ) : 'unknown_error';
			return new \WP_Error( 'dologin_kl_sso_verify_error', sprintf( __( 'KeyLockr app_verify failed: %s', 'dologin' ), $code ) );
		}

		return $body;
	}

	/**
	 * Open and validate an incoming KPS frame.
	 */
	private function open_kps( $state, $frame ) {
		$root = KLSso_MsgPack::unpack( $frame );
		if ( ! is_array( $root ) || empty( $root['kps'] ) || ! is_array( $root['kps'] ) || empty( $root['seal'] ) ) {
			throw new \Exception( __( 'Invalid KeyLockr KPS frame.', 'dologin' ) );
		}

		$kps      = $root['kps'];
		$seal     = $this->bin_value( $root['seal'] );
		$sign_pk  = isset( $state['server_sign_pk'] ) ? base64_decode( $state['server_sign_pk'], true ) : false;
		$box      = empty( $kps['box'] ) ? '' : $this->bin_value( $kps['box'] );
		if ( ! $box || empty( $kps['n'] ) || false === $sign_pk || strlen( $sign_pk ) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES || strlen( $seal ) !== SODIUM_CRYPTO_SIGN_BYTES + 32 ) {
			throw new \Exception( __( 'Invalid KeyLockr KPS frame.', 'dologin' ) );
		}
		$got_hash = sodium_crypto_sign_open( $seal, $sign_pk );
		if ( false === $got_hash ) {
			throw new \Exception( __( 'Invalid KeyLockr KPS signature.', 'dologin' ) );
		}

		$want_hash = hash( 'sha256', KLSso_MsgPack::pack( $kps ), true );
		if ( ! hash_equals( $want_hash, $got_hash ) ) {
			throw new \Exception( __( 'Invalid KeyLockr KPS hash.', 'dologin' ) );
		}

		$enc_sk        = isset( $state['enc_sk'] ) ? base64_decode( $state['enc_sk'], true ) : false;
		$server_enc_pk = isset( $state['server_enc_pk'] ) ? base64_decode( $state['server_enc_pk'], true ) : false;
		$nonce         = $this->bin_value( $kps['n'] );
		if ( false === $enc_sk || false === $server_enc_pk || strlen( $enc_sk ) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES || strlen( $server_enc_pk ) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES || strlen( $nonce ) !== SODIUM_CRYPTO_BOX_NONCEBYTES ) {
			throw new \Exception( __( 'Invalid KeyLockr KPS encryption data.', 'dologin' ) );
		}
		$keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey( $enc_sk, $server_enc_pk );
		$plain   = sodium_crypto_box_open( $box, $nonce, $keypair );
		if ( false === $plain ) {
			throw new \Exception( __( 'Failed to decrypt KeyLockr KPS frame.', 'dologin' ) );
		}

		$inner  = KLSso_MsgPack::unpack( $plain );
		if ( ! is_array( $inner ) ) {
			throw new \Exception( __( 'Invalid KeyLockr KPS frame.', 'dologin' ) );
		}
		$header = isset( $inner['header'] ) && is_array( $inner['header'] ) ? $inner['header'] : array();
		$body   = isset( $inner['body'] ) && is_array( $inner['body'] ) ? $inner['body'] : array();
		$timestamp = isset( $header['ts'] ) ? filter_var( $header['ts'], FILTER_VALIDATE_INT ) : false;
		if ( empty( $header['from'] ) || false === $timestamp || ! $this->timestamp_valid( (int) $timestamp ) ) {
			throw new \Exception( __( 'Invalid or expired KeyLockr KPS response.', 'dologin' ) );
		}
		$raw    = array();
		if ( isset( $kps['raw'] ) && ! is_array( $kps['raw'] ) ) {
			throw new \Exception( __( 'Invalid KeyLockr KPS frame.', 'dologin' ) );
		}
		if ( isset( $kps['raw'] ) ) {
			foreach ( $kps['raw'] as $raw_item ) {
				if ( ! is_string( $raw_item ) && ! ( $raw_item instanceof KLSso_MsgPack_Bin ) ) {
					throw new \Exception( __( 'Invalid KeyLockr KPS frame.', 'dologin' ) );
				}
				$raw[] = $this->bin_value( $raw_item );
			}
			$body = $this->join_raw( $body, $raw );
		}

		return array(
			empty( $header['from'] ) ? '' : (string) $header['from'],
			$body,
		);
	}

	/**
	 * Merge KPS raw binary side-channel fields into the decoded body.
	 */
	private function join_raw( $value, $raw ) {
		if ( ! is_array( $value ) ) {
			return $value;
		}

		foreach ( $value as $key => $item ) {
			if ( is_string( $key ) && substr( $key, -2 ) === '__' && is_int( $item ) && isset( $raw[ $item ] ) ) {
				unset( $value[ $key ] );
				$value[ substr( $key, 0, -2 ) ] = KLSso_MsgPack::bin( $raw[ $item ] );
				continue;
			}
			$value[ $key ] = $this->join_raw( $item, $raw );
		}

		return $value;
	}

	/**
	 * Build an outgoing KPS frame.
	 */
	private function seal_kps( $state, $action, $body, $raw = array() ) {
		$inner = KLSso_MsgPack::pack(
			array(
				'body'   => $body,
				'header' => array(
					'to' => $action,
					'ts' => time(),
				),
			)
		);

		$nonce   = random_bytes( SODIUM_CRYPTO_BOX_NONCEBYTES );
		$keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey( base64_decode( $state['enc_sk'] ), base64_decode( $state['server_enc_pk'] ) );
		$box     = sodium_crypto_box( $inner, $nonce, $keypair );
		$kps     = array(
			'app_ver' => 'dologin-' . Core::VER,
			'box'     => KLSso_MsgPack::bin( $box ),
			'id'      => $state['id'],
			'n'       => KLSso_MsgPack::bin( $nonce ),
		);
		if ( $raw ) {
			$kps['raw'] = array();
			foreach ( $raw as $raw_item ) {
				if ( ! is_string( $raw_item ) && ! ( $raw_item instanceof KLSso_MsgPack_Bin ) ) {
					throw new \Exception( __( 'Invalid KeyLockr KPS raw data.', 'dologin' ) );
				}
				$kps['raw'][] = KLSso_MsgPack::bin( $this->bin_value( $raw_item ) );
			}
		}
		$hash    = hash( 'sha256', KLSso_MsgPack::pack( $kps ), true );
		$seal    = sodium_crypto_sign( $hash, base64_decode( $state['sign_sk'] ) );

		return KLSso_MsgPack::pack(
			array(
				'kps'  => $kps,
				'seal' => KLSso_MsgPack::bin( $seal ),
			)
		);
	}

	/**
	 * Build a signed WebSocket URL for a KPS identity.
	 */
	private function ws_url_for( $id, $sign_sk ) {
		$ts  = time();
		$sig = sodium_crypto_sign( $id . '.' . $ts, $sign_sk );
		return add_query_arg( 'sig', $this->base64url_encode( $sig ), self::ws_url() );
	}

	/**
	 * Confirm that the site clock is within the window accepted by KeyLockr.
	 */
	private function check_server_clock() {
		if ( get_transient( self::CLOCK_CACHE ) ) {
			return true;
		}

		$res = wp_safe_remote_get(
			self::api_base() . '/clock',
			array(
				'timeout'             => 10,
				'redirection'         => 0,
				'limit_response_size' => 1024,
				'sslverify'           => true,
			)
		);
		if ( is_wp_error( $res ) ) {
			return $res;
		}
		if ( 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
			return new \WP_Error( 'dologin_kl_sso_clock_status', __( 'KeyLockr clock request returned an invalid status.', 'dologin' ) );
		}

		$body      = json_decode( wp_remote_retrieve_body( $res ), true );
		$timestamp = is_array( $body ) && isset( $body['ts'] ) ? filter_var( $body['ts'], FILTER_VALIDATE_INT ) : false;
		if ( ! is_array( $body ) || ! isset( $body['_res'] ) || 'ok' !== $body['_res'] || false === $timestamp ) {
			return new \WP_Error( 'dologin_kl_sso_clock_response', __( 'KeyLockr returned invalid clock data.', 'dologin' ) );
		}

		$drift = time() - (int) $timestamp;
		if ( $drift > self::CLOCK_FUTURE_LIMIT || $drift < -self::CLOCK_PAST_LIMIT ) {
			return new \WP_Error( 'dologin_kl_sso_clock_drift', __( 'This server clock is out of sync with KeyLockr. Synchronize the server time and try again.', 'dologin' ) );
		}
		set_transient( self::CLOCK_CACHE, 1, 10 * MINUTE_IN_SECONDS );
		return true;
	}

	/**
	 * Check whether a KeyLockr response timestamp is within the protocol window.
	 */
	private function timestamp_valid( $timestamp ) {
		$now = time();
		return $timestamp >= $now - self::CLOCK_PAST_LIMIT && $timestamp <= $now + self::CLOCK_FUTURE_LIMIT;
	}

	/**
	 * Detect a public IP from ip.me. Family forcing works when WP uses the cURL transport.
	 */
	private static function fetch_public_ip( $family = '' ) {
		$family = (string) $family;
		$filter = null;
		if ( in_array( $family, array( 'v4', 'v6' ), true ) && defined( 'CURLOPT_IPRESOLVE' ) ) {
			$filter = function( $handle ) use ( $family ) {
				if ( 'v4' === $family && defined( 'CURL_IPRESOLVE_V4' ) ) {
					curl_setopt( $handle, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4 );
				}
				if ( 'v6' === $family && defined( 'CURL_IPRESOLVE_V6' ) ) {
					curl_setopt( $handle, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6 );
				}
			};
			add_action( 'http_api_curl', $filter );
		}

		$res = wp_safe_remote_get(
			self::PUBLIC_IP_URL,
			array(
				'timeout'             => 5,
				'redirection'         => 2,
				'limit_response_size' => 128,
				'sslverify'           => true,
				'headers'             => array( 'Accept' => 'text/plain' ),
				'user-agent'          => 'DoLogin/' . Core::VER . '; ' . home_url(),
			)
		);

		if ( $filter ) {
			remove_action( 'http_api_curl', $filter );
		}

		if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
			return self::server_address( $family );
		}

		$ip = trim( wp_remote_retrieve_body( $res ) );
		if ( 'v4' === $family ) {
			return filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ? $ip : self::server_address( $family );
		}
		if ( 'v6' === $family ) {
			return filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ? $ip : self::server_address( $family );
		}
		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : self::server_address( $family );
	}

	/**
	 * Use a publicly routable server address when external detection fails.
	 */
	private static function server_address( $family = '' ) {
		$ip    = isset( $_SERVER['SERVER_ADDR'] ) ? trim( (string) $_SERVER['SERVER_ADDR'] ) : '';
		$flags = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
		if ( 'v4' === $family ) {
			$flags |= FILTER_FLAG_IPV4;
		} elseif ( 'v6' === $family ) {
			$flags |= FILTER_FLAG_IPV6;
		}
		return filter_var( $ip, FILTER_VALIDATE_IP, $flags ) ? $ip : '';
	}

	/**
	 * Fetch and cache server public keys.
	 */
	private function server_keys() {
		$cached = get_transient( self::SERVER_KEYS_CACHE );
		if ( is_array( $cached ) && ! empty( $cached['enc_pk'] ) && ! empty( $cached['sign_pk'] ) ) {
			$cached_enc  = base64_decode( $cached['enc_pk'], true );
			$cached_sign = base64_decode( $cached['sign_pk'], true );
			if ( strlen( (string) $cached_enc ) === SODIUM_CRYPTO_BOX_PUBLICKEYBYTES && strlen( (string) $cached_sign ) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES ) {
				return array(
					'enc_pk'  => $cached_enc,
					'sign_pk' => $cached_sign,
				);
			}
			delete_transient( self::SERVER_KEYS_CACHE );
		}

		$request_args = array(
			'timeout'             => 10,
			'redirection'         => 1,
			'limit_response_size' => 1024,
			'sslverify'           => true,
		);
		$enc          = wp_safe_remote_get( self::api_base() . '/key_enc', $request_args );
		$sign         = wp_safe_remote_get( self::api_base() . '/key_sign', $request_args );
		if ( is_wp_error( $enc ) ) {
			return $enc;
		}
		if ( is_wp_error( $sign ) ) {
			return $sign;
		}
		if ( 200 !== (int) wp_remote_retrieve_response_code( $enc ) || 200 !== (int) wp_remote_retrieve_response_code( $sign ) ) {
			return new \WP_Error( 'dologin_kl_sso_server_key_status', __( 'KeyLockr server key request returned an invalid status.', 'dologin' ) );
		}

		$enc_pk  = base64_decode( trim( wp_remote_retrieve_body( $enc ) ), true );
		$sign_pk = base64_decode( trim( wp_remote_retrieve_body( $sign ) ), true );
		if ( strlen( (string) $enc_pk ) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES || strlen( (string) $sign_pk ) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES ) {
			return new \WP_Error( 'dologin_kl_sso_bad_server_keys', __( 'Invalid KeyLockr server public keys.', 'dologin' ) );
		}

		set_transient(
			self::SERVER_KEYS_CACHE,
			array(
				'enc_pk'  => base64_encode( $enc_pk ),
				'sign_pk' => base64_encode( $sign_pk ),
			),
			DAY_IN_SECONDS
		);

		return array(
			'enc_pk'  => $enc_pk,
			'sign_pk' => $sign_pk,
		);
	}
}
