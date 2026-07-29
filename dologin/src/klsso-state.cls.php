<?php
/**
 * KeyLockr SSO session-state protection.
 *
 * @since 4.7.3
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

trait KLSso_State {
	/**
	 * Store session state with private fields sealed at rest.
	 */
	private function save_state( $state_id, $state ) {
		if ( ! preg_match( '/^[a-f0-9]{32}$/', $state_id ) || ! is_array( $state ) ) {
			return false;
		}

		$stored  = $state;
		$secrets = array();
		foreach ( $this->state_secret_fields() as $field ) {
			if ( isset( $stored[ $field ] ) && '' !== $stored[ $field ] ) {
				$secrets[ $field ] = (string) $stored[ $field ];
			}
			unset( $stored[ $field ] );
		}

		try {
			$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$box   = sodium_crypto_secretbox( KLSso_MsgPack::pack( $secrets ), $nonce, $this->state_secret_key( $state_id ) );
		} catch ( \Exception $ex ) {
			return false;
		}
		$stored['secret_box'] = base64_encode( $nonce . $box );
		return set_transient( self::TRANSIENT_PREFIX . $state_id, $stored, self::SESSION_TTL );
	}

	/**
	 * Load and authenticate sealed session state.
	 */
	private function load_state( $state_id ) {
		if ( ! preg_match( '/^[a-f0-9]{32}$/', $state_id ) ) {
			return false;
		}
		$stored = get_transient( self::TRANSIENT_PREFIX . $state_id );
		if ( ! is_array( $stored ) || empty( $stored['secret_box'] ) ) {
			return false;
		}

		$sealed = base64_decode( $stored['secret_box'], true );
		if ( false === $sealed || strlen( $sealed ) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES ) {
			return false;
		}
		$nonce = substr( $sealed, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$plain = sodium_crypto_secretbox_open( substr( $sealed, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ), $nonce, $this->state_secret_key( $state_id ) );
		if ( false === $plain ) {
			return false;
		}

		try {
			$secrets = KLSso_MsgPack::unpack( $plain );
		} catch ( \Exception $ex ) {
			return false;
		}
		if ( ! is_array( $secrets ) ) {
			return false;
		}

		unset( $stored['secret_box'] );
		foreach ( $this->state_secret_fields() as $field ) {
			if ( isset( $secrets[ $field ] ) && is_string( $secrets[ $field ] ) ) {
				$stored[ $field ] = $secrets[ $field ];
			}
		}
		return $stored;
	}

	/**
	 * Session fields that must not be stored in plaintext transients.
	 */
	private function state_secret_fields() {
		return array( 'sign_sk', 'enc_sk', 'data_filekey' );
	}

	/**
	 * Derive a site-bound key used only to seal short-lived session state.
	 */
	private function state_secret_key( $state_id ) {
		return hash( 'sha256', 'dologin-kl-sso|' . $state_id . '|' . wp_salt( 'auth' ), true );
	}

	/**
	 * Delete session state.
	 */
	private function delete_state( $state_id ) {
		delete_transient( self::TRANSIENT_PREFIX . $state_id );
	}

	/**
	 * Apply a small per-IP quota before remote handshakes and key generation.
	 */
	private function start_rate_limited() {
		return $this->request_rate_limited( 'start', self::START_LIMIT, self::START_WINDOW );
	}

	/**
	 * Apply a transient-backed per-IP request quota to public SSO endpoints.
	 */
	private function request_rate_limited( $scope, $limit, $window ) {
		$key        = 'dologin_kl_' . sanitize_key( $scope ) . '_' . hash( 'sha256', (string) IP::me() );
		$lock_id    = substr( hash( 'sha256', 'rate-limit|' . $key ), 0, 32 );
		$lock_owner = $this->acquire_state_lock( $lock_id );
		if ( ! $lock_owner ) {
			return true;
		}

		try {
			$bucket = get_transient( $key );
			if ( ! is_array( $bucket ) || empty( $bucket['started_at'] ) || (int) $bucket['started_at'] < time() - $window ) {
				$bucket = array(
					'started_at' => time(),
					'count'      => 0,
				);
			}
			if ( (int) $bucket['count'] >= $limit ) {
				return true;
			}
			$bucket['count'] = (int) $bucket['count'] + 1;
			set_transient( $key, $bucket, $window );
			return false;
		} finally {
			$this->release_state_lock( $lock_id, $lock_owner );
		}
	}

	/**
	 * Acquire an atomic short-lived lock for one SSO state.
	 */
	private function acquire_state_lock( $state_id ) {
		global $wpdb;

		if ( ! preg_match( '/^[a-f0-9]{32}$/', $state_id ) ) {
			return false;
		}
		try {
			$owner = bin2hex( random_bytes( 16 ) );
		} catch ( \Exception $ex ) {
			return false;
		}
		$key   = $this->state_lock_key( $state_id );
		$value = ( time() + 30 ) . ':' . $owner;
		if ( add_option( $key, $value, '', false ) ) {
			return $owner;
		}

		$current = get_option( $key, '' );
		$parts   = is_string( $current ) ? explode( ':', $current, 2 ) : array();
		if ( 2 !== count( $parts ) || ! preg_match( '/^[0-9]+$/D', $parts[0] ) || (int) $parts[0] >= time() ) {
			return false;
		}
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery -- $wpdb->options is the current site's internal options table; all values are prepared.
		$updated = $wpdb->query( $wpdb->prepare( "UPDATE `$wpdb->options` SET option_value=%s WHERE option_name=%s AND option_value=%s", $value, $key, $current ) );
		wp_cache_delete( $key, 'options' );
		return 1 === $updated ? $owner : false;
	}

	/**
	 * Release a state lock only when this request still owns it.
	 */
	private function release_state_lock( $state_id, $owner ) {
		global $wpdb;

		$key     = $this->state_lock_key( $state_id );
		$current = get_option( $key, '' );
		if ( ! is_string( $current ) || substr( $current, -33 ) !== ':' . $owner ) {
			return;
		}
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery -- $wpdb->options is the current site's internal options table; all values are prepared.
		$wpdb->query( $wpdb->prepare( "DELETE FROM `$wpdb->options` WHERE option_name=%s AND option_value=%s", $key, $current ) );
		wp_cache_delete( $key, 'options' );
	}

	/**
	 * Build the non-autoloaded option name used as a state lock.
	 */
	private function state_lock_key( $state_id ) {
		return 'dologin_kl_sso_lock_' . $state_id;
	}

	/**
	 * Remember a signed frame digest and reject exact transcript replay.
	 */
	private function remember_frame( &$state, $frame ) {
		$digest = hash( 'sha256', $frame );
		$seen   = isset( $state['seen_frames'] ) && is_array( $state['seen_frames'] ) ? $state['seen_frames'] : array();
		foreach ( $seen as $seen_digest ) {
			if ( is_string( $seen_digest ) && hash_equals( $seen_digest, $digest ) ) {
				return false;
			}
		}
		$seen[] = $digest;
		if ( count( $seen ) > self::FRAME_LIMIT ) {
			$seen = array_slice( $seen, -self::FRAME_LIMIT );
		}
		$state['seen_frames'] = $seen;
		return true;
	}

	/**
	 * Reject validly signed actions that do not belong to the current session phase.
	 */
	private function assert_kps_action_phase( $state, $action ) {
		$phase   = isset( $state['phase'] ) && is_string( $state['phase'] ) ? $state['phase'] : '';
		$allowed = array(
			'tmp_auth'    => array( 'connected', 'ping', 'app_auth_result' ),
			'app_filekey' => array( 'connected', 'ping', 'app_req_filekey', 'app_filekey_result' ),
			'app_write'   => array( 'connected', 'ping', 'app_set_data' ),
			'app_read'    => array( 'connected', 'ping', 'app_get_data' ),
		);
		if ( ! isset( $allowed[ $phase ] ) || ! is_string( $action ) || ! in_array( $action, $allowed[ $phase ], true ) ) {
			throw new \Exception( __( 'Unexpected KeyLockr SSO message sequence.', 'dologin' ) );
		}

		$id = isset( $state['id'] ) && is_string( $state['id'] ) ? $state['id'] : '';
		if ( 'tmp_auth' === $phase ) {
			if ( 0 !== strpos( $id, 'tmp.' ) || ! empty( $state['verified'] ) ) {
				throw new \Exception( __( 'Invalid KeyLockr SSO session phase.', 'dologin' ) );
			}
			return;
		}

		$app_id = isset( $state['app_id'] ) && is_string( $state['app_id'] ) ? $state['app_id'] : '';
		if ( empty( $state['verified'] ) || ! $app_id || ! hash_equals( 'app.' . $app_id, $id ) ) {
			throw new \Exception( __( 'Invalid KeyLockr SSO session phase.', 'dologin' ) );
		}
	}
}
