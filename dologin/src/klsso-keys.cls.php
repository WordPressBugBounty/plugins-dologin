<?php
/**
 * KeyLockr SSO site-key management.
 *
 * @since 4.7.1
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

trait KLSso_Keys {
	/**
	 * Return the site signing public-key fingerprint.
	 */
	public static function site_key_fingerprint() {
		$keys = self::site_keys();
		if ( is_wp_error( $keys ) ) {
			return $keys;
		}
		return self::site_key_fingerprint_from_keys( $keys );
	}

	/**
	 * Rotate the KeyLockr client keys for the current WordPress site.
	 */
	public function reset_site_keys() {
		$capability = apply_filters( 'dologin_admin_menu_access', 'manage_options' );
		if ( ! current_user_can( $capability ) ) {
			return REST::err( __( 'You are not allowed to reset KeyLockr site keys.', 'dologin' ) );
		}
		if ( self::force_enabled() ) {
			return REST::err( __( 'Disable Force KeyLockr SSO before resetting the site keys.', 'dologin' ) );
		}

		$keys = self::generate_site_keys();
		if ( is_wp_error( $keys ) ) {
			return REST::err( $keys->get_error_message() );
		}
		$sealed = self::seal_site_keys( $keys );
		if ( is_wp_error( $sealed ) ) {
			return REST::err( $sealed->get_error_message() );
		}
		if ( ! update_option( self::SITE_KEYS_OPTION, $sealed, false ) ) {
			return REST::err( __( 'Failed to reset KeyLockr site keys.', 'dologin' ) );
		}

		return REST::ok(
			array(
				'status'          => 'done',
				'fingerprint'     => self::site_key_fingerprint_from_keys( $keys ),
				'message'         => __( 'KeyLockr site keys were reset. Verify linked accounts again or complete a successful SSO login.', 'dologin' ),
				'binding_message' => __( 'This account has not been verified with the current KeyLockr connection identity. Verify the connection before relying on it.', 'dologin' ),
			)
		);
	}

	/**
	 * Read or create the fixed site keys.
	 */
	private static function site_keys() {
		if ( ! self::sodium_ready() ) {
			return new \WP_Error( 'dologin_kl_site_keys_sodium', __( 'Sodium cryptography support is required.', 'dologin' ) );
		}

		$stored = get_option( self::SITE_KEYS_OPTION, '' );
		if ( is_string( $stored ) && '' !== $stored ) {
			return self::open_site_keys( $stored );
		}

		$keys = self::generate_site_keys();
		if ( is_wp_error( $keys ) ) {
			return $keys;
		}
		$sealed = self::seal_site_keys( $keys );
		if ( is_wp_error( $sealed ) ) {
			return $sealed;
		}
		if ( add_option( self::SITE_KEYS_OPTION, $sealed, '', false ) ) {
			return $keys;
		}

		$stored = get_option( self::SITE_KEYS_OPTION, '' );
		return is_string( $stored ) && '' !== $stored
			? self::open_site_keys( $stored )
			: new \WP_Error( 'dologin_kl_site_keys_store', __( 'Failed to store KeyLockr site keys.', 'dologin' ) );
	}

	/**
	 * Generate Ed25519 and X25519 keypairs.
	 */
	private static function generate_site_keys() {
		if ( ! self::sodium_ready() ) {
			return new \WP_Error( 'dologin_kl_site_keys_sodium', __( 'Sodium cryptography support is required.', 'dologin' ) );
		}
		try {
			$keys = array(
				'sign_kp' => sodium_crypto_sign_keypair(),
				'box_kp'  => sodium_crypto_box_keypair(),
			);
		} catch ( \Exception $ex ) {
			return new \WP_Error( 'dologin_kl_site_keys_generate', __( 'Failed to generate KeyLockr site keys.', 'dologin' ) );
		}
		return self::site_keys_valid( $keys )
			? $keys
			: new \WP_Error( 'dologin_kl_site_keys_invalid', __( 'Generated KeyLockr site keys are invalid.', 'dologin' ) );
	}

	/**
	 * Seal long-lived keys with a key derived from the WordPress site salt.
	 */
	private static function seal_site_keys( $keys ) {
		if ( ! self::site_keys_valid( $keys ) ) {
			return new \WP_Error( 'dologin_kl_site_keys_invalid', __( 'KeyLockr site keys are invalid.', 'dologin' ) );
		}
		try {
			$plain = KLSso_MsgPack::pack(
				array(
					'v'       => 1,
					'sign_kp' => KLSso_MsgPack::bin( $keys['sign_kp'] ),
					'box_kp'  => KLSso_MsgPack::bin( $keys['box_kp'] ),
				)
			);
			$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$box   = sodium_crypto_secretbox( $plain, $nonce, self::site_key_storage_key() );
		} catch ( \Exception $ex ) {
			return new \WP_Error( 'dologin_kl_site_keys_seal', __( 'Failed to protect KeyLockr site keys.', 'dologin' ) );
		}
		return base64_encode( $nonce . $box );
	}

	/**
	 * Open and validate long-lived keys.
	 */
	private static function open_site_keys( $stored ) {
		$sealed = base64_decode( $stored, true );
		if ( false === $sealed || strlen( $sealed ) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES ) {
			return new \WP_Error( 'dologin_kl_site_keys_decode', __( 'Stored KeyLockr site keys are invalid. Reset them in settings.', 'dologin' ) );
		}
		$nonce = substr( $sealed, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$plain = sodium_crypto_secretbox_open( substr( $sealed, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ), $nonce, self::site_key_storage_key() );
		if ( false === $plain ) {
			return new \WP_Error( 'dologin_kl_site_keys_open', __( 'Stored KeyLockr site keys cannot be opened. Reset them in settings.', 'dologin' ) );
		}

		try {
			$data = KLSso_MsgPack::unpack( $plain );
		} catch ( \Exception $ex ) {
			$data = false;
		}
		$keys = is_array( $data ) && isset( $data['v'] ) && 1 === (int) $data['v']
			? array(
				'sign_kp' => self::site_key_bytes( isset( $data['sign_kp'] ) ? $data['sign_kp'] : '' ),
				'box_kp'  => self::site_key_bytes( isset( $data['box_kp'] ) ? $data['box_kp'] : '' ),
			)
			: array();
		return self::site_keys_valid( $keys )
			? $keys
			: new \WP_Error( 'dologin_kl_site_keys_invalid', __( 'Stored KeyLockr site keys are invalid. Reset them in settings.', 'dologin' ) );
	}

	/**
	 * Derive the fixed site-key storage encryption key.
	 */
	private static function site_key_storage_key() {
		return hash( 'sha256', 'dologin-kl-sso-site-keys-v1|' . wp_salt( 'auth' ), true );
	}

	/**
	 * Validate keypair lengths.
	 */
	private static function site_keys_valid( $keys ) {
		return is_array( $keys )
			&& isset( $keys['sign_kp'], $keys['box_kp'] )
			&& is_string( $keys['sign_kp'] )
			&& is_string( $keys['box_kp'] )
			&& SODIUM_CRYPTO_SIGN_KEYPAIRBYTES === strlen( $keys['sign_kp'] )
			&& SODIUM_CRYPTO_BOX_KEYPAIRBYTES === strlen( $keys['box_kp'] );
	}

	/**
	 * Convert a MessagePack binary field to bytes.
	 */
	private static function site_key_bytes( $value ) {
		return $value instanceof KLSso_MsgPack_Bin ? $value->bytes : '';
	}

	/**
	 * Build a short fingerprint without exposing public-key contents.
	 */
	private static function site_key_fingerprint_from_keys( $keys ) {
		$sign_pk = sodium_crypto_sign_publickey( $keys['sign_kp'] );
		return strtoupper( implode( ':', str_split( substr( hash( 'sha256', $sign_pk ), 0, 16 ), 2 ) ) );
	}

	/**
	 * Confirm that a session still belongs to the current site keys.
	 */
	private static function site_key_fingerprint_matches( $fingerprint ) {
		$current = self::site_key_fingerprint();
		return is_string( $fingerprint )
			&& is_string( $current )
			&& hash_equals( $current, $fingerprint );
	}
}
