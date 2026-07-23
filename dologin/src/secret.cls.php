<?php
/**
 * Salt-bound secret storage helpers.
 *
 * @since 4.7.4
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

class Secret {
	const TOKEN_PREFIX  = 'dologin:hmac:v1:';
	const SODIUM_PREFIX = 'dologin:sealed:v1:s:';
	const OPENSSL_PREFIX = 'dologin:sealed:v1:o:';

	/**
	 * Create a non-reversible token verifier bound to the WordPress authentication salt.
	 */
	public static function token_hash( $purpose, $token ) {
		if ( ! is_string( $purpose ) || '' === $purpose || ! is_string( $token ) || '' === $token ) {
			return false;
		}
		$key = hash_hmac( 'sha256', 'dologin-token-key-v1|' . $purpose, wp_salt( 'auth' ), true );
		return self::TOKEN_PREFIX . hash_hmac( 'sha256', $token, $key );
	}

	/**
	 * Verify a raw bearer token without storing the token itself.
	 */
	public static function verify_token( $purpose, $token, $stored ) {
		if ( ! self::is_token_hash( $stored ) ) {
			return false;
		}
		$expected = self::token_hash( $purpose, $token );
		return is_string( $expected ) && hash_equals( $stored, $expected );
	}

	/**
	 * Whether a value is a versioned token verifier.
	 */
	public static function is_token_hash( $stored ) {
		return is_string( $stored )
			&& 1 === preg_match( '/^' . preg_quote( self::TOKEN_PREFIX, '/' ) . '[a-f0-9]{64}$/D', $stored );
	}

	/**
	 * Encrypt and authenticate a recoverable secret with a purpose-bound site key.
	 */
	public static function seal( $purpose, $plain ) {
		if ( ! is_string( $purpose ) || '' === $purpose || ! is_string( $plain ) || '' === $plain ) {
			return false;
		}

		if ( function_exists( 'sodium_crypto_secretbox' )
			&& defined( 'SODIUM_CRYPTO_SECRETBOX_NONCEBYTES' )
			&& defined( 'SODIUM_CRYPTO_SECRETBOX_KEYBYTES' ) ) {
			try {
				$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
				$box   = sodium_crypto_secretbox( $plain, $nonce, self::storage_key( $purpose, SODIUM_CRYPTO_SECRETBOX_KEYBYTES ) );
			} catch ( \Exception $ex ) {
				return false;
			}
			return self::SODIUM_PREFIX . base64_encode( $nonce . $box );
		}

		if ( function_exists( 'openssl_encrypt' ) && defined( 'OPENSSL_RAW_DATA' ) ) {
			$cipher_name = 'aes-256-cbc';
			$iv_length   = openssl_cipher_iv_length( $cipher_name );
			if ( ! is_int( $iv_length ) || $iv_length <= 0 ) {
				return false;
			}
			try {
				$iv = random_bytes( $iv_length );
			} catch ( \Exception $ex ) {
				return false;
			}
			$keys   = self::storage_key( $purpose, 64 );
			$cipher = openssl_encrypt( $plain, $cipher_name, substr( $keys, 0, 32 ), OPENSSL_RAW_DATA, $iv );
			if ( false === $cipher ) {
				return false;
			}
			$tag = hash_hmac( 'sha256', self::OPENSSL_PREFIX . $purpose . '|' . $iv . $cipher, substr( $keys, 32, 32 ), true );
			return self::OPENSSL_PREFIX . base64_encode( $iv . $tag . $cipher );
		}

		return false;
	}

	/**
	 * Authenticate and decrypt a versioned secret.
	 */
	public static function open( $purpose, $stored ) {
		if ( ! is_string( $purpose ) || '' === $purpose || ! is_string( $stored ) ) {
			return false;
		}

		if ( 0 === strpos( $stored, self::SODIUM_PREFIX ) ) {
			if ( ! function_exists( 'sodium_crypto_secretbox_open' )
				|| ! defined( 'SODIUM_CRYPTO_SECRETBOX_NONCEBYTES' )
				|| ! defined( 'SODIUM_CRYPTO_SECRETBOX_MACBYTES' )
				|| ! defined( 'SODIUM_CRYPTO_SECRETBOX_KEYBYTES' ) ) {
				return false;
			}
			$sealed = base64_decode( substr( $stored, strlen( self::SODIUM_PREFIX ) ), true );
			if ( false === $sealed || strlen( $sealed ) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES ) {
				return false;
			}
			$nonce = substr( $sealed, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			return sodium_crypto_secretbox_open( substr( $sealed, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ), $nonce, self::storage_key( $purpose, SODIUM_CRYPTO_SECRETBOX_KEYBYTES ) );
		}

		if ( 0 === strpos( $stored, self::OPENSSL_PREFIX ) ) {
			if ( ! function_exists( 'openssl_decrypt' ) || ! defined( 'OPENSSL_RAW_DATA' ) ) {
				return false;
			}
			$cipher_name = 'aes-256-cbc';
			$iv_length   = openssl_cipher_iv_length( $cipher_name );
			$sealed      = base64_decode( substr( $stored, strlen( self::OPENSSL_PREFIX ) ), true );
			if ( ! is_int( $iv_length ) || $iv_length <= 0 || false === $sealed || strlen( $sealed ) <= $iv_length + 32 ) {
				return false;
			}
			$iv     = substr( $sealed, 0, $iv_length );
			$tag    = substr( $sealed, $iv_length, 32 );
			$cipher = substr( $sealed, $iv_length + 32 );
			$keys   = self::storage_key( $purpose, 64 );
			$expected_tag = hash_hmac( 'sha256', self::OPENSSL_PREFIX . $purpose . '|' . $iv . $cipher, substr( $keys, 32, 32 ), true );
			if ( ! hash_equals( $expected_tag, $tag ) ) {
				return false;
			}
			return openssl_decrypt( $cipher, $cipher_name, substr( $keys, 0, 32 ), OPENSSL_RAW_DATA, $iv );
		}

		return false;
	}

	/**
	 * Whether a value uses one of the supported encrypted formats.
	 */
	public static function is_sealed( $stored ) {
		return is_string( $stored )
			&& ( 0 === strpos( $stored, self::SODIUM_PREFIX ) || 0 === strpos( $stored, self::OPENSSL_PREFIX ) );
	}

	/**
	 * Derive purpose-separated key material from the WordPress authentication salt.
	 */
	private static function storage_key( $purpose, $length ) {
		$material = hash_hmac( 'sha512', 'dologin-storage-key-v1|' . $purpose, wp_salt( 'auth' ), true );
		return substr( $material, 0, $length );
	}
}
