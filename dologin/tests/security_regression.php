<?php
/**
 * Lightweight security regression checks that do not depend on WordPress.
 */

namespace dologin {
	class Core {
		const VER = 'test';
	}

	class REST {
		public static function ok( $data ) {
			$data['_res'] = 'ok';
			return $data;
		}

		public static function err( $message ) {
			return array( '_res' => 'err', '_msg' => $message );
		}
	}

	class Conf {
		public static $values = array();

		public static function val( $key ) {
			return isset( self::$values[ $key ] ) ? self::$values[ $key ] : false;
		}

		public static function update( $key, $value ) {
			self::$values[ $key ] = $value;
			return true;
		}
	}
}

namespace {
	define( 'WPINC', true );
	define( 'DOLOGIN_DIR', dirname( __DIR__ ) . '/' );

	class WP_Error {
		public $codes = array();

		public function __construct( $code = '', $message = '' ) {
			if ( $code ) {
				$this->add( $code, $message );
			}
		}

		public function add( $code, $message ) {
			$this->codes[ $code ] = $message;
		}

		public function get_error_message( $code = '' ) {
			if ( $code && isset( $this->codes[ $code ] ) ) {
				return $this->codes[ $code ];
			}
			return $this->codes ? reset( $this->codes ) : '';
		}
	}

	class WP_User {
		public $ID;

		public function __construct( $id ) {
			$this->ID = (int) $id;
		}
	}

	class Dologin_Test_WPDB {
		public $options = 'wp_options';

		public function prepare( $query ) {
			return array(
				'query' => $query,
				'args'  => array_slice( func_get_args(), 1 ),
			);
		}

		public function query( $prepared ) {
			if ( ! is_array( $prepared ) || empty( $prepared['query'] ) || ! isset( $prepared['args'] ) ) {
				return false;
			}
			$args = $prepared['args'];
			if ( 0 === strpos( $prepared['query'], 'UPDATE' ) && 3 === count( $args ) ) {
				list( $new_value, $key, $current ) = $args;
				if ( isset( $GLOBALS['dologin_test_options'][ $key ] ) && $current === $GLOBALS['dologin_test_options'][ $key ] ) {
					$GLOBALS['dologin_test_options'][ $key ] = $new_value;
					return 1;
				}
				return 0;
			}
			if ( 0 === strpos( $prepared['query'], 'DELETE' ) && 2 === count( $args ) ) {
				list( $key, $current ) = $args;
				if ( isset( $GLOBALS['dologin_test_options'][ $key ] ) && $current === $GLOBALS['dologin_test_options'][ $key ] ) {
					unset( $GLOBALS['dologin_test_options'][ $key ] );
					return 1;
				}
				return 0;
			}
			return false;
		}
	}

	function __( $message ) {
		return $message;
	}

	function esc_html( $message ) {
		return htmlspecialchars( (string) $message, ENT_QUOTES, 'UTF-8' );
	}

	function esc_attr( $message ) {
		return esc_html( $message );
	}

	function esc_attr_e( $message, $domain = null ) {
		echo esc_attr( $message );
	}

	function esc_html__( $message, $domain = null ) {
		return esc_html( $message );
	}

	function esc_html_e( $message, $domain = null ) {
		echo esc_html( $message );
	}

	function sanitize_key( $key ) {
		return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $key ) );
	}

	function sanitize_text_field( $value ) {
		return trim( (string) $value );
	}

	function wp_unslash( $value ) {
		return $value;
	}

	function esc_url_raw( $url ) {
		return is_string( $url ) ? trim( $url ) : '';
	}

	function esc_url( $url ) {
		return esc_attr( esc_url_raw( $url ) );
	}

	function wp_http_validate_url( $url ) {
		return is_string( $url ) && false !== filter_var( $url, FILTER_VALIDATE_URL ) ? $url : false;
	}

	function wp_parse_url( $url, $component = -1 ) {
		return parse_url( $url, $component );
	}

	function admin_url() {
		return 'https://example.test/wp-admin/';
	}

	$GLOBALS['dologin_test_transients'] = array();
	$GLOBALS['dologin_test_options']    = array();
	$GLOBALS['dologin_test_option_autoload'] = array();
	$GLOBALS['dologin_test_user_meta']  = array();
	$GLOBALS['dologin_test_user_id']    = 0;
	$GLOBALS['dologin_test_manage_options'] = false;
	$GLOBALS['dologin_test_hooks']      = array();
	$GLOBALS['dologin_test_remote_body'] = '';
	$GLOBALS['dologin_test_remote_args'] = array();
	$GLOBALS['dologin_test_remote_url']  = '';
	$GLOBALS['wpdb'] = new Dologin_Test_WPDB();

	function add_action( $hook ) {
		$GLOBALS['dologin_test_hooks'][] = $hook;
		return true;
	}

	function remove_action() {
		return true;
	}

	function wp_safe_remote_get( $url, $args ) {
		$GLOBALS['dologin_test_remote_url']  = $url;
		$GLOBALS['dologin_test_remote_args'] = $args;
		return array(
			'body'     => $GLOBALS['dologin_test_remote_body'],
			'response' => array( 'code' => 200 ),
		);
	}

	function wp_safe_remote_post( $url, $args ) {
		$GLOBALS['dologin_test_remote_url']  = $url;
		$GLOBALS['dologin_test_remote_args'] = $args;
		return array(
			'body'     => $GLOBALS['dologin_test_remote_body'],
			'response' => array( 'code' => 200 ),
		);
	}

	function wp_json_encode( $value ) {
		return json_encode( $value );
	}

	function add_query_arg( $key, $value, $url ) {
		return $url . '?' . rawurlencode( $key ) . '=' . rawurlencode( $value );
	}

	function wp_remote_retrieve_response_code( $response ) {
		return isset( $response['response']['code'] ) ? $response['response']['code'] : 0;
	}

	function wp_remote_retrieve_body( $response ) {
		return isset( $response['body'] ) ? $response['body'] : '';
	}

	function is_wp_error( $value ) {
		return $value instanceof WP_Error;
	}

	function set_transient( $key, $value ) {
		$GLOBALS['dologin_test_transients'][ $key ] = $value;
		return true;
	}

	function get_transient( $key ) {
		return isset( $GLOBALS['dologin_test_transients'][ $key ] ) ? $GLOBALS['dologin_test_transients'][ $key ] : false;
	}

	function delete_transient( $key ) {
		unset( $GLOBALS['dologin_test_transients'][ $key ] );
		return true;
	}

	function wp_cache_delete() {
		return true;
	}

	function wp_salt() {
		return 'dologin-test-site-salt';
	}

	function get_option( $key, $default = false ) {
		return array_key_exists( $key, $GLOBALS['dologin_test_options'] ) ? $GLOBALS['dologin_test_options'][ $key ] : $default;
	}

	function add_option( $key, $value, $deprecated = '', $autoload = 'yes' ) {
		if ( array_key_exists( $key, $GLOBALS['dologin_test_options'] ) ) {
			return false;
		}
		$GLOBALS['dologin_test_options'][ $key ] = $value;
		$GLOBALS['dologin_test_option_autoload'][ $key ] = $autoload;
		return true;
	}

	function update_option( $key, $value, $autoload = null ) {
		$GLOBALS['dologin_test_options'][ $key ] = $value;
		if ( null !== $autoload ) {
			$GLOBALS['dologin_test_option_autoload'][ $key ] = $autoload;
		}
		return true;
	}

	function current_user_can() {
		return (bool) $GLOBALS['dologin_test_manage_options'];
	}
	function user_can() { return true; }

	function apply_filters( $hook, $value ) {
		return $value;
	}

	function get_current_user_id() {
		return (int) $GLOBALS['dologin_test_user_id'];
	}

	function get_user_meta( $user_id, $key ) {
		return isset( $GLOBALS['dologin_test_user_meta'][ $user_id ][ $key ] ) ? $GLOBALS['dologin_test_user_meta'][ $user_id ][ $key ] : '';
	}

	function update_user_meta( $user_id, $key, $value ) {
		$GLOBALS['dologin_test_user_meta'][ $user_id ][ $key ] = $value;
		return true;
	}

	function delete_user_meta( $user_id, $key ) {
		unset( $GLOBALS['dologin_test_user_meta'][ $user_id ][ $key ] );
		return true;
	}

	function get_userdata( $user_id ) {
		return $user_id > 0 ? new WP_User( $user_id ) : false;
	}

	function get_users() {
		return array();
	}

	function home_url() {
		return 'https://example.test';
	}

	require_once dirname( __DIR__ ) . '/src/instance.cls.php';
	require_once dirname( __DIR__ ) . '/src/secret.cls.php';
	require_once dirname( __DIR__ ) . '/src/admin.cls.php';
	require_once dirname( __DIR__ ) . '/src/ip.cls.php';
	require_once dirname( __DIR__ ) . '/src/klsso-msgpack.cls.php';
	require_once dirname( __DIR__ ) . '/src/klsso-keys.cls.php';
	require_once dirname( __DIR__ ) . '/src/klsso-protocol.cls.php';
	require_once dirname( __DIR__ ) . '/src/klsso-repair.cls.php';
	require_once dirname( __DIR__ ) . '/src/klsso-state.cls.php';
	require_once dirname( __DIR__ ) . '/src/klsso-ui.cls.php';
	require_once dirname( __DIR__ ) . '/src/klsso.cls.php';
	require_once dirname( __DIR__ ) . '/src/auth.cls.php';
	require_once dirname( __DIR__ ) . '/src/site.cls.php';
	require_once dirname( __DIR__ ) . '/src/twofa.cls.php';
	require_once dirname( __DIR__ ) . '/lib/two-fa-lib.cls.php';

	use dologin\Admin;
	use dologin\Auth;
	use dologin\Conf;
	use dologin\IP;
	use dologin\KLSso;
	use dologin\KLSso_MsgPack;
	use dologin\lib\Two_FA_Lib;

function dologin_test_assert( $condition, $message ) {
	if ( ! $condition ) {
		fwrite( STDERR, "Failure: $message\n" );
		exit( 1 );
	}
}

function dologin_test_rejected( $payload, $message ) {
	try {
		KLSso_MsgPack::unpack( $payload );
	} catch ( Exception $exception ) {
		return;
	}
	dologin_test_assert( false, $message );
}

function dologin_test_invoke( $object, $method, $args = array() ) {
	$reflection = new ReflectionMethod( $object, $method );
	if ( PHP_VERSION_ID < 80100 ) {
		$reflection->setAccessible( true );
	}
	return $reflection->invokeArgs( $object, $args );
}

$payload = array(
	'bin'   => KLSso_MsgPack::bin( "\x00\xff" ),
	'float' => 3.25,
	'list'  => array( 1, true, 'ok' ),
);
$decoded = KLSso_MsgPack::unpack( KLSso_MsgPack::pack( $payload ) );
dologin_test_assert( 3.25 === $decoded['float'], 'MessagePack float round trip failed.' );
dologin_test_assert( $decoded['bin'] instanceof \dologin\KLSso_MsgPack_Bin && "\x00\xff" === $decoded['bin']->bytes, 'MessagePack binary round trip failed.' );
dologin_test_assert( array( 1, true, 'ok' ) === $decoded['list'], 'MessagePack array round trip failed.' );
dologin_test_assert( -2147483649 === KLSso_MsgPack::unpack( KLSso_MsgPack::pack( -2147483649 ) ), 'MessagePack signed 64-bit integer round trip failed.' );

dologin_test_rejected( "\xdd\x00\x01\x86\xa0", 'An array with an oversized declared length was accepted.' );
dologin_test_rejected( "\x01\x02", 'Trailing MessagePack data was accepted.' );
dologin_test_rejected( str_repeat( "\x91", 34 ) . "\x00", 'Excessively nested MessagePack data was accepted.' );

$klsso    = ( new ReflectionClass( KLSso::class ) )->newInstanceWithoutConstructor();
$klsso->init();
dologin_test_assert( in_array( 'show_user_profile', $GLOBALS['dologin_test_hooks'], true ) && ! in_array( 'edit_user_profile', $GLOBALS['dologin_test_hooks'], true ), 'The KeyLockr binding panel did not register only the reachable current-user profile hook.' );

$site_keys_a = dologin_test_invoke( $klsso, 'site_keys' );
$site_keys_b = dologin_test_invoke( $klsso, 'site_keys' );
$site_fingerprint_a = KLSso::site_key_fingerprint();
$stored_site_keys    = $GLOBALS['dologin_test_options'][ KLSso::SITE_KEYS_OPTION ];
dologin_test_assert(
	$site_keys_a === $site_keys_b
	&& is_string( $site_fingerprint_a )
	&& '' !== $site_fingerprint_a
	&& dologin_test_invoke( $klsso, 'site_key_fingerprint_matches', array( $site_fingerprint_a ) )
	&& false === strpos( $stored_site_keys, base64_encode( $site_keys_a['sign_kp'] ) )
	&& false === strpos( $stored_site_keys, base64_encode( $site_keys_a['box_kp'] ) ),
	'The KeyLockr site keys were not reused consistently or the private keys were stored without encryption.'
);
dologin_test_assert( false === $GLOBALS['dologin_test_option_autoload'][ KLSso::SITE_KEYS_OPTION ], 'The KeyLockr site-key option was created with autoload enabled.' );
$tampered_site_keys = base64_decode( $stored_site_keys, true );
$tampered_site_keys[ strlen( $tampered_site_keys ) - 1 ] = chr( ord( $tampered_site_keys[ strlen( $tampered_site_keys ) - 1 ] ) ^ 1 );
$GLOBALS['dologin_test_options'][ KLSso::SITE_KEYS_OPTION ] = base64_encode( $tampered_site_keys );
dologin_test_assert( is_wp_error( KLSso::site_key_fingerprint() ), 'A new connection identity was silently created after site-key corruption.' );
$GLOBALS['dologin_test_options'][ KLSso::SITE_KEYS_OPTION ] = $stored_site_keys;
$GLOBALS['dologin_test_user_meta'][3][ KLSso::META_SAFE_ID ] = 'safe-before-key-reset';
$GLOBALS['dologin_test_user_meta'][3][ KLSso::META_SITE_KEY_FP ] = $site_fingerprint_a;
$GLOBALS['dologin_test_user_meta'][3][ KLSso::META_APP_TAG ] = 'reset-test';
Conf::$values['kl_sso_svc_id'] = 'reset-test';
dologin_test_assert( dologin_test_invoke( $klsso, 'binding_uses_current_connection', array( 3 ) ), 'The current site key was not recognized as the existing binding identity.' );
$reset_denied = $klsso->reset_site_keys();
dologin_test_assert( 'err' === $reset_denied['_res'] && $site_fingerprint_a === KLSso::site_key_fingerprint(), 'A user without settings permission could reset the KeyLockr site keys.' );
$GLOBALS['dologin_test_manage_options'] = true;
$reset_done = $klsso->reset_site_keys();
$site_keys_c = dologin_test_invoke( $klsso, 'site_keys' );
dologin_test_assert(
	'ok' === $reset_done['_res']
	&& $site_fingerprint_a !== $reset_done['fingerprint']
	&& $site_keys_a !== $site_keys_c
	&& ! dologin_test_invoke( $klsso, 'site_key_fingerprint_matches', array( $site_fingerprint_a ) )
	&& ! dologin_test_invoke( $klsso, 'binding_uses_current_connection', array( 3 ) )
	&& 'safe-before-key-reset' === $GLOBALS['dologin_test_user_meta'][3][ KLSso::META_SAFE_ID ],
	'The KeyLockr site-key reset did not rotate both key pairs, invalidate the old identity, or preserve the user binding.'
);
dologin_test_assert( false === $GLOBALS['dologin_test_option_autoload'][ KLSso::SITE_KEYS_OPTION ], 'Resetting the KeyLockr site keys enabled option autoload.' );
$GLOBALS['dologin_test_manage_options'] = false;

require dirname( __FILE__ ) . '/keylockr_ui_regression.php';

$state_id = str_repeat( 'a', 32 );
$state    = array(
	'sign_sk'      => 'sign-secret',
	'enc_sk'       => 'box-secret',
	'data_filekey' => 'encrypted-filekey-envelope',
	'public_value' => 'visible',
);
dologin_test_assert( dologin_test_invoke( $klsso, 'save_state', array( $state_id, $state ) ), 'Saving the KeyLockr session state failed.' );
$stored_state = $GLOBALS['dologin_test_transients'][ KLSso::TRANSIENT_PREFIX . $state_id ];
dologin_test_assert( ! isset( $stored_state['sign_sk'], $stored_state['enc_sk'], $stored_state['data_filekey'] ), 'Private KeyLockr state was written to a transient in plaintext.' );
dologin_test_assert( false === strpos( serialize( $stored_state ), 'sign-secret' ), 'The KeyLockr signing private key appeared in transient data.' );
$loaded_state = dologin_test_invoke( $klsso, 'load_state', array( $state_id ) );
dologin_test_assert( 'sign-secret' === $loaded_state['sign_sk'] && 'box-secret' === $loaded_state['enc_sk'] && 'encrypted-filekey-envelope' === $loaded_state['data_filekey'], 'The protected KeyLockr private-state round trip failed.' );
$tampered_state               = $stored_state;
$tampered_box                 = base64_decode( $tampered_state['secret_box'], true );
$tampered_box[ strlen( $tampered_box ) - 1 ] = chr( ord( $tampered_box[ strlen( $tampered_box ) - 1 ] ) ^ 1 );
$tampered_state['secret_box'] = base64_encode( $tampered_box );
$GLOBALS['dologin_test_transients'][ KLSso::TRANSIENT_PREFIX . $state_id ] = $tampered_state;
dologin_test_assert( false === dologin_test_invoke( $klsso, 'load_state', array( $state_id ) ), 'Tampered private KeyLockr state was accepted.' );
$GLOBALS['dologin_test_transients'][ KLSso::TRANSIENT_PREFIX . $state_id ] = $stored_state;

$app_kp     = sodium_crypto_box_keypair();
$safe_kp    = sodium_crypto_box_keypair();
$app_sk     = sodium_crypto_box_secretkey( $app_kp );
$app_pk     = sodium_crypto_box_publickey( $app_kp );
$safe_sk    = sodium_crypto_box_secretkey( $safe_kp );
$safe_pk    = sodium_crypto_box_publickey( $safe_kp );
$file_key   = random_bytes( SODIUM_CRYPTO_SECRETBOX_KEYBYTES );
$key_nonce  = random_bytes( SODIUM_CRYPTO_BOX_NONCEBYTES );
$data_nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
$safe_pair  = sodium_crypto_box_keypair_from_secretkey_and_publickey( $safe_sk, $app_pk );
$enc_key    = sodium_crypto_box( $file_key, $key_nonce, $safe_pair );
$file_state = array( 'enc_sk' => base64_encode( $app_sk ) );

require dirname( __FILE__ ) . '/security_session_regression.php';

$full_envelope = KLSso_MsgPack::pack(
	array(
		'apEncPk'      => KLSso_MsgPack::bin( $safe_pk ),
		'encFileKey'   => KLSso_MsgPack::bin( $enc_key ),
		'nonceForData' => KLSso_MsgPack::bin( $data_nonce ),
		'nonceForKey'  => KLSso_MsgPack::bin( $key_nonce ),
	)
);
$loaded_file_key = dologin_test_invoke( $klsso, 'load_file_key', array( $file_state, array( 'data_filekey' => KLSso_MsgPack::bin( $full_envelope ) ) ) );
dologin_test_assert( $file_key === $loaded_file_key, 'The current full-name data_filekey envelope could not be decoded.' );

$app_plain = KLSso_MsgPack::pack( array( 'hash' => 'test-app-hash' ) );
$app_enc_a = dologin_test_invoke( $klsso, 'encrypt_appdata', array( $app_plain, $file_key ) );
$app_enc_b = dologin_test_invoke( $klsso, 'encrypt_appdata', array( $app_plain, $file_key ) );
dologin_test_assert( substr( $app_enc_a, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) !== substr( $app_enc_b, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ), 'App Data reused a nonce.' );
dologin_test_assert( $app_plain === dologin_test_invoke( $klsso, 'decrypt_appdata', array( $app_enc_a, $file_key ) ), 'Decrypting nonce-prefixed App Data failed.' );

$bind_user_id = 7;
Conf::$values['kl_sso_svc_id'] = 'wordpress-dologin';
$GLOBALS['dologin_test_user_meta'][ $bind_user_id ][ KLSso::META_APP_HASH ] = 'test-app-hash';
$app_get_state = array(
	'app_hash_ok'          => false,
	'appdata_written'      => true,
	'app_id'               => 'client-test',
	'app_tag'              => 'wordpress-dologin',
	'data_filekey'         => base64_encode( $full_envelope ),
	'enc_sk'               => base64_encode( $app_sk ),
	'id'                   => 'app.client-test',
	'mode'                 => 'bind',
	'nickname'             => 'Safe User',
	'phase'                => 'app_read',
	'safe_id'              => 'safe-test',
	'site_key_fingerprint' => $reset_done['fingerprint'],
	'user_id'              => $bind_user_id,
	'verified'             => true,
);
$app_get_args = array( &$app_get_state, 'app_get_data', array( '_res' => 'ok', 'data_encrypted' => KLSso_MsgPack::bin( $app_enc_a ), 'ver' => '3' ) );
$app_get      = dologin_test_invoke( $klsso, 'handle_kps_action', $app_get_args );
dologin_test_assert(
	'done' === $app_get['status']
	&& $reset_done['fingerprint'] === get_user_meta( $bind_user_id, KLSso::META_SITE_KEY_FP, true )
	&& 'wordpress-dologin' === get_user_meta( $bind_user_id, KLSso::META_APP_TAG, true )
	&& ! get_user_meta( $bind_user_id, 'dologin_kl_sso_client_id', true ),
	'The binding did not record the current site key or incorrectly persisted the KeyLockr app_id.'
);

$verify_state = array(
	'app_hash'             => 'test-app-hash',
	'app_tag'              => 'wordpress-dologin',
	'mode'                 => 'verify',
	'safe_id'              => 'safe-test',
	'site_key_fingerprint' => $reset_done['fingerprint'],
	'user_id'              => $bind_user_id,
	'verified'             => true,
);
$verify_meta_before = $GLOBALS['dologin_test_user_meta'][ $bind_user_id ];
$verify_args = array( &$verify_state, $app_enc_a, $file_key );
$verify_done = dologin_test_invoke( $klsso, 'process_appdata', $verify_args );
dologin_test_assert(
	'done' === $verify_done['status']
	&& isset( $verify_done['reload'] )
	&& false === $verify_done['reload']
	&& ! empty( $verify_state['app_hash_ok'] )
	&& $verify_meta_before === $GLOBALS['dologin_test_user_meta'][ $bind_user_id ],
	'The linked account did not complete standalone KeyLockr verification or still requested a reload afterward.'
);
$wrong_safe_state            = $verify_state;
$wrong_safe_state['safe_id'] = 'safe-other';
try {
	$wrong_safe_args = array( &$wrong_safe_state, $app_enc_a, $file_key );
	dologin_test_invoke( $klsso, 'process_appdata', $wrong_safe_args );
	dologin_test_assert( false, 'Connection verification accepted a different KeyLockr account.' );
} catch ( Exception $exception ) {
	dologin_test_assert( KLSso::REPAIR_REQUIRED_CODE !== $exception->getCode() && false !== strpos( $exception->getMessage(), 'does not match' ), 'A mismatched KeyLockr account did not return a clear non-repairable error.' );
}
$wrong_verify_appdata = dologin_test_invoke( $klsso, 'encrypt_appdata', array( KLSso_MsgPack::pack( array( 'hash' => 'wrong-verify-hash' ) ), $file_key ) );
try {
	$wrong_hash_state = $verify_state;
	$wrong_hash_args  = array( &$wrong_hash_state, $wrong_verify_appdata, $file_key );
	dologin_test_invoke( $klsso, 'process_appdata', $wrong_hash_args );
	dologin_test_assert( false, 'Connection verification accepted a mismatched App Data hash.' );
} catch ( Exception $exception ) {
	dologin_test_assert(
		KLSso::REPAIR_REQUIRED_CODE === $exception->getCode()
		&& false !== strpos( $exception->getMessage(), 'does not match' )
		&& false !== strpos( $exception->getMessage(), 'Repair Connection' ),
		'A mismatched App Data hash did not return a detailed repair action.'
	);
}
$wrong_tag_state            = $verify_state;
$wrong_tag_state['app_tag'] = 'other-app-tag';
try {
	$wrong_tag_args = array( &$wrong_tag_state, $app_enc_a, $file_key );
	dologin_test_invoke( $klsso, 'process_appdata', $wrong_tag_args );
	dologin_test_assert( false, 'Connection verification accepted a session for another App Tag.' );
} catch ( Exception $exception ) {
	dologin_test_assert( false !== strpos( $exception->getMessage(), 'App Tag changed' ), 'An App Tag mismatch during connection verification did not return a clear error.' );
}

$missing_hash_state = $verify_state;
try {
	$missing_hash_args = array( &$missing_hash_state, '', $file_key );
	dologin_test_invoke( $klsso, 'process_appdata', $missing_hash_args );
	dologin_test_assert( false, 'Connection verification did not require repair when the App Data hash was missing.' );
} catch ( Exception $exception ) {
	dologin_test_assert(
		KLSso::REPAIR_REQUIRED_CODE === $exception->getCode()
		&& false !== strpos( $exception->getMessage(), 'only grants permission' )
		&& false !== strpos( $exception->getMessage(), 'Repair Connection' ),
		'A missing App Data hash did not explain the cause and safe repair flow.'
	);
}

$repair_sign_kp = sodium_crypto_sign_keypair();
$repair_state   = array(
	'app_hash_ok'          => false,
	'app_id'               => 'repair-client',
	'app_tag'              => 'wordpress-dologin',
	'appdata_written'      => false,
	'enc_sk'               => base64_encode( $app_sk ),
	'id'                   => 'app.repair-client',
	'mode'                 => 'repair',
	'nickname'             => 'Repaired Safe',
	'phase'                => 'app_filekey',
	'safe_id'              => 'safe-test',
	'server_enc_pk'        => base64_encode( $safe_pk ),
	'sign_sk'              => base64_encode( sodium_crypto_sign_secretkey( $repair_sign_kp ) ),
	'site_key_fingerprint' => $reset_done['fingerprint'],
	'user_id'              => $bind_user_id,
	'verified'             => true,
);
$wrong_repair_state            = $repair_state;
$wrong_repair_state['safe_id'] = 'safe-other';
try {
	$wrong_repair_args = array(
		&$wrong_repair_state,
		'app_filekey_result',
		array(
			'_res'         => 'ok',
			'status'       => 'done',
			'data_filekey' => KLSso_MsgPack::bin( $full_envelope ),
			'data_enc'     => KLSso_MsgPack::bin( '' ),
			'ver'          => '10',
		),
	);
	dologin_test_invoke( $klsso, 'handle_kps_action', $wrong_repair_args );
	dologin_test_assert( false, 'Connection repair accepted a different KeyLockr Safe.' );
} catch ( Exception $exception ) {
	dologin_test_assert( false !== strpos( $exception->getMessage(), 'already linked' ), 'Connection repair did not clearly require the originally linked Safe.' );
}

$legacy_repair_state = $repair_state;
unset( $GLOBALS['dologin_test_user_meta'][ $bind_user_id ][ KLSso::META_APP_HASH ] );
$legacy_repair_args = array(
	&$legacy_repair_state,
	'app_filekey_result',
	array(
		'_res'         => 'ok',
		'status'       => 'done',
		'data_filekey' => KLSso_MsgPack::bin( $full_envelope ),
		'data_enc'     => KLSso_MsgPack::bin( '' ),
		'ver'          => '10',
	),
);
$legacy_repair_write = dologin_test_invoke( $klsso, 'handle_kps_action', $legacy_repair_args );
dologin_test_assert( 'send' === $legacy_repair_write['status'] && get_user_meta( $bind_user_id, KLSso::META_APP_HASH, true ), 'A legacy connection without a local hash could not begin repair with its original Safe.' );
$GLOBALS['dologin_test_user_meta'][ $bind_user_id ][ KLSso::META_APP_HASH ] = 'test-app-hash';

$repair_args = array(
	&$repair_state,
	'app_filekey_result',
	array(
		'_res'         => 'ok',
		'status'       => 'done',
		'data_filekey' => KLSso_MsgPack::bin( $full_envelope ),
		'data_enc'     => KLSso_MsgPack::bin( '' ),
		'ver'          => '10',
	),
);
$repair_write = dologin_test_invoke( $klsso, 'handle_kps_action', $repair_args );
dologin_test_assert( 'send' === $repair_write['status'] && 'test-app-hash' === $repair_state['app_hash'], 'Connection repair did not reuse the existing WordPress binding hash.' );
$repair_set_args = array( &$repair_state, 'app_set_data', array( '_res' => 'ok', 'file_id' => 'repair-file', 'ver' => '11' ) );
$repair_set      = dologin_test_invoke( $klsso, 'handle_kps_action', $repair_set_args );
dologin_test_assert( 'send' === $repair_set['status'] && ! empty( $repair_state['appdata_written'] ), 'Connection repair did not require reading App Data back after writing it.' );
$repair_appdata = dologin_test_invoke( $klsso, 'encrypt_appdata', array( KLSso_MsgPack::pack( array( 'hash' => 'test-app-hash' ) ), $file_key ) );
$repair_get_args = array( &$repair_state, 'app_get_data', array( '_res' => 'ok', 'data_encrypted' => KLSso_MsgPack::bin( $repair_appdata ), 'ver' => '11' ) );
$repair_done     = dologin_test_invoke( $klsso, 'handle_kps_action', $repair_get_args );
dologin_test_assert(
	'done' === $repair_done['status']
	&& false !== strpos( $repair_done['message'], 'repaired successfully' )
	&& 'safe-test' === get_user_meta( $bind_user_id, KLSso::META_SAFE_ID, true )
	&& 'test-app-hash' === get_user_meta( $bind_user_id, KLSso::META_APP_HASH, true )
	&& ! get_user_meta( $bind_user_id, 'dologin_kl_sso_client_id', true ),
	'Connection repair did not write and read back the existing hash on the same Safe or incorrectly persisted app_id.'
);

$connected_state = array(
	'id'    => 'tmp.connected-test',
	'phase' => 'tmp_auth',
);
$connected_args  = array( &$connected_state, 'connected', array( '_res' => 'ok', 'status' => 'ok' ) );
$connected       = dologin_test_invoke( $klsso, 'handle_kps_action', $connected_args );
dologin_test_assert( 'connected' === $connected['status'], 'The connected push was misclassified as a file-key state.' );
$unlock_state = array(
	'app_id'   => 'unlock-client',
	'id'       => 'app.unlock-client',
	'phase'    => 'app_filekey',
	'verified' => true,
);
$unlock_args  = array( &$unlock_state, 'app_req_filekey', array( '_res' => 'ok', 'status' => 'safe_auth_required' ) );
$unlock       = dologin_test_invoke( $klsso, 'handle_kps_action', $unlock_args );
dologin_test_assert( 'waiting' === $unlock['status'] && false !== strpos( $unlock['message'], 'Unlock KeyLockr' ), 'A locked phone did not produce an Unlock KeyLockr prompt.' );
try {
	$app_file_error_args = array( &$unlock_state, 'app_req_filekey', array( '_res' => 'err', 'code' => 'app_file_not_found' ) );
	dologin_test_invoke( $klsso, 'handle_kps_action', $app_file_error_args );
	dologin_test_assert( false, 'app_file_not_found was not rejected.' );
} catch ( Exception $exception ) {
	dologin_test_assert( false !== strpos( $exception->getMessage(), 'App Data Storage' ) && false !== strpos( $exception->getMessage(), 'App Tag' ), 'app_file_not_found did not provide actionable developer configuration guidance.' );
}

Conf::$values['kl_sso_svc_id'] = 'wordpress-dologin';
dologin_test_assert( 'wordpress-dologin' === KLSso::app_tag(), 'The effective KeyLockr App Tag was not read from the existing settings field.' );
$handshake_body = dologin_test_invoke( $klsso, 'handshake_body', array( 'sign-public', 'box-public', 'Example DoLogin' ) );
$handshake_data = KLSso_MsgPack::unpack( $handshake_body );
dologin_test_assert(
	true === $handshake_data['app_data']
	&& 'wordpress-dologin' === $handshake_data['app_tag']
	&& ! isset( $handshake_data['app_id'] )
	&& ! isset( $handshake_data['svc_id'] )
	&& ! isset( $handshake_data['ap'] )
	&& ! isset( $handshake_data['requested_scopes'] ),
	'The KeyLockr handshake did not use the current App Data capability contract.'
);
$handshake_data_error = dologin_test_invoke(
	$klsso,
	'handshake_error_message',
	array( array( '_res' => 'err', 'code' => 'sso_data_not_approved' ) )
);
$handshake_tag_error = dologin_test_invoke(
	$klsso,
	'handshake_error_message',
	array( array( '_res' => 'err', 'code' => 'sso_service_invalid' ) )
);
dologin_test_assert( false !== strpos( $handshake_data_error, 'App Data Storage' ) && false !== strpos( $handshake_tag_error, 'effective App Tag' ), 'Current KeyLockr handshake errors did not provide actionable guidance.' );
$auth_sign_kp = sodium_crypto_sign_keypair();
$auth_state   = array(
	'app_tag'        => 'wordpress-dologin',
	'enc_sk'         => base64_encode( $app_sk ),
	'id'             => 'tmp.current-test',
	'mode'           => 'login',
	'phase'          => 'tmp_auth',
	'server_enc_pk'  => base64_encode( $safe_pk ),
	'sign_pk'        => base64_encode( sodium_crypto_sign_publickey( $auth_sign_kp ) ),
	'sign_sk'        => base64_encode( sodium_crypto_sign_secretkey( $auth_sign_kp ) ),
);
$auth_initial_state = $auth_state;
$GLOBALS['dologin_test_remote_body'] = json_encode(
	array(
		'_res'     => 'ok',
		'nickname' => 'Current Safe',
		'valid'    => true,
	)
);
$auth_result_args = array(
	&$auth_state,
	'app_auth_result',
	array(
		'_res'         => 'ok',
		'app_id'       => 'client-current',
		'capabilities' => array( 'sso', 'app_data' ),
		'data_plain'   => KLSso_MsgPack::bin( 'metadata' ),
		'safe_id'      => 'safe-current',
		'status'       => 'done',
		'ver'          => '4',
	),
);
$auth_result      = dologin_test_invoke( $klsso, 'handle_kps_action', $auth_result_args );
$verify_request   = json_decode( $GLOBALS['dologin_test_remote_args']['body'], true );
dologin_test_assert( 'reconnect' === $auth_result['status'] && 'app.client-current' === $auth_state['id'], 'The current app_auth_result identity fields were not accepted.' );
dologin_test_assert(
	'wordpress-dologin' === $verify_request['app_tag']
	&& 'client-current' === $verify_request['app_id']
	&& ! isset( $verify_request['svc_id'], $verify_request['sso_client_id'] ),
	'app_verify did not use the current app_tag/app_id contract.'
);

$invalid_verify_state = $auth_initial_state;
$GLOBALS['dologin_test_remote_body'] = json_encode( array( '_res' => 'ok', 'valid' => 'false' ) );
try {
	$invalid_verify_args = array( &$invalid_verify_state, 'app_auth_result', $auth_result_args[2] );
	dologin_test_invoke( $klsso, 'handle_kps_action', $invalid_verify_args );
	dologin_test_assert( false, 'A non-boolean app_verify valid value was treated as success.' );
} catch ( Exception $exception ) {
	dologin_test_assert( false !== strpos( $exception->getMessage(), 'verification failed' ), 'A non-boolean app_verify valid value was not safely rejected.' );
}

try {
	$auth_only_state = array(
		'id'    => 'tmp.auth-only',
		'phase' => 'tmp_auth',
	);
	$auth_only_args  = array(
		&$auth_only_state,
		'app_auth_result',
		array(
			'_res'         => 'ok',
			'app_id'       => 'client-auth',
			'capabilities' => array( 'sso' ),
			'safe_id'      => 'safe-auth',
			'status'       => 'done',
		),
	);
	dologin_test_invoke( $klsso, 'handle_kps_action', $auth_only_args );
	dologin_test_assert( false, 'Authorization-only SSO was routed into the App Data WebSocket flow.' );
} catch ( Exception $exception ) {
	dologin_test_assert( false !== strpos( $exception->getMessage(), 'App Data Storage' ), 'Authorization-only SSO did not directly request enabling App Data Storage.' );
}
try {
	$extra_capability_state = array(
		'id'    => 'tmp.extra-capability',
		'phase' => 'tmp_auth',
	);
	$extra_capability_args  = array(
		&$extra_capability_state,
		'app_auth_result',
		array(
			'_res'         => 'ok',
			'app_id'       => 'client-extra',
			'capabilities' => array( 'sso', 'app_data', 'ap' ),
			'data_plain'   => KLSso_MsgPack::bin( 'metadata' ),
			'safe_id'      => 'safe-extra',
			'status'       => 'done',
			'ver'          => '1',
		),
	);
	dologin_test_invoke( $klsso, 'handle_kps_action', $extra_capability_args );
	dologin_test_assert( false, 'KeyLockr capabilities beyond the handshake request were accepted.' );
} catch ( Exception $exception ) {
	dologin_test_assert( false !== strpos( $exception->getMessage(), 'capabilities' ), 'Unexpected KeyLockr capabilities were not rejected with a clear error.' );
}
try {
	$invalid_args = array( &$connected_state, 'connected', array( 'status' => 'ok' ) );
	dologin_test_invoke( $klsso, 'handle_kps_action', $invalid_args );
	dologin_test_assert( false, 'A KPS body without _res=ok was accepted.' );
} catch ( Exception $exception ) {
	// Rejection is expected.
}
try {
	$invalid_connected_args = array( &$connected_state, 'connected', array( '_res' => 'ok', 'status' => 'failed' ) );
	dologin_test_invoke( $klsso, 'handle_kps_action', $invalid_connected_args );
	dologin_test_assert( false, 'A non-ok connected state was accepted.' );
} catch ( Exception $exception ) {
	// Rejection is expected.
}

$ping_sign_kp = sodium_crypto_sign_keypair();
$ping_state   = array(
	'app_id'        => 'test-client',
	'enc_sk'        => base64_encode( $app_sk ),
	'id'            => 'app.test-client',
	'phase'         => 'app_filekey',
	'server_enc_pk' => base64_encode( $safe_pk ),
	'sign_sk'       => base64_encode( sodium_crypto_sign_secretkey( $ping_sign_kp ) ),
	'verified'      => true,
);
$ping_args = array( &$ping_state, 'ping', array( '_res' => 'ok' ) );
$ping      = dologin_test_invoke( $klsso, 'handle_kps_action', $ping_args );
dologin_test_assert( 'send' === $ping['status'] && ! empty( $ping['send'] ), 'An active KeyLockr ping did not receive a pong response.' );

dologin_test_assert( IP::matches_ip_rule( '192.0.2.42', '192.0.2.*' ), 'The IPv4 wildcard did not match.' );
dologin_test_assert( ! IP::matches_ip_rule( '192.0.3.42', '192.0.2.*' ), 'The IPv4 wildcard incorrectly matched another subnet.' );
dologin_test_assert( IP::matches_ip_rule( '2001:db8::1', '2001:0db8:0:0:0:0:0:1' ), 'Equivalent IPv6 addresses did not match.' );
dologin_test_assert( IP::matches_ip_rule( '2001:db8:1:2:3:4:5:6', '2001:db8:*:*:*:*:*:*' ), 'The IPv6 wildcard did not match.' );
dologin_test_assert( ! IP::matches_ip_rule( '2001:db9::1', '2001:db8:*:*:*:*:*:*' ), 'The IPv6 wildcard incorrectly matched another prefix.' );

$ip_rules = ( new ReflectionClass( IP::class ) )->newInstanceWithoutConstructor();
$geo_prop = new ReflectionProperty( IP::class, '_visitor_geo_data' );
if ( PHP_VERSION_ID < 80100 ) {
	$geo_prop->setAccessible( true );
}
$geo_prop->setValue( $ip_rules, array( 'ip' => '1.2.3.4', 'country_code' => 'US' ) );
dologin_test_assert( $ip_rules->maybe_hit_rule( array( 'ip:1.2.3.*' ) ), 'The ip: prefix rule did not match.' );
dologin_test_assert( $ip_rules->maybe_hit_rule( array( 'ip: 1.2.3.* # comment' ) ), 'The commented ip: prefix rule did not match.' );
$geo_prop->setValue( $ip_rules, array( 'ip' => '9.9.9.9', 'country_code' => 'US' ) );
dologin_test_assert( $ip_rules->maybe_hit_rule( array( 'country_code: US, ip!: 1.2.3.4' ) ), 'The ip!: exclusion rule incorrectly rejected another IP.' );
$geo_prop->setValue( $ip_rules, array( 'ip' => '1.2.3.4', 'country_code' => 'US' ) );
dologin_test_assert( ! $ip_rules->maybe_hit_rule( array( 'country_code: US, ip!: 1.2.3.4' ) ), 'The ip!: exclusion rule did not reject the matching IP.' );

$totp       = new Two_FA_Lib();
$secret     = 'JBSWY3DPEHPK3PXP';
$time_slice = 1234567;
$code       = $totp->getCode( $secret, $time_slice );
dologin_test_assert( $time_slice === $totp->findValidTimeSlice( $secret, $code, 1, $time_slice ), 'TOTP time-slice lookup failed.' );
dologin_test_assert( false === $totp->findValidTimeSlice( $secret, '000000', 1, $time_slice ), 'An invalid TOTP was accepted.' );

$auth = ( new ReflectionClass( Auth::class ) )->newInstanceWithoutConstructor();
Conf::$values = array(
	'kl_sso_force' => true,
);
$blocked = $auth->enforce_klsso( 'password-login-user', 'user', 'password' );
dologin_test_assert( $blocked instanceof WP_Error && isset( $blocked->codes['kl_sso_required'] ), 'Forced SSO did not block another authentication provider.' );
$app_password_user = new WP_User( 11 );
dologin_test_assert( $auth->enforce_klsso( $app_password_user, 'api-user', 'regular-password' ) instanceof WP_Error, 'Unverified credentials bypassed forced SSO.' );
$auth->allow_application_password( $app_password_user );
dologin_test_assert( $app_password_user === $auth->enforce_klsso( $app_password_user, 'api-user', 'application-password' ), 'Forced SSO blocked an Application Password.' );
$credential_free_user = new WP_User( 12 );
dologin_test_assert( $auth->enforce_klsso( $credential_free_user, '', '' ) instanceof WP_Error, 'A credential-free authentication provider bypassed forced SSO.' );
Conf::$values['kl_sso_force'] = false;
dologin_test_assert( 'password-login-user' === $auth->enforce_klsso( 'password-login-user', 'user', 'password' ), 'Authentication remained blocked after forced SSO was disabled.' );

$GLOBALS['dologin_test_transients'][ KLSso::CLOCK_CACHE ] = 1;
dologin_test_assert( true === dologin_test_invoke( $klsso, 'check_server_clock' ), 'The successful KeyLockr clock-check cache was not honored.' );

$GLOBALS['dologin_test_user_id'] = $bind_user_id;
$GLOBALS['dologin_test_user_meta'][ $bind_user_id ][ KLSso::META_SAFE_ID ] = 'safe-test';
$GLOBALS['dologin_test_user_meta'][ $bind_user_id ]['dologin_kl_sso_client_id'] = 'old-client';
$GLOBALS['dologin_test_user_meta'][ $bind_user_id ]['dologin_kl_bound_at'] = 1;
Conf::$values['kl_sso_force'] = true;
$blocked_unlink = $klsso->unbind();
dologin_test_assert( 'err' === $blocked_unlink['_res'] && isset( $GLOBALS['dologin_test_user_meta'][ $bind_user_id ][ KLSso::META_SAFE_ID ] ), 'Unlinking remained available while forced SSO was enabled.' );
Conf::$values['kl_sso_force'] = false;
$unlink = $klsso->unbind();
dologin_test_assert( 'done' === $unlink['status'], 'Local KeyLockr unlinking failed.' );
foreach ( array( KLSso::META_SAFE_ID, KLSso::META_NICKNAME, KLSso::META_APP_HASH, KLSso::META_SITE_KEY_FP, KLSso::META_APP_TAG, 'dologin_kl_sso_client_id', 'dologin_kl_bound_at' ) as $meta_key ) {
	dologin_test_assert( ! isset( $GLOBALS['dologin_test_user_meta'][ $bind_user_id ][ $meta_key ] ), 'KeyLockr user data remained after unlinking.' );
}

Conf::$values['kl_sso_svc_id'] = 'wordpress-dologin';
$rebind_sign_kp = sodium_crypto_sign_keypair();
$rebind_state   = array(
	'app_hash_ok'          => false,
	'app_id'               => 'rebind-client',
	'app_tag'              => 'wordpress-dologin',
	'appdata_written'      => false,
	'enc_sk'               => base64_encode( $app_sk ),
	'id'                   => 'app.rebind-client',
	'mode'                 => 'bind',
	'nickname'             => 'Rebind Safe',
	'phase'                => 'app_filekey',
	'safe_id'              => 'safe-rebind',
	'server_enc_pk'        => base64_encode( $safe_pk ),
	'sign_sk'              => base64_encode( sodium_crypto_sign_secretkey( $rebind_sign_kp ) ),
	'site_key_fingerprint' => $reset_done['fingerprint'],
	'user_id'              => $bind_user_id,
	'verified'             => true,
);
$old_appdata = dologin_test_invoke( $klsso, 'encrypt_appdata', array( KLSso_MsgPack::pack( array( 'hash' => 'old-binding-hash' ) ), $file_key ) );
$rebind_args = array(
	&$rebind_state,
	'app_filekey_result',
	array(
		'_res'         => 'ok',
		'status'       => 'done',
		'data_filekey' => KLSso_MsgPack::bin( $full_envelope ),
		'data_enc'     => KLSso_MsgPack::bin( $old_appdata ),
		'ver'          => '7',
	),
);
$rebind      = dologin_test_invoke( $klsso, 'handle_kps_action', $rebind_args );
$new_hash    = get_user_meta( $bind_user_id, KLSso::META_APP_HASH, true );
dologin_test_assert( 'send' === $rebind['status'] && $new_hash && 'old-binding-hash' !== $new_hash, 'New App Data was not sent after unlinking.' );
dologin_test_assert( empty( $rebind_state['appdata_written'] ) && ! get_user_meta( $bind_user_id, KLSso::META_SAFE_ID, true ), 'The local binding completed before App Data write confirmation.' );

$write_frame = KLSso_MsgPack::unpack( base64_decode( $rebind['send'], true ) );
$write_kps   = $write_frame['kps'];
$write_raw   = $write_kps['raw'][0]->bytes;
$server_pair = sodium_crypto_box_keypair_from_secretkey_and_publickey( $safe_sk, $app_pk );
$write_plain = sodium_crypto_box_open( $write_kps['box']->bytes, $write_kps['n']->bytes, $server_pair );
$write_inner = KLSso_MsgPack::unpack( $write_plain );
dologin_test_assert(
	isset( $write_inner['body']['data_enc__'] )
	&& 0 === $write_inner['body']['data_enc__']
	&& '7' === $write_inner['body']['ver']
	&& ! isset( $write_inner['body']['data_enc'] )
	&& strlen( $write_raw ) >= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES,
	'app_set_data did not use the current raw/CAS wire format.'
);

try {
	$invalid_set_args = array( &$rebind_state, 'app_set_data', array( '_res' => 'ok' ) );
	dologin_test_invoke( $klsso, 'handle_kps_action', $invalid_set_args );
	dologin_test_assert( false, 'An app_set_data response without the current ver field was accepted.' );
} catch ( Exception $exception ) {
	dologin_test_assert( false !== strpos( $exception->getMessage(), 'version' ), 'An App Data write response without a CAS version was not clearly rejected.' );
}
dologin_test_assert( empty( $rebind_state['appdata_written'] ) && ! get_user_meta( $bind_user_id, KLSso::META_SAFE_ID, true ), 'The local binding completed after an invalid App Data write response.' );

$conflict_args = array( &$rebind_state, 'app_set_data', array( '_res' => 'err', 'code' => 'file_ver_conflict' ) );
$conflict      = dologin_test_invoke( $klsso, 'handle_kps_action', $conflict_args );
dologin_test_assert( 'send' === $conflict['status'] && ! empty( $rebind_state['appdata_retry_pending'] ), 'The current App Data version was not read after a CAS conflict.' );
$retry_read_args = array(
	&$rebind_state,
	'app_get_data',
	array(
		'_res'           => 'ok',
		'data_encrypted' => KLSso_MsgPack::bin( $old_appdata ),
		'ver'            => '8',
	),
);
$retry_write     = dologin_test_invoke( $klsso, 'handle_kps_action', $retry_read_args );
dologin_test_assert( 'send' === $retry_write['status'] && empty( $rebind_state['appdata_retry_pending'] ) && '8' === $rebind_state['data_ver'], 'The App Data write was not retried after reading the current CAS version.' );
try {
	dologin_test_invoke( $klsso, 'handle_kps_action', $conflict_args );
	dologin_test_assert( false, 'The App Data CAS conflict was retried without a limit.' );
} catch ( Exception $exception ) {
	dologin_test_assert( false !== strpos( $exception->getMessage(), 'changed repeatedly' ), 'Exhausted App Data CAS retries did not return a clear error.' );
}

$set_args = array( &$rebind_state, 'app_set_data', array( '_res' => 'ok', 'file_id' => 'file-test', 'ver' => '9' ) );
$set      = dologin_test_invoke( $klsso, 'handle_kps_action', $set_args );
dologin_test_assert( 'send' === $set['status'] && ! empty( $rebind_state['appdata_written'] ) && '9' === $rebind_state['data_ver'] && ! get_user_meta( $bind_user_id, KLSso::META_SAFE_ID, true ), 'The App Data write response was mistaken for completed binding.' );

$wrong_appdata = dologin_test_invoke( $klsso, 'encrypt_appdata', array( KLSso_MsgPack::pack( array( 'hash' => 'wrong-hash' ) ), $file_key ) );
try {
	$wrong_get_args = array( &$rebind_state, 'app_get_data', array( '_res' => 'ok', 'data_encrypted' => KLSso_MsgPack::bin( $wrong_appdata ), 'ver' => '9' ) );
	dologin_test_invoke( $klsso, 'handle_kps_action', $wrong_get_args );
	dologin_test_assert( false, 'Binding completed after mismatched App Data was read back.' );
} catch ( Exception $exception ) {
	dologin_test_assert( false !== strpos( $exception->getMessage(), 'Unlock KeyLockr' ), 'A failed App Data read-back check did not prompt the user to unlock the phone.' );
}
dologin_test_assert( ! get_user_meta( $bind_user_id, KLSso::META_SAFE_ID, true ), 'A local binding remained after failed App Data read-back verification.' );

$new_appdata = dologin_test_invoke( $klsso, 'encrypt_appdata', array( KLSso_MsgPack::pack( array( 'hash' => $new_hash ) ), $file_key ) );
$get_args    = array( &$rebind_state, 'app_get_data', array( '_res' => 'ok', 'data_encrypted' => KLSso_MsgPack::bin( $new_appdata ), 'ver' => '9' ) );
$get         = dologin_test_invoke( $klsso, 'handle_kps_action', $get_args );
dologin_test_assert(
	'done' === $get['status']
	&& 'safe-rebind' === get_user_meta( $bind_user_id, KLSso::META_SAFE_ID, true )
	&& $reset_done['fingerprint'] === get_user_meta( $bind_user_id, KLSso::META_SITE_KEY_FP, true )
	&& 'wordpress-dologin' === get_user_meta( $bind_user_id, KLSso::META_APP_TAG, true )
	&& ! get_user_meta( $bind_user_id, 'dologin_kl_sso_client_id', true ),
	'Binding did not complete after successful App Data write/read-back verification or incorrectly persisted the KeyLockr app_id.'
);

$_SERVER['SERVER_ADDR'] = '8.8.4.4';
dologin_test_assert( '8.8.4.4' === dologin_test_invoke( $klsso, 'server_address', array( 'v4' ) ), 'Public server IPv4 fallback detection failed.' );
$_SERVER['SERVER_ADDR'] = '127.0.0.1';
dologin_test_assert( '' === dologin_test_invoke( $klsso, 'server_address' ), 'The server-IP fallback accepted a non-publicly-routable address.' );
$GLOBALS['dologin_test_remote_body'] = '8.8.8.8';
dologin_test_assert( '8.8.8.8' === dologin_test_invoke( $klsso, 'fetch_public_ip', array( 'v4' ) ), 'The externally detected server IPv4 address could not be parsed.' );
dologin_test_assert( 'text/plain' === $GLOBALS['dologin_test_remote_args']['headers']['Accept'], 'Server-IP detection did not request a plain-text response.' );

echo "Security regression checks passed.\n";
}
