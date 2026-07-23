<?php
/**
 * Site assertion and KeyLockr session-isolation regression checks.
 */

$site = ( new ReflectionClass( \dologin\Site::class ) )->newInstanceWithoutConstructor();
$site_sign_kp = sodium_crypto_sign_keypair();
\dologin\Conf::$values['_pk'] = base64_encode( sodium_crypto_sign_publickey( $site_sign_kp ) );
$site_sign_sk = base64_encode( sodium_crypto_sign_secretkey( $site_sign_kp ) );
\dologin\Conf::$values['_sk'] = \dologin\Secret::seal( 'site-easy-login-signing-key', $site_sign_sk );
dologin_test_assert(
	\dologin\Secret::is_sealed( \dologin\Conf::$values['_sk'] )
	&& false === strpos( \dologin\Conf::$values['_sk'], $site_sign_sk ),
	'The Site Easy Login signing key was stored without authenticated encryption.'
);

$raw_passwordless_token = 'one-time-secret-token';
$passwordless_hash      = \dologin\Secret::token_hash( 'passwordless-login', $raw_passwordless_token );
dologin_test_assert(
	\dologin\Secret::is_token_hash( $passwordless_hash )
	&& false === strpos( $passwordless_hash, $raw_passwordless_token )
	&& \dologin\Secret::verify_token( 'passwordless-login', $raw_passwordless_token, $passwordless_hash )
	&& ! \dologin\Secret::verify_token( 'passwordless-login', 'wrong-token', $passwordless_hash )
	&& ! \dologin\Secret::verify_token( 'site-connection', $raw_passwordless_token, $passwordless_hash ),
	'Bearer-token HMAC storage was reversible, accepted a wrong token, or was not purpose-separated.'
);

$totp = ( new ReflectionClass( \dologin\TwoFA::class ) )->newInstanceWithoutConstructor();
$GLOBALS['dologin_test_user_meta'][41]['2fa'] = 'JBSWY3DPEHPK3PXP';
$migrated_totp = dologin_test_invoke( $totp, 'user_secret', array( 41 ) );
$stored_totp   = $GLOBALS['dologin_test_user_meta'][41]['2fa'];
dologin_test_assert(
	'JBSWY3DPEHPK3PXP' === $migrated_totp
	&& \dologin\Secret::is_sealed( $stored_totp )
	&& false === strpos( $stored_totp, 'JBSWY3DPEHPK3PXP' )
	&& 'JBSWY3DPEHPK3PXP' === \dologin\Secret::open( 'totp-user-secret', $stored_totp )
	&& false === \dologin\Secret::open( 'site-easy-login-signing-key', $stored_totp ),
	'The legacy TOTP secret was not encrypted or its ciphertext was not purpose-bound.'
);
$tampered_totp = $stored_totp;
$tampered_totp[ strlen( $tampered_totp ) - 1 ] = '=' === substr( $tampered_totp, -1 ) ? 'A' : '=';
dologin_test_assert( false === \dologin\Secret::open( 'totp-user-secret', $tampered_totp ), 'Tampered TOTP ciphertext was accepted.' );
$easy_claims = array(
	'v'   => 2,
	'uid' => 17,
	'pk'  => \dologin\Conf::$values['_pk'],
	'aud' => 'https://child.example/wp-admin/',
	'iat' => time(),
	'jti' => str_repeat( 'b', 32 ),
);
$easy_claims_json = dologin_test_invoke( $site, '_easy_login_claims_json', array( $easy_claims ) );
$easy_signature   = dologin_test_invoke( $site, '_pack_b64sign', array( $easy_claims_json ) );
$easy_token       = base64_encode( wp_json_encode( array( 'claims' => $easy_claims, 'sig' => $easy_signature ) ) );
$decoded_easy     = dologin_test_invoke( $site, '_decode_easy_login_token', array( $easy_token ) );
dologin_test_assert(
	$easy_claims_json === $decoded_easy['claims_json']
	&& $easy_claims_json === dologin_test_invoke( $site, '_unpack_b64sign', array( $decoded_easy['sig'], $easy_claims['pk'] ) ),
	'The versioned Site Easy Login assertion did not verify as one signed unit.'
);
$tampered_easy_claims        = $easy_claims;
$tampered_easy_claims['uid'] = 18;
$tampered_easy_json          = dologin_test_invoke( $site, '_easy_login_claims_json', array( $tampered_easy_claims ) );
dologin_test_assert( ! hash_equals( $tampered_easy_json, dologin_test_invoke( $site, '_unpack_b64sign', array( $easy_signature, $easy_claims['pk'] ) ) ), 'Changing the Site Easy Login user ID did not invalidate the signed assertion.' );
$tampered_easy_claims        = $easy_claims;
$tampered_easy_claims['aud'] = 'https://other.example/wp-admin/';
$tampered_easy_json          = dologin_test_invoke( $site, '_easy_login_claims_json', array( $tampered_easy_claims ) );
dologin_test_assert( ! hash_equals( $tampered_easy_json, dologin_test_invoke( $site, '_unpack_b64sign', array( $easy_signature, $easy_claims['pk'] ) ) ), 'Changing the Site Easy Login audience did not invalidate the signed assertion.' );
dologin_test_assert( false === dologin_test_invoke( $site, '_decode_easy_login_token', array( base64_encode( '17,public-key,legacy-signature' ) ) ), 'The insecure legacy Site Easy Login token format was still accepted.' );
dologin_test_assert( 'https://child.example/wp-admin/' === dologin_test_invoke( $site, '_easy_login_audience', array( 'HTTPS://CHILD.EXAMPLE/wp-admin' ) ), 'The Site Easy Login audience was not normalized consistently.' );

$site_source = file_get_contents( dirname( __DIR__ ) . '/src/site.cls.php' );
dologin_test_assert( false !== strpos( $site_source, 'last_used_at<%d' ) && false === strpos( $site_source, 'last_used_at<>%d' ), 'Site Easy Login did not atomically require tokens to be newer than the last consumed assertion.' );
$passwordless_source = file_get_contents( dirname( __DIR__ ) . '/src/pswdless.cls.php' );
dologin_test_assert(
	false !== strpos( $passwordless_source, "Secret::token_hash( 'passwordless-login', \$token )" )
	&& false !== strpos( $passwordless_source, "Secret::verify_token( 'passwordless-login'" )
	&& false !== strpos( $site_source, "Secret::token_hash( 'site-connection', \$token )" )
	&& false !== strpos( $site_source, "Secret::verify_token( 'site-connection'" ),
	'Passwordless or site-connection bearer tokens were not stored and verified through purpose-bound HMACs.'
);

$force_conf_before = \dologin\Conf::$values;
$force_user_before = $GLOBALS['dologin_test_user_id'];
$force_manage_before = $GLOBALS['dologin_test_manage_options'];
$force_uid = 42;
$force_fingerprint = \dologin\KLSso::site_key_fingerprint();
$GLOBALS['dologin_test_user_id'] = $force_uid;
$GLOBALS['dologin_test_manage_options'] = true;
$GLOBALS['dologin_test_user_meta'][ $force_uid ][ \dologin\KLSso::META_SAFE_ID ] = 'safe-force-ready';
$GLOBALS['dologin_test_user_meta'][ $force_uid ][ \dologin\KLSso::META_APP_HASH ] = 'force-binding-hash';
$GLOBALS['dologin_test_user_meta'][ $force_uid ][ \dologin\KLSso::META_APP_TAG ] = 'force-app';
$GLOBALS['dologin_test_user_meta'][ $force_uid ][ \dologin\KLSso::META_SITE_KEY_FP ] = $force_fingerprint;
\dologin\Conf::$values = array(
	'kl_sso'        => true,
	'kl_sso_force'  => true,
	'kl_sso_svc_id' => 'force-app',
);
dologin_test_assert(
	\dologin\KLSso::force_ready( 'force-app' )
	&& ! \dologin\KLSso::force_ready( 'different-app' ),
	'Force KeyLockr SSO did not require the current administrator binding to match the requested App Tag and site identity.'
);
$GLOBALS['dologin_test_user_meta'][ $force_uid ][ \dologin\KLSso::META_APP_TAG ] = 'stale-app';
dologin_test_assert(
	! \dologin\KLSso::force_ready( 'force-app' )
	&& \dologin\KLSso::force_enabled(),
	'Forced SSO fell back to another login method after its activation binding became stale.'
);
\dologin\Conf::$values['kl_sso'] = false;
\dologin\Conf::$values['kl_sso_svc_id'] = '';
dologin_test_assert( \dologin\KLSso::force_enabled(), 'Forced SSO fell back after the KeyLockr connection became unavailable or incomplete.' );
$admin_source = file_get_contents( dirname( __DIR__ ) . '/src/admin.cls.php' );
dologin_test_assert(
	false !== strpos( $admin_source, "! \$force_was_enabled && ! empty( \$list['kl_sso_force'] )" ),
	'Saving settings could automatically disable an already-active forced SSO policy after its activation binding became stale.'
);
$fingerprint_before_blocked_reset = \dologin\KLSso::site_key_fingerprint();
$blocked_force_reset = $klsso->reset_site_keys();
dologin_test_assert(
	'err' === $blocked_force_reset['_res']
	&& $fingerprint_before_blocked_reset === \dologin\KLSso::site_key_fingerprint(),
	'KeyLockr site keys could be reset while forced SSO was active.'
);
$klsso_source = file_get_contents( dirname( __DIR__ ) . '/src/klsso.cls.php' );
dologin_test_assert(
	false !== strpos( $klsso_source, 'wp_set_auth_cookie( $user->ID' )
	&& false === strpos( $klsso_source, 'wp_signon(' )
	&& false === strpos( $klsso_source, 'wp_authenticate(' )
	&& false === strpos( $klsso_source, 'DOLOGIN_DISABLE_' . 'KLSSO_FORCE' ),
	'KeyLockr completion re-entered forced-SSO enforcement or retained an internal emergency bypass.'
);
\dologin\Conf::$values = $force_conf_before;
$GLOBALS['dologin_test_user_id'] = $force_user_before;
$GLOBALS['dologin_test_manage_options'] = $force_manage_before;

$session_box_a = dologin_test_invoke( $klsso, 'new_session_box_keypair' );
$session_box_b = dologin_test_invoke( $klsso, 'new_session_box_keypair' );
dologin_test_assert(
	$session_box_a !== $session_box_b
	&& sodium_crypto_box_publickey( $session_box_a ) !== sodium_crypto_box_publickey( $site_keys_c['box_kp'] ),
	'KeyLockr handshakes did not receive fresh session encryption keys.'
);
$replay_state = array();
dologin_test_assert(
	dologin_test_invoke( $klsso, 'remember_frame', array( &$replay_state, 'signed-frame-a' ) )
	&& ! dologin_test_invoke( $klsso, 'remember_frame', array( &$replay_state, 'signed-frame-a' ) )
	&& dologin_test_invoke( $klsso, 'remember_frame', array( &$replay_state, 'signed-frame-b' ) ),
	'KeyLockr exact frame replay was not rejected per session.'
);
$lock_state_id = str_repeat( 'c', 32 );
$lock_owner    = dologin_test_invoke( $klsso, 'acquire_state_lock', array( $lock_state_id ) );
dologin_test_assert( is_string( $lock_owner ) && false === dologin_test_invoke( $klsso, 'acquire_state_lock', array( $lock_state_id ) ), 'Concurrent KeyLockr state processing was not locked.' );
dologin_test_invoke( $klsso, 'release_state_lock', array( $lock_state_id, $lock_owner ) );
dologin_test_assert( ! isset( $GLOBALS['dologin_test_options'][ 'dologin_kl_sso_lock_' . $lock_state_id ] ), 'The KeyLockr state lock was not released by its owner.' );
$stale_lock_key = 'dologin_kl_sso_lock_' . $lock_state_id;
$GLOBALS['dologin_test_options'][ $stale_lock_key ] = ( time() - 1 ) . ':' . str_repeat( 'd', 32 );
$recovered_owner = dologin_test_invoke( $klsso, 'acquire_state_lock', array( $lock_state_id ) );
dologin_test_assert( is_string( $recovered_owner ) && false !== strpos( $GLOBALS['dologin_test_options'][ $stale_lock_key ], ':' . $recovered_owner ), 'An abandoned KeyLockr state lock could not be recovered safely.' );
dologin_test_invoke( $klsso, 'release_state_lock', array( $lock_state_id, $recovered_owner ) );
$_SERVER['REMOTE_ADDR'] = '192.0.2.55';
dologin_test_assert(
	! dologin_test_invoke( $klsso, 'request_rate_limited', array( 'regression', 2, 60 ) )
	&& ! dologin_test_invoke( $klsso, 'request_rate_limited', array( 'regression', 2, 60 ) )
	&& dologin_test_invoke( $klsso, 'request_rate_limited', array( 'regression', 2, 60 ) ),
	'The serialized KeyLockr endpoint rate limit did not enforce its request quota.'
);
$tmp_phase_state = array( 'id' => 'tmp.phase-test', 'phase' => 'tmp_auth' );
dologin_test_invoke( $klsso, 'assert_kps_action_phase', array( $tmp_phase_state, 'connected' ) );
try {
	dologin_test_invoke( $klsso, 'assert_kps_action_phase', array( $tmp_phase_state, 'app_get_data' ) );
	dologin_test_assert( false, 'A KeyLockr App Data response was accepted during the temporary authorization phase.' );
} catch ( Exception $exception ) {
	dologin_test_assert( false !== strpos( $exception->getMessage(), 'sequence' ), 'A cross-phase KeyLockr response did not return a clear sequence error.' );
}

$server_sign_kp = sodium_crypto_sign_keypair();
$session_nonce  = random_bytes( SODIUM_CRYPTO_BOX_NONCEBYTES );
$session_pair   = sodium_crypto_box_keypair_from_secretkey_and_publickey( $safe_sk, sodium_crypto_box_publickey( $session_box_a ) );
$session_plain  = \dologin\KLSso_MsgPack::pack(
	array(
		'body'   => array( '_res' => 'ok', 'status' => 'ok' ),
		'header' => array( 'from' => 'connected', 'ts' => time() ),
	)
);
$session_kps = array(
	'box' => \dologin\KLSso_MsgPack::bin( sodium_crypto_box( $session_plain, $session_nonce, $session_pair ) ),
	'n'   => \dologin\KLSso_MsgPack::bin( $session_nonce ),
);
$session_frame = \dologin\KLSso_MsgPack::pack(
	array(
		'kps'  => $session_kps,
		'seal' => \dologin\KLSso_MsgPack::bin( sodium_crypto_sign( hash( 'sha256', \dologin\KLSso_MsgPack::pack( $session_kps ), true ), sodium_crypto_sign_secretkey( $server_sign_kp ) ) ),
	)
);
$session_state_a = array(
	'enc_sk'         => base64_encode( sodium_crypto_box_secretkey( $session_box_a ) ),
	'server_enc_pk'  => base64_encode( $safe_pk ),
	'server_sign_pk' => base64_encode( sodium_crypto_sign_publickey( $server_sign_kp ) ),
);
$session_state_b = $session_state_a;
$session_state_b['enc_sk'] = base64_encode( sodium_crypto_box_secretkey( $session_box_b ) );
$opened_session = dologin_test_invoke( $klsso, 'open_kps', array( $session_state_a, $session_frame ) );
dologin_test_assert( 'connected' === $opened_session[0], 'A KeyLockr frame could not be opened by its originating session.' );
try {
	dologin_test_invoke( $klsso, 'open_kps', array( $session_state_b, $session_frame ) );
	dologin_test_assert( false, 'A KeyLockr transcript was replayed into another session.' );
} catch ( Exception $exception ) {
	dologin_test_assert( false !== strpos( $exception->getMessage(), 'decrypt' ), 'A cross-session KeyLockr replay did not fail at session decryption.' );
}
