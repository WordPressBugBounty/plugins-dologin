<?php
/**
 * KeyLockr UI, route, and browser-source regression checks.
 */

$GLOBALS['dologin_test_user_id'] = 3;
$GLOBALS['dologin_test_user_meta'][3][ \dologin\KLSso::META_SAFE_ID ]     = 'safe-render-test';
$GLOBALS['dologin_test_user_meta'][3][ \dologin\KLSso::META_NICKNAME ]    = 'Render Test';
$GLOBALS['dologin_test_user_meta'][3][ \dologin\KLSso::META_SITE_KEY_FP ] = $reset_done['fingerprint'];
$GLOBALS['dologin_test_user_meta'][3][ \dologin\KLSso::META_APP_TAG ]     = 'render-test';
\dologin\Conf::$values = array(
	'kl_sso'        => true,
	'kl_sso_force'  => false,
	'kl_sso_svc_id' => 'render-test',
);
ob_start();
$klsso->bind_form();
$bound_form = ob_get_clean();
$bound_account_pos = strpos( $bound_form, 'dologin-kl-account-main' );
$bound_verify_pos  = strpos( $bound_form, 'Verify Connection' );
$bound_danger_pos  = strpos( $bound_form, 'dologin-kl-danger-actions' );
$bound_unlink_pos  = strpos( $bound_form, 'Unlink KeyLockr' );
$bound_repair_pos  = strpos( $bound_form, 'dologin-kl-repair" hidden' );
$bound_status      = \dologin\KLSso::current_user_status();
dologin_test_assert(
	false !== strpos( $bound_form, 'safe-render-test' )
	&& ! empty( $bound_status['key_current'] )
	&& false !== strpos( $bound_form, 'data-dologin-kl-autostart="false"' )
	&& false !== $bound_account_pos
	&& false !== $bound_verify_pos
	&& false !== $bound_danger_pos
	&& false !== $bound_unlink_pos
	&& false !== $bound_repair_pos
	&& false !== strpos( $bound_form, 'Repair Connection' )
	&& $bound_account_pos < $bound_verify_pos
	&& $bound_verify_pos < $bound_danger_pos
	&& $bound_danger_pos < $bound_unlink_pos
	&& false !== strpos( $bound_form, 'dologin-kl-verify-panel" hidden' )
	&& false === strpos( $bound_form, 'dologin-kl-refresh' ),
	'Bound account controls are misplaced, unlink is not separated, the repair action is absent, or QR pairing autostarts.'
);

\dologin\Conf::$values['kl_sso_svc_id'] = 'render-test-changed';
$changed_status = \dologin\KLSso::current_user_status();
ob_start();
$klsso->bind_form();
$changed_tag_form = ob_get_clean();
dologin_test_assert(
	empty( $changed_status['key_current'] )
	&& ! empty( $changed_status['app_tag_changed'] )
	&& false !== strpos( $changed_tag_form, 'Relink Connection' )
	&& false !== strpos( $changed_tag_form, 'dologin-kl-relink' )
	&& false !== strpos( $changed_tag_form, 'The KeyLockr App Tag changed' )
	&& false !== strpos( $changed_tag_form, 'data-dologin-kl-autostart="false"' )
	&& false === strpos( $changed_tag_form, 'dologin-kl-verify"' ),
	'An App Tag change did not require relinking or incorrectly displayed an automatic QR.'
);

\dologin\Conf::$values['kl_sso_svc_id'] = 'render-test';
$GLOBALS['dologin_test_user_meta'][3][ \dologin\KLSso::META_SITE_KEY_FP ] = $site_fingerprint_a;
ob_start();
$klsso->bind_form();
$stale_form   = ob_get_clean();
$stale_status = \dologin\KLSso::current_user_status();
dologin_test_assert(
	! empty( $stale_status['bound'] )
	&& empty( $stale_status['key_current'] )
	&& false !== strpos( $stale_form, 'has not been verified with the current KeyLockr connection identity' )
	&& false !== strpos( $stale_form, 'data-dologin-kl-autostart="false"' )
	&& false !== strpos( $stale_form, 'dologin-kl-verify-panel" hidden' ),
	'Key rotation did not preserve the account and request verification, or incorrectly displayed an automatic QR.'
);

$GLOBALS['dologin_test_user_meta'][3][ \dologin\KLSso::META_SITE_KEY_FP ] = $reset_done['fingerprint'];
$profile_user = new WP_User( 3 );
ob_start();
$klsso->profile_form( $profile_user );
$bound_profile = ob_get_clean();
dologin_test_assert( false === strpos( $bound_profile, 'Start Pairing' ), 'A bound profile still displays the KeyLockr pairing action.' );

unset( $GLOBALS['dologin_test_user_meta'][3][ \dologin\KLSso::META_SAFE_ID ] );
ob_start();
$klsso->bind_form();
$unbound_form = ob_get_clean();
$unbound_qr_pos       = strpos( $unbound_form, 'dologin-kl-qr' );
$unbound_controls_pos = strpos( $unbound_form, 'dologin-kl-pairing-controls' );
dologin_test_assert(
	false !== strpos( $unbound_form, 'data-dologin-kl-autostart="false"' )
	&& false !== $unbound_qr_pos
	&& false !== $unbound_controls_pos
	&& $unbound_qr_pos < $unbound_controls_pos
	&& false !== strpos( $unbound_form, 'Start Pairing' )
	&& false !== strpos( $unbound_form, 'role="img"' )
	&& false !== strpos( $unbound_form, 'aria-label="KeyLockr SSO QR code"' )
	&& false === strpos( $unbound_form, 'dologin-kl-countdown' )
	&& false === strpos( $unbound_form, 'dologin-kl-repair' ),
	'Unbound account pairing is not explicit, accessible, or arranged with QR and controls.'
);

ob_start();
$klsso->profile_form( $profile_user );
$unbound_profile = ob_get_clean();
dologin_test_assert( false !== strpos( $unbound_profile, 'Select Start Pairing' ), 'The unbound profile does not explain how to start KeyLockr pairing.' );
ob_start();
$klsso->login_form();
$login_form = ob_get_clean();
dologin_test_assert(
	false !== strpos( $login_form, 'dologin-kl-qr' )
	&& false !== strpos( $login_form, 'role="img"' )
	&& false !== strpos( $login_form, 'data-dologin-kl-autostart="false"' )
	&& false !== strpos( $login_form, 'DoLogin Security Login' )
	&& false !== strpos( $login_form, 'Start KeyLockr Login' )
	&& false !== strpos( $login_form, 'https://keylockr.app' )
	&& false === strpos( $login_form, 'Loading KeyLockr QR code' )
	&& false === strpos( $login_form, 'Refresh QR' ),
	'The login-page KeyLockr flow does not wait for an explicit start or omits its DoLogin and KeyLockr identity.'
);

\dologin\Conf::$values['kl_sso'] = false;
\dologin\Conf::$values['kl_sso_force'] = true;
\dologin\Conf::$values['kl_sso_svc_id'] = '';
ob_start();
$klsso->login_form();
$unavailable_force_form = ob_get_clean();
dologin_test_assert(
	false !== strpos( $unavailable_force_form, 'data-dologin-kl-autostart="false"' )
	&& false !== strpos( $unavailable_force_form, 'Forced login remains active' )
	&& false !== strpos( $unavailable_force_form, 'DoLogin Security Login' )
	&& false !== strpos( $unavailable_force_form, 'https://keylockr.app' )
	&& false === strpos( $unavailable_force_form, 'dologin-kl-qr' ),
	'The login page visually restored an older login method when forced KeyLockr SSO became unavailable.'
);

$kl_sso_js      = file_get_contents( dirname( __DIR__ ) . '/assets/kl-sso.js' );
$connected_pos  = strpos( $kl_sso_js, "res.status === 'connected'" );
$pending_qr_pos = strpos( $kl_sso_js, 'if ( pendingQR )' );
$repair_flag_pos = strpos( $kl_sso_js, 'res && res.repair' );
$repair_show_pos = strpos( $kl_sso_js, 'showRepairAction( $box );', $repair_flag_pos );
dologin_test_assert(
	false !== $connected_pos
	&& false !== $pending_qr_pos
	&& $connected_pos < $pending_qr_pos
	&& false === strpos( $kl_sso_js, 'renderQR( $box, res.qr );' )
	&& false !== strpos( $kl_sso_js, 'openSocket( $box, res.ws_url' )
	&& false !== strpos( $kl_sso_js, "start( \$box, 'bind', true );" )
	&& false !== strpos( $kl_sso_js, "start( \$box, 'repair' );" )
	&& false !== $repair_flag_pos
	&& false !== $repair_show_pos
	&& $repair_flag_pos < $repair_show_pos
	&& false !== strpos( $kl_sso_js, "\$button.prop( 'hidden', false ).prop( 'disabled', false ).show().trigger( 'focus' );" )
	&& false === strpos( $kl_sso_js, "\$( '<button>'" )
	&& false !== strpos( $kl_sso_js, 'ws = new WebSocket( url );' )
	&& false !== strpos( $kl_sso_js, 'apiPost( cfg.url_frame' )
	&& false !== strpos( $kl_sso_js, 'frameQueue.push( bytesToBase64( ev.data ) );' )
	&& false !== strpos( $kl_sso_js, 'frame: frameQueue.shift()' )
	&& false !== strpos( $kl_sso_js, "\$box.find( '.dologin-kl-qr' ).empty();" )
	&& false !== strpos( $kl_sso_js, "\$box.find( '.dologin-kl-refresh' ).prop( 'disabled', true );" )
	&& false !== strpos( $kl_sso_js, "\$box.find( '.dologin-kl-refresh' ).prop( 'disabled', false );" )
	&& false !== strpos( $kl_sso_js, "\$box.data( 'dologin-kl-autostart' ) !== false" )
	&& false === strpos( $kl_sso_js, 'bindTimer' )
	&& false === strpos( $kl_sso_js, 'startAdminTimer' )
	&& false === strpos( $kl_sso_js, 'cfg.timeout' )
	&& false === strpos( $kl_sso_js, 'dologin-kl-countdown' )
	&& false === strpos( $kl_sso_js, '.text( cfg.i18n.manual )' ),
	'QR persistence, cleanup, or the pre-rendered repair action is incomplete.'
);

$klsso_source = file_get_contents( dirname( __DIR__ ) . '/src/klsso.cls.php' );
dologin_test_assert(
	false !== strpos( $klsso_source, 'self::REPAIR_REQUIRED_CODE === $ex->getCode()' )
	&& false !== strpos( $klsso_source, "'verify' === \$state['mode']" )
	&& false !== strpos( $klsso_source, "\$error['repair'] = true;" ),
	'The server does not expose the structured repair flag for a repairable verification response.'
);

$rest_source = file_get_contents( dirname( __DIR__ ) . '/src/rest.cls.php' );
$reset_route_pos = strpos( $rest_source, "'/kl_sso/reset_keys'" );
$reset_callback_pos = strpos( $rest_source, "'reset_site_keys'", $reset_route_pos );
$reset_filter_pos = strpos( $rest_source, "apply_filters( 'dologin_admin_menu_access', 'manage_options' )", $reset_callback_pos );
dologin_test_assert(
	false !== $reset_route_pos
	&& false !== $reset_callback_pos
	&& false !== $reset_filter_pos
	&& $reset_route_pos < $reset_callback_pos
	&& $reset_callback_pos < $reset_filter_pos,
	'The KeyLockr reset route, callback, or filtered capability guard is missing.'
);

$admin_js = file_get_contents( dirname( __DIR__ ) . '/assets/admin.js' );
$ip_lookup_pos = strpos( $admin_js, "'#dologin_get_ip'" );
$reset_ui_pos  = strpos( $admin_js, "'.dologin-kl-reset-keys'" );
dologin_test_assert(
	false !== $ip_lookup_pos
	&& false !== strpos( $admin_js, 'ip_lookup_progress', $ip_lookup_pos )
	&& false !== strpos( $admin_js, 'ip_lookup_failed', $ip_lookup_pos )
	&& false !== strpos( $admin_js, "attr( 'aria-busy', 'true' )", $ip_lookup_pos )
	&& false !== strpos( $admin_js, '.fail( function()', $ip_lookup_pos )
	&& false !== strpos( $admin_js, '.always( function()', $ip_lookup_pos )
	&& false !== $reset_ui_pos
	&& $ip_lookup_pos < $reset_ui_pos,
	'The IP lookup does not expose busy, failure, and cleanup states.'
);
dologin_test_assert(
	false !== strpos( $admin_js, 'reset_keys_confirm', $reset_ui_pos )
	&& false !== strpos( $admin_js, "prop( 'disabled', true )", $reset_ui_pos )
	&& false !== strpos( $admin_js, 'url_kl_reset_keys', $reset_ui_pos )
	&& false !== strpos( $admin_js, 'reset_keys_failed', $reset_ui_pos )
	&& false !== strpos( $admin_js, '.fail( function()', $reset_ui_pos )
	&& false !== strpos( $admin_js, '.always( function()', $reset_ui_pos ),
	'The KeyLockr site-key reset browser flow lacks confirmation, busy, success, or failure handling.'
);

$gui_source = file_get_contents( dirname( __DIR__ ) . '/src/gui.cls.php' );
dologin_test_assert(
	false !== strpos( $gui_source, "\$is_profile_page = 'profile.php' === \$hook;" )
	&& false !== strpos( $gui_source, 'KLSso::enabled() || KLSso::force_enabled()' )
	&& false === strpos( $gui_source, "array( 'profile.php', 'user-edit.php' )" )
	&& false !== strpos( $gui_source, 'ip_lookup_progress' )
	&& false !== strpos( $gui_source, 'ip_lookup_failed' )
	&& false === strpos( $gui_source, 'KL_PAIRING_TIMEOUT_SECONDS' )
	&& false === strpos( $gui_source, "'timeout'" ),
	'Admin script loading still includes the dead user-edit path or omits localized browser configuration.'
);

$admin          = ( new ReflectionClass( \dologin\Admin::class ) )->newInstanceWithoutConstructor();
$contactmethods = $admin->user_contactmethods( array( '2fa' => 'secret' ) );
$user_columns   = $admin->manage_users_columns( array() );
dologin_test_assert(
	! isset( $contactmethods['2fa'], $contactmethods['phone_number'], $user_columns['phone_number'] )
	&& isset( $user_columns['dologin_operations'] ),
	'Removed DoLogin phone fields still appear in profile or user-list output.'
);

$GLOBALS['dologin_test_user_id'] = 0;
\dologin\Conf::$values = array();
