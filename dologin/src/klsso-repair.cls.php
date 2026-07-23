<?php
/**
 * KeyLockr SSO AppData repair flow.
 *
 * @since 4.7.2
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

trait KLSso_Repair {
	/**
	 * Check whether the session may write AppData.
	 */
	private function appdata_write_mode( $state ) {
		return is_array( $state )
			&& isset( $state['mode'] )
			&& in_array( $state['mode'], array( 'bind', 'repair' ), true );
	}

	/**
	 * Build an actionable error for missing or stale DoLogin AppData binding data.
	 */
	private function repair_required_error( $hash_mismatch = false ) {
		$message = $hash_mismatch
			? __( 'KeyLockr returned App Data for the Safe linked to this WordPress account, but its DoLogin binding hash does not match the locally stored hash. The App Data may be stale, replaced, or left from an older connection. Use Repair Connection and scan the same linked Safe again. DoLogin will rewrite the account binding hash and read it back before restoring the connection.', 'dologin' )
			: __( 'KeyLockr allowed App Data access, but the current App Tag and site connection do not contain the DoLogin binding hash. Allowing data access only grants permission; it does not create the WordPress link or write this hash. This can happen after changing the App Tag, resetting the site connection keys, migrating an older connection, or removing KeyLockr App Data. Use Repair Connection and scan the Safe already linked to this WordPress account. DoLogin will write the account binding hash and read it back before restoring the connection.', 'dologin' );
		return new \Exception(
			$message,
			self::REPAIR_REQUIRED_CODE
		);
	}

	/**
	 * Confirm that a repair scan still belongs to the Safe linked to this WordPress user.
	 */
	private function validate_repair_state( $state ) {
		$uid     = $this->validate_bind_state( $state );
		$safe_id = trim( (string) get_user_meta( $uid, self::META_SAFE_ID, true ) );
		if ( ! $safe_id || empty( $state['safe_id'] ) || ! hash_equals( $safe_id, (string) $state['safe_id'] ) ) {
			throw new \Exception( __( 'Repair Connection must use the KeyLockr Safe already linked to this WordPress account.', 'dologin' ) );
		}
		return $uid;
	}

	/**
	 * Complete a repair session after AppData write and read-back verification.
	 */
	private function complete_repair_session( &$state ) {
		$uid = $this->validate_repair_state( $state );

		update_user_meta( $uid, self::META_NICKNAME, $state['nickname'] );
		update_user_meta( $uid, self::META_SITE_KEY_FP, $state['site_key_fingerprint'] );
		update_user_meta( $uid, self::META_APP_TAG, $state['app_tag'] );

		return array(
			'status'        => 'done',
			'_delete_state' => true,
			'message'       => __( 'KeyLockr SSO connection repaired successfully.', 'dologin' ),
		);
	}
}
