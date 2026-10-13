<?php
/**
 * Bounded, atomic storage for local verification challenges.
 *
 * @package dologin
 */
namespace dologin;

defined( 'WPINC' ) || exit;

class Captcha_State {

	const PREFIX = 'dologin.captcha.state.';
	const MAX_RECORDS = 256;
	const MAX_CLIENTS = 256;
	const CLIENT_RECORDS = 5;
	const CAS_ATTEMPTS = 4;
	const REQUEST_LIMIT = 30;
	const REQUEST_WINDOW = 60;

	/**
	 * One of sixteen fixed shards owns each client. Expiry is pruned on access.
	 * The callback must have no external effects: a competing write reruns it.
	 * No unbounded per-request options or persistent object-cache reads are used.
	 */
	public static function change( $client, $callback ) {
		global $wpdb;
		$key = self::PREFIX . substr( hash( 'sha256', $client ), 0, 1 );
		for ( $attempt = 0; $attempt < self::CAS_ATTEMPTS; $attempt++ ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Internal table; prepared option name. Read the database for CAS coherence.
			$old = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM `$wpdb->options` WHERE option_name=%s", $key ) );
			if ( null === $old ) {
				add_option( $key, '{"records":{},"clients":{}}', '', false );
				continue;
			}
			$state = json_decode( $old, true );
			if ( ! is_array( $state ) || ! isset( $state['records'], $state['clients'] ) || ! is_array( $state['records'] ) || ! is_array( $state['clients'] ) ) {
				throw new \Exception( 'local_captcha_unavailable' );
			}
			foreach ( array( 'records', 'clients' ) as $group ) {
				foreach ( $state[ $group ] as $id => $item ) {
					if ( ! isset( $item['expires'] ) || $item['expires'] <= time() ) {
						unset( $state[ $group ][ $id ] );
					}
				}
			}
			$result = call_user_func_array( $callback, array( &$state ) );
			$new = wp_json_encode( $state );
			if ( ! is_string( $new ) ) {
				throw new \Exception( 'local_captcha_unavailable' );
			}
			if ( $new === $old ) {
				return $result;
			}
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Atomic compare-and-swap on a prepared, non-autoloaded option.
			$changed = $wpdb->query( $wpdb->prepare( "UPDATE `$wpdb->options` SET option_value=%s WHERE option_name=%s AND option_value=%s", $new, $key, $old ) );
			wp_cache_delete( $key, 'options' );
			if ( 1 === $changed ) {
				return $result;
			}
			if ( false === $changed ) {
				break;
			}
		}
		throw new \Exception( 'local_captcha_unavailable' );
	}

	/** Bound each quota owner; replace only its oldest unsolved record, never a ticket. */
	public static function reserve( &$state, $client, $id, $record ) {
		if ( ! isset( $state['clients'][ $client ] ) ) {
			if ( count( $state['clients'] ) >= self::MAX_CLIENTS ) {
				throw new \Exception( 'local_captcha_busy' );
			}
			$state['clients'][ $client ] = array( 'count' => 0, 'expires' => time() + self::REQUEST_WINDOW );
		}
		if ( $state['clients'][ $client ]['count'] >= self::REQUEST_LIMIT ) {
			throw new \Exception( 'local_captcha_busy' );
		}
		$count = 0; $oldest = null;
		foreach ( $state['records'] as $key => $item ) {
			if ( isset( $item['quota'] ) && $item['quota'] === $client ) {
				$count++;
				if ( 'issued' === $item['phase'] && ( null === $oldest || $item['expires'] < $state['records'][ $oldest ]['expires'] ) ) { $oldest = $key; }
			}
		}
		if ( $count >= self::CLIENT_RECORDS ) {
			if ( null === $oldest ) { throw new \Exception( 'local_captcha_busy' ); }
			unset( $state['records'][ $oldest ] );
		}
		if ( count( $state['records'] ) >= self::MAX_RECORDS ) { throw new \Exception( 'local_captcha_busy' ); }
		$state['clients'][ $client ]['count']++;
		$record['quota'] = $client;
		$state['records'][ $id ] = $record;
		return true;
	}
}
