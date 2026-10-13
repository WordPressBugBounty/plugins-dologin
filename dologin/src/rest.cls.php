<?php

/**
 * Rest class
 *
 * @since 1.0
 */

namespace dologin;

defined( 'WPINC' ) || exit;

class REST extends Instance {

	/**
	 * Init
	 *
	 * @since  1.0
	 * @access public
	 */
	public function init() {
		add_action( 'rest_api_init', array( $this, 'rest_api_init' ) );
	}

	/**
	 * Register REST hooks
	 *
	 * @since  1.0
	 * @access public
	 */
	public function rest_api_init() {
		foreach ( array( 'challenge', 'verify', 'demo_challenge', 'demo_verify' ) as $action ) {
			$is_demo = 0 === strpos( $action, 'demo_' );
			register_rest_route( 'dologin/v1', '/captcha/' . $action, array(
				'methods' => 'POST',
				'callback' => array( $this->cls( 'Captcha_Local' ), $action ),
				'permission_callback' => $is_demo ? array( $this, 'captcha_preview_allowed' ) : '__return_true',
			) );
		}
		register_rest_route( 'dologin/v1', '/captcha/demo_turnstile', array(
			'methods' => 'POST',
			'callback' => array( $this->cls( 'Captcha' ), 'demo_turnstile' ),
			'permission_callback' => array( $this, 'captcha_preview_allowed' ),
		) );
		register_rest_route(
			'dologin/v1',
			'/myip',
			array(
				'methods'             => 'GET',
				'callback'            => __CLASS__ . '::geoip',
				'permission_callback' => function () {
					return current_user_can( 'manage_network_options' ) || current_user_can( 'manage_options' );
				},
			)
		);

		register_rest_route(
			'dologin/v1',
			'/2fa',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'twofa' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			'dologin/v1',
			'/kl_sso/start',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this->cls( 'KLSso' ), 'start' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			'dologin/v1',
			'/kl_sso/frame',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this->cls( 'KLSso' ), 'frame' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			'dologin/v1',
			'/kl_sso/unbind',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this->cls( 'KLSso' ), 'unbind' ),
				'permission_callback' => 'is_user_logged_in',
			)
		);

		register_rest_route(
			'dologin/v1',
			'/kl_sso/reset_keys',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this->cls( 'KLSso' ), 'reset_site_keys' ),
				'permission_callback' => function () {
					return current_user_can( apply_filters( 'dologin_admin_menu_access', 'manage_options' ) );
				},
			)
		);
	}

	public function captcha_preview_allowed() {
		return current_user_can( apply_filters( 'dologin_admin_menu_access', 'manage_options' ) );
	}

	/**
	 * Get GeoIP info
	 */
	public static function geoip() {
		return IP::geo();
	}

	/**
	 * Check 2fa
	 */
	public function twofa() {
		return $this->cls( 'TwoFA' )->check();
	}

	/**
	 * Return content
	 */
	public static function ok( $data ) {
		$data['_res'] = 'ok';
		return $data;
	}

	/**
	 * Return error
	 */
	public static function err( $msg ) {
		defined( 'debug' ) && debug( '❌ [err] ' . $msg );
		return array(
			'_res' => 'err',
			'_msg' => $msg,
		);
	}
}
