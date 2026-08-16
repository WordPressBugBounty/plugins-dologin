<?php
/**
 * Utility class
 *
 * @since 1.1
 */
namespace dologin;

defined( 'WPINC' ) || exit;

class Util extends Instance {
	/**
	 * Init Utility
	 *
	 * @since 1.1
	 * @access public
	 */
	public function init() {
	}

	/**
	 * Builds an url with an action and a nonce.
	 *
	 * @since  1.4
	 * @access public
	 */
	public static function build_url( $action, $type = false, $is_ajax = false, $page = null, $append_arr = null ) {
		$prefix = '?';

		if ( ! $is_ajax ) {
			if ( $page ) {
				// If use admin url
				if ( $page === true ) {
					$page = 'admin.php';
				} elseif ( strpos( $page, '?' ) !== false ) {
						$prefix = '&';
				}
				$combined = $page . $prefix . Router::ACTION . '=' . $action;
			} else {
				// Current page rebuild URL
				$params = $_GET; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- rebuilding the current admin page URL only, no state change.

				if ( ! empty( $params ) ) {
					if ( isset( $params['DOLOGIN_ACTION'] ) ) {
						unset( $params['DOLOGIN_ACTION'] );
					}
					if ( isset( $params['_wpnonce'] ) ) {
						unset( $params['_wpnonce'] );
					}
					if ( ! empty( $params ) ) {
						$prefix .= http_build_query( $params ) . '&';
					}
				}
				global $pagenow;
				$combined = $pagenow . $prefix . Router::ACTION . '=' . $action;
			}
		} else {
			$combined = 'admin-ajax.php?action=dologin_ajax&' . Router::ACTION . '=' . $action;
		}

		if ( is_network_admin() ) {
			$prenonce = network_admin_url( $combined );
		} else {
			$prenonce = admin_url( $combined );
		}
		$url = wp_nonce_url( $prenonce, $action, Router::NONCE );

		if ( $type ) {
			// Remove potential param `type` from url
			$url = wp_parse_url( htmlspecialchars_decode( $url ) );
			parse_str( $url['query'], $query );

			$built_arr = array_merge( $query, array( Router::TYPE => $type ) );
			if ( $append_arr ) {
				$built_arr = array_merge( $built_arr, $append_arr );
			}
			$url['query'] = http_build_query( $built_arr );
			self::compatibility();
			$url = http_build_url( $url );
		}

		return $url;
	}

	/**
	 * Improve compatibility to PHP old versions
	 *
	 * @since  1.2.2
	 */
	public static function compatibility() {
		require_once DOLOGIN_DIR . 'lib/php-compatibility.func.php';
	}

	/**
	 * Check if is login page or not
	 *
	 * @since  1.3
	 * @access public
	 */
	public static function is_login_page() {
		$is_login_page = in_array( $GLOBALS['pagenow'], array( 'wp-login.php', 'wp-register.php' ), true );

		return apply_filters( 'dologin_is_login_page', $is_login_page );
	}

	/**
	 * Version check
	 *
	 * @since 1.1
	 * @access public
	 */
	public static function version_check( $tag ) {
		return false;
	}

	/**
	 * Set seconds/timestamp to readable format
	 *
	 * @since  1.2
	 * @access public
	 */
	public static function readable_time( $seconds_or_timestamp, $timeout = 3600, $backward = true ) {
		if ( strlen( $seconds_or_timestamp ) == 10 ) {
			$seconds = time() - $seconds_or_timestamp;
			if ( $seconds > $timeout ) {
				return date_i18n( 'm/d/Y H:i:s', $seconds_or_timestamp + get_option( 'gmt_offset' ) * 60 * 60 );
			}
		} else {
			$seconds = $seconds_or_timestamp;
		}
		$res = '';
		if ( $seconds > 86400 ) {
			$num      = floor( $seconds / 86400 );
			$res     .= $num . 'd';
			$seconds %= 86400;
		}
		if ( $seconds > 3600 ) {
			if ( $res ) {
				$res .= ', ';
			}
			$num      = floor( $seconds / 3600 );
			$res     .= $num . 'h';
			$seconds %= 3600;
		}
		if ( $seconds > 60 ) {
			if ( $res ) {
				$res .= ', ';
			}
			$num      = floor( $seconds / 60 );
			$res     .= $num . 'm';
			$seconds %= 60;
		}
		if ( $seconds > 0 ) {
			if ( $res ) {
				$res .= ' ';
			}
			$res .= $seconds . 's';
		}
		if ( ! $res ) {
			return $backward ? __( 'just now', 'dologin' ) : __( 'right now', 'dologin' );
		}
		/* translators: %s: human-readable elapsed time such as "5m" or "2h". */
		$res = $backward ? sprintf( __( ' %s ago', 'dologin' ), $res ) : $res;
		return $res;
	}

	/**
	 * Generate pagination
	 *
	 * @since 2.7
	 * @access public
	 */
	public static function pagination( $total, $limit, $return_offset = false ) {
		$pagenum      = isset( $_GET['pagenum'] ) ? max( 1, absint( $_GET['pagenum'] ) ) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- reading pagination index only, no state change.
		$total        = max( 0, absint( $total ) );
		$limit        = max( 1, absint( $limit ) );
		$num_of_pages = (int) ceil( $total / $limit );
		$pagenum      = min( $pagenum, max( 1, $num_of_pages ) );
		$offset       = ( $pagenum - 1 ) * $limit;

		if ( $return_offset ) {
			return $offset;
		}

		$page_links = paginate_links(
			array(
				'base'      => add_query_arg( 'pagenum', '%#%' ),
				'format'    => '',
				'prev_text' => __( '&laquo;', 'dologin' ),
				'next_text' => __( '&raquo;', 'dologin' ),
				'total'     => $num_of_pages,
				'current'   => $pagenum,
			)
		);

		return '<div class="tablenav"><div class="tablenav-pages" style="margin: 1em 0">' . $page_links . '</div></div>';
	}

	/**
	 * Deactivate
	 *
	 * @since  1.1
	 * @access public
	 */
	public static function deactivate() {
		delete_transient( 'dologin_activation_redirect' );

		self::version_check( 'deactivate' );
	}

	/**
	 * Uninstall clearance
	 *
	 * @since  1.1
	 * @access public
	 */
	public static function uninstall() {
		self::version_check( 'uninstall' );

		if ( is_multisite() ) {
			self::run_for_sites( 'delete_data' );
		} else {
			self::delete_site_data();
		}
		self::delete_user_data();
	}

	/**
	 * Delete plugin tables and options from the current site.
	 */
	private static function delete_site_data() {
		global $wpdb;

		Data::cls()->tables_del();
		$q = "SELECT option_name FROM `$wpdb->options` WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s";
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery -- $wpdb->options is the current site's internal options table; prefixes are prepared and delete_option() clears caches.
		$option_names = $wpdb->get_col(
			$wpdb->prepare(
				$q,
				$wpdb->esc_like( 'dologin.' ) . '%',
				$wpdb->esc_like( 'dologin_kl_' ) . '%',
				$wpdb->esc_like( '_transient_dologin_' ) . '%',
				$wpdb->esc_like( '_transient_timeout_dologin_' ) . '%'
			)
		);
		foreach ( (array) $option_names as $option_name ) {
			delete_option( (string) $option_name );
		}
	}

	/**
	 * Delete plugin user metadata shared by the WordPress installation.
	 */
	private static function delete_user_data() {
		global $wpdb;

		$q = "SELECT DISTINCT meta_key FROM `$wpdb->usermeta` WHERE meta_key = %s OR meta_key LIKE %s";
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery -- $wpdb->usermeta is the internal usermeta table; keys are prepared and delete_metadata() clears caches.
		$meta_keys = $wpdb->get_col(
			$wpdb->prepare(
				$q,
				'2fa',
				$wpdb->esc_like( 'dologin_kl_' ) . '%'
			)
		);
		foreach ( (array) $meta_keys as $meta_key ) {
			delete_metadata( 'user', 0, (string) $meta_key, '', true );
		}
	}

	/**
	 * Activation redirect
	 *
	 * @since  1.2.2
	 * @access public
	 */
	public static function activate( $network_wide = false ) {
		if ( ! defined( 'SILENCE_INSTALL' ) ) {
			set_transient( 'dologin_activation_redirect', true, 30 );
		}

		if ( is_multisite() && $network_wide ) {
			self::run_for_sites( 'create_tables' );
			return;
		}
		Data::cls()->tables_create();
	}

	/**
	 * Provision plugin tables for a newly created site during network activation.
	 *
	 * @since 4.6.5
	 */
	public static function new_site( $site ) {
		if ( ! is_multisite() || ! self::is_network_active() ) {
			return;
		}
		$site_id = is_object( $site ) && isset( $site->blog_id ) ? (int) $site->blog_id : (int) $site;
		if ( $site_id > 0 ) {
			self::run_for_site( $site_id, 'create_tables' );
		}
	}

	/**
	 * Run plugin data lifecycle operations on every site in a multisite network.
	 */
	private static function run_for_sites( $operation ) {
		$site_ids = array();
		if ( function_exists( 'get_sites' ) ) {
			$site_ids = get_sites(
				array(
					'fields' => 'ids',
					'number' => 0,
				)
			);
		} elseif ( function_exists( 'wp_get_sites' ) ) {
			$legacy_sites = wp_get_sites( array( 'limit' => 0 ) );
			foreach ( $legacy_sites as $legacy_site ) {
				if ( isset( $legacy_site['blog_id'] ) ) {
					$site_ids[] = (int) $legacy_site['blog_id'];
				}
			}
		}

		foreach ( $site_ids as $site_id ) {
			self::run_for_site( (int) $site_id, $operation );
		}
	}

	/**
	 * Safely switch site context and run a plugin data lifecycle operation.
	 */
	private static function run_for_site( $site_id, $operation ) {
		$switched = is_multisite() && (int) get_current_blog_id() !== (int) $site_id;
		if ( $switched ) {
			switch_to_blog( $site_id );
		}
		if ( 'delete_data' === $operation ) {
			self::delete_site_data();
		} elseif ( 'delete_tables' === $operation ) {
			Data::cls()->tables_del();
		} else {
			Data::cls()->tables_create();
		}
		if ( $switched ) {
			restore_current_blog();
		}
	}

	/**
	 * Check network activation without assuming admin helper functions are loaded.
	 */
	private static function is_network_active() {
		if ( ! function_exists( 'is_plugin_active_for_network' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		return is_plugin_active_for_network( plugin_basename( DOLOGIN_DIR . 'dologin.php' ) );
	}
}
