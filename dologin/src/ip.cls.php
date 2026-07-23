<?php

/**
 * IP class
 *
 * @since 1.0
 */

namespace dologin;

defined( 'WPINC' ) || exit;

class IP extends Instance {

	private $_visitor_geo_data = array();

	public static $PREFIX_SET = array(
		'continent',
		'continent_code',
		'country',
		'country_code',
		'subdivision',
		'subdivision_code',
		'city',
		'postal',
	);

	/**
	 * Get visitor's IP
	 *
	 * @since  1.0
	 * @access public
	 */
	public static function me() {
		$_ip = '';

		if ( ! $_ip ) {
			$_ip = ! empty( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : false;
		}

		if ( strpos( $_ip, ',' ) ) {
			$_ip = explode( ',', $_ip );
			$_ip = trim( $_ip[0] );
		}

		return preg_replace( '/^(\d+\.\d+\.\d+\.\d+):\d+$/', '\1', $_ip );
	}

	/**
	 * Get geolocation info of visitor IP
	 *
	 * @since 1.0
	 * @access public
	 */
	public static function geo( $ip = false ) {
		if ( ! $ip ) {
			$ip = self::me();
		}
		$ip = trim( (string) $ip );
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return array( 'ip' => $ip );
		}

		$cache_key = 'dologin_geo_' . md5( $ip );
		$cached    = get_transient( $cache_key );
		if ( is_array( $cached ) ) {
			return $cached;
		}

		$response = wp_safe_remote_get(
			'https://www.doapi.us/ip/' . rawurlencode( $ip ) . '/json',
			array(
				'timeout'             => 3,
				'redirection'         => 0,
				'limit_response_size' => 32768,
				'sslverify'           => true,
			)
		);

		$data = array();
		if ( ! is_wp_error( $response ) && 200 === (int) wp_remote_retrieve_response_code( $response ) ) {
			$decoded = json_decode( wp_remote_retrieve_body( $response ), true );
			if ( is_array( $decoded ) ) {
				$data = $decoded;
			}
		}

		// Build geo data
		$geo_list = array( 'ip' => $ip );
		foreach ( self::$PREFIX_SET as $tag ) {
			$geo_list[ $tag ] = isset( $data[ $tag ] ) && is_scalar( $data[ $tag ] ) ? sanitize_text_field( trim( (string) $data[ $tag ] ) ) : false;
		}
		set_transient( $cache_key, $geo_list, $data ? HOUR_IN_SECONDS : 5 * MINUTE_IN_SECONDS );

		return $geo_list;
	}

	/**
	 * Match an IP address against an exact or segmented wildcard rule.
	 *
	 * @since 4.6.5
	 */
	public static function matches_ip_rule( $visitor, $rule ) {
		$visitor = strtolower( trim( (string) $visitor ) );
		$rule    = strtolower( trim( (string) $rule ) );
		if ( ! filter_var( $visitor, FILTER_VALIDATE_IP ) || '' === $rule ) {
			return false;
		}
		if ( false === strpos( $rule, '*' ) ) {
			$rule_bytes = filter_var( $rule, FILTER_VALIDATE_IP ) ? inet_pton( $rule ) : false;
			return false !== $rule_bytes && inet_pton( $visitor ) === $rule_bytes;
		}

		$is_v4       = (bool) filter_var( $visitor, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
		$separator   = $is_v4 ? '.' : ':';
		$replacement = str_replace( '*', '0', $rule );
		$flag        = $is_v4 ? FILTER_FLAG_IPV4 : FILTER_FLAG_IPV6;
		if ( ! filter_var( $replacement, FILTER_VALIDATE_IP, $flag ) ) {
			return false;
		}

		if ( ! $is_v4 ) {
			$unpacked     = unpack( 'n8', inet_pton( $visitor ) );
			$visitor_parts = array_map( 'dechex', array_values( $unpacked ) );
			$rule_parts    = self::expand_ipv6_rule( $rule );
			if ( false === $rule_parts ) {
				return false;
			}
		} else {
			$visitor_parts = explode( $separator, $visitor );
			$rule_parts    = explode( $separator, $rule );
		}
		if ( count( $visitor_parts ) !== count( $rule_parts ) ) {
			return false;
		}

		foreach ( $visitor_parts as $index => $part ) {
			if ( '*' === $rule_parts[ $index ] ) {
				continue;
			}
			if ( $is_v4 ) {
				if ( (int) $part !== (int) $rule_parts[ $index ] ) {
					return false;
				}
			} elseif ( ltrim( $part, '0' ) !== ltrim( $rule_parts[ $index ], '0' ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Expand a validated IPv6 wildcard rule to eight segments.
	 */
	private static function expand_ipv6_rule( $rule ) {
		if ( substr_count( $rule, '::' ) > 1 ) {
			return false;
		}
		if ( false !== strpos( $rule, '::' ) ) {
			$halves = explode( '::', $rule, 2 );
			$left   = '' === $halves[0] ? array() : explode( ':', $halves[0] );
			$right  = '' === $halves[1] ? array() : explode( ':', $halves[1] );
			$fill   = 8 - count( $left ) - count( $right );
			if ( $fill < 1 ) {
				return false;
			}
			$parts = array_merge( $left, array_fill( 0, $fill, '0' ), $right );
		} else {
			$parts = explode( ':', $rule );
		}
		if ( 8 !== count( $parts ) ) {
			return false;
		}
		foreach ( $parts as $part ) {
			if ( '*' !== $part && ! preg_match( '/^[0-9a-f]{1,4}$/', $part ) ) {
				return false;
			}
		}
		return $parts;
	}

	/**
	 * Validate if hit the list
	 *
	 * @since  1.0
	 * @access public
	 */
	public function maybe_hit_rule( $list, $ip_only = false ) {
		if ( ! $this->_visitor_geo_data ) {
			$this->_visitor_geo_data = $ip_only ? array( 'ip' => self::me() ) : self::geo();
		}

		foreach ( $list as $v ) {
			// Drop comments
			if ( strpos( $v, '#' ) !== false ) {
				$v = trim( substr( $v, 0, strpos( $v, '#' ) ) );
			}

			if ( ! $v ) {
				continue;
			}

			$v = explode( ',', $v );

			// Go through each rule
			foreach ( $v as $v2 ) {
				$negative_match = false;

				$rule_prefix = false;
				if ( false !== strpos( $v2, ':' ) ) {
					$prefix_candidate = trim( substr( $v2, 0, strpos( $v2, ':' ) ) );
					$prefix_key       = rtrim( $prefix_candidate, '!' );
					$rule_prefix      = 'ip' === $prefix_key || in_array( $prefix_key, self::$PREFIX_SET, true );
				}

				if ( ! $rule_prefix ) { // Treat values without a known key prefix as IP addresses, including IPv6.
					$curr_k = 'ip';
				} else {
					list($curr_k, $v2) = explode( ':', $v2, 2 );
					$curr_k            = trim( $curr_k );
					if ( substr( $curr_k, -1 ) === '!' ) {
						$negative_match = true;
						$curr_k         = trim( substr( $curr_k, 0, -1 ) );
					}
				}

				$v2 = trim( $v2 );

				// Invalid rule
				if ( ! $v2 ) {
					continue 2;
				}

				// Rule set not match
				if ( empty( $this->_visitor_geo_data[ $curr_k ] ) ) {
					continue 2;
				}

				$v2        = strtolower( $v2 );
				$visitor_v = strtolower( $this->_visitor_geo_data[ $curr_k ] );
				$visitor_v = trim( $visitor_v );

				$matched = 'ip' === $curr_k ? self::matches_ip_rule( $visitor_v, $v2 ) : $visitor_v === $v2;

				if ( ! $negative_match && ! $matched ) {
					continue 2;
				}

				if ( $negative_match && $matched ) {
					continue 2;
				}
			}

			return true;
		}

		return false;
	}
}
