<?php
/**
 * Bounded MessagePack codec for KeyLockr SSO.
 *
 * @since 4.6.5
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

class KLSso_MsgPack_Bin {
	public $bytes;

	public function __construct( $bytes ) {
		$this->bytes = (string) $bytes;
	}
}

class KLSso_MsgPack {
	const MAX_INPUT_BYTES = 262144;
	const MAX_ITEMS       = 4096;
	const MAX_DEPTH       = 32;

	public static function bin( $bytes ) {
		return new KLSso_MsgPack_Bin( $bytes );
	}

	public static function pack( $value ) {
		if ( $value instanceof KLSso_MsgPack_Bin ) {
			return self::pack_bin( $value->bytes );
		}
		if ( is_null( $value ) ) {
			return "\xc0";
		}
		if ( is_bool( $value ) ) {
			return $value ? "\xc3" : "\xc2";
		}
		if ( is_int( $value ) ) {
			return self::pack_int( $value );
		}
		if ( is_float( $value ) ) {
			return "\xcb" . self::pack_float_be( $value, 'd' );
		}
		if ( is_string( $value ) ) {
			return self::pack_str( $value );
		}
		if ( is_array( $value ) ) {
			return self::is_list( $value ) ? self::pack_array( $value ) : self::pack_map( $value );
		}
		return self::pack_str( (string) $value );
	}

	public static function unpack( $bytes ) {
		$bytes = (string) $bytes;
		if ( '' === $bytes ) {
			throw new \Exception( 'Empty msgpack input' );
		}
		if ( strlen( $bytes ) > self::MAX_INPUT_BYTES ) {
			throw new \Exception( 'Msgpack input exceeds size limit' );
		}
		$offset = 0;
		$items  = 0;
		$value  = self::read( $bytes, $offset, 0, $items );
		if ( $offset !== strlen( $bytes ) ) {
			throw new \Exception( 'Trailing msgpack data' );
		}
		return $value;
	}

	private static function pack_int( $num ) {
		if ( $num >= 0 ) {
			if ( $num < 0x80 ) {
				return chr( $num );
			}
			if ( $num <= 0xff ) {
				return "\xcc" . pack( 'C', $num );
			}
			if ( $num <= 0xffff ) {
				return "\xcd" . pack( 'n', $num );
			}
			if ( $num <= 0xffffffff ) {
				return "\xce" . pack( 'N', $num );
			}
		} elseif ( $num >= -32 ) {
			return chr( 0xe0 | ( $num + 32 ) );
		} elseif ( $num >= -128 ) {
			return "\xd0" . pack( 'c', $num );
		} elseif ( $num >= -32768 ) {
			return "\xd1" . pack( 'n', $num & 0xffff );
		} elseif ( $num >= -2147483648 ) {
			return "\xd2" . pack( 'N', $num & 0xffffffff );
		}

		$hi = (int) floor( $num / 4294967296 );
		$lo = (int) ( $num & 0xffffffff );
		return ( $num >= 0 ? "\xcf" : "\xd3" ) . pack( 'NN', $hi, $lo );
	}

	private static function pack_str( $str ) {
		$len = strlen( $str );
		if ( $len < 32 ) {
			return chr( 0xa0 | $len ) . $str;
		}
		if ( $len <= 0xff ) {
			return "\xd9" . pack( 'C', $len ) . $str;
		}
		if ( $len <= 0xffff ) {
			return "\xda" . pack( 'n', $len ) . $str;
		}
		return "\xdb" . pack( 'N', $len ) . $str;
	}

	private static function pack_bin( $str ) {
		$len = strlen( $str );
		if ( $len <= 0xff ) {
			return "\xc4" . pack( 'C', $len ) . $str;
		}
		if ( $len <= 0xffff ) {
			return "\xc5" . pack( 'n', $len ) . $str;
		}
		return "\xc6" . pack( 'N', $len ) . $str;
	}

	private static function pack_array( $array ) {
		$len = count( $array );
		$out = $len < 16 ? chr( 0x90 | $len ) : ( $len <= 0xffff ? "\xdc" . pack( 'n', $len ) : "\xdd" . pack( 'N', $len ) );
		foreach ( $array as $item ) {
			$out .= self::pack( $item );
		}
		return $out;
	}

	private static function pack_map( $map ) {
		ksort( $map, SORT_STRING );
		$len = count( $map );
		$out = $len < 16 ? chr( 0x80 | $len ) : ( $len <= 0xffff ? "\xde" . pack( 'n', $len ) : "\xdf" . pack( 'N', $len ) );
		foreach ( $map as $key => $val ) {
			$out .= self::pack_str( (string) $key ) . self::pack( $val );
		}
		return $out;
	}

	private static function read( $bytes, &$offset, $depth, &$items ) {
		if ( $depth > self::MAX_DEPTH ) {
			throw new \Exception( 'Msgpack nesting limit exceeded' );
		}
		if ( $offset >= strlen( $bytes ) ) {
			throw new \Exception( 'Truncated msgpack input' );
		}
		$items++;
		if ( $items > self::MAX_ITEMS ) {
			throw new \Exception( 'Msgpack item limit exceeded' );
		}
		$prefix = ord( $bytes[ $offset++ ] );
		if ( $prefix <= 0x7f ) {
			return $prefix;
		}
		if ( $prefix >= 0xe0 ) {
			return $prefix - 0x100;
		}
		if ( ( $prefix & 0xe0 ) === 0xa0 ) {
			return self::read_bytes( $bytes, $offset, $prefix & 0x1f );
		}
		if ( ( $prefix & 0xf0 ) === 0x90 ) {
			return self::read_array( $bytes, $offset, $prefix & 0x0f, $depth, $items );
		}
		if ( ( $prefix & 0xf0 ) === 0x80 ) {
			return self::read_map( $bytes, $offset, $prefix & 0x0f, $depth, $items );
		}

		switch ( $prefix ) {
			case 0xc0:
				return null;
			case 0xc2:
				return false;
			case 0xc3:
				return true;
			case 0xc4:
				return new KLSso_MsgPack_Bin( self::read_bytes( $bytes, $offset, self::read_uint( $bytes, $offset, 1 ) ) );
			case 0xc5:
				return new KLSso_MsgPack_Bin( self::read_bytes( $bytes, $offset, self::read_uint( $bytes, $offset, 2 ) ) );
			case 0xc6:
				return new KLSso_MsgPack_Bin( self::read_bytes( $bytes, $offset, self::read_uint( $bytes, $offset, 4 ) ) );
			case 0xca:
				return self::unpack_float_be( self::read_bytes( $bytes, $offset, 4 ), 'f' );
			case 0xcb:
				return self::unpack_float_be( self::read_bytes( $bytes, $offset, 8 ), 'd' );
			case 0xcc:
				return self::read_uint( $bytes, $offset, 1 );
			case 0xcd:
				return self::read_uint( $bytes, $offset, 2 );
			case 0xce:
				return self::read_uint( $bytes, $offset, 4 );
			case 0xcf:
				return self::read_uint64( $bytes, $offset );
			case 0xd0:
				$val = unpack( 'c', self::read_bytes( $bytes, $offset, 1 ) );
				return $val[1];
			case 0xd1:
				$val = self::read_uint( $bytes, $offset, 2 );
				return $val & 0x8000 ? $val - 0x10000 : $val;
			case 0xd2:
				$val = self::read_uint( $bytes, $offset, 4 );
				return $val & 0x80000000 ? $val - 0x100000000 : $val;
			case 0xd3:
				return self::read_int64( $bytes, $offset );
			case 0xd9:
				return self::read_bytes( $bytes, $offset, self::read_uint( $bytes, $offset, 1 ) );
			case 0xda:
				return self::read_bytes( $bytes, $offset, self::read_uint( $bytes, $offset, 2 ) );
			case 0xdb:
				return self::read_bytes( $bytes, $offset, self::read_uint( $bytes, $offset, 4 ) );
			case 0xdc:
				return self::read_array( $bytes, $offset, self::read_uint( $bytes, $offset, 2 ), $depth, $items );
			case 0xdd:
				return self::read_array( $bytes, $offset, self::read_uint( $bytes, $offset, 4 ), $depth, $items );
			case 0xde:
				return self::read_map( $bytes, $offset, self::read_uint( $bytes, $offset, 2 ), $depth, $items );
			case 0xdf:
				return self::read_map( $bytes, $offset, self::read_uint( $bytes, $offset, 4 ), $depth, $items );
		}

		throw new \Exception( 'Unsupported msgpack type: ' . dechex( $prefix ) );
	}

	private static function read_bytes( $bytes, &$offset, $len ) {
		$len = (int) $len;
		if ( $len < 0 || $offset < 0 || $len > strlen( $bytes ) - $offset ) {
			throw new \Exception( 'Truncated msgpack input' );
		}
		$out     = substr( $bytes, $offset, $len );
		$offset += $len;
		return $out;
	}

	private static function read_uint( $bytes, &$offset, $len ) {
		$data = self::read_bytes( $bytes, $offset, $len );
		if ( 1 === $len ) {
			$val = unpack( 'C', $data );
		} elseif ( 2 === $len ) {
			$val = unpack( 'n', $data );
		} else {
			$val = unpack( 'N', $data );
		}
		return $val[1];
	}

	private static function read_uint64( $bytes, &$offset ) {
		$parts = unpack( 'Nhi/Nlo', self::read_bytes( $bytes, $offset, 8 ) );
		return $parts['hi'] * 4294967296 + $parts['lo'];
	}

	private static function read_int64( $bytes, &$offset ) {
		$parts = unpack( 'Nhi/Nlo', self::read_bytes( $bytes, $offset, 8 ) );
		if ( $parts['hi'] & 0x80000000 ) {
			$hi = ( ~ $parts['hi'] ) & 0xffffffff;
			$lo = ( ~ $parts['lo'] ) & 0xffffffff;
			return -1 * ( $hi * 4294967296 + $lo + 1 );
		}
		return $parts['hi'] * 4294967296 + $parts['lo'];
	}

	private static function read_array( $bytes, &$offset, $len, $depth, &$items ) {
		$len = (int) $len;
		if ( $len < 0 || $len > self::MAX_ITEMS - $items || $len > strlen( $bytes ) - $offset ) {
			throw new \Exception( 'Invalid msgpack array length' );
		}
		$out = array();
		for ( $i = 0; $i < $len; $i++ ) {
			$out[] = self::read( $bytes, $offset, $depth + 1, $items );
		}
		return $out;
	}

	private static function read_map( $bytes, &$offset, $len, $depth, &$items ) {
		$len = (int) $len;
		if ( $len < 0 || $len > (int) floor( ( self::MAX_ITEMS - $items ) / 2 ) || $len > (int) floor( ( strlen( $bytes ) - $offset ) / 2 ) ) {
			throw new \Exception( 'Invalid msgpack map length' );
		}
		$out = array();
		for ( $i = 0; $i < $len; $i++ ) {
			$key = self::read( $bytes, $offset, $depth + 1, $items );
			if ( ! is_int( $key ) && ! is_string( $key ) ) {
				throw new \Exception( 'Invalid msgpack map key' );
			}
			$out[ $key ] = self::read( $bytes, $offset, $depth + 1, $items );
		}
		return $out;
	}

	/**
	 * Encode native floats in network byte order without PHP 7-only pack codes.
	 */
	private static function pack_float_be( $value, $format ) {
		$bytes = pack( $format, $value );
		return self::is_little_endian() ? strrev( $bytes ) : $bytes;
	}

	/**
	 * Decode network-byte-order floats with PHP 5.6-compatible pack codes.
	 */
	private static function unpack_float_be( $bytes, $format ) {
		if ( self::is_little_endian() ) {
			$bytes = strrev( $bytes );
		}
		$value = unpack( $format, $bytes );
		if ( false === $value || ! isset( $value[1] ) ) {
			throw new \Exception( 'Invalid msgpack float' );
		}
		return $value[1];
	}

	private static function is_little_endian() {
		static $little = null;
		if ( null === $little ) {
			$little = "\x01\x00" === pack( 'S', 1 );
		}
		return $little;
	}

	private static function is_list( $array ) {
		if ( empty( $array ) ) {
			return false;
		}
		return array_keys( $array ) === range( 0, count( $array ) - 1 );
	}
}
