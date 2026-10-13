<?php
/**
 * Server-only geometry and bounded raster artwork; pixels are not proof of humanity.
 *
 * @package dologin
 */
namespace dologin;

defined( 'WPINC' ) || exit;

class Captcha_Image {

	const WIDTH = 280;
	const HEIGHT = 168;
	const RADIUS = 28;

	public static function available() {
		return function_exists( 'imagecreatetruecolor' ) && function_exists( 'imagepng' );
	}

	/** Cryptographic shuffling must not share the process-wide mt_rand state. */
	public static function shuffled( $items ) {
		for ( $i = count( $items ) - 1; $i > 0; $i-- ) {
			$j = random_int( 0, $i );
			$tmp = $items[ $i ]; $items[ $i ] = $items[ $j ]; $items[ $j ] = $tmp;
		}
		return $items;
	}

	/** Random placement has no fixed grid; private acceptance circles cannot overlap. */
	public static function layout() {
		// A partial packing can have no room left; restart the layout, with a fixed work bound.
		for ( $round = 0; $round < 16; $round++ ) {
			$layout = array();
			foreach ( self::shuffled( range( 1, 6 ) ) as $id ) {
				for ( $attempt = 0; $attempt < 100; $attempt++ ) {
					$x = random_int( 30, self::WIDTH - 30 ); $y = random_int( 30, self::HEIGHT - 30 );
					$clear = true;
					foreach ( $layout as $point ) {
						if ( pow( $x - $point['x'], 2 ) + pow( $y - $point['y'], 2 ) < 60 * 60 ) { $clear = false; break; }
					}
					if ( $clear ) { $layout[ $id ] = array( 'x' => $x, 'y' => $y ); break; }
				}
				if ( ! isset( $layout[ $id ] ) ) { break; }
			}
			if ( count( $layout ) === 6 ) { return $layout; }
		}
		throw new \Exception( 'local_captcha_unavailable' );
	}

	private static function canvas( $width, $height, $color ) {
		$image = imagecreatetruecolor( $width, $height );
		if ( false === $image ) { throw new \Exception( 'local_captcha_unavailable' ); }
		imagefill( $image, 0, 0, $color );
		return $image;
	}

	private static function polygon( $image, $points, $color ) {
		// The plugin also supports PHP versions before the optional point-count signature.
		if ( PHP_VERSION_ID >= 80100 ) { imagefilledpolygon( $image, $points, $color ); }
		else { imagefilledpolygon( $image, $points, count( $points ) / 2, $color ); }
	}

	/** PNG encodes pixels only: no SVG paths, transforms, hitboxes or answer metadata. */
	private static function png( $image ) {
		ob_start();
		try {
			if ( ! imagepng( $image ) ) { throw new \Exception( 'local_captcha_unavailable' ); }
			return 'data:image/png;base64,' . base64_encode( ob_get_contents() );
		} finally {
			ob_end_clean();
			if ( is_resource( $image ) ) { imagedestroy( $image ); }
		}
	}

	private static function shape( $image, $id, $x, $y, $color, $angle = 0, $skew = 0 ) {
		$points = array();
		if ( 1 === $id || 2 === $id ) {
			$count = 1 === $id ? 10 : 48;
			for ( $i = 0; $i < $count; $i++ ) {
				$t = 2 * M_PI * $i / $count;
				if ( 1 === $id ) {
					$r = $i % 2 ? 10 : 23;
					$points[] = $r * sin( $t ); $points[] = -$r * cos( $t );
				} else {
					$points[] = 1.3 * 16 * pow( sin( $t ), 3 );
					$points[] = -1.3 * ( 13 * cos( $t ) - 5 * cos( 2 * $t ) - 2 * cos( 3 * $t ) - cos( 4 * $t ) );
				}
			}
		} else {
			$shapes = array(
				3 => array( -18,18, -21,2, -15,-13, 0,-20, 19,-20, 21,-4, 12,12, -4,18 ),
				4 => array( -2,-22, -14,-17, -22,-5, -19,9, -8,20, 8,20, 18,12, 5,12, -5,4, -6,-8 ),
				5 => array( 4,-22, -17,3, -3,3, -8,23, 18,-5, 4,-5 ),
				6 => array( -22,-12, -12,-4, -5,-12, 8,-12, 22,0, 8,12, -5,12, -12,4, -22,12, -18,0 ),
			);
			$points = $shapes[ $id ];
		}
		$transformed = array(); $angle = deg2rad( $angle );
		for ( $i = 0; $i < count( $points ); $i += 2 ) {
			$px = $points[ $i ] + $skew * $points[ $i + 1 ]; $py = $points[ $i + 1 ];
			$transformed[] = (int) round( $x + $px * cos( $angle ) - $py * sin( $angle ) );
			$transformed[] = (int) round( $y + $px * sin( $angle ) + $py * cos( $angle ) );
		}
		self::polygon( $image, $transformed, $color );
	}

	public static function sequence( $layout, $targets ) {
		$image = self::canvas( self::WIDTH, self::HEIGHT, random_int( 0xe8, 0xf4 ) * 0x010101 );
		for ( $i = 0; $i < 22; $i++ ) {
			$color = imagecolorallocatealpha( $image, random_int( 70, 180 ), random_int( 70, 180 ), random_int( 70, 180 ), 95 );
			imagefilledellipse( $image, random_int( 0, 280 ), random_int( 0, 168 ), random_int( 15, 90 ), random_int( 10, 70 ), $color );
		}
		foreach ( $layout as $id => $point ) {
			$color = ( random_int( 40, 155 ) << 16 ) | ( random_int( 40, 155 ) << 8 ) | random_int( 40, 155 );
			self::shape( $image, $id, $point['x'], $point['y'], $color, random_int( -65, 65 ), random_int( -10, 10 ) / 100 );
		}
		for ( $i = 0; $i < 16; $i++ ) {
			$color = imagecolorallocatealpha( $image, random_int( 70, 180 ), random_int( 70, 180 ), random_int( 70, 180 ), 90 );
			imageline( $image, 0, random_int( 0, 168 ), 280, random_int( 0, 168 ), $color );
		}
		self::texture( $image );
		$view = array( 'picture' => self::png( $image ), 'targets' => array() );
		$names = array( 1 => __( 'Star', 'dologin' ), __( 'Heart', 'dologin' ), __( 'Leaf', 'dologin' ), __( 'Moon', 'dologin' ), __( 'Lightning', 'dologin' ), __( 'Fish', 'dologin' ) );
		foreach ( $targets as $id ) {
			$target = self::canvas( 56, 56, 0xf6f7f7 );
			self::shape( $target, $id, 28, 28, 0x173f42 );
			$view['targets'][] = array( 'image' => self::png( $target ), 'label' => $names[ $id ] );
		}
		return $view;
	}

	/** Bounded RGB grain removes exact palette segmentation, not machine vision. */
	private static function texture( $image ) {
		$width = imagesx( $image ); $height = imagesy( $image );
		$grain = random_bytes( $width * $height * 3 ); $offset = 0;
		for ( $y = 0; $y < $height; $y++ ) {
			for ( $x = 0; $x < $width; $x++ ) {
				$original = imagecolorat( $image, $x, $y ); $color = 0;
				foreach ( array( 16, 8, 0 ) as $shift ) {
					$value = ( ( $original >> $shift ) & 255 ) + ord( $grain[ $offset++ ] ) % 25 - 12;
					$color |= max( 0, min( 255, $value ) ) << $shift;
				}
				imagesetpixel( $image, $x, $y, $color );
			}
		}
	}

	/** Crop before painting the gap; neither PNG exposes the crop origin as metadata. */
	public static function puzzle( $x ) {
		$image = self::canvas( 280, 140, 0xdceef8 );
		imagefilledellipse( $image, 220, 30, 32, 32, 0xe8ac36 );
		self::polygon( $image, array( 0,120, 70,30, 150,130, 210,55, 280,120, 280,140, 0,140 ), 0x277f79 );
		self::polygon( $image, array( 0,130, 100,65, 180,140, 0,140 ), 0x15594e );
		$piece = self::canvas( 44, 44, 0xffffff );
		imagecopy( $piece, $image, 0, 0, $x, 60, 44, 44 );
		imagefilledrectangle( $image, $x, 60, $x + 43, 103, 0x172b4d );
		imagerectangle( $image, $x, 60, $x + 43, 103, 0xffffff );
		self::texture( $image );
		self::texture( $piece );
		return array( 'picture' => self::png( $image ), 'piece' => self::png( $piece ) );
	}
}
