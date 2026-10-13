<?php
/**
 * Local proof-of-work and interaction verification. The server owns every decision.
 *
 * @package dologin
 */
namespace dologin;

defined( 'WPINC' ) || exit;

class Captcha_Local extends Instance {

	const TTL = 300;
	const WORK_BITS = 16;
	const PUZZLE_WIDTH = 280;
	const PIECE_WIDTH = 44;
	const PUZZLE_TOLERANCE = 4;

	/** IPv6 /64 shares a quota; changing addresses or UA cannot cheaply multiply capacity. */
	private static function client() {
		$ip = (string) IP::me();
		$packed = inet_pton( $ip );
		if ( false !== $packed && 16 === strlen( $packed ) ) {
			// IPv4-mapped addresses belong to the same quota as their IPv4 form.
			$ip = substr( $packed, 0, 12 ) === str_repeat( "\0", 10 ) . "\xff\xff" ? inet_ntop( substr( $packed, 12 ) ) : bin2hex( substr( $packed, 0, 8 ) ) . '/64';
		}
		return hash_hmac( 'sha256', $ip, wp_salt( 'auth' ) );
	}

	private static function binding() {
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) && is_string( $_SERVER['HTTP_USER_AGENT'] ) ? substr( $_SERVER['HTTP_USER_AGENT'], 0, 512 ) : '';
		// Quota grouping never widens the ticket's exact IP and UA binding.
		return hash_hmac( 'sha256', (string) IP::me() . '|' . $ua, wp_salt( 'auth' ) );
	}

	public function challenge( $request ) {
		return $this->begin( $request, false );
	}

	public function demo_challenge( $request ) {
		return $this->begin( $request, true );
	}

	/** Public callers cannot choose a weaker provider or a preview context. */
	private function begin( $request, $demo ) {
		nocache_headers();
		try {
			$context = $demo ? 'demo' : $request->get_param( 'context' );
			if ( ! function_exists( 'random_bytes' ) || ! function_exists( 'random_int' ) ) {
				throw new \Exception( 'local_captcha_unavailable' );
			}
			$method = $demo ? $request->get_param( 'method' ) : Captcha::method();
			if ( ! in_array( $method, array( 'pow', 'sequence', 'puzzle' ), true ) || ( ! $demo && ! Captcha::enabled( $context ) ) ) {
				throw new \Exception( 'local_captcha_invalid' );
			}
			if ( $demo && ! current_user_can( apply_filters( 'dologin_admin_menu_access', 'manage_options' ) ) ) {
				throw new \Exception( 'local_captcha_invalid' );
			}
			if ( ! $demo && ( Auth::cls()->is_ip_denied() || Auth::cls()->is_rate_limited() ) ) {
				throw new \Exception( 'local_captcha_busy' );
			}
			if ( 'pow' !== $method && ! Captcha_Image::available() ) {
				throw new \Exception( 'local_captcha_image_unavailable' );
			}
			$id = bin2hex( random_bytes( 16 ) );
			$record = array(
				'client' => self::binding(), 'method' => $method, 'context' => $context,
				'expires' => time() + self::TTL, 'phase' => 'issued', 'answer' => '',
				'uid' => $demo ? get_current_user_id() : 0,
			);
			$view = array( 'id' => $id, 'method' => $method, 'prefix' => $id . ':', 'bits' => self::WORK_BITS, 'ttl' => self::TTL );
			if ( 'sequence' === $method ) {
				$layout = Captcha_Image::layout();
				$targets = array_slice( Captcha_Image::shuffled( range( 1, 6 ) ), 0, 3 );
				$record['answer'] = array();
				foreach ( $targets as $target ) {
					$record['answer'][] = $layout[ $target ];
				}
			} elseif ( 'puzzle' === $method ) {
				$record['answer'] = random_int( 80, self::PUZZLE_WIDTH - self::PIECE_WIDTH - 8 );
			}
			$client = self::client();
			Captcha_State::change( $client, function ( &$state ) use ( $client, $id, $record ) {
				return Captcha_State::reserve( $state, $client, $id, $record );
			} );
			// Enforce storage/IP quotas before allocating raster images. A render failure expires normally.
			if ( 'sequence' === $method ) { $view = array_merge( $view, Captcha_Image::sequence( $layout, $targets ) ); }
			elseif ( 'puzzle' === $method ) { $view = array_merge( $view, Captcha_Image::puzzle( $record['answer'] ) ); }
			return REST::ok( $view );
		} catch ( \Exception $ex ) {
			return $this->failure( $ex->getMessage() );
		}
	}

	public function verify( $request ) {
		return $this->finish( $request, false );
	}

	public function demo_verify( $request ) {
		return $this->finish( $request, true );
	}

	/** One attempt consumes the issued challenge, including an incorrect answer. */
	private function finish( $request, $demo ) {
		nocache_headers();
		try {
			if ( ! function_exists( 'random_bytes' ) ) {
				throw new \Exception( 'local_captcha_unavailable' );
			}
			$id = $request->get_param( 'id' );
			$nonce = $request->get_param( 'nonce' );
			$answer = $request->get_param( 'answer' );
			if ( ! is_string( $id ) || ! preg_match( '/^[a-f0-9]{32}$/D', $id ) || ! is_string( $nonce ) || ! preg_match( '/^[0-9]{1,10}$/D', $nonce ) || ! is_string( $answer ) || strlen( $answer ) > 32 ) {
				throw new \Exception( 'local_captcha_invalid' );
			}
			$binding = self::binding();
			$ticket = bin2hex( random_bytes( 24 ) );
			$result = Captcha_State::change( self::client(), function ( &$state ) use ( $id, $nonce, $answer, $binding, $ticket, $demo ) {
				if ( ! isset( $state['records'][ $id ] ) ) {
					return false;
				}
				$record = $state['records'][ $id ];
				if ( 'issued' !== $record['phase'] || ! hash_equals( $record['client'], $binding ) || ( 'demo' === $record['context'] ) !== $demo ) {
					return false;
				}
				if ( $demo && ( ! current_user_can( apply_filters( 'dologin_admin_menu_access', 'manage_options' ) ) || (int) $record['uid'] !== get_current_user_id() ) ) {
					return false;
				}
				unset( $state['records'][ $id ] );
				if ( ! $demo && ( ! Captcha::enabled( $record['context'] ) || Captcha::method() !== $record['method'] ) ) {
					return false;
				}
				// A 16-bit target requires 65,536 hashes on average but one server hash.
				$zero_digits = self::WORK_BITS / 4;
				if ( str_repeat( '0', $zero_digits ) !== substr( hash( 'sha256', $id . ':' . $nonce ), 0, $zero_digits ) ) {
					return false;
				}
				if ( 'sequence' === $record['method'] && ! self::sequence_answer( $record['answer'], $answer ) ) {
					return false;
				}
				if ( 'puzzle' === $record['method'] && ( ! preg_match( '/^[0-9]{1,3}$/D', $answer ) || abs( (int) $answer - $record['answer'] ) > self::PUZZLE_TOLERANCE ) ) {
					return false;
				}
				if ( ! $demo ) {
					$record['phase'] = 'verified';
					$record['ticket'] = Secret::token_hash( 'captcha-ticket', $ticket );
					unset( $record['answer'] );
					$state['records'][ $id ] = $record;
				}
				return true;
			} );
			if ( ! $result ) {
				throw new \Exception( 'local_captcha_invalid' );
			}
			return REST::ok( array( 'ticket' => $demo ? '' : $id . '.' . $ticket, 'message' => __( 'Passed: verified by this server.', 'dologin' ) ) );
		} catch ( \Exception $ex ) {
			return $this->failure( $ex->getMessage() );
		}
	}

	/** A preflight permits exactly one final submission with the same credentials. */
	public function authenticate( $context, $username = '', $password = '' ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- The server-issued one-time ticket authenticates this public request.
		$ticket = isset( $_POST['dologin-captcha-ticket'] ) ? $_POST['dologin-captcha-ticket'] : '';
		if ( ! is_string( $ticket ) || ! preg_match( '/^([a-f0-9]{32})\.([a-f0-9]{48})$/D', $ticket, $parts ) ) {
			throw new \Exception( 'local_captcha_missing' );
		}
		$id = $parts[1];
		$raw = $parts[2];
		$binding = self::binding();
		$preflight = 'login' === $context && TwoFA::is_dry_run();
		$credentials = Secret::token_hash( 'captcha-credentials', strlen( $username ) . ':' . $username . $password );
		$valid = Captcha_State::change( self::client(), function ( &$state ) use ( $id, $raw, $binding, $context, $preflight, $credentials ) {
			if ( ! isset( $state['records'][ $id ] ) ) {
				return false;
			}
			$record = $state['records'][ $id ];
			if ( $context !== $record['context'] || Captcha::method() !== $record['method'] || ! hash_equals( $record['client'], $binding ) || empty( $record['ticket'] ) || ! Secret::verify_token( 'captcha-ticket', $raw, $record['ticket'] ) ) {
				return false;
			}
			if ( 'verified' === $record['phase'] ) {
				if ( $preflight ) {
					$record['phase'] = 'preflight';
					$record['credentials'] = $credentials;
					$state['records'][ $id ] = $record;
				} else {
					unset( $state['records'][ $id ] );
				}
				return true;
			}
			if ( 'preflight' === $record['phase'] && ! $preflight && hash_equals( $record['credentials'], $credentials ) ) {
				unset( $state['records'][ $id ] );
				return true;
			}
			return false;
		} );
		if ( ! $valid ) {
			throw new \Exception( 'local_captcha_invalid' );
		}
	}

	private function failure( $code ) {
		$known = array( 'local_captcha_invalid', 'local_captcha_busy', 'local_captcha_unavailable', 'local_captcha_image_unavailable' );
		return REST::err( Lang::text( in_array( $code, $known, true ) ? $code : 'local_captcha_unavailable' ) );
	}

	/** Coordinates are checked only here; no per-click correctness oracle is exposed. */
	private static function sequence_answer( $expected, $answer ) {
		if ( ! is_array( $expected ) || count( $expected ) !== 3 || ! preg_match( '/^[0-9]{1,3},[0-9]{1,3};[0-9]{1,3},[0-9]{1,3};[0-9]{1,3},[0-9]{1,3}$/D', $answer ) ) {
			return false;
		}
		foreach ( explode( ';', $answer ) as $index => $point ) {
			list( $x, $y ) = array_map( 'intval', explode( ',', $point ) );
			if ( $x >= Captcha_Image::WIDTH || $y >= Captcha_Image::HEIGHT || pow( $x - $expected[ $index ]['x'], 2 ) + pow( $y - $expected[ $index ]['y'], 2 ) > pow( Captcha_Image::RADIUS, 2 ) ) {
				return false;
			}
		}
		return true;
	}
}
