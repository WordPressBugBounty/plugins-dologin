document.addEventListener( 'DOMContentLoaded', function() { jQuery( document ).ready( function( $ ) {
	var cfg = window.dologin_kl_sso || {};
	var ws = null;
	var state = '';
	var done = false;
	var runId = 0;
	var activeMode = '';
	var activeRelink = false;

	function closeSocket() {
		if ( ws ) {
			ws.onclose = null;
			ws.close();
			ws = null;
		}
	}

	function stopSession( $box, showRetry ) {
		done = true;
		closeSocket();
		$box.find( '.dologin-kl-qr' ).empty();
		$box.find( '.dologin-kl-refresh' ).prop( 'disabled', false );
		$box.find( '.dologin-kl-verify' ).prop( 'disabled', false );
		$box.find( '.dologin-kl-relink' ).prop( 'disabled', false );
		$box.find( '.dologin-kl-repair' ).prop( 'disabled', false );
		if ( showRetry && activeMode === 'bind' && ! activeRelink ) {
			$box.find( '.dologin-kl-refresh' ).text( cfg.i18n.new_qr ).prop( 'hidden', false ).show();
		}
		if ( showRetry && activeMode === 'repair' ) {
			showRepairAction( $box );
		}
	}

	function msg( $box, text, cls ) {
		$box.find( '.dologin-kl-msg' ).attr( 'class', 'dologin-kl-msg ' + ( cls || '' ) ).text( text || '' );
	}

	function showRepairAction( $box ) {
		var $button = $box.find( '.dologin-kl-repair' );
		$button.prop( 'hidden', false ).prop( 'disabled', false ).show().trigger( 'focus' );
	}

	function bytesToBase64( buffer ) {
		var bytes = new Uint8Array( buffer );
		var binary = '';
		var chunk = 0x8000;
		for ( var i = 0; i < bytes.length; i += chunk ) {
			binary += String.fromCharCode.apply( null, bytes.subarray( i, i + chunk ) );
		}
		return btoa( binary );
	}

	function base64ToBytes( b64 ) {
		var binary = atob( b64 );
		var bytes = new Uint8Array( binary.length );
		for ( var i = 0; i < binary.length; i++ ) {
			bytes[ i ] = binary.charCodeAt( i );
		}
		return bytes;
	}

	function apiPost( url, data ) {
		var headers = {};
		if ( cfg.nonce ) {
			headers['X-WP-Nonce'] = cfg.nonce;
		}
		return $.ajax( {
			url: url,
			method: 'POST',
			data: JSON.stringify( data ),
			contentType: 'application/json',
			dataType: 'json',
			headers: headers
		} );
	}

	function renderQR( $box, qrText ) {
		var qr = qrcode( 0, 'M' );
		qr.addData( qrText );
		qr.make();
		$box.find( '.dologin-kl-qr' ).html( qr.createSvgTag( 5, 3 ) );
	}

	function sendFrame( frame ) {
		if ( ! ws || ws.readyState !== WebSocket.OPEN || ! frame ) {
			return;
		}
		ws.send( base64ToBytes( frame ) );
	}

	function processResponse( $box, res, id ) {
		if ( id !== runId ) {
			return;
		}
		if ( ! res || res._res !== 'ok' ) {
			stopSession( $box, true );
			msg( $box, res && res._msg ? res._msg : cfg.i18n.failed, 'dologin-danger' );
			if ( ( res && res.repair ) || activeMode === 'repair' ) {
				showRepairAction( $box );
			}
			return;
		}

		if ( res.message ) {
			var messageClass = res.status === 'done' ? 'dologin-success' : 'dologin-warn';
			if ( res.status === 'waiting' && activeMode === 'login' ) {
				messageClass = 'dologin-kl-action-required';
			}
			msg( $box, res.message, messageClass );
		}

		if ( res.status === 'reconnect' ) {
			openSocket( $box, res.ws_url, res.send, id, '' );
			return;
		}

		if ( res.status === 'send' ) {
			sendFrame( res.send );
			return;
		}

		if ( res.status === 'done' ) {
			stopSession( $box, false );
			msg( $box, res.message || cfg.i18n.done, 'dologin-success' );
			if ( res.redirect ) {
				window.location.href = res.redirect;
			} else if ( res.reload !== false ) {
				window.setTimeout( function() {
					window.location.reload();
				}, 700 );
			} else {
				$box.find( '.dologin-kl-key-note' ).remove();
			}
		}
	}

	function openSocket( $box, url, frameToSend, id, qrText ) {
		closeSocket();

		ws = new WebSocket( url );
		ws.binaryType = 'arraybuffer';
		var socket = ws;
		var pendingFrame = frameToSend || '';
		var pendingQR = qrText || '';
		var frameQueue = [];
		var frameBusy = false;

		function forwardFrame() {
			if ( frameBusy || ! frameQueue.length || id !== runId || done || socket !== ws ) {
				return;
			}
			frameBusy = true;
			apiPost( cfg.url_frame, {
				state: state,
				frame: frameQueue.shift()
			} ).done( function( res ) {
				if ( id !== runId || done || socket !== ws ) {
					return;
				}
				processResponse( $box, res, id );
				if ( id === runId && ! done && res && res._res === 'ok' && res.status === 'connected' ) {
					if ( pendingQR ) {
						renderQR( $box, pendingQR );
						pendingQR = '';
					}
					if ( pendingFrame ) {
						sendFrame( pendingFrame );
						pendingFrame = '';
					}
				}
			} ).fail( function() {
				if ( id !== runId || done || socket !== ws ) {
					return;
				}
				stopSession( $box, true );
				msg( $box, cfg.i18n.failed, 'dologin-danger' );
				if ( activeMode === 'repair' ) {
					showRepairAction( $box );
				}
			} ).always( function() {
				frameBusy = false;
				forwardFrame();
			} );
		}

		socket.onopen = function() {
			if ( id !== runId || done || socket !== ws ) {
				return;
			}
			msg( $box, cfg.i18n.connecting, 'dologin-warn' );
		};

		socket.onmessage = function( ev ) {
			if ( id !== runId || done || socket !== ws || typeof ev.data === 'string' ) {
				return;
			}
			frameQueue.push( bytesToBase64( ev.data ) );
			forwardFrame();
		};

		socket.onerror = function() {
			if ( id !== runId || done || socket !== ws ) {
				return;
			}
			stopSession( $box, true );
			msg( $box, cfg.i18n.failed, 'dologin-danger' );
			if ( activeMode === 'repair' ) {
				showRepairAction( $box );
			}
		};

		socket.onclose = function() {
			if ( id !== runId || done || socket !== ws ) {
				return;
			}
			ws = null;
			stopSession( $box, true );
			msg( $box, cfg.i18n.failed, 'dologin-danger' );
			if ( activeMode === 'repair' ) {
				showRepairAction( $box );
			}
		};
	}

	function start( $box, requestedMode, relink ) {
		var mode = requestedMode || $box.data( 'dologin-kl-mode' ) || cfg.mode || 'login';
		var id = ++runId;
		activeMode = mode;
		stopSession( $box, false );
		activeRelink = !! relink;
		done = false;
		$box.find( '.dologin-kl-refresh' ).prop( 'disabled', true );
		$box.find( '.dologin-kl-repair' ).prop( 'hidden', true ).hide();
		if ( mode === 'bind' ) {
			$box.find( '.dologin-kl-refresh' ).prop( 'hidden', true ).hide();
		}
		if ( mode === 'verify' || mode === 'repair' || activeRelink ) {
			$box.find( '.dologin-kl-verify-panel' ).prop( 'hidden', false );
			$box.find( activeRelink ? '.dologin-kl-relink' : ( mode === 'repair' ? '.dologin-kl-repair' : '.dologin-kl-verify' ) ).attr( 'aria-expanded', 'true' ).prop( 'disabled', true );
		}
		msg( $box, cfg.i18n.connecting, 'dologin-warn' );
		$box.find( '.dologin-kl-qr' ).empty();

		apiPost( cfg.url_start, {
			mode: mode
		} ).done( function( res ) {
			if ( id !== runId || done ) {
				return;
			}
			if ( res._res !== 'ok' ) {
				stopSession( $box, true );
				msg( $box, res._msg || cfg.i18n.failed, 'dologin-danger' );
				if ( activeMode === 'repair' ) {
					showRepairAction( $box );
				}
				return;
			}
			state = res.state;
			openSocket( $box, res.ws_url, '', id, res.qr );
		} ).fail( function() {
			if ( id !== runId || done ) {
				return;
			}
			stopSession( $box, true );
			msg( $box, cfg.i18n.failed, 'dologin-danger' );
			if ( activeMode === 'repair' ) {
				showRepairAction( $box );
			}
		} );
	}

	if ( cfg.force && cfg.lostpassword_url ) {
		var resetUrl = document.createElement( 'a' );
		resetUrl.href = cfg.lostpassword_url;
		var $nav = $( '#nav' );
		$nav.find( 'a' ).filter( function() {
			return this.href === resetUrl.href;
		} ).each( function() {
			if ( this.previousSibling && this.previousSibling.nodeType === 3 ) {
				$( this.previousSibling ).remove();
			}
			$( this ).remove();
		} );
		if ( ! $nav.find( 'a' ).length ) {
			$nav.hide();
		}
	}

	$( '.dologin-kl-sso' ).each( function() {
		var $box = $( this );
		var $form = $box.closest( 'form' );
		if ( cfg.force && $box.data( 'dologin-kl-mode' ) === 'login' ) {
			$form.addClass( 'dologin-kl-force' );
		}
		$box.find( '.dologin-kl-refresh' ).on( 'click', function() {
			start( $box );
		} );
		$box.find( '.dologin-kl-verify' ).on( 'click', function() {
			start( $box, 'verify' );
		} );
		$box.find( '.dologin-kl-relink' ).on( 'click', function() {
			start( $box, 'bind', true );
		} );
		$box.on( 'click', '.dologin-kl-repair', function() {
			start( $box, 'repair' );
		} );
		$box.find( '.dologin-kl-unlink' ).on( 'click', function() {
			if ( ! window.confirm( cfg.i18n.unlink ) ) {
				return;
			}
			var id = ++runId;
			stopSession( $box, false );
			done = false;
			apiPost( cfg.url_unbind, {} ).done( function( res ) {
				processResponse( $box, res, id );
			} ).fail( function() {
				if ( id !== runId || done ) {
					return;
				}
				stopSession( $box, false );
				msg( $box, cfg.i18n.failed, 'dologin-danger' );
			} );
		} );
		if ( $box.data( 'dologin-kl-autostart' ) !== false && $box.find( '.dologin-kl-qr' ).length ) {
			start( $box );
		}
	} );
} ); } );
