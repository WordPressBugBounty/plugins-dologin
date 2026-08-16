document.addEventListener( 'DOMContentLoaded', function() { jQuery( document ).ready( function( $ ) {
	var cfg = window.dologin_kl_sso || {};
	var ws = null;
	var state = '';
	var done = false;
	var runId = 0;
	var activeMode = '';
	var activeRelink = false;
	var deepLinkContext = null;
	var deepLinkResumeRunId = 0;
	var deepLinkResumePending = false;
	var deepLinkDeferredResponse = null;
	var returnParam = 'dologin_kl_return';
	var returnResultParam = 'keylockr_result';
	var returnStoragePrefix = 'dologin-kl-sso-return:';
	var returnStorageTTL = 600000;
	var returnStorageCleanupMaxEntries = 32;
	var returnResultMaxBytes = 12288;
	var storedReturnId = '';

	function closeSocket() {
		if ( ws ) {
			ws.onclose = null;
			ws.close();
			ws = null;
		}
	}

	function clearStoredReturn() {
		if ( ! storedReturnId ) {
			return;
		}
		try {
			window.localStorage.removeItem( returnStoragePrefix + storedReturnId );
		} catch ( error ) {
			// Storage can be disabled by browser privacy settings.
		}
		storedReturnId = '';
	}

	function invalidReturnExpiry( expires, now ) {
		return typeof expires !== 'number' || ! isFinite( expires )
			|| expires <= now || expires > now + returnStorageTTL;
	}

	function validStoredReturnFrame( frame ) {
		if ( typeof frame !== 'string' || ! frame || frame.length > 4096
			|| frame.length % 4 !== 0 || ! /^[A-Za-z0-9+/]+={0,2}$/.test( frame ) ) {
			return false;
		}
		try {
			return btoa( atob( frame ) ) === frame;
		} catch ( error ) {
			return false;
		}
	}

	function validStoredReturnSession( saved, now ) {
		if ( ! saved || typeof saved !== 'object' ) {
			return false;
		}
		var savedQR = typeof saved.qr === 'string' ? saved.qr : '';
		var savedFrame = typeof saved.frame === 'string' ? saved.frame : '';
		var tmpResume = /^keylockr:\/\/sso\?tmp_id=[A-Za-z0-9-]{36}$/.test( savedQR ) && ! savedFrame;
		var appResume = ! savedQR && validStoredReturnFrame( savedFrame );
		return /^[a-f0-9]{32}$/.test( saved.state || '' )
			&& /^wss:\/\/api\.keylockr\.app\/v3\/ws\?sig=[A-Za-z0-9_-]+$/.test( saved.ws_url || '' )
			&& ( tmpResume || appResume )
			&& [ 'login', 'bind', 'verify', 'repair' ].indexOf( saved.mode ) !== -1
			&& [ 'dologin-kl-sso', 'dologin-kl-sso-bind' ].indexOf( saved.box ) !== -1
			&& ! invalidReturnExpiry( saved.expires, now );
	}

	function cleanupStoredReturns() {
		try {
			var keys = [];
			var keyCount = window.localStorage.length;
			for ( var i = 0; i < keyCount && keys.length < returnStorageCleanupMaxEntries; i++ ) {
				var key = window.localStorage.key( i );
				if ( typeof key === 'string' && key.indexOf( returnStoragePrefix ) === 0 ) {
					keys.push( key );
				}
			}
			var now = Date.now();
			keys.forEach( function( key ) {
				var returnId = key.slice( returnStoragePrefix.length );
				var remove = ! /^[a-f0-9]{32}$/.test( returnId );
				try {
					if ( ! remove ) {
						var raw = window.localStorage.getItem( key );
						var saved = raw && raw.length <= 8192 ? JSON.parse( raw ) : null;
						remove = ! validStoredReturnSession( saved, now );
					}
				} catch ( error ) {
					remove = true;
				}
				if ( remove ) {
					try {
						window.localStorage.removeItem( key );
					} catch ( error ) {
						// Storage can become unavailable while the page is active.
					}
				}
			} );
		} catch ( error ) {
			// Storage can be disabled by browser privacy settings.
		}
	}

	function deepLinkExpired( context ) {
		return ! context || invalidReturnExpiry( context.expires, Date.now() );
	}

	function clearDeepLink( $box ) {
		$box.find( '.dologin-kl-open' ).removeAttr( 'href' ).prop( 'hidden', true ).hide();
		$box.find( '.dologin-kl-open-note' ).prop( 'hidden', true ).hide();
		deepLinkContext = null;
		deepLinkResumeRunId = 0;
		deepLinkResumePending = false;
		deepLinkDeferredResponse = null;
	}

	function stopSession( $box, showRetry ) {
		done = true;
		closeSocket();
		clearStoredReturn();
		$box.find( '.dologin-kl-qr' ).empty();
		clearDeepLink( $box );
		$box.find( '.dologin-kl-refresh' ).prop( 'disabled', false );
		if ( showRetry && activeMode === 'login' ) {
			$box.find( '.dologin-kl-refresh' ).prop( 'hidden', false ).show();
		}
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

	function normalizeReturnFrame( value ) {
		if ( typeof value !== 'string' || ! value || value.length > 16384
			|| value.length % 4 === 1 || ! /^[A-Za-z0-9_-]+$/.test( value ) ) {
			return '';
		}
		var encoded = value.replace( /-/g, '+' ).replace( /_/g, '/' );
		while ( encoded.length % 4 ) {
			encoded += '=';
		}
		try {
			var binary = atob( encoded );
			if ( ! binary || binary.length > returnResultMaxBytes ) {
				return '';
			}
			var standard = btoa( binary );
			var canonical = standard.replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=+$/, '' );
			return canonical === value ? standard : '';
		} catch ( error ) {
			return '';
		}
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

	function randomReturnId() {
		if ( ! window.crypto || typeof window.crypto.getRandomValues !== 'function' ) {
			return '';
		}
		var bytes = new Uint8Array( 16 );
		try {
			window.crypto.getRandomValues( bytes );
		} catch ( error ) {
			return '';
		}
		var value = '';
		for ( var i = 0; i < bytes.length; i++ ) {
			value += ( '0' + bytes[ i ].toString( 16 ) ).slice( -2 );
		}
		return value;
	}

	function buildReturnURL( returnId ) {
		if ( typeof window.URL !== 'function' ) {
			return '';
		}
		try {
			var returnURL = new window.URL( window.location.href );
			if ( ( returnURL.protocol !== 'https:' && returnURL.protocol !== 'http:' ) || returnURL.username || returnURL.password ) {
				return '';
			}
			returnURL.hash = '';
			returnURL.searchParams.delete( returnParam );
			returnURL.searchParams.delete( returnResultParam );
			if ( returnId ) {
				returnURL.searchParams.set( returnParam, returnId );
			}
			var value = returnURL.href;
			var byteLength = encodeURIComponent( value ).replace( /%[0-9A-F]{2}|./gi, 'x' ).length;
			return byteLength <= 2048 ? value : '';
		} catch ( error ) {
			return '';
		}
	}

	function persistReturnSession( $box ) {
		if ( ! deepLinkContext || ! deepLinkContext.returnId || deepLinkExpired( deepLinkContext )
			|| ! /^[a-f0-9]{32}$/.test( state ) ) {
			return;
		}
		var returnId = deepLinkContext.returnId;
		var boxId = $box.attr( 'id' ) || '';
		var payload = {
			state: state,
			ws_url: deepLinkContext.url,
			frame: '',
			qr: deepLinkContext.qr,
			mode: activeMode,
			relink: activeRelink,
			box: boxId,
			expires: deepLinkContext.expires
		};
		try {
			window.localStorage.setItem( returnStoragePrefix + returnId, JSON.stringify( payload ) );
			storedReturnId = returnId;
			window.setTimeout( function() {
				if ( storedReturnId === returnId ) {
					clearStoredReturn();
				}
			}, Math.max( 0, payload.expires - Date.now() ) );
		} catch ( error ) {
			storedReturnId = '';
		}
	}

	function updateStoredReturnSocket( url, frame ) {
		if ( ! storedReturnId
			|| ! /^wss:\/\/api\.keylockr\.app\/v3\/ws\?sig=[A-Za-z0-9_-]+$/.test( url || '' )
			|| ! validStoredReturnFrame( frame ) ) {
			return;
		}
		try {
			var raw = window.localStorage.getItem( returnStoragePrefix + storedReturnId );
			var saved = raw && raw.length <= 8192 ? JSON.parse( raw ) : null;
			if ( ! saved || typeof saved !== 'object' ) {
				return;
			}
			saved.ws_url = url;
			saved.frame = frame;
			saved.qr = '';
			window.localStorage.setItem( returnStoragePrefix + storedReturnId, JSON.stringify( saved ) );
		} catch ( error ) {
			clearStoredReturn();
		}
	}

	function takeReturnedSession() {
		if ( typeof window.URL !== 'function' ) {
			return null;
		}
		var currentURL;
		try {
			currentURL = new window.URL( window.location.href );
		} catch ( error ) {
			return null;
		}
		if ( ! currentURL.searchParams || typeof currentURL.searchParams.getAll !== 'function' ) {
			return null;
		}
		var returnIds = currentURL.searchParams.getAll( returnParam );
		var returnResults = currentURL.searchParams.getAll( returnResultParam );
		if ( ! returnIds.length && ! returnResults.length ) {
			return null;
		}
		currentURL.searchParams.delete( returnParam );
		currentURL.searchParams.delete( returnResultParam );
		if ( window.history && typeof window.history.replaceState === 'function' ) {
			window.history.replaceState( null, document.title, currentURL.href );
		}
		if ( returnIds.length !== 1 || returnResults.length > 1 ) {
			return null;
		}
		var returnId = returnIds[0];
		if ( ! /^[a-f0-9]{32}$/.test( returnId ) ) {
			return null;
		}
		var saved;
		try {
			var raw = window.localStorage.getItem( returnStoragePrefix + returnId );
			window.localStorage.removeItem( returnStoragePrefix + returnId );
			saved = raw && raw.length <= 8192 ? JSON.parse( raw ) : null;
		} catch ( error ) {
			return null;
		}
		var savedQR = saved && typeof saved.qr === 'string' ? saved.qr : '';
		var savedFrame = saved && typeof saved.frame === 'string' ? saved.frame : '';
		var tmpResume = /^keylockr:\/\/sso\?tmp_id=[A-Za-z0-9-]{36}$/.test( savedQR ) && ! savedFrame;
		if ( ! validStoredReturnSession( saved, Date.now() ) ) {
			return null;
		}
		var returnFrame = '';
		if ( tmpResume && returnResults.length ) {
			returnFrame = normalizeReturnFrame( returnResults[0] );
			if ( ! returnFrame ) {
				return null;
			}
		}
		saved.relink = !! saved.relink;
		saved.return_frame = tmpResume ? returnFrame : '';
		return saved;
	}

	function showDeepLink( $box, qrText, url, id ) {
		if ( ! /^keylockr:\/\/sso\?tmp_id=[A-Za-z0-9-]{36}$/.test( qrText ) ) {
			return;
		}
		var returnId = randomReturnId();
		var returnURL = returnId ? buildReturnURL( returnId ) : '';
		var deepLink = qrText + ( returnURL ? '&return_url=' + encodeURIComponent( returnURL ) : '' );
		deepLinkContext = {
			$box: $box,
			url: url,
			id: id,
			qr: qrText,
			returnId: returnId,
			expires: Date.now() + returnStorageTTL
		};
		$box.find( '.dologin-kl-open' ).attr( 'href', deepLink ).prop( 'hidden', false ).show();
		$box.find( '.dologin-kl-open-note' ).prop( 'hidden', ! returnURL ).toggle( !! returnURL );
		if ( activeMode === 'login' ) {
			$box.find( '.dologin-kl-refresh' ).prop( 'hidden', true ).hide();
		}
	}

	function resumeDeepLink() {
		if ( document.hidden ) {
			if ( deepLinkContext && deepLinkResumeRunId === runId && ! done ) {
				deepLinkResumePending = true;
				closeSocket();
			}
			return;
		}
		var context = deepLinkContext;
		var recoveryActive = deepLinkResumePending || deepLinkDeferredResponse || deepLinkResumeRunId === runId;
		if ( recoveryActive && context && context.id === runId && ! done && deepLinkExpired( context ) ) {
			var $box = context.$box;
			var mode = activeMode;
			var relink = activeRelink;
			deepLinkDeferredResponse = null;
			deepLinkResumeRunId = 0;
			deepLinkResumePending = false;
			start( $box, mode, relink );
			return;
		}
		if ( deepLinkDeferredResponse ) {
			var deferred = deepLinkDeferredResponse;
			deepLinkDeferredResponse = null;
			processResponse( deferred.$box, deferred.res, deferred.id );
			return;
		}
		if ( ! deepLinkResumePending || ! deepLinkContext ) {
			return;
		}
		context = deepLinkContext;
		deepLinkResumePending = false;
		if ( context.id !== runId || done ) {
			return;
		}
		msg( context.$box, cfg.i18n.connecting, 'dologin-warn' );
		openSocket( context.$box, context.url, '', context.id, '' );
	}

	function queueDeepLinkRecovery( id ) {
		if ( ! deepLinkContext || deepLinkContext.id !== id || deepLinkResumeRunId !== id ) {
			return false;
		}
		deepLinkResumeRunId = 0;
		deepLinkResumePending = true;
		if ( ! document.hidden ) {
			window.setTimeout( resumeDeepLink, 0 );
		}
		return true;
	}

	function sendFrame( frame ) {
		if ( ! ws || ws.readyState !== window.WebSocket.OPEN || ! frame ) {
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
			updateStoredReturnSocket( res.ws_url, res.send );
			if ( document.hidden && deepLinkContext && deepLinkContext.id === id && deepLinkResumeRunId === id ) {
				deepLinkDeferredResponse = {
					$box: $box,
					res: res,
					id: id
				};
				deepLinkResumeRunId = 0;
				deepLinkResumePending = false;
				closeSocket();
				return;
			}
			clearDeepLink( $box );
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

		if ( typeof window.WebSocket !== 'function' ) {
			stopSession( $box, true );
			msg( $box, cfg.i18n.failed, 'dologin-danger' );
			return;
		}
		try {
			ws = new window.WebSocket( url );
		} catch ( error ) {
			stopSession( $box, true );
			msg( $box, cfg.i18n.failed, 'dologin-danger' );
			return;
		}
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
						showDeepLink( $box, pendingQR, url, id );
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
			if ( queueDeepLinkRecovery( id ) ) {
				closeSocket();
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
			if ( queueDeepLinkRecovery( id ) ) {
				return;
			}
			stopSession( $box, true );
			msg( $box, cfg.i18n.failed, 'dologin-danger' );
			if ( activeMode === 'repair' ) {
				showRepairAction( $box );
			}
		};
	}

	function prepareSession( $box, mode, relink ) {
		activeMode = mode;
		activeRelink = !! relink;
		done = false;
		state = '';
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
	}

	function restoreSession( $box, saved ) {
		var id = ++runId;
		stopSession( $box, false );
		prepareSession( $box, saved.mode, saved.relink );
		state = saved.state;
		if ( saved.mode === 'login' ) {
			$box.find( '.dologin-kl-refresh' ).prop( 'hidden', true ).hide();
		}
		if ( saved.return_frame ) {
			apiPost( cfg.url_frame, {
				state: state,
				frame: saved.return_frame
			} ).done( function( res ) {
				if ( id !== runId || done ) {
					return;
				}
				processResponse( $box, res, id );
			} ).fail( function() {
				if ( id !== runId || done ) {
					return;
				}
				stopSession( $box, true );
				msg( $box, cfg.i18n.failed, 'dologin-danger' );
			} );
			return;
		}
		openSocket( $box, saved.ws_url, saved.frame || '', id, saved.qr || '' );
	}

	function start( $box, requestedMode, relink ) {
		var mode = requestedMode || $box.data( 'dologin-kl-mode' ) || cfg.mode || 'login';
		var id = ++runId;
		stopSession( $box, false );
		prepareSession( $box, mode, relink );

		apiPost( cfg.url_start, { mode: mode } ).done( function( res ) {
			if ( id !== runId || done ) {
				return;
			}
			if ( ! res || res._res !== 'ok' || ! res.state ) {
				processResponse( $box, res, id );
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

	cleanupStoredReturns();
	var returnedSession = takeReturnedSession();

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
		$box.find( '.dologin-kl-open' ).on( 'click', function() {
			if ( deepLinkContext && deepLinkContext.id === runId && ! done ) {
				persistReturnSession( $box );
				deepLinkResumeRunId = runId;
				deepLinkResumePending = false;
			}
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
		if ( returnedSession && returnedSession.box === $box.attr( 'id' ) && $box.find( '.dologin-kl-qr' ).length ) {
			restoreSession( $box, returnedSession );
			returnedSession = null;
		} else if ( $box.data( 'dologin-kl-autostart' ) !== false && $box.find( '.dologin-kl-qr' ).length ) {
			start( $box );
		}
	} );

	$( document ).on( 'visibilitychange', resumeDeepLink );
} ); } );
