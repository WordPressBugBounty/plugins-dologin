/* Shared public controls and admin previews; only server responses can pass verification. */
( function() {
	'use strict';
	const cfg = window.dologin_captcha;
	if ( ! cfg ) { return; }
	const text = cfg.i18n;
	let turnstileLoad;
	let helpSequence = 0;
	function element( tag, className, content ) {
		const node = document.createElement( tag );
		if ( className ) { node.className = className; }
		if ( content ) { node.textContent = content; }
		return node;
	}
	function loadTurnstile() {
		if ( window.turnstile ) { return Promise.resolve(); }
		if ( ! turnstileLoad ) {
			turnstileLoad = new Promise( ( resolve, reject ) => {
				// Only the selected Turnstile preview loads the external provider.
				const script = document.createElement( 'script' );
				script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
				const timeout = setTimeout( () => reject( new Error( text.failed ) ), 15000 );
				script.onload = () => { clearTimeout( timeout ); resolve(); };
				script.onerror = () => { clearTimeout( timeout ); reject( new Error( text.failed ) ); };
				document.head.appendChild( script );
			} ).catch( error => { turnstileLoad = null; throw error; } );
		}
		return turnstileLoad;
	}

	class Verification {
		constructor( root ) {
			this.root = root;
			this.demo = root.dataset.demo === '1';
			this.method = root.dataset.method;
			this.context = root.dataset.context;
			this.stage = root.querySelector( '.dologin-captcha-stage' );
			this.status = root.querySelector( '.dologin-captcha-status' );
			this.surface = element( 'div', 'dologin-captcha-surface' );
			this.stage.before( this.surface );
			this.surface.append( this.stage, this.status );
			this.startButton = root.querySelector( '.dologin-captcha-refresh' );
			this.ticket = root.querySelector( '[name="dologin-captcha-ticket"]' );
			this.generation = 0;
			this.startButton.addEventListener( 'click', () => this.start() );
			root.dologinVerification = this;
			if ( ! this.demo ) {
				const form = root.closest( 'form' );
				if ( form ) {
					form.addEventListener( 'submit', event => {
						if ( ! this.ticket.value ) {
							event.preventDefault();
							event.stopImmediatePropagation();
							this.message( text.required, '', false );
							// Focus the pending answer control; the refresh icon only when nothing is in progress, so Enter cannot discard running work.
							const pending = this.stage.querySelector( 'button:not(:disabled), input:not(:disabled)' ) || ( this.worker || this.checking ? null : this.startButton );
							if ( pending ) { pending.focus(); }
						}
					}, true );
				}
			}
			this.start();
		}

		// Disabling a focused control drops focus to the body; park it on the status that announces the verdict, never on refresh, which would discard the running check. Untouched when focus is elsewhere, so the admin preview never steals focus.
		keepFocus( control ) {
			if ( document.activeElement !== control ) { return; }
			this.status.tabIndex = -1;
			this.status.focus();
		}

		message( value, result = '', overlay = !! result || value === text.loading || value === text.checking || value === text.off ) {
			this.status.textContent = value;
			this.status.dataset.result = result;
			this.status.classList.toggle( 'dologin-captcha-overlay', overlay );
		}

		cancel() {
			this.generation++;
			if ( this.worker ) { this.worker.terminate(); this.worker = null; }
			if ( this.request ) { this.request.abort(); this.request = null; }
			if ( this.widget !== undefined && window.turnstile ) { window.turnstile.remove( this.widget ); this.widget = undefined; }
			clearTimeout( this.expiry );
			this.challenge = null;
			this.nonce = null;
			this.answer = null;
			this.checking = false;
			this.root.removeAttribute( 'aria-busy' );
			if ( this.ticket ) { this.ticket.value = ''; }
		}

		async api( action, body, generation ) {
			const controller = new AbortController();
			this.request = controller;
			const timeout = setTimeout( () => controller.abort(), 15000 );
			try {
				const headers = { 'Content-Type': 'application/json' };
				if ( this.demo ) { headers[ 'X-WP-Nonce' ] = cfg.nonce; }
				let response, data;
				try {
					response = await fetch( cfg.url + action, { method: 'POST', credentials: 'same-origin', headers, body: JSON.stringify( body ), signal: controller.signal, cache: 'no-store' } );
					data = await response.json();
				} catch ( error ) {
					// Never surface raw browser network or JSON parser messages in the status line.
					if ( error.name === 'AbortError' ) { throw error; }
					throw new Error( text.failed );
				}
				if ( generation !== this.generation ) { throw new Error( 'cancelled' ); }
				if ( ! response.ok || ! data || data._res !== 'ok' ) { throw new Error( data && data._msg ? data._msg : text.failed ); }
				return data;
			} finally {
				clearTimeout( timeout );
				if ( this.request === controller ) { this.request = null; }
			}
		}

		fail( error, generation ) {
			if ( generation !== this.generation ) { return; }
			this.cancel();
			this.stage.querySelectorAll( 'button, input' ).forEach( item => { item.disabled = true; } );
			this.message( error && error.name !== 'AbortError' ? error.message : text.failed, 'failed' );
			this.startButton.hidden = false;
			this.startButton.disabled = false;
		}

		async start() {
			this.cancel();
			const generation = this.generation;
			this.started = performance.now();
			this.stage.replaceChildren();
			this.startButton.hidden = this.method === 'off';
			if ( this.method === 'off' ) { this.message( text.off ); return; }
			this.startButton.disabled = true;
			this.root.setAttribute( 'aria-busy', 'true' );
			this.message( text.loading );
			try {
				if ( this.method === 'turnstile' ) { await this.turnstile( generation ); return; }
				if ( ! window.isSecureContext || ! window.Worker || ! window.crypto || ! window.crypto.subtle ) { throw new Error( text.unsupported ); }
				const challenge = await this.api( this.demo ? 'demo_challenge' : 'challenge', { method: this.method, context: this.context }, generation );
				this.challenge = challenge;
				this.expiry = setTimeout( () => this.fail( new Error( text.expired ), generation ), challenge.ttl * 1000 - ( performance.now() - this.started ) );
				this.interaction( challenge );
				this.message( text.working );
				try {
					this.worker = new Worker( cfg.worker );
				} catch ( error ) {
					// A CSP or origin refusal throws a raw SecurityError; show the localized requirement instead.
					throw new Error( text.unsupported );
				}
				this.worker.onerror = () => this.fail( new Error( text.unsupported ), generation );
				this.worker.onmessage = event => {
					if ( generation !== this.generation ) { return; }
					this.workProgress( event.data );
					if ( ! event.data.error && event.data.nonce === undefined ) { return; }
					this.worker.terminate();
					this.worker = null;
					if ( event.data.error ) { this.fail( new Error( text[ event.data.error ] || text.failed ), generation ); return; }
					this.nonce = event.data.nonce;
					this.root.removeAttribute( 'aria-busy' );
					// The interaction instruction already sits in the stage paragraph directly below; repeating it in the status would show it twice.
					this.message( this.method === 'pow' ? text.checking : '' );
					this.finish( generation );
				};
				this.worker.postMessage( { prefix: challenge.prefix, bits: challenge.bits } );
				this.startButton.disabled = false;
			} catch ( error ) { this.fail( error, generation ); }
		}

		interaction( challenge ) {
			this.answer = this.method === 'pow' ? '' : null;
			if ( this.method === 'sequence' ) {
				const targets = element( 'ol', 'dologin-captcha-targets' );
				challenge.targets.forEach( target => {
					const item = element( 'li' );
					const image = element( 'img' );
					image.src = target.image; image.alt = target.label;
					item.appendChild( image ); targets.appendChild( item );
				} );
				const grid = element( 'button', 'dologin-captcha-patterns' );
				grid.type = 'button';
				// The image alt names the control; the visible help paragraph describes it instead of being read twice.
				const help = element( 'p', 'dologin-captcha-point-help', text.point );
				help.id = 'dologin-captcha-point-help-' + ( ++helpSequence );
				grid.setAttribute( 'aria-describedby', help.id );
				const picture = element( 'img' );
				picture.src = challenge.picture; picture.alt = text.patterns;
				picture.draggable = false;
				// Rings and the keyboard cursor live in a frame sized by the image, so their percentages share the image coordinate space even if a theme pads the button.
				const frame = element( 'span', 'dologin-captcha-frame' );
				frame.appendChild( picture );
				grid.appendChild( frame );
				const selected = [];
				const announce = () => this.message( text.points.replace( '%1$d', String( selected.length ) ).replace( '%2$d', '3' ), '', false );
				const undo = () => {
					if ( grid.disabled || ! selected.length ) { return; }
					selected.pop(); frame.querySelector( '.dologin-captcha-mark:last-child' ).remove(); announce();
				};
				const cursor = element( 'span', 'dologin-captcha-cursor' );
				cursor.hidden = true; cursor.setAttribute( 'aria-hidden', 'true' );
				frame.appendChild( cursor );
				let x = 140, y = 84;
				const position = ( node, px, py ) => { node.style.left = ( px / 280 * 100 ) + '%'; node.style.top = ( py / 168 * 100 ) + '%'; };
				const mark = ( px, py ) => {
					if ( grid.disabled || selected.length >= 3 ) { return; }
					// All points, including blank space and repeated points, receive identical feedback.
					selected.push( px + ',' + py );
					const ring = element( 'span', 'dologin-captcha-mark', String( selected.length ) );
					ring.setAttribute( 'aria-hidden', 'true' ); position( ring, px, py ); frame.appendChild( ring );
					announce();
					if ( selected.length === 3 ) {
						this.keepFocus( grid ); grid.disabled = true; cursor.hidden = true;
						this.answer = selected.join( ';' ); this.finish( this.generation );
					}
				};
				grid.addEventListener( 'click', event => {
					if ( event.detail === 0 ) { mark( x, y ); return; }
					// Map against the image itself so theme border or padding on the button cannot shift intrinsic coordinates; fall back to the button before the image has a size.
					const drawn = picture.getBoundingClientRect();
					const bounds = drawn.width && drawn.height ? drawn : grid.getBoundingClientRect();
					cursor.hidden = true;
					mark( Math.max( 0, Math.min( 279, Math.round( ( event.clientX - bounds.left ) / bounds.width * 280 ) ) ), Math.max( 0, Math.min( 167, Math.round( ( event.clientY - bounds.top ) / bounds.height * 168 ) ) ) );
				} );
				grid.addEventListener( 'keydown', event => {
					if ( event.key === 'Backspace' ) { event.preventDefault(); undo(); return; }
					if ( [ 'Enter', ' ' ].includes( event.key ) ) { event.preventDefault(); if ( ! event.repeat ) { mark( x, y ); } return; }
					if ( ! [ 'ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown' ].includes( event.key ) ) { return; }
					event.preventDefault();
					const step = event.shiftKey ? 10 : 1;
					x = Math.max( 0, Math.min( 279, x + ( event.key === 'ArrowRight' ? step : event.key === 'ArrowLeft' ? -step : 0 ) ) );
					y = Math.max( 0, Math.min( 167, y + ( event.key === 'ArrowDown' ? step : event.key === 'ArrowUp' ? -step : 0 ) ) );
					cursor.hidden = false; position( cursor, x, y );
				} );
				// Space activates a button on keyup; cancel it so a keyboard mark is never recorded twice.
				grid.addEventListener( 'keyup', event => { if ( event.key === ' ' ) { event.preventDefault(); } } );
				// Show where Enter or Space will mark as soon as keyboard focus arrives, not only after the first arrow key.
				grid.addEventListener( 'focus', () => {
					let keyboard = false;
					try { keyboard = grid.matches( ':focus-visible' ); } catch ( error ) { keyboard = false; }
					if ( keyboard && ! grid.disabled ) { cursor.hidden = false; position( cursor, x, y ); }
				} );
				grid.addEventListener( 'blur', () => { cursor.hidden = true; } );
				this.stage.append( element( 'p', '', text.order ), targets, grid, help );
			} else if ( this.method === 'puzzle' ) {
				this.stage.appendChild( element( 'p', '', text.drag ) );
				const scene = element( 'div', 'dologin-captcha-scene' );
				const picture = element( 'img' );
				picture.src = challenge.picture;
				picture.alt = text.picture;
				const piece = element( 'img', 'dologin-captcha-piece' );
				piece.src = challenge.piece;
				piece.alt = '';
				scene.append( picture, piece );
				const label = element( 'label', '', text.position );
				const slider = element( 'input' );
				slider.type = 'range'; slider.min = '0'; slider.max = '236'; slider.step = '1'; slider.value = '0';
				// Image coordinates are physical; an RTL range would move the thumb opposite to the piece.
				slider.dir = 'ltr';
				label.appendChild( slider );
				slider.addEventListener( 'input', () => { piece.style.left = ( Number( slider.value ) / 280 * 100 ) + '%'; } );
				// Pointer release submits; keyboard adjustments remain editable until Enter.
				const release = () => {
					if ( slider.disabled ) { return; }
					this.answer = slider.value; this.keepFocus( slider ); slider.disabled = true;
					this.finish( this.generation );
				};
				slider.addEventListener( 'pointerup', release );
				slider.addEventListener( 'keydown', event => {
					if ( event.key === 'Enter' ) { event.preventDefault(); release(); }
				} );
				this.stage.append( scene, label );
			}
			const work = element( 'div', 'dologin-captcha-work' );
			this.workStats = element( 'p', 'dologin-captcha-work-stats', text.work_wait );
			this.workDigest = element( 'code', 'dologin-captcha-work-digest' );
			this.workDigest.hidden = true;
			work.append( element( 'p', '', text.work_target ), this.workStats, this.workDigest );
			this.stage.appendChild( work );
		}

		workProgress( data ) {
			if ( typeof data.hashes !== 'number' ) { return; }
			const elapsed = Math.max( 1, data.elapsed );
			this.workStats.textContent = text.work_stats.replace( '%1$s', data.hashes.toLocaleString() ).replace( '%2$s', data.elapsed.toLocaleString() ).replace( '%3$s', Math.round( data.hashes * 1000 / elapsed ).toLocaleString() );
			if ( data.digest ) { this.workDigest.textContent = data.digest; this.workDigest.hidden = false; }
		}

		async finish( generation ) {
			if ( this.answer === null || this.checking ) { return; }
			if ( this.nonce === null ) { this.message( text.working, '', true ); return; }
			this.checking = true;
			this.message( text.checking );
			this.root.setAttribute( 'aria-busy', 'true' );
			this.stage.querySelectorAll( 'button, input' ).forEach( item => { item.disabled = true; } );
			try {
				const result = await this.api( this.demo ? 'demo_verify' : 'verify', { id: this.challenge.id, nonce: this.nonce, answer: this.answer }, generation );
				if ( this.ticket ) { this.ticket.value = result.ticket; }
				this.success( result.message );
			} catch ( error ) { this.fail( error, generation ); }
		}

		success( message ) {
			if ( this.demo ) { clearTimeout( this.expiry ); }
			this.root.removeAttribute( 'aria-busy' );
			this.message( message + ( this.demo ? ' ' + text.elapsed.replace( '%s', String( Math.round( performance.now() - this.started ) ) ) : '' ), 'passed' );
			this.startButton.disabled = false;
		}

		async turnstile( generation ) {
			if ( ! this.demo || ! cfg.has_keys ) { throw new Error( text.keys ); }
			await loadTurnstile();
			if ( generation !== this.generation ) { return; }
			this.message( text.cloudflare );
			this.root.removeAttribute( 'aria-busy' );
			this.widget = window.turnstile.render( this.stage, {
				sitekey: cfg.sitekey,
				callback: async response => {
					if ( generation !== this.generation ) { return; }
					if ( this.checking ) { return; }
					this.checking = true;
					this.root.setAttribute( 'aria-busy', 'true' );
					this.message( text.checking );
					try {
						const result = await this.api( 'demo_turnstile', { response }, generation );
						this.success( result.message );
					} catch ( error ) { this.fail( error, generation ); }
				},
				'error-callback': () => this.fail( new Error( text.failed ), generation ),
				'expired-callback': () => this.fail( new Error( text.expired ), generation )
			} );
			this.startButton.disabled = false;
		}
	}

	function boot() {
		const instances = Array.from( document.querySelectorAll( '.dologin-captcha' ), root => new Verification( root ) );
		document.querySelectorAll( '[name="captcha_method"]' ).forEach( radio => radio.addEventListener( 'change', () => {
			if ( ! radio.checked ) { return; }
			const method = radio.value;
			document.querySelectorAll( '[data-captcha-desc]' ).forEach( node => {
				node.hidden = node.dataset.captchaDesc !== method && ! ( node.dataset.captchaDesc === 'local' && [ 'pow', 'sequence', 'puzzle' ].includes( method ) );
			} );
			instances.filter( item => item.demo ).forEach( item => { item.method = method; item.start(); } );
		} ) );
		window.addEventListener( 'pagehide', () => instances.forEach( item => item.cancel() ) );
		window.addEventListener( 'pageshow', event => {
			if ( event.persisted ) { instances.forEach( item => item.start() ); }
		} );
	}
	if ( document.readyState === 'loading' ) { document.addEventListener( 'DOMContentLoaded', boot ); } else { boot(); }
} )();
