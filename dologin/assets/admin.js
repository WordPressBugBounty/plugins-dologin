document.addEventListener( 'DOMContentLoaded', function() { jQuery( document ).ready( function( $ ) {
	var dologin_kl_copy_feedback_ms = 2000;
	var dologin_kl_copy_reset_timer = null;

	function dologin_keycode( num ) {
		var num = num || 13 ;
		var code = window.event ? event.keyCode : event.which ;
		if( num == code ) return true ;
		return false ;
	}

	function dologin_display_tab(tab) {
		jQuery('[data-dologin-tab]').removeClass('nav-tab-active');
		jQuery('[data-dologin-tab="'+tab+'"]').addClass('nav-tab-active');
		jQuery('[data-dologin-layout]').hide();
		jQuery('[data-dologin-layout="'+tab+'"]').show();
	}

	/*** Admin Panel JS ***/
	// page tab switch functionality
	if($('[data-dologin-tab]').length > 0){
		// display default tab
		var dologin_tab_current = document.cookie.replace(/(?:(?:^|.*;\s*)dologin_tab\s*\=\s*([^;]*).*$)|^.*$/, "$1") ;
		if(window.location.hash.substr(1)) {
			dologin_tab_current = window.location.hash.substr(1) ;
		}
		if(!dologin_tab_current || !$('[data-dologin-tab="'+dologin_tab_current+'"]').length) {
			dologin_tab_current = $('[data-dologin-tab]').first().data('dologin-tab') ;
		}
		dologin_display_tab(dologin_tab_current) ;
		// tab switch
		$('[data-dologin-tab]').click(function(event) {
			dologin_display_tab($(this).data('dologin-tab')) ;
			document.cookie = 'dologin_tab='+$(this).data('dologin-tab') ;
			$(this).blur() ;
		}) ;
	}

	/** Accesskey **/
	$( '[dologin-accesskey]' ).map( function() {
		var thiskey = $( this ).attr( 'dologin-accesskey' ) ;
		$( this ).attr( 'title', 'Shortcut : ' + thiskey.toLocaleUpperCase() ) ;
		var that = this ;
		$( document ).on( 'keydown', function( e ) {
			if( $(":input:focus").length > 0 ) return ;
			if( event.metaKey ) return ;
			if( event.ctrlKey ) return ;
			if( event.altKey ) return ;
			if( event.shiftKey ) return ;
			if( dologin_keycode( thiskey.charCodeAt( 0 ) ) ) $( that )[ 0 ].click() ;
		});
	});

	$( '.dologin-clear-log' ).click( function( event ) {
		if ( ! window.confirm( dologin_admin.clear_log_confirm ) ) {
			event.preventDefault();
		}
	} );

	$( '#dologin_get_ip' ).click( function( e ) {
		e.preventDefault();
		var $button = $( this );
		var $status = $( '#dologin_mygeolocation' );
		$button.prop( 'disabled', true ).attr( 'aria-busy', 'true' );
		$status.attr( 'class', 'dologin-warn' ).text( dologin_admin.ip_lookup_progress );
		$.ajax( {
			url: dologin_admin.url_myip,
			dataType: 'json',
			headers: {
				'X-WP-Nonce': dologin_admin.nonce
			}
		} ).done( function( data ) {
			var html = [];
			$.each( data, function( k, v ) {
				html.push( k + ':' + v );
			} );
			$status.attr( 'class', '' ).text( html.join( ', ' ) );
		} ).fail( function() {
			$status.attr( 'class', 'dologin-danger' ).text( dologin_admin.ip_lookup_failed );
		} ).always( function() {
			$button.prop( 'disabled', false ).removeAttr( 'aria-busy' );
		} );
	} );

	function dologin_clearPublicKeyCopyFeedback() {
		if ( dologin_kl_copy_reset_timer ) {
			window.clearTimeout( dologin_kl_copy_reset_timer );
			dologin_kl_copy_reset_timer = null;
		}
		return $( '.dologin-kl-copy-status' ).attr( 'class', 'dologin-kl-copy-status' ).text( '' );
	}

	function dologin_resetPublicKeyCopyButton() {
		dologin_clearPublicKeyCopyFeedback();
		var $button = $( '.dologin-kl-copy-public-key' );
		if ( ! $button.length ) {
			$button = $( '<button>' )
				.attr( 'type', 'button' )
				.addClass( 'button dologin-kl-copy-public-key' )
				.insertAfter( '#dologin-kl-encryption-public-key' );
		}
		return $button.text( dologin_admin.copy_public_key ).prop( 'disabled', false );
	}

	function dologin_showPublicKeyCopyFeedback( $button, message, copied ) {
		var $status = dologin_clearPublicKeyCopyFeedback();
		$button.prop( 'disabled', false );
		$status
			.addClass( copied ? 'dologin-success' : 'dologin-danger' )
			.text( message );
		dologin_kl_copy_reset_timer = window.setTimeout( function() {
			dologin_resetPublicKeyCopyButton();
		}, dologin_kl_copy_feedback_ms );
	}

	$( '.dologin-kl-reset-keys' ).click( function() {
		if ( ! window.confirm( dologin_admin.reset_keys_confirm ) ) {
			return;
		}
		dologin_clearPublicKeyCopyFeedback();
		var $button = $( this );
		var $status = $( '.dologin-kl-site-key-status' );
		$button.prop( 'disabled', true );
		$status.attr( 'class', 'dologin-kl-site-key-status dologin-warn' ).text( dologin_admin.resetting_keys );
		$.ajax( {
			url: dologin_admin.url_kl_reset_keys,
			method: 'POST',
			dataType: 'json',
			headers: {
				'X-WP-Nonce': dologin_admin.nonce
			}
		} ).done( function( data ) {
			if ( ! data || data._res !== 'ok' ) {
				$status.attr( 'class', 'dologin-kl-site-key-status dologin-danger' ).text( data && data._msg ? data._msg : dologin_admin.reset_keys_failed );
				return;
			}
			$( '#dologin-kl-site-key-fingerprint' ).text( data.fingerprint );
			$( '.dologin-kl-encryption-public-key' ).text( data.encryption_public_key );
			dologin_resetPublicKeyCopyButton();
			$status.attr( 'class', 'dologin-kl-site-key-status dologin-success' ).text( data.message );
			if ( $( '.dologin-kl-account' ).length && data.binding_message ) {
				var $note = $( '.dologin-kl-key-note' );
				if ( !$note.length ) {
					$note = $( '<div>' ).addClass( 'dologin-warn dologin-kl-key-note' ).insertAfter( '.dologin-kl-account' );
				}
				$note.text( data.binding_message );
			}
		} ).fail( function() {
			$status.attr( 'class', 'dologin-kl-site-key-status dologin-danger' ).text( dologin_admin.reset_keys_failed );
		} ).always( function() {
			$button.prop( 'disabled', false );
		} );
	} );

	$( document ).on( 'click', '.dologin-kl-copy-public-key', function() {
		var $button = $( this );
		var text = $( '#dologin-kl-encryption-public-key' ).text();
		dologin_clearPublicKeyCopyFeedback();
		$button.prop( 'disabled', true );
		dologin_copyToClipboard( text ).done( function( copied ) {
			if ( text !== $( '#dologin-kl-encryption-public-key' ).text() ) {
				dologin_resetPublicKeyCopyButton();
				return;
			}
			dologin_showPublicKeyCopyFeedback( $button, copied ? dologin_admin.copied : dologin_admin.copy_failed, copied );
		} );
	} );

	function dologin_copyToClipboardFallback( text ) {
		var copied = false;
		var $temp = $( '<textarea>' )
			.attr( 'readonly', 'readonly' )
			.css( { position: 'fixed', left: '-9999px', opacity: 0 } )
			.appendTo( 'body' )
			.val( text );
		$temp[ 0 ].select();
		try {
			copied = document.execCommand( 'copy' );
		} catch ( error ) {
			copied = false;
		}
		$temp.remove();
		return copied;
	}

	function dologin_copyToClipboard( text ) {
		var deferred = $.Deferred();
		var fallback = function() {
			deferred.resolve( dologin_copyToClipboardFallback( text ) );
		};
		if ( navigator.clipboard && typeof navigator.clipboard.writeText === 'function' ) {
			try {
				navigator.clipboard.writeText( text ).then( function() {
					deferred.resolve( true );
				}, fallback );
			} catch ( error ) {
				fallback();
			}
		} else {
			fallback();
		}
		return deferred.promise();
	}

} ); } );
