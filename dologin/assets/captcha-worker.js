/* Local work only: no network, storage or third-party code in this worker. */
'use strict';
self.onmessage = async function( event ) {
	const prefix = event.data.prefix;
	if ( typeof prefix !== 'string' || ! /^[a-f0-9]{32}:$/.test( prefix ) || event.data.bits !== 16 || ! self.crypto || ! self.crypto.subtle ) {
		self.postMessage( { error: 'unsupported' } );
		return;
	}
	const encoder = new TextEncoder();
	const started = Date.now();
	const budgetMs = 90000;
	const batchSize = 64;
	let lastReport = started;
	self.postMessage( { hashes: 0, elapsed: 0 } );
	try {
		for ( let base = 0; Date.now() - started < budgetMs; base += batchSize ) {
			const hashes = await Promise.all( Array.from( { length: batchSize }, ( _, index ) =>
				crypto.subtle.digest( 'SHA-256', encoder.encode( prefix + ( base + index ) ) )
			) );
			for ( let index = 0; index < hashes.length; index++ ) {
				const bytes = new Uint8Array( hashes[ index ] );
				if ( bytes[ 0 ] === 0 && bytes[ 1 ] === 0 ) {
					self.postMessage( { nonce: String( base + index ), hashes: base + batchSize, elapsed: Date.now() - started, digest: Array.from( bytes, byte => byte.toString( 16 ).padStart( 2, '0' ) ).join( '' ) } );
					return;
				}
			}
			if ( Date.now() - lastReport >= 200 ) {
				lastReport = Date.now();
				self.postMessage( { hashes: base + batchSize, elapsed: lastReport - started } );
			}
		}
		self.postMessage( { error: 'expired' } );
	} catch ( error ) {
		self.postMessage( { error: 'unsupported' } );
	}
};
