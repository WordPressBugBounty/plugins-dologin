<?php
/**
 * Early WordPress plugin-load regression checks.
 */

define( 'WPINC', true );

$GLOBALS['dologin_bootstrap_hooks'] = array();

function plugin_dir_url() {
	return 'https://example.test/wp-content/plugins/dologin/';
}

function did_action( $hook ) {
	return 0;
}

function add_action( $hook, $callback, $priority = 10 ) {
	$GLOBALS['dologin_bootstrap_hooks'][] = array( $hook, $callback, $priority );
	return true;
}

require dirname( __DIR__ ) . '/dologin.php';

$bootstrap_hook = end( $GLOBALS['dologin_bootstrap_hooks'] );
$valid_callback = is_array( $bootstrap_hook )
	&& isset( $bootstrap_hook[1] )
	&& is_array( $bootstrap_hook[1] )
	&& isset( $bootstrap_hook[1][0], $bootstrap_hook[1][1] )
	&& '\\dologin\\Core' === $bootstrap_hook[1][0]
	&& 'cls' === $bootstrap_hook[1][1];

if ( function_exists( 'wp_salt' )
	|| ! is_array( $bootstrap_hook )
	|| ! isset( $bootstrap_hook[0], $bootstrap_hook[2] )
	|| 'plugins_loaded' !== $bootstrap_hook[0]
	|| ! $valid_callback
	|| 0 !== $bootstrap_hook[2] ) {
	fwrite( STDERR, "Failure: DoLogin initialized before WordPress pluggable functions were available.\n" );
	exit( 1 );
}

echo "Bootstrap regression checks passed.\n";
