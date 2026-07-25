<?php
/**
 * Bootstrap for the WordPress integration test suite.
 *
 * Loads the WP test library (installed by bin/install-wp-tests.sh) and the plugin
 * at muplugins_loaded, so the real gate hooks are wired against a live WordPress +
 * MySQL. Requires WP_TESTS_DIR to point at the installed test suite.
 */

declare( strict_types = 1 );

$_tests_dir = getenv( 'WP_TESTS_DIR' );
if ( ! $_tests_dir ) {
	$_tmp       = getenv( 'TMPDIR' ) ? rtrim( getenv( 'TMPDIR' ), '/' ) : '/tmp';
	$_tests_dir = $_tmp . '/wordpress-tests-lib';
}

if ( ! file_exists( $_tests_dir . '/includes/functions.php' ) ) {
	fwrite( STDERR, "Could not find the WordPress test suite at {$_tests_dir}.\n" );
	fwrite( STDERR, "Run: bin/install-wp-tests.sh <db-name> <db-user> <db-pass> [db-host] [wp-version]\n" );
	exit( 1 );
}

$_root = dirname( __DIR__, 2 );

// Composer dev deps (phpunit-polyfills is required by the WP test suite).
require_once $_root . '/vendor/autoload.php';
if ( ! defined( 'WP_TESTS_PHPUNIT_POLYFILLS_PATH' ) ) {
	define( 'WP_TESTS_PHPUNIT_POLYFILLS_PATH', $_root . '/vendor/yoast/phpunit-polyfills' );
}

require_once $_tests_dir . '/includes/functions.php';

// Load the plugin before WordPress finishes booting.
tests_add_filter(
	'muplugins_loaded',
	static function () use ( $_root ) {
		require $_root . '/consequential-actions.php';
	}
);

require $_tests_dir . '/includes/bootstrap.php';
