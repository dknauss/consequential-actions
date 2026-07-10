<?php
/**
 * Unit-test bootstrap.
 *
 * WordPress is NOT loaded. Brain\Monkey stubs the WordPress functions the code
 * calls. The two no-op hook functions below exist ONLY so the plugin file (which
 * registers hooks at include time) can be required once without a fatal — they
 * live here, in the test harness, never in the production plugin.
 */

require_once __DIR__ . '/../vendor/autoload.php';

// Constants the plugin expects from WordPress core.
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}
if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
	define( 'MINUTE_IN_SECONDS', 60 );
}

// The plugin calls these at include time to register hooks; stub as no-ops so a
// single require does not fatal. triggered_actions() (the unit under test) never
// calls them, so Brain\Monkey does not need to mock them.
if ( ! function_exists( 'add_action' ) ) {
	function add_action() {}
}
if ( ! function_exists( 'add_filter' ) ) {
	function add_filter() {}
}

require_once __DIR__ . '/../consequential-actions.php';
