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

// Minimal WP_User stand-in: on_login() type-checks its argument against it.
// Only the ID property is read.
if ( ! class_exists( 'WP_User' ) ) {
	class WP_User {
		public $ID;

		public function __construct( int $id = 0 ) {
			$this->ID = $id;
		}
	}
}

// Minimal WP_Session_Tokens stand-in. verified_session_token() asks it whether a
// token is one of the user's live sessions; tests declare which tokens are live
// via the $valid list, so the verification branch is genuinely exercised rather
// than stubbed away.
if ( ! class_exists( 'WP_Session_Tokens' ) ) {
	class WP_Session_Tokens {
		/** @var string[] Tokens this stub treats as live sessions. */
		public static $valid = array();

		public static function get_instance( $user_id ) {
			return new self();
		}

		public function verify( $token ) {
			return in_array( $token, self::$valid, true );
		}
	}
}

require_once __DIR__ . '/../consequential-actions.php';
