<?php
/**
 * Sanity check that the integration harness boots: real WordPress is loaded and
 * the plugin's hooks are registered.
 */

declare( strict_types = 1 );

namespace ConsequentialActions\Tests\Integration;

use WP_UnitTestCase;

use function ConsequentialActions\actions;

final class SmokeTest extends WP_UnitTestCase {

	public function test_wordpress_is_loaded(): void {
		$this->assertTrue( defined( 'ABSPATH' ) );
		$this->assertTrue( function_exists( 'wp_insert_user' ) );
	}

	public function test_plugin_is_loaded_and_registry_populated(): void {
		$this->assertTrue( function_exists( 'ConsequentialActions\\actions' ) );
		$this->assertArrayHasKey( 'core/promote-user', actions() );
	}

	public function test_gate_hooks_are_registered(): void {
		$this->assertNotFalse( has_action( 'user_profile_update_errors', 'ConsequentialActions\\gate' ) );
		$this->assertNotFalse( has_action( 'load-users.php', 'ConsequentialActions\\gate_bulk_promote' ) );
		$this->assertNotFalse( has_filter( 'rest_pre_dispatch', 'ConsequentialActions\\gate_rest' ) );
	}
}
