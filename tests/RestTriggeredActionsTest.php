<?php
/**
 * Unit tests for ConsequentialActions\triggered_actions_rest() — the REST twin of
 * triggered_actions(). Same catalog, but reads a request's own field names
 * (password/email/roles) so the gate covers /wp/v2/users as well as the forms.
 */

namespace ConsequentialActions\Tests;

use Brain\Monkey;
use Brain\Monkey\Functions;
use PHPUnit\Framework\TestCase;

use function ConsequentialActions\triggered_actions_rest;

final class RestTriggeredActionsTest extends TestCase {

	protected function setUp() : void {
		parent::setUp();
		Monkey\setUp();

		Functions\when( '__' )->returnArg( 1 );
		Functions\when( 'apply_filters' )->returnArg( 2 );
		Functions\when( 'sanitize_email' )->returnArg( 1 );
		Functions\when( 'sanitize_key' )->returnArg( 1 );
	}

	protected function tearDown() : void {
		Monkey\tearDown();
		parent::tearDown();
	}

	/** Minimal user object shaped like WP_User for the fields the detector reads. */
	private function user( int $id, string $email = 'user@example.test', array $roles = array( 'subscriber' ) ) : object {
		return (object) array(
			'ID'         => $id,
			'user_email' => $email,
			'roles'      => $roles,
		);
	}

	/** Same role/capability map as the form test, including a privileged custom role. */
	private function stub_roles() : void {
		$admin_caps = array_fill_keys(
			array( 'manage_options', 'promote_users', 'edit_users', 'delete_users', 'create_users', 'activate_plugins', 'install_plugins', 'edit_plugins', 'update_core' ),
			true
		);
		$roles = array(
			'administrator' => (object) array( 'capabilities' => $admin_caps ),
			'editor'        => (object) array( 'capabilities' => array( 'edit_posts' => true ) ),
			'subscriber'    => (object) array( 'capabilities' => array( 'read' => true ) ),
			'shop_manager'  => (object) array( 'capabilities' => array( 'manage_options' => true, 'edit_posts' => true ) ),
		);
		Functions\when( 'get_role' )->alias(
			static function ( $slug ) use ( $roles ) {
				return $roles[ $slug ] ?? null;
			}
		);
	}

	public function test_create_ignores_fields_and_triggers_create() : void {
		Functions\when( 'get_current_user_id' )->justReturn( 1 );

		// Even a create that sets password + admin role is just "create-user":
		// the creation itself is the consequential action (a backdoor admin).
		$this->assertSame(
			array( 'core/create-user' ),
			triggered_actions_rest(
				array( 'password' => 'x', 'roles' => array( 'administrator' ) ),
				false,
				null
			)
		);
	}

	public function test_other_users_password_change_over_rest() : void {
		Functions\when( 'get_current_user_id' )->justReturn( 1 );

		$this->assertSame(
			array( 'core/change-user-password' ),
			triggered_actions_rest( array( 'password' => 'new-pass' ), true, $this->user( 2 ) )
		);
	}

	public function test_own_email_change_over_rest() : void {
		Functions\when( 'get_current_user_id' )->justReturn( 5 );

		$this->assertSame(
			array( 'core/change-own-email' ),
			triggered_actions_rest( array( 'email' => 'new@example.test' ), true, $this->user( 5, 'old@example.test' ) )
		);
	}

	public function test_unchanged_email_triggers_nothing() : void {
		Functions\when( 'get_current_user_id' )->justReturn( 5 );

		$this->assertSame(
			array(),
			triggered_actions_rest( array( 'email' => 'same@example.test' ), true, $this->user( 5, 'same@example.test' ) )
		);
	}

	public function test_roles_array_promotion_to_privileged_custom_role() : void {
		$this->stub_roles();
		Functions\when( 'get_current_user_id' )->justReturn( 1 );
		Functions\when( 'current_user_can' )->justReturn( true );

		// REST sends roles as an array; shop_manager is not literally administrator
		// but grants manage_options, so it must still be caught.
		$this->assertSame(
			array( 'core/promote-user' ),
			triggered_actions_rest( array( 'roles' => array( 'shop_manager' ) ), true, $this->user( 2, 'user@example.test', array( 'editor' ) ) )
		);
	}

	public function test_promotion_requires_capability() : void {
		Functions\when( 'get_current_user_id' )->justReturn( 1 );
		Functions\when( 'current_user_can' )->justReturn( false );

		$this->assertSame(
			array(),
			triggered_actions_rest( array( 'roles' => array( 'administrator' ) ), true, $this->user( 2, 'user@example.test', array( 'editor' ) ) )
		);
	}

	public function test_sideways_role_change_does_not_escalate() : void {
		$this->stub_roles();
		Functions\when( 'get_current_user_id' )->justReturn( 1 );
		Functions\when( 'current_user_can' )->justReturn( true );

		$this->assertSame(
			array(),
			triggered_actions_rest( array( 'roles' => array( 'editor' ) ), true, $this->user( 2, 'user@example.test', array( 'subscriber' ) ) )
		);
	}

	public function test_password_and_email_change_together_over_rest() : void {
		Functions\when( 'get_current_user_id' )->justReturn( 1 );

		$this->assertSame(
			array( 'core/change-user-password', 'core/change-user-email' ),
			triggered_actions_rest(
				array( 'password' => 'new-pass', 'email' => 'new@example.test' ),
				true,
				$this->user( 2, 'old@example.test' )
			)
		);
	}

	public function test_plain_update_triggers_nothing() : void {
		Functions\when( 'get_current_user_id' )->justReturn( 5 );

		$this->assertSame(
			array(),
			triggered_actions_rest( array( 'name' => 'New Display Name' ), true, $this->user( 5 ) )
		);
	}
}
