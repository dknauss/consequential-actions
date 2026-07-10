<?php
/**
 * Unit tests for ConsequentialActions\triggered_actions() — the pure logic that
 * decides which consequential actions a user create/edit submission triggers.
 */

namespace ConsequentialActions\Tests;

use Brain\Monkey;
use Brain\Monkey\Functions;
use PHPUnit\Framework\TestCase;

use function ConsequentialActions\triggered_actions;

final class TriggeredActionsTest extends TestCase {

	protected function setUp() : void {
		parent::setUp();
		Monkey\setUp();

		// Passthrough stubs for the sanitizers/helpers the logic calls.
		Functions\when( '__' )->returnArg( 1 );
		Functions\when( 'apply_filters' )->returnArg( 2 );
		Functions\when( 'wp_unslash' )->returnArg( 1 );
		Functions\when( 'sanitize_email' )->returnArg( 1 );
		Functions\when( 'sanitize_key' )->returnArg( 1 );

		$_POST = array();
	}

	protected function tearDown() : void {
		$_POST = array();
		Monkey\tearDown();
		parent::tearDown();
	}

	/** Build a minimal user object shaped like WP_User for the fields we read. */
	private function user( int $id, string $email = 'user@example.test', array $roles = array( 'subscriber' ) ) : object {
		return (object) array(
			'ID'         => $id,
			'user_email' => $email,
			'roles'      => $roles,
		);
	}

	public function test_create_user_triggers_create() : void {
		Functions\when( 'get_current_user_id' )->justReturn( 1 );

		$this->assertSame(
			array( 'core/create-user' ),
			triggered_actions( false, null )
		);
	}

	public function test_own_password_change() : void {
		Functions\when( 'get_current_user_id' )->justReturn( 5 );
		$_POST['pass1'] = 'a-new-password';

		$this->assertSame(
			array( 'core/change-own-password' ),
			triggered_actions( true, $this->user( 5 ) )
		);
	}

	public function test_other_users_password_change() : void {
		Functions\when( 'get_current_user_id' )->justReturn( 1 );
		$_POST['pass1'] = 'a-new-password';

		$this->assertSame(
			array( 'core/change-user-password' ),
			triggered_actions( true, $this->user( 2 ) )
		);
	}

	public function test_own_email_change() : void {
		Functions\when( 'get_current_user_id' )->justReturn( 5 );
		$_POST['email'] = 'new@example.test';

		$this->assertSame(
			array( 'core/change-own-email' ),
			triggered_actions( true, $this->user( 5, 'old@example.test' ) )
		);
	}

	public function test_unchanged_email_triggers_nothing() : void {
		Functions\when( 'get_current_user_id' )->justReturn( 5 );
		$_POST['email'] = 'same@example.test';

		$this->assertSame(
			array(),
			triggered_actions( true, $this->user( 5, 'same@example.test' ) )
		);
	}

	public function test_promotion_to_administrator() : void {
		Functions\when( 'get_current_user_id' )->justReturn( 1 );
		Functions\when( 'current_user_can' )->justReturn( true );
		$_POST['role'] = 'administrator';

		$this->assertSame(
			array( 'core/promote-user' ),
			triggered_actions( true, $this->user( 2, 'user@example.test', array( 'editor' ) ) )
		);
	}

	public function test_no_promotion_when_already_administrator() : void {
		Functions\when( 'get_current_user_id' )->justReturn( 1 );
		Functions\when( 'current_user_can' )->justReturn( true );
		$_POST['role'] = 'administrator';

		$this->assertSame(
			array(),
			triggered_actions( true, $this->user( 2, 'user@example.test', array( 'administrator' ) ) )
		);
	}

	public function test_promotion_requires_capability() : void {
		Functions\when( 'get_current_user_id' )->justReturn( 1 );
		Functions\when( 'current_user_can' )->justReturn( false );
		$_POST['role'] = 'administrator';

		$this->assertSame(
			array(),
			triggered_actions( true, $this->user( 2, 'user@example.test', array( 'editor' ) ) )
		);
	}

	public function test_plain_self_edit_triggers_nothing() : void {
		Functions\when( 'get_current_user_id' )->justReturn( 5 );

		$this->assertSame(
			array(),
			triggered_actions( true, $this->user( 5 ) )
		);
	}

	public function test_password_and_email_change_together() : void {
		Functions\when( 'get_current_user_id' )->justReturn( 5 );
		$_POST['pass1'] = 'a-new-password';
		$_POST['email'] = 'new@example.test';

		$this->assertSame(
			array( 'core/change-own-password', 'core/change-own-email' ),
			triggered_actions( true, $this->user( 5, 'old@example.test' ) )
		);
	}
}
