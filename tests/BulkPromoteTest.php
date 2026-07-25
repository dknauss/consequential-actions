<?php
/**
 * Unit tests for ConsequentialActions\escalating_bulk_targets() — the pure logic
 * behind gating the Users-list bulk "Change role" action (issue #3). Given the
 * selected user ids, the new role key, and a per-user current-roles lookup, it
 * returns the ids whose promotion escalates them to administrator-equivalent
 * authority (reusing role_change_escalates(), so a privileged CUSTOM role counts,
 * not just the literal "administrator" slug).
 */

namespace ConsequentialActions\Tests;

use Brain\Monkey;
use Brain\Monkey\Functions;
use PHPUnit\Framework\TestCase;

use function ConsequentialActions\escalating_bulk_targets;

final class BulkPromoteTest extends TestCase {

	protected function setUp() : void {
		parent::setUp();
		Monkey\setUp();
		$this->stub_roles();
	}

	protected function tearDown() : void {
		Monkey\tearDown();
		parent::tearDown();
	}

	/**
	 * Role/capability map. `shop_manager` is a privileged custom role (grants
	 * manage_options) that is NOT literally "administrator" — the case detection
	 * by capability must catch. `CustomAdmin` is a privileged custom role with a
	 * mixed-case key and no lowercase twin. `editor` is non-privileged.
	 */
	private function stub_roles() : void {
		$admin_caps = array_fill_keys(
			array( 'manage_options', 'promote_users', 'edit_users', 'delete_users', 'create_users', 'activate_plugins', 'install_plugins', 'edit_plugins', 'update_core' ),
			true
		);
		$map = array(
			'administrator' => $admin_caps,
			'shop_manager'  => array( 'manage_options' => true, 'read' => true ),
			'CustomAdmin'   => array( 'manage_options' => true, 'read' => true ),
			'editor'        => array( 'edit_posts' => true, 'read' => true ),
			'subscriber'    => array( 'read' => true ),
		);
		Functions\when( 'get_role' )->alias(
			function ( $slug ) use ( $map ) {
				return isset( $map[ $slug ] ) ? (object) array( 'capabilities' => $map[ $slug ] ) : null;
			}
		);
	}

	/** Build a lookup callable from an id => current-role-slugs map. */
	private function roles_of( array $by_id ) : callable {
		return static function ( int $id ) use ( $by_id ) : array {
			return $by_id[ $id ] ?? array();
		};
	}

	public function test_promoting_a_subscriber_to_admin_escalates() : void {
		$targets = escalating_bulk_targets(
			'administrator',
			array( 5 ),
			$this->roles_of( array( 5 => array( 'subscriber' ) ) )
		);
		$this->assertSame( array( 5 ), $targets );
	}

	public function test_existing_admin_is_not_an_escalation() : void {
		$targets = escalating_bulk_targets(
			'administrator',
			array( 5 ),
			$this->roles_of( array( 5 => array( 'administrator' ) ) )
		);
		$this->assertSame( array(), $targets );
	}

	public function test_privileged_custom_role_is_caught() : void {
		// subscriber -> shop_manager grants manage_options the user lacked.
		$targets = escalating_bulk_targets(
			'shop_manager',
			array( 9 ),
			$this->roles_of( array( 9 => array( 'subscriber' ) ) )
		);
		$this->assertSame( array( 9 ), $targets );
	}

	/**
	 * A mixed-case custom role key must be matched exactly. sanitize_key() would
	 * lowercase 'CustomAdmin' to a non-existent role, so get_role() would miss it
	 * and the escalation would go ungated while core still assigns it.
	 */
	public function test_mixed_case_custom_role_key_is_matched() : void {
		$targets = escalating_bulk_targets(
			'CustomAdmin',
			array( 9 ),
			$this->roles_of( array( 9 => array( 'subscriber' ) ) )
		);
		$this->assertSame( array( 9 ), $targets );
	}

	public function test_sideways_move_to_nonprivileged_role_does_not_escalate() : void {
		$targets = escalating_bulk_targets(
			'editor',
			array( 7 ),
			$this->roles_of( array( 7 => array( 'subscriber' ) ) )
		);
		$this->assertSame( array(), $targets );
	}

	public function test_empty_new_role_returns_no_targets() : void {
		$targets = escalating_bulk_targets(
			'',
			array( 5, 6 ),
			$this->roles_of( array( 5 => array( 'subscriber' ), 6 => array( 'subscriber' ) ) )
		);
		$this->assertSame( array(), $targets );
	}

	public function test_mixed_batch_returns_only_escalating_ids() : void {
		$targets = escalating_bulk_targets(
			'administrator',
			array( 5, 6, 7 ),
			$this->roles_of(
				array(
					5 => array( 'subscriber' ),    // escalates
					6 => array( 'administrator' ), // already admin — no
					7 => array( 'editor' ),        // escalates (editor lacks admin caps)
				)
			)
		);
		$this->assertSame( array( 5, 7 ), $targets );
	}
}
