<?php
/**
 * Integration coverage for gate_bulk_promote() on load-users.php — the live bulk
 * "Change role" interception, driven exactly as core's WP_Users_List_Table does,
 * with a real bulk-users nonce and real bcrypt.
 *
 * The gate answers an unconfirmed escalation with wp_die(), so each case fires the
 * load-users.php hook under a throwing wp_die handler and inspects the message
 * (null message = the gate let the request through).
 */

declare( strict_types = 1 );

namespace ConsequentialActions\Tests\Integration;

use WP_UnitTestCase;

final class BulkGateTest extends WP_UnitTestCase {

	private int $admin_id;
	private int $subscriber_id;

	public function set_up(): void {
		parent::set_up();
		$this->admin_id      = self::factory()->user->create(
			array(
				'role'      => 'administrator',
				'user_pass' => 'adminpass',
			)
		);
		$this->subscriber_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		wp_set_current_user( $this->admin_id );
	}

	public function tear_down(): void {
		$_REQUEST = array();
		$_GET     = array();
		$_POST    = array();
		parent::tear_down();
	}

	/**
	 * Fire load-users.php with the given request. Returns the wp_die message, or
	 * null if the gate let the request through (no wp_die).
	 */
	private function run_gate( array $request ): ?string {
		$_REQUEST = $request;
		$_GET     = $request;
		$captured = null;

		add_filter(
			'wp_die_handler',
			static function () use ( &$captured ) {
				return static function ( $message ) use ( &$captured ) {
					$captured = is_wp_error( $message ) ? $message->get_error_message() : (string) $message;
					throw new \Exception( 'wp_die' );
				};
			}
		);

		try {
			do_action( 'load-users.php' );
		} catch ( \Exception $e ) {
			// Expected when the gate blocks.
		} finally {
			remove_all_filters( 'wp_die_handler' );
			$_REQUEST = array();
			$_GET     = array();
		}

		return $captured;
	}

	private function bulk_params( array $extra = array() ): array {
		return array_merge(
			array(
				'changeit' => 'Change',
				'new_role' => 'administrator',
				'users'    => array( (string) $this->subscriber_id ),
				'_wpnonce' => wp_create_nonce( 'bulk-users' ),
			),
			$extra
		);
	}

	public function test_bulk_promote_is_blocked_without_confirmation(): void {
		$message = $this->run_gate( $this->bulk_params() );

		$this->assertNotNull( $message, 'the gate should wp_die on an unconfirmed bulk promote' );
		$this->assertStringContainsString( 'Grant administrator privileges', $message );
	}

	public function test_bulk_promote_is_blocked_with_wrong_password(): void {
		$message = $this->run_gate( $this->bulk_params( array( 'ca_confirm_password' => 'not-the-password' ) ) );

		$this->assertNotNull( $message );
		$this->assertStringContainsString( 'incorrect', $message );
	}

	public function test_bulk_promote_passes_with_correct_password(): void {
		$message = $this->run_gate( $this->bulk_params( array( 'ca_confirm_password' => 'adminpass' ) ) );

		$this->assertNull( $message, 'a correct password should pass the gate (no wp_die)' );
	}

	public function test_crafted_action_promote_without_changeit_is_blocked(): void {
		// No `changeit`, but action=promote — core's current_action() still resolves
		// this to a promote and runs set_role(); the gate must catch it too.
		$message = $this->run_gate(
			array(
				'action'   => 'promote',
				'new_role' => 'administrator',
				'users'    => array( (string) $this->subscriber_id ),
				'_wpnonce' => wp_create_nonce( 'bulk-users' ),
			)
		);

		$this->assertNotNull( $message, 'action=promote must be gated like changeit' );
		$this->assertStringContainsString( 'Grant administrator privileges', $message );
	}

	public function test_non_escalating_change_passes_through(): void {
		// subscriber -> editor is not administrator-equivalent; not a gated action.
		$message = $this->run_gate( $this->bulk_params( array( 'new_role' => 'editor' ) ) );

		$this->assertNull( $message, 'a non-escalating bulk change should not be gated' );
	}
}
