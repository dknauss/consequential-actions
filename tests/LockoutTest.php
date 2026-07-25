<?php
/**
 * Unit tests for the failed-confirm lockout — the bound that stops the inline
 * confirm field from being used to brute-force the actor's current password.
 *
 * Verifies the pure counter logic (is_locked_out / record_failed_confirm /
 * clear_failed_confirms) against an in-memory transient store, with no live
 * WordPress. The threat: a stolen cookie or leaked Application Password could
 * otherwise guess the actor's password through unbounded confirm attempts.
 */

namespace ConsequentialActions\Tests;

use Brain\Monkey;
use Brain\Monkey\Functions;
use PHPUnit\Framework\TestCase;

use function ConsequentialActions\clear_failed_confirms;
use function ConsequentialActions\is_locked_out;
use function ConsequentialActions\record_failed_confirm;

final class LockoutTest extends TestCase {

	/** @var array<string,mixed> In-memory transient store. */
	private array $store = array();

	protected function setUp() : void {
		parent::setUp();
		Monkey\setUp();

		$this->store = array();

		Functions\when( '__' )->returnArg( 1 );
		// Default: filters return their provided default unchanged (cap = 5).
		Functions\when( 'apply_filters' )->returnArg( 2 );

		Functions\when( 'get_transient' )->alias(
			function ( $key ) {
				return $this->store[ $key ] ?? false;
			}
		);
		Functions\when( 'set_transient' )->alias(
			function ( $key, $value ) {
				$this->store[ $key ] = $value;
				return true;
			}
		);
		Functions\when( 'delete_transient' )->alias(
			function ( $key ) {
				unset( $this->store[ $key ] );
				return true;
			}
		);
	}

	protected function tearDown() : void {
		Monkey\tearDown();
		parent::tearDown();
	}

	public function test_not_locked_out_before_any_failures() : void {
		$this->assertFalse( is_locked_out( 7 ) );
	}

	public function test_locks_out_only_after_reaching_the_cap() : void {
		// Default cap is 5: the first four failures stay under the line.
		for ( $i = 1; $i <= 4; $i++ ) {
			record_failed_confirm( 7 );
			$this->assertFalse( is_locked_out( 7 ), "should not lock out after {$i} failure(s)" );
		}
		// The fifth failure trips the lockout.
		record_failed_confirm( 7 );
		$this->assertTrue( is_locked_out( 7 ) );
	}

	public function test_lockout_is_per_user() : void {
		for ( $i = 0; $i < 5; $i++ ) {
			record_failed_confirm( 7 );
		}
		$this->assertTrue( is_locked_out( 7 ) );
		$this->assertFalse( is_locked_out( 8 ), 'a different user must not inherit the lockout' );
	}

	public function test_success_clears_the_counter() : void {
		for ( $i = 0; $i < 5; $i++ ) {
			record_failed_confirm( 7 );
		}
		$this->assertTrue( is_locked_out( 7 ) );

		clear_failed_confirms( 7 );
		$this->assertFalse( is_locked_out( 7 ), 'a successful confirm must reset the counter' );
	}

	public function test_filter_of_zero_disables_the_lockout() : void {
		// ca_max_attempts => 0 means "never lock out" (opt-out escape hatch).
		Functions\when( 'apply_filters' )->alias(
			function ( $hook, $default ) {
				return 'ca_max_attempts' === $hook ? 0 : $default;
			}
		);

		for ( $i = 0; $i < 20; $i++ ) {
			record_failed_confirm( 7 );
		}
		$this->assertFalse( is_locked_out( 7 ) );
	}
}
