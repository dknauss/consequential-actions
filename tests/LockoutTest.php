<?php
/**
 * Unit tests for the failed-confirm lockout — the bound that stops the inline
 * confirm field from being used to brute-force the actor's current password.
 *
 * Verifies the pure counter logic (is_locked_out / reserve_attempt /
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
use function ConsequentialActions\lockout_seconds;
use function ConsequentialActions\reserve_attempt;

final class LockoutTest extends TestCase {

	/** @var array<string,mixed> In-memory transient store. */
	private array $store = array();

	/** @var array<string,int> In-memory object-cache store (keyed "group:key"). */
	private array $cache = array();

	protected function setUp() : void {
		parent::setUp();
		Monkey\setUp();

		$this->store = array();
		$this->cache = array();

		Functions\when( '__' )->returnArg( 1 );
		// Default: filters return their provided default unchanged (cap = 5).
		Functions\when( 'apply_filters' )->returnArg( 2 );
		// Default: no persistent object cache — exercise the transient path.
		Functions\when( 'wp_using_ext_object_cache' )->justReturn( false );

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

	/**
	 * Switch the code under test onto the atomic object-cache path, backed by an
	 * in-memory cache whose wp_cache_add/incr behave like the real atomics.
	 */
	private function enable_object_cache() : void {
		Functions\when( 'wp_using_ext_object_cache' )->justReturn( true );
		Functions\when( 'wp_cache_add' )->alias(
			function ( $key, $value, $group = '' ) {
				$id = "{$group}:{$key}";
				if ( array_key_exists( $id, $this->cache ) ) {
					return false; // add-if-absent, like the real atomic add.
				}
				$this->cache[ $id ] = (int) $value;
				return true;
			}
		);
		Functions\when( 'wp_cache_incr' )->alias(
			function ( $key, $offset = 1, $group = '' ) {
				$id = "{$group}:{$key}";
				if ( ! array_key_exists( $id, $this->cache ) ) {
					return false;
				}
				$this->cache[ $id ] += (int) $offset;
				return $this->cache[ $id ];
			}
		);
		Functions\when( 'wp_cache_get' )->alias(
			function ( $key, $group = '' ) {
				return $this->cache[ "{$group}:{$key}" ] ?? false;
			}
		);
		Functions\when( 'wp_cache_set' )->alias(
			function ( $key, $value, $group = '' ) {
				$this->cache[ "{$group}:{$key}" ] = (int) $value;
				return true;
			}
		);
		Functions\when( 'wp_cache_delete' )->alias(
			function ( $key, $group = '' ) {
				unset( $this->cache[ "{$group}:{$key}" ] );
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
			reserve_attempt( 7 );
			$this->assertFalse( is_locked_out( 7 ), "should not lock out after {$i} failure(s)" );
		}
		// The fifth failure trips the lockout.
		reserve_attempt( 7 );
		$this->assertTrue( is_locked_out( 7 ) );
	}

	public function test_lockout_is_per_user() : void {
		for ( $i = 0; $i < 5; $i++ ) {
			reserve_attempt( 7 );
		}
		$this->assertTrue( is_locked_out( 7 ) );
		$this->assertFalse( is_locked_out( 8 ), 'a different user must not inherit the lockout' );
	}

	public function test_success_clears_the_counter() : void {
		for ( $i = 0; $i < 5; $i++ ) {
			reserve_attempt( 7 );
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
			reserve_attempt( 7 );
		}
		$this->assertFalse( is_locked_out( 7 ) );
		$this->assertSame( 0, reserve_attempt( 7 ), 'reserve is a no-op returning 0 when disabled' );
	}

	/**
	 * reserve_attempt() returns the running count and bumps each call, so the caller
	 * can reject a reservation past the cap BEFORE hashing — the fix for the
	 * check-then-count race. (Transient path.) (Codex #4 P1 — reserve-before-check.)
	 */
	public function test_reserve_returns_running_count_transient() : void {
		$this->assertSame( 1, reserve_attempt( 7 ) );
		$this->assertSame( 2, reserve_attempt( 7 ) );
		$this->assertSame( 3, reserve_attempt( 7 ) );
		$this->assertSame( 4, reserve_attempt( 7 ) );
		$this->assertSame( 5, reserve_attempt( 7 ) );
		// The 6th reservation exceeds the default cap of 5 — the caller blocks here
		// without performing a password check.
		$this->assertSame( 6, reserve_attempt( 7 ) );
	}

	/** The atomic object-cache path returns the same running count. */
	public function test_reserve_returns_running_count_object_cache() : void {
		$this->enable_object_cache();
		$this->assertSame( 1, reserve_attempt( 7 ) );
		$this->assertSame( 2, reserve_attempt( 7 ) );
		$this->assertSame( 3, reserve_attempt( 7 ) );
	}

	/**
	 * A zero (or negative) ca_lockout_seconds must NOT reach the transient as a
	 * 0 TTL — WordPress reads that as "never expire", which would make the
	 * lockout permanent. It falls back to the default instead. (Codex #4 P2.)
	 */
	public function test_nonpositive_cooldown_falls_back_to_default() : void {
		Functions\when( 'apply_filters' )->alias(
			function ( $hook, $default ) {
				return 'ca_lockout_seconds' === $hook ? 0 : $default;
			}
		);
		$this->assertSame( 5 * 60, lockout_seconds(), 'zero cooldown must normalise to the default' );
	}

	/**
	 * The atomic object-cache path enforces the same cap. Exercising it proves
	 * record/is_locked_out/clear all agree on the cache store, not just the
	 * transient store. (Codex #4 P1 — atomic increment path.)
	 */
	public function test_object_cache_path_locks_out_after_cap_and_clears() : void {
		$this->enable_object_cache();

		for ( $i = 1; $i <= 4; $i++ ) {
			reserve_attempt( 7 );
			$this->assertFalse( is_locked_out( 7 ), "cache path should not lock out after {$i}" );
		}
		reserve_attempt( 7 );
		$this->assertTrue( is_locked_out( 7 ), 'cache path must lock out at the cap' );

		clear_failed_confirms( 7 );
		$this->assertFalse( is_locked_out( 7 ), 'clear must reset the cache counter' );
	}
}
