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
use function ConsequentialActions\window_seconds;
use function ConsequentialActions\confirmed_recently;
use function ConsequentialActions\confirm_key;

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

	/**
	 * Stub get_role() with a small role/capability map. `shop_manager` is a
	 * privileged custom role (grants manage_options) but is NOT literally
	 * "administrator" — the case the promotion fix must catch.
	 */
	private function stub_roles() : void {
		$admin_caps = array_fill_keys(
			array( 'manage_options', 'promote_users', 'edit_users', 'delete_users', 'create_users', 'activate_plugins', 'install_plugins', 'edit_plugins', 'update_core' ),
			true
		);
		$roles = array(
			'administrator' => (object) array( 'capabilities' => $admin_caps ),
			'editor'        => (object) array( 'capabilities' => array( 'edit_posts' => true, 'edit_others_posts' => true, 'unfiltered_html' => true ) ),
			'subscriber'    => (object) array( 'capabilities' => array( 'read' => true ) ),
			'shop_manager'  => (object) array( 'capabilities' => array( 'manage_options' => true, 'edit_posts' => true ) ),
		);
		Functions\when( 'get_role' )->alias(
			static function ( $slug ) use ( $roles ) {
				return $roles[ $slug ] ?? null;
			}
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
		$this->stub_roles();
		Functions\when( 'get_current_user_id' )->justReturn( 1 );
		Functions\when( 'current_user_can' )->justReturn( true );
		$_POST['role'] = 'administrator';

		$this->assertSame(
			array( 'core/promote-user' ),
			triggered_actions( true, $this->user( 2, 'user@example.test', array( 'editor' ) ) )
		);
	}

	public function test_promotion_to_privileged_custom_role_escalates() : void {
		$this->stub_roles();
		Functions\when( 'get_current_user_id' )->justReturn( 1 );
		Functions\when( 'current_user_can' )->justReturn( true );
		// Not literally "administrator", but grants manage_options.
		$_POST['role'] = 'shop_manager';

		$this->assertSame(
			array( 'core/promote-user' ),
			triggered_actions( true, $this->user( 2, 'user@example.test', array( 'editor' ) ) )
		);
	}

	public function test_sideways_change_to_nonadmin_role_does_not_escalate() : void {
		$this->stub_roles();
		Functions\when( 'get_current_user_id' )->justReturn( 1 );
		Functions\when( 'current_user_can' )->justReturn( true );
		// editor grants no administrator-equivalent capability.
		$_POST['role'] = 'editor';

		$this->assertSame(
			array(),
			triggered_actions( true, $this->user( 2, 'user@example.test', array( 'subscriber' ) ) )
		);
	}

	public function test_no_promotion_when_already_administrator() : void {
		$this->stub_roles();
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

	public function test_window_defaults_to_five_minutes() : void {
		// setUp stubs apply_filters to return the default (arg 2).
		$this->assertSame( 300, window_seconds() );
	}

	public function test_window_is_filterable() : void {
		Functions\when( 'apply_filters' )->alias(
			static function ( $tag, $value ) {
				return 'ca_sudo_window' === $tag ? 0 : $value;
			}
		);
		$this->assertSame( 0, window_seconds() );
	}

	public function test_zero_window_never_counts_as_recently_confirmed() : void {
		Functions\when( 'apply_filters' )->alias(
			static function ( $tag, $value ) {
				return 'ca_sudo_window' === $tag ? 0 : $value;
			}
		);
		Functions\when( 'get_current_user_id' )->justReturn( 5 );
		// A browser session is behind the request; the sessionless case is
		// covered by test_no_session_token_means_no_window().
		Functions\when( 'wp_get_session_token' )->justReturn( 'browser-session-token' );
		// Even if a stale confirm transient exists (and no forced-relogin one-shot),
		// a 0 window must short-circuit to false.
		Functions\when( 'get_transient' )->alias(
			static function ( $key ) {
				return 0 === strpos( (string) $key, 'ca_reauthed_' ) ? false : time();
			}
		);

		$this->assertFalse( confirmed_recently() );
	}

	public function test_recently_confirmed_true_within_window() : void {
		Functions\when( 'get_current_user_id' )->justReturn( 5 );
		// A browser session is behind the request; the sessionless case is
		// covered by test_no_session_token_means_no_window().
		Functions\when( 'wp_get_session_token' )->justReturn( 'browser-session-token' );
		// Confirm transient present, no forced-relogin one-shot → true via the window.
		Functions\when( 'get_transient' )->alias(
			static function ( $key ) {
				return 0 === strpos( (string) $key, 'ca_reauthed_' ) ? false : time();
			}
		);

		$this->assertTrue( confirmed_recently() );
	}

	public function test_forced_relogin_one_shot_passes_once_even_with_zero_window() : void {
		// Hardened mode + window=0: a forced re-login sets a one-shot pass that
		// confirmed_recently() honors exactly once, then consumes (Codex #6 P2).
		Functions\when( 'apply_filters' )->alias(
			static function ( $tag, $value ) {
				return 'ca_sudo_window' === $tag ? 0 : $value;
			}
		);
		Functions\when( 'get_current_user_id' )->justReturn( 5 );
		// A browser session is behind the request; the sessionless case is
		// covered by test_no_session_token_means_no_window().
		Functions\when( 'wp_get_session_token' )->justReturn( 'browser-session-token' );
		$store = array( 'ca_reauthed_5' => 1 );
		Functions\when( 'get_transient' )->alias(
			static function ( $key ) use ( &$store ) {
				return $store[ $key ] ?? false;
			}
		);
		Functions\when( 'delete_transient' )->alias(
			static function ( $key ) use ( &$store ) {
				unset( $store[ $key ] );
				return true;
			}
		);

		$this->assertTrue( confirmed_recently(), 'one-shot honored despite window=0' );
		$this->assertFalse( confirmed_recently(), 'one-shot consumed after one use' );
	}

	/**
	 * A caller with no login session — Application Password, JWT, OAuth, CLI —
	 * has no session token, so it can hold no window no matter what transients
	 * exist for that user. This is the property that makes the fix cover every
	 * bearer credential rather than only core Application Passwords.
	 */
	public function test_no_session_token_means_no_window() : void {
		Functions\when( 'get_current_user_id' )->justReturn( 5 );
		Functions\when( 'wp_get_session_token' )->justReturn( '' );
		// Both a live confirm transient AND a forced-relogin one-shot are present.
		Functions\when( 'get_transient' )->justReturn( time() );

		$this->assertSame( '', confirm_key( 5 ), 'no session ⇒ no addressable window' );
		$this->assertFalse(
			confirmed_recently(),
			'a sessionless caller must not inherit a window, nor consume the one-shot'
		);
	}

	public function test_confirm_key_is_distinct_per_session_and_hides_the_token() : void {
		Functions\when( 'wp_get_session_token' )->justReturn( 'token-one' );
		$first = confirm_key( 5 );

		Functions\when( 'wp_get_session_token' )->justReturn( 'token-two' );
		$second = confirm_key( 5 );

		$this->assertNotSame( $first, $second, 'each session addresses its own window' );
		$this->assertStringNotContainsString( 'token-two', $second, 'the token must not land in an option name' );
	}
}
