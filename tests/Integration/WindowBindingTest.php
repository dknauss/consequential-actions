<?php
/**
 * Integration coverage for the session-bound sudo window.
 *
 * The window used to be a bare per-user transient, so one browser's confirmation
 * elevated every concurrent session and every API credential on that account
 * (finding CA-1). These tests pin the binding: a window belongs to the login
 * session that opened it, and a caller with no login session — an Application
 * Password, JWT, OAuth, or any other bearer credential — can never hold one.
 */

declare( strict_types = 1 );

namespace ConsequentialActions\Tests\Integration;

use WP_REST_Request;
use WP_Session_Tokens;
use WP_UnitTestCase;

use function ConsequentialActions\confirm_key;
use function ConsequentialActions\confirmed_recently;
use function ConsequentialActions\mark_confirmed;

final class WindowBindingTest extends WP_UnitTestCase {

	private int $admin_id;

	public function set_up(): void {
		parent::set_up();
		$this->admin_id = self::factory()->user->create(
			array(
				'role'       => 'administrator',
				'user_pass'  => 'adminpass',
				'user_email' => 'admin-window@example.test',
			)
		);
		wp_set_current_user( $this->admin_id );
		do_action( 'rest_api_init' );
	}

	public function tear_down(): void {
		unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
		parent::tear_down();
	}

	/**
	 * Put a real login session behind the current request, so
	 * wp_get_session_token() resolves the way it does for a browser.
	 *
	 * @param int $user_id User to open the session for.
	 * @return string The session token.
	 */
	private function start_session( int $user_id ): string {
		$expiry  = time() + DAY_IN_SECONDS;
		$manager = WP_Session_Tokens::get_instance( $user_id );
		$token   = $manager->create( $expiry );

		$_COOKIE[ LOGGED_IN_COOKIE ] = wp_generate_auth_cookie( $user_id, $expiry, 'logged_in', $token );

		return $token;
	}

	/**
	 * The CA-1 regression: a window opened by the legitimate browser must not
	 * elevate a second, concurrent session on the same account.
	 */
	public function test_window_from_one_session_does_not_elevate_another(): void {
		$this->start_session( $this->admin_id );
		mark_confirmed( $this->admin_id );
		$this->assertTrue( confirmed_recently(), 'sanity: the opening session holds the window' );

		// A second session for the same user — a cloned cookie, or a second device.
		$this->start_session( $this->admin_id );

		$this->assertFalse(
			confirmed_recently(),
			'a window opened in one session must not carry into another session'
		);
	}

	/**
	 * A caller with no login session (Application Password, JWT, OAuth, CLI)
	 * can neither open a window nor inherit one.
	 */
	public function test_a_sessionless_caller_can_never_hold_a_window(): void {
		// A browser opens a window.
		$this->start_session( $this->admin_id );
		mark_confirmed( $this->admin_id );
		$this->assertTrue( confirmed_recently(), 'sanity: the browser holds the window' );

		// Same user, but now authenticated without a login cookie.
		unset( $_COOKIE[ LOGGED_IN_COOKIE ] );

		$this->assertFalse(
			confirmed_recently(),
			'a bearer-credential caller must not inherit the browser window'
		);

		// And it cannot open one of its own.
		mark_confirmed( $this->admin_id );
		$this->assertFalse( confirmed_recently(), 'a sessionless caller must not be able to open a window' );
	}

	public function test_key_is_empty_without_a_session_and_distinct_per_session(): void {
		$this->assertSame( '', confirm_key( $this->admin_id ), 'no session ⇒ no addressable window' );

		$this->start_session( $this->admin_id );
		$first = confirm_key( $this->admin_id );

		$this->start_session( $this->admin_id );
		$second = confirm_key( $this->admin_id );

		$this->assertNotSame( '', $first );
		$this->assertNotSame( $first, $second, 'each session addresses its own window' );
		$this->assertStringNotContainsString(
			wp_get_session_token(),
			$second,
			'the raw session token must not appear in an option name'
		);
	}

	/** The legitimate flow must keep working: same session, window applies. */
	public function test_window_applies_within_the_same_session(): void {
		$this->start_session( $this->admin_id );
		mark_confirmed( $this->admin_id );

		$req = new WP_REST_Request( 'POST', '/wp/v2/users/me' );
		$req->set_param( 'email', 'same-session@example.test' );
		$res = rest_do_request( $req );

		$this->assertSame( 200, $res->get_status() );
		$this->assertSame( 'same-session@example.test', get_userdata( $this->admin_id )->user_email );
	}
}
