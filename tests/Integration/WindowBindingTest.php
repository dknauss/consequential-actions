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

	/**
	 * wp_get_session_token() only *parses* the cookie — wp_parse_auth_cookie()
	 * explodes on '|', counts four parts, and returns them, verifying no HMAC
	 * and no expiry. So a caller with no session at all can make it non-empty.
	 * Nothing may trust it without verifying the token against the user's own
	 * session store.
	 */
	public function test_a_forged_login_cookie_is_not_a_session(): void {
		$_COOKIE[ LOGGED_IN_COOKIE ] = 'someone|9999999999|forged-token|deadbeef';

		$this->assertSame(
			'',
			\ConsequentialActions\verified_session_token( $this->admin_id ),
			'a forged cookie must not pass as a live session'
		);
		$this->assertSame( '', confirm_key( $this->admin_id ) );
		$this->assertFalse( confirmed_recently() );
	}

	/**
	 * The forged cookie must not be able to consume hardened mode's one-time
	 * pass, which is keyed per-user and so is the one piece of state a
	 * sessionless caller could otherwise race the victim for.
	 */
	public function test_a_forged_cookie_cannot_consume_the_hardened_one_shot(): void {
		set_transient( \ConsequentialActions\reauthed_key( $this->admin_id ), 1, 900 );
		$_COOKIE[ LOGGED_IN_COOKIE ] = 'someone|9999999999|forged-token|deadbeef';

		$this->assertFalse( confirmed_recently(), 'a forged cookie must not consume the one-shot' );
		$this->assertNotFalse(
			get_transient( \ConsequentialActions\reauthed_key( $this->admin_id ) ),
			'and must not burn it either — the real browser still needs it'
		);
	}

	/**
	 * Hardened mode, consumption half: the one-time pass a forced re-login
	 * leaves behind must authorize the retry AND open the session-bound window,
	 * because that first post-login request is the earliest moment a session
	 * exists to bind to.
	 *
	 * Regression guard: binding the window initially broke hardened mode
	 * outright. on_login() runs before the new cookie is in $_COOKIE, so
	 * mark_confirmed() there silently stored nothing, and with a non-zero window
	 * the user looped logout → login → retry → logout forever.
	 *
	 * The producing half (on_login always granting the pass) is covered in the
	 * unit suite, where CA_TERMINATE_SESSION can be defined without forcing
	 * every other integration test down the logout path.
	 */
	public function test_hardened_one_shot_authorizes_the_retry_and_opens_the_window(): void {
		set_transient( \ConsequentialActions\reauthed_key( $this->admin_id ), 1, 900 );

		// The first request after the forced re-login carries a real session.
		$this->start_session( $this->admin_id );

		$this->assertTrue( confirmed_recently(), 'the retry after a forced re-login must be authorized' );
		$this->assertFalse(
			get_transient( \ConsequentialActions\reauthed_key( $this->admin_id ) ),
			'the one-shot is consumed'
		);
		$this->assertTrue(
			confirmed_recently(),
			'and the window it opened covers the rest of the TTL, so the user is not looped out'
		);
	}
}
