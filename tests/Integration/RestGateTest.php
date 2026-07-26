<?php
/**
 * Integration coverage for gate_rest() on /wp/v2/users — the live REST save path,
 * with real WordPress, real bcrypt, and the real rest_pre_dispatch chain.
 */

declare( strict_types = 1 );

namespace ConsequentialActions\Tests\Integration;

use WP_REST_Request;
use WP_UnitTestCase;

final class RestGateTest extends WP_UnitTestCase {

	private int $admin_id;

	public function set_up(): void {
		parent::set_up();
		$this->admin_id = self::factory()->user->create(
			array(
				'role'       => 'administrator',
				'user_pass'  => 'adminpass',
				'user_email' => 'admin-rest@example.test',
			)
		);
		wp_set_current_user( $this->admin_id );
		do_action( 'rest_api_init' );
	}

	private function change_own_email( ?string $confirm ) {
		$req = new WP_REST_Request( 'POST', '/wp/v2/users/me' );
		$req->set_param( 'email', 'changed-rest@example.test' );
		if ( null !== $confirm ) {
			$req->set_param( 'ca_confirm_password', $confirm );
		}
		return rest_do_request( $req );
	}

	public function test_email_change_is_blocked_without_confirmation(): void {
		$res = $this->change_own_email( null );

		$this->assertSame( 403, $res->get_status() );
		$this->assertSame( 'ca_reauth_required', $res->get_data()['code'] );
		// The change must not have committed.
		$this->assertSame( 'admin-rest@example.test', get_userdata( $this->admin_id )->user_email );
	}

	public function test_email_change_is_blocked_with_wrong_password(): void {
		$res = $this->change_own_email( 'not-the-password' );

		$this->assertSame( 403, $res->get_status() );
		$this->assertSame( 'ca_reauth_required', $res->get_data()['code'] );
		$this->assertSame( 'admin-rest@example.test', get_userdata( $this->admin_id )->user_email );
	}

	/**
	 * The oracle-closing assertion.
	 *
	 * REST no longer accepts a password as proof of intent, so even the CORRECT
	 * password does not let the change through. This is what removes the
	 * unthrottled guessing channel: wp_check_password() is never reached from a
	 * REST request, for any credential class, so there is no yes/no signal to
	 * mine. Proof of intent must come from an interactive session.
	 */
	public function test_correct_password_over_rest_is_ignored_and_does_not_commit(): void {
		$res = $this->change_own_email( 'adminpass' );

		$this->assertSame( 403, $res->get_status() );
		$this->assertSame( 'ca_reauth_required', $res->get_data()['code'] );
		$this->assertSame(
			'admin-rest@example.test',
			get_userdata( $this->admin_id )->user_email,
			'a correct password sent over REST must not commit the change'
		);
	}

	/**
	 * A wrong and a right password must be indistinguishable from outside —
	 * same status, same code, same effect. That equivalence IS the fix.
	 */
	public function test_right_and_wrong_passwords_are_indistinguishable_over_rest(): void {
		$wrong = $this->change_own_email( 'not-the-password' );
		$right = $this->change_own_email( 'adminpass' );

		$this->assertSame( $wrong->get_status(), $right->get_status() );
		$this->assertSame( $wrong->get_data()['code'], $right->get_data()['code'] );
		$this->assertSame( 'admin-rest@example.test', get_userdata( $this->admin_id )->user_email );
	}

	/** The REST refusal should tell an integrator where intent can be proven. */
	public function test_rest_refusal_points_at_wp_admin(): void {
		$res = $this->change_own_email( null );

		$this->assertStringContainsString( 'wp-admin', $res->get_data()['message'] );
		$this->assertArrayNotHasKey(
			'actions',
			$res->get_data()['data'],
			'the refusal must not echo which fields were detected as consequential'
		);
	}

	/**
	 * Core's REST dispatcher matches routes case-insensitively
	 * (WP_REST_Server::dispatch, '@^' . $route . '$@i'), so a case-varied path
	 * dispatches normally and must not slip past the gate.
	 */
	public function test_mixed_case_route_is_still_gated(): void {
		$req = new WP_REST_Request( 'POST', '/wp/v2/Users/me' );
		$req->set_param( 'email', 'case-bypass@example.test' );
		$res = rest_do_request( $req );

		$this->assertSame( 403, $res->get_status() );
		$this->assertSame(
			'admin-rest@example.test',
			get_userdata( $this->admin_id )->user_email,
			'a mixed-case route must not bypass the gate'
		);
	}
}
