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

	public function test_email_change_succeeds_with_correct_password(): void {
		$res = $this->change_own_email( 'adminpass' );

		$this->assertSame( 200, $res->get_status() );
		$this->assertSame( 'changed-rest@example.test', get_userdata( $this->admin_id )->user_email );
	}

	public function test_open_window_lets_a_subsequent_request_through_without_password(): void {
		// Confirm once...
		$this->change_own_email( 'adminpass' );
		// ...then a second gated change within the window needs no password.
		$req = new WP_REST_Request( 'POST', '/wp/v2/users/me' );
		$req->set_param( 'email', 'second-change@example.test' );
		$res = rest_do_request( $req );

		$this->assertSame( 200, $res->get_status() );
		$this->assertSame( 'second-change@example.test', get_userdata( $this->admin_id )->user_email );
	}
}
