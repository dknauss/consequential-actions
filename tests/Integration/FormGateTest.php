<?php
/**
 * Integration coverage for gate() on the admin user forms — the live
 * user_profile_update_errors save path (real edit_user(), real bcrypt, real nonce).
 */

declare( strict_types = 1 );

namespace ConsequentialActions\Tests\Integration;

use WP_Error;
use WP_UnitTestCase;

final class FormGateTest extends WP_UnitTestCase {

	private int $admin_id;

	public function set_up(): void {
		parent::set_up();
		$this->admin_id = self::factory()->user->create(
			array(
				'role'      => 'administrator',
				'user_pass' => 'adminpass',
			)
		);
		wp_set_current_user( $this->admin_id );
	}

	/**
	 * Drive the create-user form the way wp-admin/user-new.php does: populate
	 * $_POST and call edit_user(0). Returns an int user id on success or a WP_Error
	 * when a validation hook (our gate) blocks the save.
	 *
	 * @return int|WP_Error
	 */
	private function create_user( ?string $confirm ) {
		$_POST = $_REQUEST = array(
			'user_login' => 'newformuser',
			'email'      => 'newform@example.test',
			'pass1'      => 'NewUserPass123!',
			'pass2'      => 'NewUserPass123!',
			'role'       => 'subscriber',
		);
		if ( null !== $confirm ) {
			$_POST['ca_confirm_password'] = $confirm;
			$_POST['ca_confirm_nonce']    = wp_create_nonce( \ConsequentialActions\NONCE_ACTION );
		}
		$result       = edit_user( 0 );
		$_POST        = array();
		$_REQUEST     = array();
		return $result;
	}

	public function test_create_user_is_blocked_without_confirmation(): void {
		$result = $this->create_user( null );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertContains( 'ca_reauth_required', $result->get_error_codes() );
		$this->assertFalse( username_exists( 'newformuser' ) );
	}

	public function test_create_user_is_blocked_with_wrong_password(): void {
		$result = $this->create_user( 'not-the-password' );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertContains( 'ca_reauth_required', $result->get_error_codes() );
		$this->assertFalse( username_exists( 'newformuser' ) );
	}

	public function test_create_user_succeeds_with_correct_password(): void {
		$result = $this->create_user( 'adminpass' );

		$this->assertIsInt( $result );
		$this->assertNotFalse( username_exists( 'newformuser' ) );
	}
}
