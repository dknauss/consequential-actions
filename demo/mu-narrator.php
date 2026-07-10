<?php
/**
 * Consequential Actions — demo narrator (demo only).
 *
 * DEMO SCAFFOLDING, not part of the plugin. It only narrates the walkthrough and
 * tunes two demo-only things; it enforces nothing.
 *   - Sets the sudo window to 0 so every gated action re-challenges (repeatable).
 *   - Once the admin has changed their own password, stops showing the original
 *     demo credential and points at the new password instead.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Every gated action re-challenges in the demo.
add_filter( 'ca_sudo_window', '__return_zero' );

// Remember when the current admin has changed their own password.
add_action(
	'profile_update',
	function ( $user_id, $old ) {
		if ( (int) $user_id !== get_current_user_id() ) {
			return;
		}
		$user = get_userdata( $user_id );
		if ( $user && isset( $old->user_pass ) && $user->user_pass !== $old->user_pass ) {
			update_user_meta( $user_id, '_ca_demo_pw_changed', 1 );
		}
	},
	10,
	2
);

add_action(
	'admin_notices',
	function () {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen ) {
			return;
		}

		$changed = (bool) get_user_meta( get_current_user_id(), '_ca_demo_pw_changed', true );
		// Which credential the confirmation dialog now wants.
		$cred = $changed ? 'your <em>new</em> password' : '<code>password</code>';

		$profile = $changed
			? '<strong>&#10003; Password changed.</strong> Use your <em>new</em> password from now on &mdash; both to sign in and whenever the confirmation dialog asks for your current password.'
			: '<strong>Demo 1 &mdash; change your password.</strong> Set a New Password and click Update Profile. A dialog asks for your <em>current</em> password (' . $cred . ') before it saves, and re-challenges every time. Log out and back in to prove it changed.';

		$notices = array(
			'profile'   => $profile,
			'user'      => '<strong>Demo 2 &mdash; create a user.</strong> Creating a user is a consequential action too, so the same challenge guards it (confirm with ' . $cred . '). Then open <em>WP Mail Logging</em> in the menu to see the notification WordPress sent.',
			'users'     => '<strong>Demo 3 &mdash; promote to Administrator.</strong> Edit <code>targetuser</code> and set Role to Administrator to see the same challenge.',
			'user-edit' => '<strong>Demo 3 &mdash; promote to Administrator.</strong> Change this user\'s Role to Administrator and Update. Gated the same way &mdash; and notice you never need <em>their</em> password, only your own recent sign-in. The challenge guards the <em>action</em>, not one field.',
		);

		if ( isset( $notices[ $screen->id ] ) ) {
			echo '<div class="notice notice-info"><p>' . wp_kses_post( $notices[ $screen->id ] ) . '</p></div>';
		}
	}
);
