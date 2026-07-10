<?php
/**
 * Consequential Actions — demo narrator (demo only).
 *
 * DEMO SCAFFOLDING, not part of the plugin. It only narrates the walkthrough and
 * tunes two demo-only things; it enforces nothing.
 *   - Sets the sudo window to 0 so every gated action re-challenges (repeatable).
 *   - Once the admin has changed their own password, points at the new password.
 *
 * The narration frames one story: a stolen-session account takeover, and the wall
 * the gate puts in front of every step of it.
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

		$profile = $changed
			? '<strong>&#10003; Password changed.</strong> Use your <em>new</em> password from now on, including at the confirmation dialog. Note the wall appeared <em>before</em> the change saved &mdash; a stolen session, lacking your password, stops right there.'
			: '<strong>&#128274; Account takeover, live.</strong> Picture an attacker holding this admin\'s stolen session cookie: logged in, but they do not know the password, and their goal is to lock you out for good. Every takeover step below hits a wall. (You know the password here &mdash; <code>password</code> &mdash; so you can walk through; a stolen cookie cannot.) The real prize is your <strong>email</strong>: it is your recovery path, so if an attacker changed it silently, even your own &ldquo;Lost your password?&rdquo; reset would reach <em>them</em>. Change the password or email below &mdash; both demand your current password first, so your email stays yours. <em>Prove it:</em> log out, run &ldquo;Lost your password?&rdquo; for <code>admin</code>, sign back in, and open WP Mail Logging &mdash; the reset went to the original admin, not an attacker.';

		$notices = array(
			'profile'   => $profile,
			'user'      => '<strong>Backdoor attempt.</strong> Planting a fresh Administrator is the classic way to keep access &mdash; so creating a user is a consequential action too, gated the same way.',
			'users'     => '<strong>Persistence attempt.</strong> Edit <code>targetuser</code> and set its Role to Administrator to hit the same wall.',
			'user-edit' => '<strong>Persistence attempt.</strong> Set this user\'s Role to Administrator and Update &mdash; gated the same way, and it never needs <em>their</em> password, only the attacker\'s (which they do not have). The gate guards the <em>action</em>, not one field. (It closes account-takeover; note a hijacked <em>admin</em> could still install a plugin &mdash; deliberately out of scope for this MVP.)',
		);

		if ( isset( $notices[ $screen->id ] ) ) {
			echo '<div class="notice notice-info"><p>' . wp_kses_post( $notices[ $screen->id ] ) . '</p></div>';
		}
	}
);
