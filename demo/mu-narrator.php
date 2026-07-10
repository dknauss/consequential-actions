<?php
/**
 * Consequential Actions — guided-tour narrator (demo only).
 *
 * This mu-plugin is DEMO SCAFFOLDING, not part of the plugin. It only narrates:
 * it prints step-by-step notices on the relevant admin screens so a first-time
 * visitor can experience the password/email/reauth sequence without a tour guide.
 * It changes no behavior and enforces nothing.
 *
 * The guided-tour blueprint enables the plugin's hardened force-logout mode
 * (CA_TERMINATE_SESSION), so the notices below describe that flow.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

add_action(
	'admin_notices',
	function () {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen ) {
			return;
		}

		$notices = array(
			// Own profile: password + email change.
			'profile'   => '<strong>Step 1 — change your own account.</strong> Set a <em>New Password</em> (or change the email) and click <em>Update Profile</em>. Because force-logout mode is on in this demo, WordPress will sign you out and ask you to reauthenticate before the change can complete. Log back in with <code>admin</code> / <code>password</code>.',
			// Add new user.
			'user'      => '<strong>Step 2 — create a user.</strong> Creating a user is a consequential action too. In force-logout mode this also requires reauthentication first.',
			// Users list — point at promotion + the target user.
			'users'     => '<strong>Step 3 — promote a user.</strong> Try changing <code>targetuser</code> to Administrator (Users → hover → Edit → Role). Granting admin is gated the same way. Note you never need <code>targetuser</code>\'s password — only your own recent sign-in.',
			// Mail log viewer.
			'toplevel_page_wpml_plugin_log' => '<strong>Read the mail.</strong> Every email WordPress sent during this demo is captured here — the email-change confirmation and any password/reset notices. This is the "change the email, then use password reset" bypass path made visible: gating one field is not enough, which is why the plugin targets the <em>action</em>, not the input.',
		);

		$id = $screen->id;
		if ( isset( $notices[ $id ] ) ) {
			echo '<div class="notice notice-info"><p>' . wp_kses_post( $notices[ $id ] ) . '</p></div>';
		}
	}
);
