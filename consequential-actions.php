<?php
/**
 * Plugin Name:       Consequential Actions (Reauth MVP)
 * Plugin URI:        https://github.com/dknauss/consequential-actions
 * Description:       Requires the acting user to re-confirm their current password before account-takeover actions (password/email change, user creation, promotion to administrator) commit. A minimal demonstrator for a possible WordPress core "consequential actions" registry + proof-of-intent primitive. See Trac #20140.
 * Version:           0.1.4
 * Requires at least: 6.4
 * Requires PHP:      7.4
 * Author:            Dan Knauss
 * Author URI:        https://github.com/dknauss
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       consequential-actions
 *
 * This is a wedge MVP, not a finished product. It deliberately does two things
 * and stops:
 *   Layer 1 — NAME a small catalog of consequential actions (the valuable-alone
 *             part; a real core version would be an Actions API).
 *   Layer 2 — GATE those actions with step-up reauthentication of the *actor*.
 *
 * Out of scope on purpose: REST / Application Passwords / WP-CLI / cron policy,
 * request stash-and-replay, 2FA-aware challenges, multisite network sessions.
 * Those are exactly the heavy framework pieces this MVP argues core should NOT
 * have to standardize in the same release. WP Sudo covers them for real sites.
 *
 * Two modes:
 *   - Default (window): block the save and show an inline "confirm your
 *     password" field; a successful confirm opens a short sudo window.
 *   - Hardened (force-logout): define CA_TERMINATE_SESSION truthy. An unconfirmed
 *     gated action logs the user out and forces a full reauthentication before
 *     they can retry. This is the stronger reading of Trac #20140 comment 31.
 */

namespace ConsequentialActions;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

const CONFIRM_FIELD = 'ca_confirm_password';
const NONCE_ACTION  = 'ca_confirm_action';
const NONCE_FIELD   = 'ca_confirm_nonce';

/**
 * Length of the "sudo window": after one successful confirm (or, in hardened
 * mode, a fresh login), further consequential actions by the same user skip the
 * prompt for this long.
 *
 * NOTE this is NOT a session. It is a single per-user transient flag with a TTL
 * (see confirm_key()) — a deliberately minimal imitation of sudo-mode's short
 * elevation. It is not cookie- or session-bound, so it is shared across all of
 * the user's sessions/devices for the window's duration. A real implementation
 * binds elevation to the session (WP Sudo does); this MVP intentionally does not.
 *
 * Trade-off: a window is friendlier but widens exposure — a session hijacked
 * right after a confirm inherits it. Filter to 0 to always re-challenge.
 *
 * @return int Seconds. 0 = always re-challenge.
 */
function window_seconds() : int {
	/**
	 * Filter the sudo-window length in seconds.
	 *
	 * @param int $seconds Default 5 minutes. Return 0 to always re-challenge.
	 */
	return (int) apply_filters( 'ca_sudo_window', 5 * MINUTE_IN_SECONDS );
}

/**
 * @return bool Whether hardened force-logout mode is enabled.
 */
function terminate_mode() : bool {
	return defined( 'CA_TERMINATE_SESSION' ) && CA_TERMINATE_SESSION;
}

/**
 * Layer 1 — the registry.
 *
 * A stable, filterable catalog of *named* consequential actions. This is the
 * wedge: it is useful on its own (audit trails, UI affordances, policy tooling)
 * even if nothing ever gates it. Everything below is just one possible consumer.
 *
 * @return array<string,array{label:string}>
 */
function actions() : array {
	$actions = array(
		'core/change-own-password'  => array( 'label' => __( 'Change your password', 'consequential-actions' ) ),
		'core/change-own-email'     => array( 'label' => __( 'Change your email address', 'consequential-actions' ) ),
		'core/change-user-password' => array( 'label' => __( "Change another user's password", 'consequential-actions' ) ),
		'core/change-user-email'    => array( 'label' => __( "Change another user's email address", 'consequential-actions' ) ),
		'core/create-user'          => array( 'label' => __( 'Create a user', 'consequential-actions' ) ),
		'core/promote-user'         => array( 'label' => __( 'Grant administrator privileges', 'consequential-actions' ) ),
	);

	/**
	 * Filter the consequential-actions catalog.
	 *
	 * @param array<string,array{label:string}> $actions Map of action ID => metadata.
	 */
	return (array) apply_filters( 'consequential_actions', $actions );
}

/**
 * Which consequential actions does this user create/edit submission trigger?
 *
 * Reads $_POST after core has already verified its own nonce in edit_user(),
 * which is why this is safe without an additional nonce check here.
 *
 * @param bool          $is_update Whether editing an existing user (false = create).
 * @param \WP_User|null $existing  The user being edited, if any.
 * @return string[] Triggered action IDs (subset of actions()).
 */
function triggered_actions( bool $is_update, $existing ) : array {
	$editing_self = $is_update && $existing && get_current_user_id() === (int) $existing->ID;
	$triggered    = array();

	if ( ! $is_update ) {
		$triggered[] = 'core/create-user';
	}

	// phpcs:disable WordPress.Security.NonceVerification.Missing -- core verified its nonce before this hook fires.

	// New password: core populates pass1 only when a password is actually being set.
	if ( ! empty( $_POST['pass1'] ) ) {
		$triggered[] = $editing_self ? 'core/change-own-password' : 'core/change-user-password';
	}

	// Email change: compare submitted address to the stored one.
	if ( isset( $_POST['email'] ) && $existing ) {
		$new_email = sanitize_email( wp_unslash( $_POST['email'] ) );
		if ( $new_email && ! hash_equals( strtolower( $existing->user_email ), strtolower( $new_email ) ) ) {
			$triggered[] = $editing_self ? 'core/change-own-email' : 'core/change-user-email';
		}
	}

	// Promotion to administrator (the escalation path that matters most).
	if ( isset( $_POST['role'] ) && current_user_can( 'promote_users' ) ) {
		$new_role = sanitize_key( wp_unslash( $_POST['role'] ) );
		$old_role = ( $existing && ! empty( $existing->roles ) ) ? (string) reset( $existing->roles ) : '';
		if ( 'administrator' === $new_role && 'administrator' !== $old_role ) {
			$triggered[] = 'core/promote-user';
		}
	}

	// phpcs:enable WordPress.Security.NonceVerification.Missing

	return array_values( array_intersect( array_unique( $triggered ), array_keys( actions() ) ) );
}

/**
 * Layer 2 — the gate. Runs during user create/edit validation.
 *
 * If any consequential action is triggered and the acting user has not proven
 * recent authentication, either block the save (window mode) or force a full
 * reauthentication (hardened mode). Nothing is written until the actor proves
 * intent.
 *
 * The credential checked is ALWAYS the current user's own password — never the
 * edited user's. That is the correct security boundary: it proves who is at the
 * keyboard, and lets an admin edit another account without knowing its password
 * (Trac #20140, comments 8-10).
 *
 * @param \WP_Error          $errors Accumulates validation errors (blocks save if any).
 * @param bool               $update True on edit, false on create.
 * @param \stdClass|\WP_User $user   The user object being saved.
 */
function gate( $errors, $update, $user ) : void {
	$existing  = ( $update && ! empty( $user->ID ) ) ? get_userdata( (int) $user->ID ) : null;
	$triggered = triggered_actions( (bool) $update, $existing );

	if ( empty( $triggered ) || confirmed_recently() ) {
		return;
	}

	$actor = wp_get_current_user();

	// Hardened mode: a sensitive action forces a full reauthentication. The save
	// is discarded; the user logs back in (fresh authentication) and retries.
	// A pending marker (set here, consumed on the next login) is what lets the
	// forced re-login satisfy the gate — so an ordinary boot/login does NOT.
	if ( terminate_mode() ) {
		set_transient( pending_key( (int) $actor->ID ), 1, 15 * MINUTE_IN_SECONDS );
		wp_logout();
		wp_safe_redirect( add_query_arg( 'ca_reauth', '1', wp_login_url( admin_url( 'profile.php' ) ) ) );
		exit;
	}

	// Default mode: verify the actor's password inline, on this same form.
	$password = isset( $_POST[ CONFIRM_FIELD ] ) ? (string) wp_unslash( $_POST[ CONFIRM_FIELD ] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce checked on the next line.
	$nonce_ok = isset( $_POST[ NONCE_FIELD ] ) && wp_verify_nonce( sanitize_key( wp_unslash( $_POST[ NONCE_FIELD ] ) ), NONCE_ACTION );

	if ( '' !== $password && $nonce_ok && wp_check_password( $password, $actor->user_pass, $actor->ID ) ) {
		mark_confirmed( (int) $actor->ID );
		return;
	}

	$labels = array_map(
		static function ( $id ) {
			$catalog = actions();
			return $catalog[ $id ]['label'];
		},
		$triggered
	);

	$errors->add(
		'ca_reauth_required',
		sprintf(
			/* translators: %s: comma-separated list of action labels. */
			esc_html__( 'Please confirm your current password to proceed with: %s.', 'consequential-actions' ),
			implode( ', ', $labels )
		)
	);
}

/**
 * Render the inline "confirm your password" field on the user forms.
 *
 * Deliberately no JavaScript and no modal: the field lives on the same form as
 * the action, and core's own error mechanism blocks the save. Not shown in
 * hardened mode (which forces a login instead of an inline confirm).
 *
 * @param \WP_User|string $context WP_User on profile/edit screens; a context string on user-new.
 */
function render_field( $context = '' ) : void {
	if ( terminate_mode() || confirmed_recently() ) {
		return;
	}
	// #ca-fallback is the no-JS path; the enqueued modal script hides it and
	// collects the same field via a dialog instead (progressive enhancement).
	?>
	<div id="ca-fallback">
	<h2><?php esc_html_e( 'Confirm it is you', 'consequential-actions' ); ?></h2>
	<table class="form-table" role="presentation">
		<tr>
			<th scope="row">
				<label for="<?php echo esc_attr( CONFIRM_FIELD ); ?>">
					<?php esc_html_e( 'Your current password', 'consequential-actions' ); ?>
				</label>
			</th>
			<td>
				<?php wp_nonce_field( NONCE_ACTION, NONCE_FIELD ); ?>
				<input
					type="password"
					autocomplete="current-password"
					name="<?php echo esc_attr( CONFIRM_FIELD ); ?>"
					id="<?php echo esc_attr( CONFIRM_FIELD ); ?>"
					class="regular-text"
				/>
				<p class="description">
					<?php esc_html_e( 'Required only when changing a password or email address, creating a user, or granting administrator access.', 'consequential-actions' ); ?>
				</p>
			</td>
		</tr>
	</table>
	</div>
	<?php
}

/**
 * Enqueue the optional modal enhancement (window mode only).
 *
 * The modal is pure UX: it collects the same confirm field and submits the same
 * form, so the server-side gate in gate() remains the sole authority. With
 * JavaScript off, #ca-fallback stays visible and the server still enforces —
 * the modal never becomes the enforcement point.
 *
 * @param string $hook Current admin screen hook.
 */
function enqueue_modal( $hook ) : void {
	if ( terminate_mode() || ! in_array( $hook, array( 'profile.php', 'user-edit.php', 'user-new.php' ), true ) ) {
		return;
	}

	wp_enqueue_script(
		'ca-modal',
		plugins_url( 'assets/modal.js', __FILE__ ),
		array(),
		'0.1.4',
		true
	);

	// Originals so the script can tell client-side whether a gated action is
	// being attempted. Best-effort only — if detection misses, the server gate
	// still catches it (a fallback round-trip), so this is a UX hint, not a check.
	$screen_user = null;
	if ( 'profile.php' === $hook ) {
		$screen_user = wp_get_current_user();
	} elseif ( 'user-edit.php' === $hook && isset( $_GET['user_id'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only UX hint, no state change.
		$screen_user = get_userdata( (int) $_GET['user_id'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	}

	wp_localize_script(
		'ca-modal',
		'caModalData',
		array(
			'isCreate' => ( 'user-new.php' === $hook ),
			'email'    => $screen_user ? strtolower( $screen_user->user_email ) : '',
			'role'     => ( $screen_user && ! empty( $screen_user->roles ) ) ? (string) reset( $screen_user->roles ) : '',
			'i18n'     => array(
				'title'   => __( 'Confirm it is you', 'consequential-actions' ),
				'label'   => __( 'Enter your current password to continue.', 'consequential-actions' ),
				'confirm' => __( 'Confirm', 'consequential-actions' ),
				'cancel'  => __( 'Cancel', 'consequential-actions' ),
			),
		)
	);
}

/**
 * Explain the forced logout on the login screen (hardened mode).
 *
 * @param string $message Existing login message markup.
 * @return string
 */
function login_message( $message ) : string {
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only display flag, no state change.
	if ( empty( $_GET['ca_reauth'] ) ) {
		return $message;
	}
	$notice = '<p class="message">' . esc_html__( 'For your security, a sensitive account action requires you to sign in again. Please reauthenticate, then retry the action.', 'consequential-actions' ) . '</p>';
	return $notice . $message;
}

/**
 * After a login that WE forced (hardened mode), treat it as recent authentication
 * so the retried action proceeds. A login without a pending marker — the ordinary
 * boot/login case — does NOT confirm, so the first gated attempt is still gated.
 *
 * @param string        $user_login
 * @param \WP_User|null $user
 */
function on_login( $user_login, $user = null ) : void {
	if ( ! terminate_mode() || ! $user instanceof \WP_User ) {
		return;
	}
	if ( get_transient( pending_key( (int) $user->ID ) ) ) {
		delete_transient( pending_key( (int) $user->ID ) );
		mark_confirmed( (int) $user->ID );
	}
}

/**
 * @param int $user_id
 * @return string Transient key for a user's recent-confirmation flag.
 */
function confirm_key( int $user_id ) : string {
	return 'ca_confirmed_' . $user_id;
}

/**
 * @param int $user_id
 * @return string Transient key marking a forced-logout awaiting reauthentication.
 */
function pending_key( int $user_id ) : string {
	return 'ca_reauth_pending_' . $user_id;
}

/**
 * @return bool Whether the current user confirmed within the sudo window.
 */
function confirmed_recently() : bool {
	if ( window_seconds() <= 0 ) {
		return false;
	}
	return (bool) get_transient( confirm_key( get_current_user_id() ) );
}

/**
 * Record a successful confirmation, opening the sudo window.
 *
 * @param int $user_id
 */
function mark_confirmed( int $user_id ) : void {
	$window = window_seconds();
	if ( $window > 0 ) {
		set_transient( confirm_key( $user_id ), time(), $window );
	}
}

add_action( 'user_profile_update_errors', __NAMESPACE__ . '\\gate', 10, 3 );
add_action( 'show_user_profile', __NAMESPACE__ . '\\render_field' );
add_action( 'edit_user_profile', __NAMESPACE__ . '\\render_field' );
add_action( 'user_new_form', __NAMESPACE__ . '\\render_field' );
add_action( 'admin_enqueue_scripts', __NAMESPACE__ . '\\enqueue_modal' );
add_filter( 'login_message', __NAMESPACE__ . '\\login_message' );
add_action( 'wp_login', __NAMESPACE__ . '\\on_login', 10, 2 );
