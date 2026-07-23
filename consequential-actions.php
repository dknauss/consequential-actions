<?php
/**
 * Plugin Name:       Consequential Actions (Reauth MVP)
 * Plugin URI:        https://github.com/dknauss/consequential-actions
 * Description:       Requires the acting user to re-confirm their current password before account-takeover actions (password/email change, user creation, promotion to administrator) commit. A minimal demonstrator for a possible WordPress core "consequential actions" registry + proof-of-intent primitive. See Trac #20140.
 * Version:           0.2.0
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
 * Surfaces: the same gate covers the admin user forms AND cookie- or
 * application-password-authenticated writes to the REST users routes
 * (/wp/v2/users), so the block is on the consequential *action*, not one screen —
 * the "one guard, every surface" point this MVP exists to make. Still out of
 * scope on purpose: WP-CLI / cron policy, request stash-and-replay, 2FA-aware
 * challenges, multisite network sessions. Those are the heavy framework pieces
 * this MVP argues core should NOT standardize in the same release; WP Sudo
 * covers them for real sites.
 *
 * Two modes:
 *   - Default (window): block the save and show an inline "confirm your
 *     password" field; a successful confirm opens a short sudo window.
 *   - Hardened (force-logout): define CA_TERMINATE_SESSION truthy. An unconfirmed
 *     gated action logs the user out and forces a full reauthentication before
 *     they can retry. This is a stricter opt-in for stolen-cookie-sensitive
 *     sites; the recommended primitive — and the one proposed to core in Trac
 *     #20140 comment 32 — is the short reauth *window*, not forced re-login.
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

	// Promotion into administrator-equivalent authority — detected by capability,
	// not the literal "administrator" role name, so privileged custom roles count.
	if ( isset( $_POST['role'] ) && current_user_can( 'promote_users' ) ) {
		$new_role  = sanitize_key( wp_unslash( $_POST['role'] ) );
		$old_roles = ( $existing && ! empty( $existing->roles ) ) ? (array) $existing->roles : array();
		if ( '' !== $new_role && role_change_escalates( $new_role, $old_roles ) ) {
			$triggered[] = 'core/promote-user';
		}
	}

	// phpcs:enable WordPress.Security.NonceVerification.Missing

	return array_values( array_intersect( array_unique( $triggered ), array_keys( actions() ) ) );
}

/**
 * Which consequential actions does a REST users write trigger?
 *
 * The REST twin of triggered_actions(). It reads the request's own field names
 * (`password`, `email`, `roles`) instead of the admin form's ($_POST pass1/
 * email/role), so the SAME catalog is enforced whether the change arrives
 * through wp-admin or through /wp/v2/users. Kept pure (params array in, IDs out)
 * so it is unit-testable without a live request.
 *
 * Creating any user is itself the consequential action — it is how a hijacked
 * session plants a backdoor admin — so a create needs no field analysis.
 *
 * @param array<string,mixed> $params    Merged request params (WP_REST_Request::get_params()).
 * @param bool                $is_update True for an update, false for a create.
 * @param \WP_User|null       $existing  The user being updated, if any.
 * @return string[] Triggered action IDs (subset of actions()).
 */
function triggered_actions_rest( array $params, bool $is_update, $existing ) : array {
	if ( ! $is_update ) {
		return array_values( array_intersect( array( 'core/create-user' ), array_keys( actions() ) ) );
	}

	$editing_self = $existing && get_current_user_id() === (int) $existing->ID;
	$triggered    = array();

	// New password: REST field is "password".
	if ( isset( $params['password'] ) && is_string( $params['password'] ) && '' !== $params['password'] ) {
		$triggered[] = $editing_self ? 'core/change-own-password' : 'core/change-user-password';
	}

	// Email change: REST field is "email". Compare to the stored address.
	if ( isset( $params['email'] ) && is_string( $params['email'] ) && '' !== $params['email'] && $existing ) {
		$new_email = sanitize_email( $params['email'] );
		if ( $new_email && ! hash_equals( strtolower( $existing->user_email ), strtolower( $new_email ) ) ) {
			$triggered[] = $editing_self ? 'core/change-own-email' : 'core/change-user-email';
		}
	}

	// Promotion: REST field is "roles" (array). Only for users who can promote,
	// and only when a role newly grants administrator-equivalent authority.
	if ( ! empty( $params['roles'] ) && current_user_can( 'promote_users' ) ) {
		$old_roles = ( $existing && ! empty( $existing->roles ) ) ? (array) $existing->roles : array();
		foreach ( (array) $params['roles'] as $new_role ) {
			$new_role = sanitize_key( (string) $new_role );
			if ( '' !== $new_role && role_change_escalates( $new_role, $old_roles ) ) {
				$triggered[] = 'core/promote-user';
				break;
			}
		}
	}

	return array_values( array_intersect( array_unique( $triggered ), array_keys( actions() ) ) );
}

/**
 * Layer 2 for REST — gate the users routes before dispatch.
 *
 * The point of this MVP is that the gate is on the *action*, not one form. So the
 * same reauth rule that guards the admin user screens also guards writes to
 * /wp/v2/users, whether the request is cookie-authenticated or uses an
 * Application Password. A caller proves intent the same way as on the form: by
 * sending THEIR OWN current password (never the target's) in ca_confirm_password
 * — the one thing a hijacked session or a leaked Application Password cannot do.
 * A recent confirm from either surface opens the shared sudo window, so a
 * confirm in wp-admin also lets a follow-up REST call through for the window.
 *
 * @param mixed            $result  Dispatch result; non-null means already handled.
 * @param \WP_REST_Server  $server  REST server (unused).
 * @param \WP_REST_Request $request The request being dispatched.
 * @return mixed Unchanged $result to proceed, or a WP_Error(403) to block.
 */
function gate_rest( $result, $server, $request ) {
	// Only act on an otherwise-unhandled request from a logged-in user; let core
	// return the normal 401 for anonymous requests.
	if ( null !== $result || ! is_user_logged_in() || ! $request instanceof \WP_REST_Request ) {
		return $result;
	}

	if ( ! preg_match( '#^/wp/v2/users(?:/(me|\d+))?$#', (string) $request->get_route(), $m ) ) {
		return $result;
	}
	// Reads and DELETE pass through (delete-user is not in this MVP catalog).
	if ( ! in_array( $request->get_method(), array( 'POST', 'PUT', 'PATCH' ), true ) ) {
		return $result;
	}

	$target_seg = $m[1] ?? '';
	$is_update  = ( '' !== $target_seg ); // POST/PUT to /users/<id|me> = update; POST to /users = create.
	$existing   = null;
	if ( $is_update ) {
		$id       = ( 'me' === $target_seg ) ? get_current_user_id() : (int) $target_seg;
		$existing = $id ? get_userdata( $id ) : null;
	}

	$triggered = triggered_actions_rest( (array) $request->get_params(), $is_update, $existing );
	if ( empty( $triggered ) || confirmed_recently() ) {
		return $result;
	}

	// Inline confirm: the actor's OWN current password, sent with the request.
	$password = $request->get_param( CONFIRM_FIELD );
	if ( is_string( $password ) && '' !== $password ) {
		$actor = wp_get_current_user();
		if ( wp_check_password( $password, $actor->user_pass, $actor->ID ) ) {
			mark_confirmed( (int) $actor->ID );
			return $result;
		}
	}

	$labels = array_map(
		static function ( $id ) {
			$catalog = actions();
			return $catalog[ $id ]['label'];
		},
		$triggered
	);

	return new \WP_Error(
		'ca_reauth_required',
		sprintf(
			/* translators: %s: comma-separated list of action labels. */
			__( 'Reauthentication required before: %s. Resend the request with your current password in the "ca_confirm_password" field, or confirm once in wp-admin to open a short window.', 'consequential-actions' ),
			implode( ', ', $labels )
		),
		array( 'status' => 403, 'actions' => $triggered )
	);
}

/**
 * Does assigning $new_role grant administrator-equivalent authority the user's
 * current roles do not already hold?
 *
 * Detects privilege escalation by capability rather than by the literal
 * "administrator" role name, so a privileged custom role — one granting, say,
 * manage_options or activate_plugins — is caught too. Returns false for a
 * sideways move into a non-privileged role, or when the user already holds the
 * authority the new role would grant.
 *
 * @param string   $new_role  Slug of the role being assigned.
 * @param string[] $old_roles Slugs of the user's current roles.
 * @return bool
 */
function role_change_escalates( string $new_role, array $old_roles ) : bool {
	// Capabilities that mark administrator-equivalent authority.
	$sensitive = array(
		'manage_options',
		'promote_users',
		'edit_users',
		'delete_users',
		'create_users',
		'activate_plugins',
		'install_plugins',
		'edit_plugins',
		'update_core',
	);

	$new = get_role( $new_role );
	if ( ! $new ) {
		return false;
	}

	// Sensitive caps the target role grants.
	$new_sensitive = array();
	foreach ( $sensitive as $cap ) {
		if ( ! empty( $new->capabilities[ $cap ] ) ) {
			$new_sensitive[] = $cap;
		}
	}
	if ( empty( $new_sensitive ) ) {
		return false; // Target role is not administrator-equivalent.
	}

	// Sensitive caps the user already holds through their current roles.
	$held = array();
	foreach ( $old_roles as $slug ) {
		$role = get_role( (string) $slug );
		if ( ! $role ) {
			continue;
		}
		foreach ( $sensitive as $cap ) {
			if ( ! empty( $role->capabilities[ $cap ] ) ) {
				$held[ $cap ] = true;
			}
		}
	}

	// Escalation if the new role grants any sensitive cap the user lacks today.
	foreach ( $new_sensitive as $cap ) {
		if ( empty( $held[ $cap ] ) ) {
			return true;
		}
	}
	return false;
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

	// Labels come from the filterable registry, so escape each one — a third-party
	// filter must not be able to inject markup into the error notice.
	$labels = array_map(
		static function ( $id ) {
			$catalog = actions();
			return esc_html( $catalog[ $id ]['label'] );
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
		'0.2.0',
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
add_filter( 'rest_pre_dispatch', __NAMESPACE__ . '\\gate_rest', 10, 3 );
add_action( 'show_user_profile', __NAMESPACE__ . '\\render_field' );
add_action( 'edit_user_profile', __NAMESPACE__ . '\\render_field' );
add_action( 'user_new_form', __NAMESPACE__ . '\\render_field' );
add_action( 'admin_enqueue_scripts', __NAMESPACE__ . '\\enqueue_modal' );
add_filter( 'login_message', __NAMESPACE__ . '\\login_message' );
add_action( 'wp_login', __NAMESPACE__ . '\\on_login', 10, 2 );
