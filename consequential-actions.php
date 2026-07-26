<?php
/**
 * Plugin Name:       Consequential Actions (Reauth MVP)
 * Plugin URI:        https://github.com/dknauss/consequential-actions
 * Description:       Requires the acting user to re-confirm their current password before account-takeover actions (password/email change, user creation, promotion to administrator) commit. A minimal demonstrator for a possible WordPress core "consequential actions" registry + proof-of-intent primitive. See Trac #20140.
 * Version:           0.3.0
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
 * the same-guard-across-surfaces point this MVP exists to make. Note the honest
 * limit: these are three *enumerated* surface hooks, not a data-layer chokepoint.
 * A real chokepoint gate would sit inside wp_update_user()/set_role() and cover
 * every caller; enumerating surfaces is whack-a-mole, and issue #3 (bulk promote)
 * was exactly that mole. That gap is the argument for a core primitive. Out of
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
 * Each entry carries the metadata shape a core Actions API would register
 * (label, capabilities, category, consequence_class, scope, annotations), so the
 * catalog literal is a faithful preview of Layer 1 and can be lifted toward the
 * core proposal unchanged. This MVP only reads `label`; the other fields are
 * deliberately unused here — they exist so the "this is what registration looks
 * like" story is consistent across demo, the core spec, and any Make/Core post.
 * The shape is standalone on purpose: a core version exposes these through a
 * single query surface that ALSO reads consequence-annotated abilities, but at
 * wedge scale there are no consequential core abilities to union in, so modelling
 * that surface here would be pure overhead. For the union design see the WP Sudo
 * core spec (https://github.com/dknauss/Sudo/blob/main/docs/core-sudo-gate-implementation-spec.md)
 * and the registry-vs-Abilities decision memo, committed at
 * https://github.com/dknauss/Sudo/blob/cee2cc9730366bec9dda71683bae03bd92795f80/docs/core-actions-registry-vs-abilities-decision.md .
 *
 * @return array<string,array{
 *     label:string,
 *     capabilities:string[],
 *     category:string,
 *     consequence_class:string,
 *     scope:string,
 *     annotations:array{destructive:bool,requires_recent_auth:bool}
 * }>
 */
function actions() : array {
	$users_defaults = array(
		'category'    => 'user-management',
		'scope'       => 'users',
		'annotations' => array(
			'destructive'          => false,
			'requires_recent_auth' => true,
		),
	);

	$actions = array(
		'core/change-own-password'  => array(
			'label'             => __( 'Change your password', 'consequential-actions' ),
			'capabilities'      => array( 'edit_user' ),
			'consequence_class' => 'account-takeover',
		) + $users_defaults,
		'core/change-own-email'     => array(
			'label'             => __( 'Change your email address', 'consequential-actions' ),
			'capabilities'      => array( 'edit_user' ),
			'consequence_class' => 'account-takeover',
		) + $users_defaults,
		'core/change-user-password' => array(
			'label'             => __( "Change another user's password", 'consequential-actions' ),
			'capabilities'      => array( 'edit_user' ),
			'consequence_class' => 'account-takeover',
		) + $users_defaults,
		'core/change-user-email'    => array(
			'label'             => __( "Change another user's email address", 'consequential-actions' ),
			'capabilities'      => array( 'edit_user' ),
			'consequence_class' => 'account-takeover',
		) + $users_defaults,
		'core/create-user'          => array(
			'label'             => __( 'Create a user', 'consequential-actions' ),
			'capabilities'      => array( 'create_users' ),
			'consequence_class' => 'privilege-escalation',
		) + $users_defaults,
		'core/promote-user'         => array(
			'label'             => __( 'Grant administrator privileges', 'consequential-actions' ),
			'capabilities'      => array( 'promote_users' ),
			'consequence_class' => 'privilege-escalation',
		) + $users_defaults,
	);

	/**
	 * Filter the consequential-actions catalog.
	 *
	 * @param array<string,array{label:string,capabilities:string[],category:string,consequence_class:string,scope:string,annotations:array{destructive:bool,requires_recent_auth:bool}}> $actions Map of action ID => metadata.
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
 * Which selected users would a Users-list bulk "promote" escalate to
 * administrator-equivalent authority?
 *
 * The pure detector behind gating the bulk "Change role" action (issue #3). Given
 * the new role key, the selected ids, and a per-user current-roles lookup, it
 * returns the subset whose promotion escalates — reusing role_change_escalates(),
 * so a privileged CUSTOM role counts, not just the literal "administrator" slug.
 * Side-effect-free and lookup-injected so it is unit-testable without a live
 * request (the caller wires get_userdata()).
 *
 * @param string   $new_role Role key assigned to every selected user (matched
 *                           exactly, case-preserving — see below).
 * @param int[]    $user_ids Selected user ids.
 * @param callable $roles_of fn(int $id): string[] — the user's current role slugs.
 * @return int[] Subset of $user_ids whose promotion escalates.
 */
function escalating_bulk_targets( string $new_role, array $user_ids, callable $roles_of ) : array {
	// Match the role key EXACTLY as core does: wp-admin/users.php assigns the raw
	// submitted new_role (validated against get_editable_roles()); lowercasing it
	// with sanitize_key() would miss a mixed-case custom role key and leave that
	// promotion ungated. get_role() validates existence downstream.
	if ( '' === $new_role ) {
		return array();
	}

	$escalating = array();
	foreach ( $user_ids as $id ) {
		$id = (int) $id;
		if ( $id > 0 && role_change_escalates( $new_role, (array) $roles_of( $id ) ) ) {
			$escalating[] = $id;
		}
	}

	return $escalating;
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
 * Does this request resolve to the Users-list "promote" bulk action, the way core
 * does?
 *
 * Core's WP_Users_List_Table::current_action() returns 'promote' when the "Change
 * role" button (`changeit`) is set, and otherwise delegates to WP_List_Table, which
 * returns the `action`/`action2` bulk selection. So a crafted `action=promote` with
 * no `changeit` reaches the same set_role() branch and must be gated too. Pure
 * (request array in) so it is unit-testable.
 *
 * @param array<string,mixed> $req Request params (typically $_REQUEST).
 * @return bool
 */
function is_bulk_promote_request( array $req ) : bool {
	if ( isset( $req['changeit'] ) ) {
		return true;
	}
	// Mirror WP_List_Table::current_action(): a filter submit is not a bulk action.
	if ( ! empty( $req['filter_action'] ) ) {
		return false;
	}
	// The parent returns the first of action/action2 that is set and not the "-1"
	// sentinel, using a LOOSE `-1 != $value` check — so numeric variants like "-01"
	// also count as "no action". Mirror that exactly, or a crafted action=-01 with
	// action2=promote would slip past here while core still runs the promote branch.
	foreach ( array( 'action', 'action2' ) as $k ) {
		if ( ! isset( $req[ $k ] ) || is_array( $req[ $k ] ) ) {
			continue;
		}
		if ( -1 == $req[ $k ] ) { // phpcs:ignore WordPress.PHP.StrictComparisons.LooseComparison -- intentionally mirrors core's loose -1 sentinel.
			continue;
		}
		return 'promote' === $req[ $k ];
	}
	return false;
}

/**
 * Layer 2 for the Users-list bulk action — gate "Change role → …" before it runs.
 *
 * The single-user form (gate()) and REST (gate_rest()) paths are covered, but the
 * Users-list BULK promote submits `changeit` + `new_role` + `users[]` to
 * wp-admin/users.php, which calls WP_User::set_role() directly and NEVER fires
 * user_profile_update_errors. This runs on load-users.php — which core fires from
 * admin.php BEFORE users.php processes the bulk action — and blocks a promotion
 * that escalates a user to administrator-equivalent authority unless the actor
 * proves recent intent. Nothing is mutated at block time.
 *
 * Confirm path: an inline interstitial. Because the bulk screen has no password
 * field, an unconfirmed escalation is answered with a small challenge page that
 * re-POSTs the same bulk request plus the actor's current password; a correct
 * password lets that request through (and opens the shared window if one is
 * enabled). This works in every window mode, including `ca_sudo_window` = 0.
 *
 * Like the form/REST gates, the confirm is NOT rate-limited — throttling and
 * lockouts are the framework hardening this wedge deliberately leaves to WP Sudo.
 *
 * Scope is deliberately narrow: single-site, interactive admin only. Programmatic
 * set_role() and WP-CLI/cron stay WP Sudo's domain; the network Users screen (also
 * $pagenow = users.php) has no role bulk action, so is_network_admin() is skipped.
 */
function gate_bulk_promote() : void {
	if ( is_network_admin() ) {
		return;
	}

	// Detect the "promote" bulk action exactly as core's current_action() does — the
	// `changeit` button OR a bulk action=promote / action2=promote. Detecting only
	// `changeit` would miss a crafted action=promote request, which core still runs
	// through the same set_role() branch.
	if ( ! is_bulk_promote_request( $_REQUEST ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- nonce verified below before any effect.
		return;
	}

	if ( ! current_user_can( 'promote_users' ) ) {
		return;
	}

	// Genuine bulk submission only; core guards the same action with this nonce.
	check_admin_referer( 'bulk-users' );

	// Raw role key (unslashed, NOT sanitize_key'd), to match exactly what core
	// assigns — see escalating_bulk_targets(). Only used for get_role() lookup and
	// esc_attr() output, both safe with an arbitrary string.
	$new_role = isset( $_REQUEST['new_role'] ) ? (string) wp_unslash( $_REQUEST['new_role'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- nonce verified above; role validated by get_role() and escaped on output.
	$user_ids = isset( $_REQUEST['users'] ) ? array_map( 'intval', (array) wp_unslash( $_REQUEST['users'] ) ) : array();
	if ( '' === $new_role || empty( $user_ids ) ) {
		return; // Nothing actionable (incl. demotion to "none"); let core handle it.
	}

	// If the registry filter removed core/promote-user, do not gate — stay
	// consistent with the form/REST detectors, which intersect with actions().
	$catalog = actions();
	if ( ! isset( $catalog['core/promote-user'] ) ) {
		return;
	}

	$escalating = escalating_bulk_targets(
		$new_role,
		$user_ids,
		static function ( int $id ) : array {
			$user = get_userdata( $id );
			return ( $user && ! empty( $user->roles ) ) ? (array) $user->roles : array();
		}
	);
	if ( empty( $escalating ) ) {
		return; // No admin-equivalent escalation; not a consequential action.
	}

	// Intent already proven within an open window → allow.
	if ( confirmed_recently() ) {
		return;
	}

	$label = (string) $catalog['core/promote-user']['label'];
	$actor = wp_get_current_user();

	// Hardened mode: force a full reauthentication instead of an inline confirm, so
	// the bulk surface matches gate() — the fresh login pipeline (2FA) is the whole
	// point of CA_TERMINATE_SESSION. on_login consumes the pending marker and opens
	// the window, so retrying the bulk change after re-login passes.
	if ( terminate_mode() ) {
		set_transient( pending_key( (int) $actor->ID ), 1, 15 * MINUTE_IN_SECONDS );
		wp_logout();
		wp_safe_redirect( add_query_arg( 'ca_reauth', '1', wp_login_url( admin_url( 'users.php' ) ) ) );
		exit;
	}

	// Inline confirm re-POSTed with the bulk request? Verify the actor's password.
	$password = isset( $_REQUEST[ CONFIRM_FIELD ] ) ? (string) wp_unslash( $_REQUEST[ CONFIRM_FIELD ] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- nonce verified above.
	$error    = '';
	if ( '' !== $password ) {
		if ( wp_check_password( $password, $actor->user_pass, $actor->ID ) ) {
			mark_confirmed( (int) $actor->ID );
			return; // Allow — core proceeds to set_role().
		}
		$error = __( 'The password you entered is incorrect. Please try again.', 'consequential-actions' );
	}

	bulk_promote_challenge( $label, $new_role, $user_ids, $error );
}

/**
 * Render the inline confirm interstitial for a gated bulk role change and exit.
 *
 * A small challenge page that re-POSTs the original bulk request (new_role, the
 * selected users, a fresh bulk-users nonce, and the `changeit` trigger core keys
 * off) together with the actor's current password, back to wp-admin/users.php.
 * Re-entry lands in gate_bulk_promote(), which verifies the password and lets the
 * request through. POST (not GET) keeps the password out of the URL.
 *
 * @param string $label    The action label, e.g. "Grant administrator privileges".
 * @param string $new_role Target role key to re-submit.
 * @param int[]  $user_ids Selected user ids to re-submit.
 * @param string $error    Optional error to show above the field (plain text).
 */
function bulk_promote_challenge( string $label, string $new_role, array $user_ids, string $error = '' ) : void {
	$fields  = wp_nonce_field( 'bulk-users', '_wpnonce', true, false );
	$fields .= '<input type="hidden" name="new_role" value="' . esc_attr( $new_role ) . '" />';
	foreach ( $user_ids as $id ) {
		$fields .= '<input type="hidden" name="users[]" value="' . (int) $id . '" />';
	}

	$intro = sprintf(
		/* translators: %s: the action label, e.g. "Grant administrator privileges". */
		__( 'Reauthentication required before: %s. Confirm your current password to continue with this bulk role change.', 'consequential-actions' ),
		$label
	);

	$html = '<p>' . esc_html( $intro ) . '</p>';
	if ( '' !== $error ) {
		$html .= '<p style="color:#b32d2e;font-weight:600;">' . esc_html( $error ) . '</p>';
	}
	$html .= '<form method="post" action="' . esc_url( admin_url( 'users.php' ) ) . '">';
	$html .= $fields;
	$html .= '<p><label for="ca_confirm_password">' . esc_html__( 'Current password', 'consequential-actions' ) . '</label><br />';
	$html .= '<input type="password" id="ca_confirm_password" name="' . esc_attr( CONFIRM_FIELD ) . '" autocomplete="current-password" required /></p>';
	$html .= '<p><button type="submit" name="changeit" value="1" class="button button-primary">' . esc_html__( 'Confirm and change role', 'consequential-actions' ) . '</button></p>';
	$html .= '</form>';

	// $html is assembled from escaped parts above; wp_die() renders a string
	// message as HTML, so no further escaping (which would corrupt the markup).
	wp_die(
		$html, // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from escaped fragments.
		esc_html__( 'Confirmation required', 'consequential-actions' ),
		array( 'response' => 403 )
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
		'0.3.0',
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
		// A forced re-login IS the reauthentication. When the window is disabled
		// (ca_sudo_window = 0), mark_confirmed() stores nothing, so grant a one-time
		// pass to authorize the retry — otherwise hardened mode loops the user
		// straight back out. Only in zero-window mode: when a window IS configured,
		// mark_confirmed() already covers the retry, and a longer-lived one-shot
		// would let reauth outlive ca_sudo_window.
		if ( window_seconds() <= 0 ) {
			set_transient( reauthed_key( (int) $user->ID ), 1, 15 * MINUTE_IN_SECONDS );
		}
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
 * @param int $user_id
 * @return string Transient key for the one-time pass a forced re-login grants,
 *                honored even when the sudo window is disabled (ca_sudo_window = 0).
 */
function reauthed_key( int $user_id ) : string {
	return 'ca_reauthed_' . $user_id;
}

/**
 * @return bool Whether the current user has proven recent intent — an open sudo
 *              window, or a one-time pass from a forced re-login (hardened mode).
 */
function confirmed_recently() : bool {
	$uid = get_current_user_id();
	// A forced re-login grants a one-time pass, honored even when the window is
	// disabled — consume it here so it authorizes exactly one retry.
	if ( get_transient( reauthed_key( $uid ) ) ) {
		delete_transient( reauthed_key( $uid ) );
		return true;
	}
	if ( window_seconds() <= 0 ) {
		return false;
	}
	return (bool) get_transient( confirm_key( $uid ) );
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
add_action( 'load-users.php', __NAMESPACE__ . '\\gate_bulk_promote' );
add_filter( 'rest_pre_dispatch', __NAMESPACE__ . '\\gate_rest', 10, 3 );
add_action( 'show_user_profile', __NAMESPACE__ . '\\render_field' );
add_action( 'edit_user_profile', __NAMESPACE__ . '\\render_field' );
add_action( 'user_new_form', __NAMESPACE__ . '\\render_field' );
add_action( 'admin_enqueue_scripts', __NAMESPACE__ . '\\enqueue_modal' );
add_filter( 'login_message', __NAMESPACE__ . '\\login_message' );
add_action( 'wp_login', __NAMESPACE__ . '\\on_login', 10, 2 );
