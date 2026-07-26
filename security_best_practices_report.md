# Consequential Actions security review

> **Re-run against `main` after the bulk-promote gate (#3) and the integration
> suite (#11) landed.** Line references and the test count in the previous
> revision were stale by ~400 lines and 3×; two findings (CA-3, CA-4) had been
> fixed but were still reported as open. Both are now marked resolved, and two
> previously-unreported gaps (CA-6, CA-7) are added.

## Executive summary

The plugin does what it says for the three user-management surfaces it enumerates: it names a small registry of account-takeover actions and blocks user create/update/promote before commit until the acting user reconfirms **their own** password, or until hardened mode forces a fresh login. Enforcement is server-side at every gate; the modal is only progressive enhancement.

I did not find a direct unauthenticated vulnerability, SQL injection, arbitrary file access, REST permission bypass, or XSS in first-party code.

The security limitations are design/scope issues, and one of them has grown more serious as the REST gate matured. In descending order: the confirm field is an **un-throttled password oracle** reachable over an Application-Password-authenticated request (CA-2, now **High**); the sudo window is per-user rather than session-bound, so the legitimate browser's confirmation elevates every concurrent session and credential for that account (CA-1); and two account-takeover-adjacent REST routes go ungated — one outside the gate's route pattern (CA-6), one admitted by the pattern but excluded by its method filter (CA-7). These are documented or deliberate to varying degrees, but they matter precisely because this artifact is offered as a *security* demonstration.

## Verification performed

- Reviewed repository files, README/readme claims, plugin PHP, modal JavaScript, demo files, and both test suites.
- Verified against WordPress trunk that `user_profile_update_errors` fires before `wp_update_user()`/`wp_insert_user()` in `edit_user()` (`wp-admin/includes/user.php`), and that `rest_pre_dispatch` runs **after** `check_authentication()` in `WP_REST_Server::serve_request()` — i.e. Application-Password auth is fully resolved before the REST gate runs.
- Verified `wp_check_password()` (`wp-includes/pluggable.php`) fires only the `check_password` filter — never `wp_login_failed` and never the `authenticate` chain.
- Ran PHP syntax checks on first-party PHP files: passed.
- Ran `composer validate --strict`: passed.
- Ran the unit suite: passed, 45 tests / 147 assertions.
- Integration suite: 15 tests across `FormGateTest`, `RestGateTest`, `BulkGateTest`, `SmokeTest`; green in CI (integration runs on PHP 8.2 and 8.3, against WP 6.4 and latest; the unit matrix is the one that spans PHP 7.4–8.3). Not runnable locally without the WP test library.
- Ran `composer audit --format=plain`: no advisory found.

## Findings

### High: CA-2 — The confirm field is an un-throttled password oracle

**Location:** `consequential-actions.php:318` (REST), `:489` (form), `:646` (bulk)

All three gates verify the actor's password by calling `wp_check_password()` directly. That is the *correct* credential to check — it is the whole point of the wedge — but the call bypasses the login pipeline entirely. `wp_check_password()` fires only the `check_password` filter; it never fires `wp_login_failed` and never runs the `authenticate` / `wp_authenticate_user` chain. The mainstream throttles that hook those (Limit Login Attempts Reloaded, Wordfence, WP Fail2Ban) therefore **never see a failed confirm**. WP Sudo does not see one either, for a different reason: its lockout is an internal counter inside its own reauth flow (`_wp_sudo_failed_attempts`), not a `wp_login_failed` listener, so it counts only its own challenges. There is no first-party counter, cooldown, or cap either, and no `do_action` fires on failure, so the attempts are not auditable.

The REST gate makes this materially worse than the previous revision recorded. It reads the guess from `$request->get_param( CONFIRM_FIELD )` with no nonce requirement, and nothing in the plugin distinguishes cookie authentication from Application-Password authentication. So `POST /wp/v2/users/me` with `{"email":"…","ca_confirm_password":"<guess>"}` over a leaked Application Password is an **unlimited, unlogged yes/no oracle on the account's main password** — and a correct guess is the takeover the plugin exists to prevent.

**Impact:** Installing the plugin adds a password-guessing surface that did not exist beforehand, and the demo's own antagonist (a stolen session / leaked credential) is exactly the actor who can use it.

**Recommended fix:** Stop accepting a login password over an API-credential channel — block Application-Password callers at the REST gate, or require cookie auth for the confirm. Then bound failed attempts on every direct verifier. [PR #4](https://github.com/dknauss/consequential-actions/pull/4) implemented precisely this bound (counter, 5 attempts / 5-minute cooldown, `ca_max_attempts` / `ca_lockout_seconds` filters, REST `429`, and an atomic reserve-before-check) and was review-clean; it was closed for **scope**, not correctness, and the branch is preserved. Until one of those lands, the README and readme.txt must say plainly that this is not safe to run on a real site.

### Medium: CA-1 — Sudo confirmation is per-user, not session-bound

**Location:** `consequential-actions.php:843-845` (`confirm_key()`), `:868-880` (`confirmed_recently()`)

`confirm_key()` returns `'ca_confirmed_' . $user_id`, and `confirmed_recently()` trusts that transient for the current user. One successful confirmation opens the window for **every session, device, and Application Password** for that account until the TTL expires (default 5 minutes, `ca_sudo_window`).

The plugin advertises this cross-surface sharing as a convenience feature at `:278-280` ("a confirm in wp-admin also lets a follow-up REST call through for the window"). In the stolen-cookie threat model the plugin is demonstrating, that is backwards: **the legitimate admin's keystroke is what unlocks the attacker's channel.**

**Impact:** A concurrent stolen session inherits the elevation window. This is the central failure the wedge argues core should close, so leaving it open in the default configuration undercuts the argument.

**Aggravating factor:** `demo/mu-narrator.php:19` sets `add_filter( 'ca_sudo_window', '__return_zero' )`, so the Playground walkthrough — the artifact most reviewers will actually run — never exercises the window and therefore never exposes this weakness. The demo demonstrates a stricter system than the README recommends.

**Recommended fix:** Bind the confirmation to the current session token — include `wp_get_session_token()` (hashed) in the transient key, or store it in session-token metadata. Failing that, ship the demo at the real default so the limitation is visible.

### Medium: CA-6 — Application Password issuance is outside the gate's route pattern

**Location:** `consequential-actions.php:293`

The REST route test is `preg_match( '#^/wp/v2/users(?:/(me|\d+))?$#', … )`. The pattern is anchored, so it does **not** match `/wp/v2/users/me/application-passwords` — a real core route (`WP_REST_Application_Passwords_Controller`, `rest_base = 'users/(?P<user_id>(?:[\d]+|me))/application-passwords'`).

**Impact:** A hijacked session can mint a durable Application Password with no confirmation. That is a cleaner persistence mechanism than the backdoor-admin the demo *does* gate, and — because the credential is independent of the password — it **survives the password change the demo protects**. This is squarely inside the account-takeover class the plugin claims to cover, and it is not listed in the scope matrix.

**Recommended fix:** Either gate the route (it is a credential-issuance pivot, and the core spec treats it as one) or add it explicitly to the scope table's ungated rows so the omission is disclosed rather than implied.

### Low: CA-7 — REST user deletion passes through

**Location:** `consequential-actions.php:297`

The method filter admits only `POST`, `PUT`, `PATCH`; `DELETE` passes through. This is intentional and carries a code comment ("delete-user is not in this MVP catalog"), but "delete the site's other administrators" is part of the takeover narrative the demo tells, and the scope matrix does not mention it.

**Recommended fix:** Add a row to the scope matrix. Gating it is optional for an MVP; silently omitting it from the table is not.

### Low: CA-5 — Hardened-mode pending marker is also per-user

**Location:** `consequential-actions.php:851-866` (`pending_key()` / `reauthed_key()`), `:868-880`

Hardened mode destroys the current session and sets a pending marker by user ID; after the next login for that user it opens the same per-user window. Consistent with the documented transient limitation, but less precise than session-bound reauth state. Same root cause as CA-1.

**Recommended fix:** Include the post-login session token in the resulting confirmed state.

## Resolved since the previous revision

### ✅ CA-3 — Promotion detection only gated the literal `administrator` role — **FIXED**

`role_change_escalates()` (`consequential-actions.php:357-408`) now compares **effective sensitive capabilities** (`manage_options`, `promote_users`, `edit_users`, `delete_users`, `create_users`, `activate_plugins`, `install_plugins`, `update_core`, …) against the capabilities the user already holds, rather than matching the role slug. Custom administrator-equivalent roles are caught. Bulk promotion is covered by the same predicate via `escalating_bulk_targets()` (`:427-445`).

### ✅ CA-4 — Error message labels should be escaped individually — **FIXED**

`consequential-actions.php:494-502` maps every registry label through `esc_html()` before `implode()`. Correctly **not** applied in `gate_rest()` (`:324-328`), where the labels go into a JSON payload rather than an HTML sink.

## Positive notes

- Enforcement is server-side at all three gates; the modal is never trusted for authorization.
- The form gate runs before `wp_update_user()`/`wp_insert_user()` in the core flow; the bulk gate runs on `load-users.php` before core reaches `set_role()`.
- **Confirmation checks the actor's password, never the target user's** — the correctness point of Trac #20140, and the reason an admin can still change another user's password without knowing it.
- Bulk-promote detection mirrors core's own `WP_List_Table::current_action()` semantics, including the loose `-1 !=` sentinel, and is covered by both crafted-request and custom-role tests.
- Input reads are sanitized or cast; redirects use `wp_safe_redirect()` and exit.
- No direct database queries, file includes from user input, or unserialize/eval patterns in first-party code.
- Integration tests assert the *absence of commit* (`username_exists()` false, email unchanged), not merely that an error was returned.

## Overall assessment

Sound as a clearly scoped MVP/demonstrator of "authenticate the actor, not the target," and the strongest thing about it — gating on `wp_get_current_user()`'s credential — dissolves the objection that stalled Trac #20140 for over a decade.

It is **not** safe to run on a production site, and the gap between those two statements is now wide enough to state explicitly rather than leave to inference. CA-2 is the reason: in default configuration the plugin introduces an unmetered, unlogged password-guessing channel that core's login pipeline cannot see, reachable over an API credential. CA-1 and CA-6 mean a determined attacker with a concurrent session has two ways around the gate even without guessing. Either land the PR #4 bound and block API-credential callers from the confirm, or label the artifact unambiguously — the current readme language is not strong enough for something a reader can install.
