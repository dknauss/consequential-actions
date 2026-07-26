# Consequential Actions security review

> **Re-run after the session-bound window landed.** CA-1 is fixed and CA-2 is
> downgraded and narrowed — the REST password channel is gone entirely. Line
> references are re-derived against the current file.

## Executive summary

The plugin does what it says for the three user-management surfaces it enumerates: it names a small registry of account-takeover actions and blocks user create/update/promote before commit until the acting user reconfirms **their own** password, or until hardened mode forces a fresh login. Enforcement is server-side at every gate; the modal is only progressive enhancement.

I did not find a direct unauthenticated vulnerability, SQL injection, arbitrary file access, REST permission bypass, or XSS in first-party code.

The remaining limitations are design/scope issues. In descending order: the wp-admin confirm field is still an un-throttled password oracle, reachable by a caller who already holds an admin session (CA-2 — no longer reachable over REST); two account-takeover-adjacent REST routes go ungated, one outside the gate's route pattern (CA-6), one admitted by the pattern but excluded by its method filter (CA-7); and hardened mode's pending marker stays per-user, though only a browser can consume it (CA-5).

Two findings closed in this revision. **CA-1** — the window was a bare per-user transient, so one browser's confirmation elevated every concurrent session and credential on the account — is fixed by binding the window to the login session that opened it. And the REST gate no longer accepts a password at all, which removes the guessing channel for every bearer credential rather than special-casing Application Passwords.

A live gate bypass was also found and fixed alongside: the plugin's route pattern was case-sensitive while core's dispatcher matches case-insensitively, so `POST /wp/v2/Users/me` dispatched normally and skipped the gate entirely.

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

### Medium: CA-2 — The wp-admin confirm field is an un-throttled password oracle

**Location:** `consequential-actions.php:489` (form), `:646` (bulk)

**Downgraded from High, and narrowed from three call sites to two.** The REST call site is gone: `gate_rest()` no longer reads the confirm field or calls `wp_check_password()` at all, so there is no password-guessing channel over the API for any credential class.

What remains: the form and bulk gates verify the actor's password by calling `wp_check_password()` directly, which bypasses the login pipeline. `wp_check_password()` fires only the `check_password` filter; it never fires `wp_login_failed` and never runs the `authenticate` / `wp_authenticate_user` chain. The mainstream throttles that hook those (Limit Login Attempts Reloaded, Wordfence, WP Fail2Ban) therefore never see a failed confirm. WP Sudo does not see one either, for a different reason: its lockout is an internal counter inside its own reauth flow (`_wp_sudo_failed_attempts`), not a `wp_login_failed` listener. There is no first-party counter, and no `do_action` fires on failure, so attempts are not auditable.

**Why still Medium rather than Low:** reaching these two sites requires a live authenticated admin session with a valid nonce — which is precisely this artifact's stated threat model. A stolen cookie can scrape a nonce from any admin page in one request. So for the threat the demo dramatises, the oracle is open; it is simply no longer reachable by a bearer token with no browser session.

**Recommended fix:** bound failed attempts on the two remaining verifiers. [PR #4](https://github.com/dknauss/consequential-actions/pull/4) implemented exactly this and was review-clean; it was closed for **scope**, not correctness, and the branch is preserved. Tracked in [#13](https://github.com/dknauss/consequential-actions/issues/13).

### ✅ CA-1 — Sudo confirmation was per-user, not session-bound — **FIXED**

`confirm_key()` now mixes a hash of `wp_get_session_token()` into the transient key, so a window belongs to the login session that opened it. A second browser, a cloned cookie, or an API credential cannot inherit it, and a caller with **no** login session gets an empty key — it can neither open a window nor read one. That covers every bearer credential (Application Password, JWT, OAuth, CLI), not only the one core exposes a getter for.

The raw token is hashed rather than stored, since the key becomes an option name and a session token is a credential.

Regression coverage: `tests/Integration/WindowBindingTest.php` asserts a window from one session does not elevate another, that a sessionless caller can neither inherit nor open one, and that the legitimate same-session flow still works.

**Residual:** a session hijacked *within its own* open window still inherits that window. That is inherent to any window primitive and is why the TTL is short (`ca_sudo_window`, default 5 min; return 0 to always re-challenge).

### Medium: CA-6 — Application Password issuance is outside the gate's route pattern

**Location:** `consequential-actions.php:293`

The REST route test is `preg_match( '#^/wp/v2/users(?:/(me|\d+))?$#', … )`. The pattern is anchored, so it does **not** match `/wp/v2/users/me/application-passwords` — a real core route (`WP_REST_Application_Passwords_Controller`, `rest_base = 'users/(?P<user_id>(?:[\d]+|me))/application-passwords'`).

**Impact:** A hijacked session can mint a durable Application Password with no confirmation. That is a cleaner persistence mechanism than the backdoor-admin the demo *does* gate, and — because the credential is independent of the password — it **survives the password change the demo protects**. This is squarely inside the account-takeover class the plugin claims to cover, and it is not listed in the scope matrix.

**Recommended fix:** Either gate the route (it is a credential-issuance pivot, and the core spec treats it as one) or add it explicitly to the scope table's ungated rows so the omission is disclosed rather than implied.

### Low: CA-7 — REST user deletion passes through

**Location:** `consequential-actions.php:297`

The method filter admits only `POST`, `PUT`, `PATCH`; `DELETE` passes through. This is intentional and carries a code comment ("delete-user is not in this MVP catalog"), but "delete the site's other administrators" is part of the takeover narrative the demo tells, and the scope matrix does not mention it.

**Recommended fix:** Add a row to the scope matrix. Gating it is optional for an MVP; silently omitting it from the table is not.

### Low: CA-5 — Hardened-mode pending marker is still per-user

**Location:** `consequential-actions.php:851-866` (`pending_key()` / `reauthed_key()`)

**Partially mitigated.** These two markers remain keyed per-user, and deliberately so: the pending marker has to survive the forced logout that creates it, so there is no session to bind it to at write time. (Binding at `wp_login` would not work either — the new auth cookie is not yet in `$_COOKIE` on that request, so the key would be unreadable afterwards.)

What changed: `confirmed_recently()` now only honours the one-time pass when the request carries a login session, so a bearer credential racing the victim's re-login cannot consume it. The marker is per-user; the *consumption* is browser-only.

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
