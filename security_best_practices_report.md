# Consequential Actions security review

## Executive summary

The plugin largely does what it says for classic WordPress admin user forms: it names a small registry of account-takeover actions and blocks user create/update before commit until the acting user reconfirms their own password, or until hardened mode forces a fresh login. The core enforcement point is server-side (`user_profile_update_errors`), and the modal is only progressive enhancement.

I did not find a direct unauthenticated vulnerability, SQL injection, arbitrary file access, REST permission issue, or obvious XSS in first-party code. The main security limitations are design/scope issues: the default sudo window is per-user rather than session-bound, the inline password check has no first-party rate limiting or 2FA/passkey integration, and promotion detection only recognizes the literal `administrator` role. These limitations are mostly documented, but they matter if this is judged as production security software rather than an MVP demonstrator.

## Verification performed

- Reviewed repository files, README/readme claims, plugin PHP, modal JavaScript, demo files, and tests.
- Verified against WordPress trunk source that `user_profile_update_errors` fires before `wp_update_user()`/`wp_insert_user()` in `edit_user()`.
- Ran PHP syntax checks on first-party PHP files: passed.
- Ran `composer validate --strict`: passed.
- Ran `composer test`: passed, 14 tests / 14 assertions.
- Ran `composer audit --format=plain`: no advisory found.

## Findings

### Medium: CA-1 — Sudo confirmation is per-user, not session-bound

**Location:** `consequential-actions.php:346-376`

`confirm_key()` stores `ca_confirmed_$user_id`, and `confirmed_recently()` trusts that transient for the current user. This means one successful confirmation opens the window for every session/device for that user until the TTL expires. A stolen session that exists at the same time as a legitimate confirmed session can inherit the elevation window.

**Impact:** A session-hijack scenario is materially weaker during the sudo window, especially in default window mode.

**Recommended fix:** Bind the confirmation to the current session token, e.g. include `wp_get_session_token()` or a hash of it in the transient key, or store the confirmation in session-token metadata. Keep `ca_sudo_window = 0` for repeat-challenge demos.

### Medium: CA-2 — Inline password challenge lacks login-pipeline controls

**Location:** `consequential-actions.php:188-194`

Default mode verifies the current password with `wp_check_password()`. That correctly checks the actor's password, but it does not invoke the login pipeline, so it does not naturally inherit 2FA/passkeys, login throttling, lockouts, anomaly detection, or central authentication policy.

**Impact:** A compromised logged-in session can make repeated password guesses through the profile/user forms unless another plugin or upstream control limits it.

**Recommended fix:** Prefer hardened mode for high-assurance deployments, add attempt throttling for inline mode, and document that inline mode is proof-of-password only, not full reauthentication.

### Medium: CA-3 — Promotion detection only gates the literal `administrator` role

**Location:** `consequential-actions.php:136-142`

The plugin gates role changes only when the submitted role key is exactly `administrator`. That matches default WordPress persistence paths, but it misses custom roles with administrator-equivalent capabilities such as `manage_options`, `install_plugins`, or `promote_users`.

**Impact:** On sites with privileged custom roles, an attacker with a stolen privileged session may be able to grant a dangerous custom role without this gate treating it as `core/promote-user`.

**Recommended fix:** Compare effective capabilities, not just the role slug. For example, treat promotion as consequential when the new editable role grants a sensitive capability that the old role set did not grant.

### Low: CA-4 — Error message labels should be escaped individually

**Location:** `consequential-actions.php:197-211`

The format string is escaped, but labels from the filterable action registry are interpolated without individual escaping. A malicious plugin could already execute code, so this is not a standalone vulnerability in normal threat models, but escaping filterable output is still the correct WordPress pattern.

**Recommended fix:** Escape each label at interpolation time, e.g. map labels through `esc_html()` before `implode()`.

### Low: CA-5 — Hardened-mode pending marker is also per-user

**Location:** `consequential-actions.php:181-185`, `consequential-actions.php:332-339`, `consequential-actions.php:354-376`

Hardened mode destroys the current session and sets a pending marker by user ID. After the next login for that user, it opens the same per-user confirmation window. This is mostly consistent with the MVP's documented transient limitation, but it is less precise than a session-bound reauth state.

**Recommended fix:** Include the post-login session token in the resulting confirmed state, and consider destroying all sessions for the user if the mode is intended to contain stolen-cookie risk strongly.

## Positive notes

- Enforcement is server-side on `user_profile_update_errors`; the modal is not trusted for authorization.
- The gate runs before `wp_update_user()`/`wp_insert_user()` in the core flow.
- Confirmation checks the actor's password, not the target user's password.
- Input reads are mostly sanitized or cast (`email`, `role`, `user_id`, nonce field).
- Redirect uses `wp_safe_redirect()` and exits.
- No direct database queries, REST routes, file includes from user input, or unserialize/eval patterns were found.
- Demo-only HTML is output via `wp_kses_post()`.

## Overall assessment

Reasonably secure as a clearly scoped MVP/demonstrator. I would not describe it as a production-grade stolen-session defense in default mode because the elevation window is global to the user and the inline password prompt lacks login-pipeline protections. Hardened mode is the safer posture, but it should also become session-token-bound if the goal is high assurance.
