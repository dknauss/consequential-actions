> [!CAUTION]
> **Historical demonstrator — do not install.** This repository is archived and
> read-only. It was a wedge demonstrator for a possible WordPress core primitive
> (Trac #20140), not a maintained plugin. Its companion project, WP Sudo,
> concluded as a research prototype after an adversarial audit found seven
> high-severity bypasses of its own central claim. See
> [dknauss/Sudo/blob/main/docs/finding.md](https://github.com/dknauss/Sudo/blob/main/docs/finding.md)
> for the finding and the resulting core proposal. All code, tags, and history
> here are preserved as historical record.

# Consequential Actions (Reauth MVP)

A minimal, five-minute-readable demonstrator for a possible WordPress **core**
primitive: *name a small catalog of consequential actions, then require a fresh
proof of intent before they commit.* Built to make the argument in
[Core Trac #20140](https://core.trac.wordpress.org/ticket/20140) concrete and
runnable — not to be yet another standalone reauth plugin.

> **This was a wedge, not a product.** Its companion project,
> [WP Sudo](https://github.com/dknauss/Sudo), attempted broader enforcement and
> has also concluded. The [final finding](https://github.com/dknauss/Sudo/blob/main/docs/finding.md)
> explains why enumerating request surfaces could not sustain that security
> claim and what a Core-owned consequential-action primitive would need instead.
> Both repositories remain public as evidence, not maintained security controls.

> ## ⚠️ Do not run this on a production site
>
> The **wp-admin** confirm field is an un-throttled password oracle, deliberately.
> The form and bulk gates call `wp_check_password()` directly, which fires neither
> `wp_login_failed` nor the `authenticate` chain — so failed guesses are invisible
> to the login throttles that hook those (Limit Login Attempts, Wordfence, WP
> Fail2Ban), are not rate-limited by this plugin, and are not logged anywhere.
>
> Reaching it requires a live admin session, which is exactly this MVP's stated
> threat, so treat it as open. Throttling is the framework hardening this wedge
> defers to WP Sudo ([PR #4](https://github.com/dknauss/consequential-actions/pull/4)
> implemented a bounded lockout and was closed for scope, not correctness — the
> branch is preserved).
>
> **REST no longer accepts a password at all**, so that channel is closed for every
> credential class — see [Two modes](#two-modes).
>
> Two further account-takeover routes are ungated: REST user deletion (deliberately
> out of the MVP catalog) and Application-Password issuance (an oversight found while
> writing this warning — the route pattern is anchored and never matches it). Both are
> now in the scope table.
>
> Run it in [Playground](#try-it-live-wordpress-playground) or a throwaway site. Nowhere else.

## Scope and guarantees

This prototype **demonstrates** proof-of-intent on the surfaces below. It is not a
complete action-gating control, and the table is the honest boundary — read it
before relying on any single claim elsewhere in this README. What the gate covers
today:

| Surface | Operation | Gated? | Reauth mode | Tested |
|---|---|:---:|---|:---:|
| Profile / edit-user / new-user form | Change own/other password or email, promote a user to an admin-equivalent role, create user | ✅ | Window (default) or hardened force-logout | Unit + integration + manual Playground |
| REST `/wp/v2/users` (any credential) | Same account-takeover changes | ✅ | **Gated, not satisfiable from REST.** Passes only inside a window opened by confirming in wp-admin *in the same browser*; otherwise `403`. No password is accepted in the request | Unit + integration + manual Playground |
| Users list — **bulk** "Change role → Administrator" | Promote to admin-equivalent | ✅ | Inline interstitial (password re-POST) or hardened force-logout | Unit + integration + manual Playground |
| REST `/wp/v2/users/<id>/application-passwords` | Mint a durable API credential | ❌ *(ungated — the route pattern is anchored and does not match; the credential **survives** the password change this MVP protects)* | — | — |
| REST `DELETE /wp/v2/users/<id>` | Delete a user | ❌ *(ungated — not in the MVP catalog)* | — | — |
| Direct `set_role()` / `add_role()` / custom PHP | Promote / role change | ❌ *(out of scope — WP Sudo's domain)* | — | — |
| WP-CLI, cron | Any change | ❌ *(out of scope by design)* | — | — |

**Known gaps / limitations:**

- **Bulk role promotion is now gated** ([#3](https://github.com/dknauss/consequential-actions/issues/3),
  landed) — the Users-list bulk "Change role" is intercepted on `load-users.php`
  before core runs `set_role()`, matching core's own promote detection (`changeit`
  or `action`/`action2` = `promote`). Gating *arbitrary* programmatic `set_role()`
  from custom code remains a different, effect-level problem left to WP Sudo (the
  `set_role()` row above).
- **REST hardened mode.** The REST gate always returns `403` and does not force a
  logout, even when `CA_TERMINATE_SESSION` is set.
- **REST cannot satisfy the gate on its own.** A gated action over REST is refused
  unless the caller's own login session already holds a window opened in wp-admin.
  This is deliberate — it is what removes the password-guessing channel — but it
  does break legitimate API automation that changes emails, creates users, or
  promotes roles. `POST /wp/v2/users` (user provisioning) is affected for **all**
  API callers, not just the ones this MVP is arguing about.
- **Coverage is unit + WordPress-integration.** The pure detectors have Brain\Monkey
  unit coverage, and all three gates have *automated* integration tests that drive the
  **real save paths** against a live WordPress + MySQL (`WP_UnitTestCase`): `FormGateTest`
  calls real `edit_user()` and asserts `username_exists()` is false when blocked;
  `RestGateTest` calls real `rest_do_request()` and asserts the email did not commit;
  `BulkGateTest` covers the bulk-promote interstitial. Both suites run in CI: units
  across PHP 7.4–8.3, integration on PHP 8.2 and 8.3 against WordPress 6.4 (the
  plugin's "Requires at least") and latest.
  All three gates were *additionally* verified by hand in Playground (block →
  interstitial → correct password → promotion; wrong password re-challenges; a
  non-escalating change and a crafted `action=promote` both behave correctly).
  What is still missing is **browser-level E2E** (Playwright) covering the modal and
  the interstitial as a user drives them — rung 3 of
  [#9](https://github.com/dknauss/consequential-actions/issues/9).

The wedge now gates the action across **three enumerated user-management surfaces**:
the form, the REST route, and the Users-list bulk action. Arbitrary programmatic
`set_role()` from custom code, and non-interactive surfaces (WP-CLI, cron), are
explicitly WP Sudo's domain — not gaps this prototype intends to close.

## The idea, in two layers

1. **Name the actions (Layer 1).** A stable, filterable registry of action IDs —
   `core/change-own-password`, `core/change-user-password`, `core/create-user`,
   `core/promote-user`, and so on — each carrying the metadata a core Actions API
   would register (capabilities, category, consequence class, scope, annotations).
   Useful on its own for auditing, UI, and policy,
   even if nothing gates it. A real core version would be an Actions API.
2. **Gate them (Layer 2).** Before an account-takeover action commits, require the
   **acting user** to prove recent authentication. The credential checked is
   always the current user's own password — *never* the target user's. That is the
   correct security boundary (Trac #20140, comments 8–10): it proves who is at the
   keyboard, and lets an admin edit another account without knowing its password.

## Two modes

| Mode | How to enable | Behavior |
|------|---------------|----------|
| **Window** (default, recommended) | — | On a gated submit in wp-admin, a modal asks for your current password and submits it with the form (no scrolling, no re-entry). With JavaScript off, an inline "confirm your current password" field is the fallback and the server still enforces. A successful confirm opens a short "sudo window" (default 5 min; filter `ca_sudo_window`, return 0 to always re-challenge). The window is **bound to the login session that opened it** — the transient key mixes in a hash of `wp_get_session_token()` — so a second browser, a cloned cookie, or an Application Password cannot inherit it, and a caller with no login session can hold no window at all. REST therefore has no way to satisfy the gate on its own; that is deliberate, and it is what removes the password-guessing channel. |
| **Hardened** (force-logout) | `define( 'CA_TERMINATE_SESSION', true );` | An unconfirmed gated action signs the user out and forces a full re-login before they can retry — a stricter opt-in, the literal reading of Trac #20140 comment 31. |

### The window is the primitive; force-logout is a stricter opt-in

Earlier framing here (and Trac #20140 comment 31) reached for full session
termination. Comment **32 walks that back**: forced re-login "is heavier than the
problem needs," and the right primitive is step-up reauthentication into a short
elevated **window**. That is what this MVP defaults to and what the
[core spec](https://github.com/dknauss/Sudo/blob/main/docs/core-sudo-gate-implementation-spec.md)
proposes to core. Force-logout stays available for sites that want it, but it is
not the recommended answer.

What force-logout buys, at a friction cost (you lose the session and any unsaved
work):

- **Ejects a possibly-hijacked session** — the attacker must re-present credentials
  they don't have.
- **Reauthenticates through the real login pipeline**, inheriting its **2FA /
  passkeys / rate-limiting / lockouts**.
- **Leaves no lingering elevation window** on the old session.
- **Produces a real, audited `wp_login` event.**

Most of that assurance is available without the friction once the window is done
properly: a **session-bound** window (WP Sudo, and the core spec) runs its confirm
through the same 2FA/lockout pipeline **and** is revoked by logout and "log out
everywhere" — so the window, not forced re-login, is the primitive worth
standardizing. Reserve force-logout for high-assurance or stolen-cookie-sensitive
sites that accept the cost.

## Try it live (WordPress Playground)

No install — runs entirely in your browser. The demo tells **one story**: an
account takeover from a hijacked (stolen-cookie) session, and the wall the gate
puts in front of every step. Try to change the account's **email** (its recovery
path), create a backdoor **admin**, or **promote** a user — each demands the
account password the attacker doesn't have. WP Mail Logging is bundled so you can
watch a "Lost your password?" reset go to the *real* owner, because the email
could not be silently hijacked.

On the surfaces in the [Scope and guarantees](#scope-and-guarantees) table, the gate
blocks the **account-takeover** class; it does not make a hijacked *admin* omnipotent
(that admin could still install a plugin — out of scope for this MVP). Bulk role
changes *are* covered ([#3](https://github.com/dknauss/consequential-actions/issues/3),
landed); arbitrary programmatic `set_role()` is not.

[**Open in Playground**](https://playground.wordpress.net/?blueprint-url=https://raw.githubusercontent.com/dknauss/consequential-actions/main/demo/blueprint.json) &nbsp;·&nbsp; [Stable fallback (pinned `v0.3.0`)](https://playground.wordpress.net/?blueprint-url=https://raw.githubusercontent.com/dknauss/consequential-actions/v0.3.0/demo/blueprint-pinned.json)

The primary link tracks `main`, and the blueprint it loads installs the plugin
from `main` too — so the live demo always runs current code (including the REST
walkthrough) rather than a stale pinned release. The **fallback** pins every source
(plugin, narrator, blueprint) to the immutable `v0.3.0` tag, so it keeps working even
if `main` is temporarily broken. Both blueprints live in [`demo/`](demo/).

(Maintainer note: the pin must move every release. CI enforces that
`demo/blueprint-pinned.json` references the same version as the plugin header,
so a bump without a repoint fails the build — that mismatch previously shipped
a "stable" demo with neither the bulk gate nor the session-bound window.)

## What this deliberately does NOT do

No WP-CLI / cron policy. No request stash-and-replay. No 2FA / passkeys. No
multisite network-session semantics. Those are the heavy framework pieces this MVP
argues core should not have to standardize all at once — and exactly what a full
implementation (WP Sudo) takes on.

It **does** now cover the REST users routes (`/wp/v2/users`), for both cookie- and
Application-Password-authenticated writes, so the gate spans the admin form **and**
the REST route for these actions — not just one screen. It also covers the Users-list
**bulk** role change ([#3](https://github.com/dknauss/consequential-actions/issues/3),
landed). It does not reach every path to the same *effect*: arbitrary programmatic
`set_role()` from custom code is **deliberately out of scope** (WP Sudo's domain). See [Scope and guarantees](#scope-and-guarantees). What it also does not add is
per-surface *policy* (allow/block/deny tuning), stash-and-replay, or an
interactive challenge for non-browser callers. A REST caller cannot prove intent
over REST at all: it must confirm in wp-admin, in the same browser, and reuse that
session's window.

## How it works

Core hooks, no new machinery:

- `show_user_profile` / `edit_user_profile` / `user_new_form` — render the inline
  confirm field (window mode), progressively enhanced into a modal by a small
  no-build script (`assets/modal.js`) that submits the same field to the same gate.
- `user_profile_update_errors` — detect which consequential actions the submission
  triggers and gate them (block-and-confirm, or force-logout).
- `rest_pre_dispatch` — gate the same actions on cookie- or Application-Password-
  authenticated writes to `/wp/v2/users`, using the same actor-password rule, so
  the block is not limited to the admin forms.
- `login_message` / `wp_login` — explain the forced logout and treat the fresh
  login as recent authentication (hardened mode).

## Status & next steps

`v0.3.0` is a demonstrator. Status of the follow-ups:

- **Tests.** ✅ Two suites. **Unit** (Brain\Monkey, no database): `triggered_actions()`,
  its REST twin `triggered_actions_rest()`, the bulk-promote detectors, the sudo-window
  helpers, and the `actions()` registry metadata contract — `tests/TriggeredActionsTest.php`,
  `tests/RestTriggeredActionsTest.php`, `tests/BulkPromoteTest.php`,
  `tests/RegistryContractTest.php`. **Integration** (`WP_UnitTestCase`, real WordPress +
  MySQL, driving the actual save paths): `tests/Integration/FormGateTest.php`,
  `RestGateTest.php`, `BulkGateTest.php`, `SmokeTest.php`. Run units with
  `composer install && composer test`; both run in CI (units PHP 7.4–8.3;
  integration PHP 8.2/8.3 against WP 6.4 + latest). Browser-level E2E is still outstanding
  ([#9](https://github.com/dknauss/consequential-actions/issues/9) rung 3).
- **REST coverage.** ✅ `rest_pre_dispatch` gates `/wp/v2/users` writes with the same
  rule, so the gate spans the form **and** the REST route — though not yet every path
  to the same effect (see [Scope and guarantees](#scope-and-guarantees)).
- **Progressive enhancement.** ✅ A no-build modal collects the password on submit;
  the inline field is the no-JS fallback.
- **The registry as its own thing.** Layer 1 deserves to be proposed to core
  independently of the gate — still open.
- **Exercise REST in the live demo.** ✅ Done (v0.2.1). The profile-screen narration
  now includes a paste-into-DevTools snippet that attempts the same password
  takeover over `POST /wp/v2/users/me` and logs the `403 ca_reauth_required` — the
  gate on the action, not the form. (The blueprint also now tracks `main` instead
  of the stale `v0.1.6` pin, so the live demo runs the current code.)

## License

GPL-2.0-or-later. See [LICENSE](LICENSE).
