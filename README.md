# Consequential Actions (Reauth MVP)

A minimal, five-minute-readable demonstrator for a possible WordPress **core**
primitive: *name a small catalog of consequential actions, then require a fresh
proof of intent before they commit.* Built to make the argument in
[Core Trac #20140](https://core.trac.wordpress.org/ticket/20140) concrete and
runnable — not to be yet another standalone reauth plugin.

> **This is a wedge, not a product.** For a maintained, production reauthentication
> plugin that gates actions across admin/AJAX/REST and applies policy to
> non-interactive surfaces, see [WP Sudo](https://wordpress.org/plugins/wp-sudo/).
> This repo exists to show the *shape* of a core primitive at minimum size.

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
| **Window** (default, recommended) | — | On a gated submit, a modal asks for your current password and submits it with the form (no scrolling, no re-entry). With JavaScript off, an inline "confirm your current password" field is the fallback and the server still enforces. A successful confirm opens a short "sudo window" (default 5 min; filter `ca_sudo_window`, return 0 to always re-challenge). Note: in this MVP the window is a per-user transient flag, **not** a session — it is not session/cookie-bound. A real implementation binds the window to the login session so logout revokes it (WP Sudo does; the [core spec](https://github.com/dknauss/Sudo/blob/main/docs/core-sudo-gate-implementation-spec.md) proposes storing it on `WP_Session_Tokens`). |
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

The gate closes the **account-takeover** class; it does not make a hijacked *admin*
omnipotent (that admin could still install a plugin — out of scope for this MVP).

[**Open in Playground**](https://playground.wordpress.net/?blueprint-url=https://raw.githubusercontent.com/dknauss/consequential-actions/main/demo/blueprint.json)

The link tracks `main`, and the blueprint it loads installs the plugin from `main`
too — so the live demo always runs current code (including the REST walkthrough)
rather than a stale pinned release. The blueprint lives in [`demo/`](demo/).

## What this deliberately does NOT do

No WP-CLI / cron policy. No request stash-and-replay. No 2FA / passkeys. No
multisite network-session semantics. Those are the heavy framework pieces this MVP
argues core should not have to standardize all at once — and exactly what a full
implementation (WP Sudo) takes on.

It **does** now cover the REST users routes (`/wp/v2/users`), for both cookie- and
Application-Password-authenticated writes, so the demonstration is "gate the
action, every surface" rather than "gate the form." What it does not add is
per-surface *policy* (allow/block/deny tuning), stash-and-replay, or an
interactive challenge for non-browser callers — a REST caller proves intent by
resending with `ca_confirm_password`, or by confirming once in wp-admin to open
the shared window.

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

`v0.2.0` is a demonstrator. Status of the follow-ups:

- **Tests.** ✅ `triggered_actions()`, its REST twin `triggered_actions_rest()`, and
  the sudo-window helpers have Brain\Monkey unit coverage
  (`tests/TriggeredActionsTest.php`, `tests/RestTriggeredActionsTest.php`). Run with
  `composer install && composer test`.
- **REST coverage.** ✅ `rest_pre_dispatch` gates `/wp/v2/users` writes with the same
  rule, so the demo argues "gate the action, every surface," not "gate the form."
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
