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
   `core/promote-user`, and so on. Useful on its own for auditing, UI, and policy,
   even if nothing gates it. A real core version would be an Actions API.
2. **Gate them (Layer 2).** Before an account-takeover action commits, require the
   **acting user** to prove recent authentication. The credential checked is
   always the current user's own password — *never* the target user's. That is the
   correct security boundary (Trac #20140, comments 8–10): it proves who is at the
   keyboard, and lets an admin edit another account without knowing its password.

## Two modes

| Mode | How to enable | Behavior |
|------|---------------|----------|
| **Window** (default) | — | On a gated submit, a modal asks for your current password and submits it with the form (no scrolling, no re-entry). With JavaScript off, an inline "confirm your current password" field is the fallback and the server still enforces. A successful confirm opens a short "sudo window" (default 5 min; filter `ca_sudo_window`, return 0 to always re-challenge). Note: the window is a per-user transient flag, **not** a session — it is not session/cookie-bound (WP Sudo does that properly). |
| **Hardened** (force-logout) | `define( 'CA_TERMINATE_SESSION', true );` | An unconfirmed gated action signs the user out and forces a full reauthentication before they can retry — the stronger reading of Trac #20140 comment 31. |

## Try it live (WordPress Playground)

No install — runs entirely in your browser. The demo walks all three
account-takeover actions (change your password, create a user, promote one to
Administrator); each pops the same reauth challenge. WP Mail Logging is bundled so
you can see the emails those actions send.

[**Open in Playground**](https://playground.wordpress.net/?blueprint-url=https://raw.githubusercontent.com/dknauss/consequential-actions/v0.1.4/demo/blueprint.json)

The link pins to the immutable `v0.1.4` tag, so it keeps working. The blueprint
lives in [`demo/`](demo/).

## What this deliberately does NOT do

No REST / Application Password / WP-CLI / cron policy. No request stash-and-replay.
No 2FA / passkeys. No multisite network-session semantics. Those are the
heavy framework pieces this MVP argues core should not have to standardize all at
once — and exactly what a full implementation (WP Sudo) takes on.

## How it works

Core hooks, no new machinery:

- `show_user_profile` / `edit_user_profile` / `user_new_form` — render the inline
  confirm field (window mode), progressively enhanced into a modal by a small
  no-build script (`assets/modal.js`) that submits the same field to the same gate.
- `user_profile_update_errors` — detect which consequential actions the submission
  triggers and gate them (block-and-confirm, or force-logout).
- `login_message` / `wp_login` — explain the forced logout and treat the fresh
  login as recent authentication (hardened mode).

## Status & next steps

`v0.1.4` is a demonstrator. Status of the follow-ups:

- **Tests.** ✅ `triggered_actions()` and the sudo-window helpers have Brain\Monkey
  unit coverage (`tests/TriggeredActionsTest.php`, 14 tests). Run with
  `composer install && composer test`.
- **Progressive enhancement.** ✅ A no-build modal collects the password on submit;
  the inline field is the no-JS fallback.
- **The registry as its own thing.** Layer 1 deserves to be proposed to core
  independently of the gate — still open.

## License

GPL-2.0-or-later. See [LICENSE](LICENSE).
