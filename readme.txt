=== Consequential Actions (Reauth MVP) ===
Contributors: dknauss
Tags: security, reauthentication, sudo, two-factor
Requires at least: 6.4
Requires PHP: 7.4
Stable tag: 0.1.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Name a small catalog of consequential actions, then require the acting user to
re-confirm their own password before those actions commit. A runnable argument
for the core path in Trac #20140.

== Description ==

WordPress checks your password once, at login. Everything after rides the auth
cookie. Anyone holding a live session — a walk-up to an unlocked screen, or a
stolen session cookie — can change the account's password or email, create a
user, or promote one to administrator, with no fresh proof it is really you.

This plugin is **not** trying to be a complete solution (see WP Sudo for that).
It exists to make one argument as small as possible, in runnable code:

1. **Name the actions (Layer 1).** A stable, filterable registry of consequential
   action IDs — core/change-own-password, core/change-user-password,
   core/create-user, core/promote-user, and so on. This is valuable on its own for
   auditing, UI, and policy, even if nothing gates it. A real core version would be
   an Actions API.

2. **Gate them (Layer 2).** For account-takeover actions, require the acting user
   to re-enter *their own* current password (never the target user's). On success,
   open a short "sudo window" so the prompt is not repeated for a few minutes.

The security boundary is **recent authentication by the actor**, not the target
user's old password. That reframing is the whole point of Trac #20140: it lets an
administrator change another user's password without knowing it, while still
proving who is at the keyboard, and it unifies password, email, create-user, and
promotion under one idea.

An optional hardened mode (define CA_TERMINATE_SESSION truthy) signs the user out
and forces a full reauthentication instead of an inline confirm.

== What this deliberately does NOT do ==

* No REST / Application Password / WP-CLI / cron policy.
* No request stash-and-replay.
* No 2FA-aware challenge, passkeys, or modal.
* No multisite network-session semantics.

Those are the heavy framework pieces this MVP argues core should not have to
standardize all at once. They are exactly what a full implementation (WP Sudo)
takes on.

== Frequently Asked Questions ==

= Why not just require the old password on the profile screen? =

Because an attacker with a hijacked admin session can bypass a single field: create
a new admin, change the email and use password reset, or use the plugin installer.
The unit worth protecting is the consequential *action*, not one form input.

= Isn't this just password-confirm-action / WP Sudo again? =

For a single site, yes — those already work. The point of this build is the *shape*:
a named registry plus a thin gate, offered as a wedge for a core primitive rather
than as another standalone product.

== Changelog ==

= 0.1.1 =
* Window mode: progressive-enhancement modal (no build step) collects the current
  password on submit, so there is no scrolling to a bottom-of-page field and no
  re-entry after a block. Inline field remains the no-JS fallback; the server-side
  gate is unchanged and still authoritative.

= 0.1.0 =
* Initial wedge MVP: action registry + actor-password step-up on account-takeover
  actions, with an optional hardened force-logout mode.
