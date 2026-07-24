=== Consequential Actions (Reauth MVP) ===
Contributors: dknauss
Tags: security, reauthentication, sudo, two-factor
Requires at least: 6.4
Requires PHP: 7.4
Stable tag: 0.2.1
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

The recommended primitive is that short window. An optional hardened mode (define
CA_TERMINATE_SESSION truthy) instead signs the user out and forces a full
reauthentication — a stricter opt-in for stolen-cookie-sensitive sites, not the
default. (Trac #20140 comment 32 walks back the earlier "just terminate the
session" idea in favor of the window.)

The same gate covers the REST users routes (/wp/v2/users), for both cookie- and
Application-Password-authenticated writes, so the block is on the consequential
*action*, not one screen. A REST caller proves intent by resending with its own
current password in ca_confirm_password, or by confirming once in wp-admin.

== What this deliberately does NOT do ==

* No WP-CLI / cron policy.
* No per-surface REST policy tuning, and no interactive challenge for non-browser callers.
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

= 0.2.1 =
* Registry: each catalog entry now carries the full metadata shape a core Actions
  API would register (label, capabilities, category, consequence_class, scope,
  annotations) instead of a bare label. The MVP still only reads `label`; the
  other fields are a deliberate, unused-here preview so the "this is what
  registration looks like" story is identical across the demo, the core spec, and
  a Make/Core post. No behavior change; the `consequential_actions` filter now
  receives the richer arrays (label remains present, so existing filters keep
  working).
* Demo: the Playground blueprint now tracks main instead of the stale v0.1.6 pin
  (so the live demo actually runs the current REST-gating code), and the
  profile-screen narration includes a paste-into-DevTools snippet that attempts
  the same password takeover over POST /wp/v2/users/me and shows the resulting
  403 ca_reauth_required — the same gate over REST as on the form.

= 0.2.0 =
* Coverage: the gate now also runs on the REST users routes (/wp/v2/users) via
  rest_pre_dispatch, for cookie- and Application-Password-authenticated writes, so
  a password/email change, user creation, or promotion is blocked the same way
  whether it arrives through wp-admin or the API. A REST caller proves intent with
  its own current password in ca_confirm_password, or by confirming in wp-admin to
  open the shared window. Adds unit coverage for the REST detector.
* Docs: reframe force-logout as a stricter opt-in, not "the stronger answer." The
  recommended primitive is the short reauth window (Trac #20140 comment 32); a
  session-bound window captures most of force-logout's assurance without the
  lost-work cost.

= 0.1.6 =
* Security: promotion is now detected by capability, not the literal
  "administrator" role name, so escalation into a privileged custom role (one
  granting manage_options, activate_plugins, etc.) is also gated.
* Hardening: escape each registry action label individually before it is shown
  in the reauth error, so a third-party filter cannot inject markup.

= 0.1.5 =
* Demo rewritten around one story: a stolen-session account takeover and the wall
  the gate puts in front of every step, including the reset-email recovery point
  (change the email and even "Lost your password?" would reach the attacker — so
  gating email-change keeps recovery pointed at the real owner).
* Force-logout mode is now documented as a preferred alternative for stolen-cookie
  containment (reuses the login pipeline's 2FA/lockouts), not a deprecated path.

= 0.1.4 =
* One demo instead of two: the guided-tour blueprint is removed and its useful
  part (mail logging) folds into the single demo, which now bundles WP Mail
  Logging so you can see the emails the gated actions send.
* Demo notice acknowledges a password change and points at the new password once
  you have changed it, instead of showing the original credential.

= 0.1.3 =
* Minimal demo now walks all three account-takeover actions — change password,
  create user, and promote to Administrator — to show the same challenge guards
  the whole class, not one field. (No change to gating logic: create-user and
  promote-user were already gated; the demo simply now exercises them.)

= 0.1.2 =
* The sudo window is now filterable (`ca_sudo_window`, return 0 to always
  re-challenge) and documented as a per-user transient flag, not a session.
* Minimal demo sets the window to 0 so the challenge is repeatable and the effect
  is verifiable by signing out and back in.

= 0.1.1 =
* Window mode: progressive-enhancement modal (no build step) collects the current
  password on submit, so there is no scrolling to a bottom-of-page field and no
  re-entry after a block. Inline field remains the no-JS fallback; the server-side
  gate is unchanged and still authoritative.

= 0.1.0 =
* Initial wedge MVP: action registry + actor-password step-up on account-takeover
  actions, with an optional hardened force-logout mode.
