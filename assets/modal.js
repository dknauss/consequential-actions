/**
 * Consequential Actions — modal enhancement (window mode).
 *
 * Progressive enhancement over the server-side gate. When a gated action is
 * attempted, intercept the submit and collect the actor's current password in a
 * dialog, then submit the SAME form with the SAME confirm field. The server
 * (user_profile_update_errors) is still the sole authority; with JS off, the
 * inline #ca-fallback field stays visible and the server still enforces.
 */
( function () {
	var data = window.caModalData || {};
	var form = document.getElementById( 'your-profile' ) || document.getElementById( 'createuser' );
	if ( ! form ) {
		return;
	}
	var field = document.getElementById( 'ca_confirm_password' );
	if ( ! field ) {
		return;
	}

	// Hide the no-JS fallback; the modal replaces it.
	var fallback = document.getElementById( 'ca-fallback' );
	if ( fallback ) {
		fallback.style.display = 'none';
	}

	// Mirror the server's triggered_actions() well enough to know when to prompt.
	// A miss just falls back to the server round-trip — never a bypass.
	function isGatedAttempt() {
		if ( data.isCreate ) {
			return true;
		}
		var pass1 = document.getElementById( 'pass1' );
		if ( pass1 && pass1.value ) {
			return true;
		}
		var email = document.getElementById( 'email' );
		if ( email && data.email && email.value.trim().toLowerCase() !== data.email ) {
			return true;
		}
		var role = document.getElementById( 'role' );
		if ( role && 'administrator' === role.value && 'administrator' !== data.role ) {
			return true;
		}
		return false;
	}

	function openModal( onConfirm ) {
		var i18n = data.i18n || {};
		var overlay = document.createElement( 'div' );
		overlay.setAttribute( 'style', 'position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100000;display:flex;align-items:center;justify-content:center;' );

		var box = document.createElement( 'div' );
		box.setAttribute( 'style', 'background:#fff;max-width:380px;width:90%;padding:24px;border-radius:4px;box-shadow:0 4px 24px rgba(0,0,0,.3);' );
		box.setAttribute( 'role', 'dialog' );
		box.setAttribute( 'aria-modal', 'true' );
		box.innerHTML =
			'<h2 style="margin-top:0;font-size:1.2em;"></h2>' +
			'<p></p>' +
			'<input type="password" autocomplete="current-password" class="regular-text" style="width:100%;margin-bottom:16px;" />' +
			'<p style="text-align:right;margin:0;">' +
			'<button type="button" class="button" data-ca="cancel"></button> ' +
			'<button type="button" class="button button-primary" data-ca="ok"></button>' +
			'</p>';
		box.querySelector( 'h2' ).textContent = i18n.title || 'Confirm it is you';
		box.querySelector( 'p' ).textContent = i18n.label || 'Enter your current password to continue.';
		var input = box.querySelector( 'input' );
		var cancel = box.querySelector( '[data-ca="cancel"]' );
		var ok = box.querySelector( '[data-ca="ok"]' );
		cancel.textContent = i18n.cancel || 'Cancel';
		ok.textContent = i18n.confirm || 'Confirm';

		overlay.appendChild( box );
		document.body.appendChild( overlay );
		input.focus();

		function close() {
			if ( overlay.parentNode ) {
				overlay.parentNode.removeChild( overlay );
			}
		}
		function submit() {
			onConfirm( input.value );
			close();
		}
		cancel.addEventListener( 'click', close );
		ok.addEventListener( 'click', submit );
		input.addEventListener( 'keydown', function ( e ) {
			if ( 'Enter' === e.key ) {
				e.preventDefault();
				submit();
			} else if ( 'Escape' === e.key ) {
				close();
			}
		} );
	}

	// Capture phase + stopImmediatePropagation so we run before core's own
	// submit handlers (e.g. the weak-password confirmation).
	form.addEventListener(
		'submit',
		function ( e ) {
			if ( '1' === form.dataset.caReady ) {
				return; // our own re-submit — let it through
			}
			if ( ! isGatedAttempt() ) {
				return;
			}
			e.preventDefault();
			e.stopImmediatePropagation();
			openModal( function ( password ) {
				field.value = password;
				form.dataset.caReady = '1';
				var btn = document.getElementById( 'submit' ) || document.getElementById( 'createusersub' );
				if ( btn ) {
					btn.click();
				} else if ( form.requestSubmit ) {
					form.requestSubmit();
				}
			} );
		},
		true
	);
} )();
