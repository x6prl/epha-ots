/*
 * Copyright (C) 2026 adnihilum authors
 *
 * This file is part of adnihilum.
 *
 * adnihilum is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * adnihilum is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with adnihilum.  If not, see <https://www.gnu.org/licenses/>.
 */
// SPDX-License-Identifier: GPL-3.0-or-later

(function () {
	const shared = window.AdNihilumShared;
	let suppressGeneratedStateReset = false;

	function setPrimaryButtonLabel(text, stateClass) {
		const button = shared.$('btnGetLink');
		const label = shared.$('btnGetLinkLabel');
		if (!button || !label)
			return;

		if (!button.dataset.defaultLabel)
			button.dataset.defaultLabel = label.textContent;

		button.classList.remove('is-busy', 'is-ready', 'is-success');
		if (stateClass)
			button.classList.add('is-' + stateClass);

		label.textContent = text ||
			button.dataset.defaultLabel ||
			'Create and copy link';
	}

	function resetPrimaryButton() {
		const button = shared.$('btnGetLink');
		setPrimaryButtonLabel(
			button ? button.dataset.defaultLabel : 'Create and copy link');
	}

	function clearGeneratedState() {
		if (suppressGeneratedStateReset)
			return;
		if (shared.state.link)
			shared.setLink(null, null, null);
		resetPrimaryButton();
	}

	function friendlySendError(err) {
		const message = err && err.message ? err.message : String(err || '');
		if (/^Invalid service origin URL$/i.test(message))
			return shared.i18n('invalid_service_url');
		if (/^Origin must not include credentials$/i.test(message))
			return shared.i18n('origin_credentials');
		if (/^Origin must not include path, query, or fragment$/i.test(message))
			return shared.i18n('origin_path');
		if (/^Service origin must use https:\/\//i.test(message))
			return shared.i18n('origin_https');
		if (/^Key length mismatch$|^ID length mismatch$|^Invalid base64 data$/i.test(message))
			return shared.i18n('generated_invalid');
		if (/^Image clipboard is not available/i.test(message))
			return shared.i18n('clipboard_image_unavailable');
		if (/^Clipboard API unavailable$/i.test(message))
			return shared.i18n('clipboard_text_unavailable');
		if (/Failed to fetch|NetworkError|Load failed/i.test(message))
			return shared.i18n('service_unreachable');
		if (/POST .* 40[034]\b/i.test(message))
			return shared.i18n('server_refused');
		if (/POST .* 41[03]\b/i.test(message))
			return shared.i18n('server_busy');
		if (/POST .* 42[39]\b/i.test(message))
			return shared.i18n('rate_limited');
		if (/POST .* 5\d\d\b/i.test(message))
			return shared.i18n('server_failed');
		return shared.i18n('create_secret_failed');
	}

	function showSendError(err) {
		shared.showPopup(shared.i18n('create_link_error'), friendlySendError(err));
	}

	function setInputsDisabled(disabled) {
		['btnGetLink', 'btnCopyLink', 'btnCopyLinkInline', 'btnCopyQrImage', 'optionalPassword']
			.forEach((id) => {
				const el = shared.$(id);
				if (el)
					el.disabled = disabled;
			});
	}

	function shouldAutoScrollComposer() {
		if (typeof window === 'undefined' ||
			typeof window.matchMedia !== 'function') {
			return false;
		}
		return window.matchMedia('(max-width: 900px)').matches ||
			window.matchMedia('(pointer: coarse)').matches;
	}

	function scrollComposerToTop(target) {
		const SCROLL_DELAY = 30;
		if (!target || !shouldAutoScrollComposer())
			return;

		const composerPanel = target.closest('.composer-panel');
		const scrollTarget = composerPanel || target;
		const doScroll = () => {
			scrollTarget.scrollIntoView({
				block: 'start',
				inline: 'nearest',
				behavior: 'smooth',
			});
		};

		doScroll();
		if (typeof window.requestAnimationFrame === 'function')
			window.requestAnimationFrame(doScroll);
		setTimeout(doScroll, SCROLL_DELAY);
	}

	function bindComposerFieldAutoScroll(field) {
		const FIELD_SELECTED_SCROLL_DELAY = 40;
		let viewprotTimer = null;
		const triggerScroll = () => {
			scrollComposerToTop(field);
		}
		const handleViewportChange = () => {
			if (viewprotTimer != null)
				clearTimeout(viewprotTimer);
			viewprotTimer = setTimeout(() => {
				viewprotTimer = null;
				if (document.activeElement === field)
					triggerScroll();
			}, FIELD_SELECTED_SCROLL_DELAY);
		}

		field.addEventListener('focus', triggerScroll);
		field.addEventListener('click', triggerScroll);

		if (window.visualViewport && typeof window.visualViewport.addEventListener === 'function') {
			field.addEventListener('focus', () => {
				window.visualViewport.addEventListener('resize', handleViewportChange);
			});
			field.addEventListener('blur', () => {
				window.visualViewport.removeEventListener('resize', handleViewportChange);
				if (viewprotTimer != null) {
					clearTimeout(viewprotTimer);
					viewprotTimer = null;
				}
			})
		}
	}

	async function sendSecret() {
		shared.clearPendingSecret();
		shared.lockTextarea(true);
		setInputsDisabled(true);
		setPrimaryButtonLabel(shared.i18n('creating_link'), 'busy');

		let keyBytes = null;
		let nonce = null;
		let salt = null;
		let idBytes = null;
		let payload = null;
		let taggedPayload = null;
		let ciphertext = null;
		let blob = null;

		try {
			const origin = shared.getOrigin();
			const textField = shared.$('text');
			const passwordInput = shared.$('optionalPassword');
			if (!textField || !passwordInput)
				return;

			if (!textField.value) {
				resetPrimaryButton();
				textField.focus();
				shared.showPopup(shared.i18n('nothing_to_send'),
					shared.i18n('enter_secret'));
				return;
			}

			const passwordValue = passwordInput.value;
			const hasPassword = typeof passwordValue === 'string' &&
				passwordValue.length > 0;
			payload = shared.encoder.encode(textField.value);
			keyBytes = crypto.getRandomValues(new Uint8Array(shared.KEY_SIZE));
			nonce = crypto.getRandomValues(new Uint8Array(shared.NONCE_SIZE));
			salt = crypto.getRandomValues(new Uint8Array(shared.SALT_SIZE));
			idBytes = await shared.deriveIdFromKeyAndSalt(keyBytes, salt);
			const idBase64Url = shared.base64UrlEncode(idBytes);
			const aad = shared.encoder.encode('id=' + idBase64Url);

			if (hasPassword) {
				const passwordKey = await shared.derivePasswordKey(
					passwordValue, salt, ['encrypt']);
				const wrappedBuffer = await crypto.subtle.encrypt(
					{ name: 'AES-GCM', iv: nonce, additionalData: aad },
					passwordKey,
					payload);
				payload.fill(0);
				payload = new Uint8Array(wrappedBuffer);
			}

			const tagBytes = hasPassword ?
				shared.BLOB_TYPE_PASSWORD :
				shared.BLOB_TYPE_TEXT;
			taggedPayload = new Uint8Array(shared.BLOB_TYPE_SIZE +
				payload.length);
			taggedPayload.set(tagBytes, 0);
			taggedPayload.set(payload, shared.BLOB_TYPE_SIZE);

			const aesKey = await crypto.subtle.importKey(
				'raw',
				keyBytes,
				{ name: 'AES-GCM', length: shared.KEY_SIZE * 8 },
				false,
				['encrypt']);
			ciphertext = new Uint8Array(await crypto.subtle.encrypt(
				{ name: 'AES-GCM', iv: nonce, additionalData: aad },
				aesKey,
				taggedPayload));

			taggedPayload.fill(0);
			taggedPayload = null;
			payload.fill(0);
			payload = null;

			blob = new Uint8Array(nonce.length + salt.length + ciphertext.length);
			blob.set(nonce, 0);
			blob.set(salt, nonce.length);
			blob.set(ciphertext, nonce.length + salt.length);
			if (blob.length > shared.BLOB_SIZE_MAX - 100) {
				resetPrimaryButton();
				shared.showPopup(shared.i18n('secret_too_large'),
					shared.i18n('shorten_secret'));
				return;
			}

			const url = shared.normalizeOrigin(origin) + '/blob/' +
				shared.bytesToHex(idBytes);
			const res = await fetch(url, {
				method: 'POST',
				body: blob,
			});
			if (!res.ok) {
				const responseText = await shared.safeText(res);
				throw new Error(`POST ${url} ${res.status}: ${responseText || res.statusText}`);
			}

			passwordInput.value = '';
			shared.setLink(origin, shared.base64UrlEncode(idBytes),
				shared.base64UrlEncode(keyBytes));

			try {
				if (typeof navigator === 'undefined' ||
					!navigator.clipboard ||
					typeof navigator.clipboard.writeText !== 'function') {
					throw new Error(shared.i18n('clipboard_text_unavailable'));
				}
				await navigator.clipboard.writeText(shared.state.link);
				setPrimaryButtonLabel(shared.i18n('link_copied'), 'success');
			} catch (copyErr) {
				console.error(copyErr);
				setPrimaryButtonLabel(shared.i18n('link_ready'), 'ready');
				shared.showPopup(shared.i18n('link_created'),
					friendlySendError(copyErr));
			}

			// NOTE: randomize text field background in order to
			// notify the user that something was changed
			if (textField)
				textField.style.backgroundColor =
					`hsl(${Math.floor(Math.random() * 360)} 35% 10%)`;
		} catch (err) {
			console.error(err);
			resetPrimaryButton();
			showSendError(err);
		} finally {
			if (payload)
				payload.fill(0);
			if (taggedPayload)
				taggedPayload.fill(0);
			if (ciphertext)
				ciphertext.fill(0);
			if (blob)
				blob.fill(0);
			if (keyBytes)
				keyBytes.fill(0);
			if (nonce)
				nonce.fill(0);
			if (salt)
				salt.fill(0);
			if (idBytes)
				idBytes.fill(0);
			suppressGeneratedStateReset = true;
			shared.lockTextarea(false);
			suppressGeneratedStateReset = false;
			setInputsDisabled(false);

			const copyBtn = shared.$('btnCopyLink');
			const qrBtn = shared.$('btnCopyQrImage');
			if (copyBtn)
				copyBtn.disabled = false;
			if (qrBtn)
				qrBtn.disabled = false;
		}
	}

	function init() {
		const btnGetLink = shared.$('btnGetLink');
		const btnCopyLink = shared.$('btnCopyLink');
		const btnCopyLinkInline = shared.$('btnCopyLinkInline'); // NOTE: only in client.html
		const btnCopyQrImage = shared.$('btnCopyQrImage');
		const optionalPasswordField = shared.$('optionalPassword');
		const textArea = shared.$('text');

		if (!btnGetLink || !btnCopyLink || !optionalPasswordField || !textArea) {
			return;
		}

		if (shared.state.originalPlaceholder === null) {
			const initial = textArea.getAttribute('placeholder');
			shared.state.originalPlaceholder =
				typeof initial === 'string' ? initial : '';
		}

		btnGetLink.addEventListener('click', () => { void sendSecret(); });
		btnCopyLink.addEventListener('click', shared.copyLink);
		btnCopyLinkInline && btnCopyLinkInline.addEventListener('click', shared.copyLink); // NOTE: because only in client.html
		if (btnCopyQrImage)
			btnCopyQrImage.addEventListener('click', () => {
				void shared.copyQrImage();
			});

		textArea.addEventListener('keydown', (event) => {
			const modifierPressed = shared.isMacLike ? event.metaKey : event.ctrlKey;
			if (event.key === 'Enter' && modifierPressed) {
				if (!event.repeat)
					void sendSecret();
				event.preventDefault();
			}
		});

		optionalPasswordField.addEventListener('keydown', (event) => {
			const modifierPressed = shared.isMacLike ? event.metaKey : event.ctrlKey;
			if (event.key === 'Enter' && modifierPressed) {
				if (!event.repeat)
					void sendSecret();
				event.preventDefault();
			}
		});

		textArea.addEventListener('input', clearGeneratedState);
		optionalPasswordField.addEventListener('input', clearGeneratedState);
		bindComposerFieldAutoScroll(textArea);
		bindComposerFieldAutoScroll(optionalPasswordField);

		resetPrimaryButton();
	}

	window.AdNihilumSend = { init };
})();
