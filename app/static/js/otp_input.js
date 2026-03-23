/**
 * GhostPortal — OTP Input Handler
 *
 * Features:
 *  - Enable submit button only when field reaches OTP_LENGTH characters (stripped)
 *  - Visual formatting: insert space every 5 characters for readability (display only)
 */

(function () {
  'use strict';

  // Read config from the script tag's data attributes (CSP-safe, no inline script needed).
  // document.currentScript is null for defer-ed scripts, so fall back to querySelector.
  const scriptEl  = document.querySelector('script[data-otp-length]');
  const OTP_LENGTH = scriptEl ? parseInt(scriptEl.dataset.otpLength, 10) : 20;

  const input     = document.getElementById('otp');
  const submitBtn = document.getElementById('otp-submit');
  const form      = document.getElementById('otp-form');

  if (!input || !submitBtn) return;

  /**
   * Strip all spaces/separators, return raw OTP characters.
   */
  function getRawOTP(value) {
    return value.replace(/\s+/g, '');
  }

  /**
   * Format OTP with visual spaces every 5 characters.
   * "ABCDE12345fghij67890" → "ABCDE  12345  fghij  67890"
   */
  function formatOTP(raw) {
    const chunks = [];
    for (let i = 0; i < raw.length; i += 5) {
      chunks.push(raw.slice(i, i + 5));
    }
    return chunks.join('  ');
  }

  /**
   * Update the submit button state based on input length.
   */
  function updateSubmitState() {
    const raw = getRawOTP(input.value);
    submitBtn.disabled = raw.length < OTP_LENGTH;

    if (raw.length === OTP_LENGTH) {
      submitBtn.classList.add('btn-ready');
    } else {
      submitBtn.classList.remove('btn-ready');
    }
  }

  /**
   * Handle input changes — format display and update button.
   */
  input.addEventListener('input', function () {
    const raw = getRawOTP(this.value);

    // Limit to OTP_LENGTH characters
    const limited = raw.slice(0, OTP_LENGTH);

    // Re-format with visual spaces
    const formatted = formatOTP(limited);

    // Only update if changed (avoid cursor jump on already-formatted input)
    if (this.value !== formatted) {
      const cursorPos = this.selectionStart;
      this.value = formatted;
      // Adjust cursor position after formatting
    }

    updateSubmitState();
  });

  /**
   * Before form submit: strip spaces from OTP value.
   * The server receives the raw OTP without spaces.
   */
  if (form) {
    form.addEventListener('submit', function () {
      input.value = getRawOTP(input.value);
    });
  }

  /**
   * Allow paste — strip spaces on paste.
   */
  input.addEventListener('paste', function (e) {
    e.preventDefault();
    const pasted = (e.clipboardData || window.clipboardData).getData('text');
    const raw = getRawOTP(pasted).slice(0, OTP_LENGTH);
    this.value = formatOTP(raw);
    updateSubmitState();
  });

  // Initial state
  updateSubmitState();
  input.focus();

})();
