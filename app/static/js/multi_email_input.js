// GhostPortal — Multi-Email Input
// Copyright (C) 2026 Spade — AGPL-3.0 License

(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', function () {
    var container = document.getElementById('recipients-container');
    if (!container) return;

    container.addEventListener('input', function (e) {
      if (e.target.type === 'email') validateEmail(e.target);
    });

    function validateEmail(input) {
      var val = input.value.trim();
      var valid = !val || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val);
      input.classList.toggle('input-error', !valid && val.length > 0);
      input.classList.toggle('input-valid', valid && val.length > 0);
    }
  });
})();
