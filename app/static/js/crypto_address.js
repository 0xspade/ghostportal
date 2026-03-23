// GhostPortal — Crypto Address Display
// Copyright (C) 2026 Spade — AGPL-3.0 License

(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', function () {
    var addrInput = document.getElementById('crypto-address');
    if (!addrInput) return;

    addrInput.addEventListener('input', function () {
      renderHighlighted(this.value);
    });

    function renderHighlighted(addr) {
      var display = document.getElementById('address-highlight');
      if (!display) return;
      if (!addr) { display.innerHTML = ''; return; }
      var html = '';
      for (var i = 0; i < addr.length; i++) {
        var cls = (Math.floor(i / 4) % 2 === 0) ? 'addr-even' : 'addr-odd';
        html += '<span class="' + cls + '">' + escapeHtml(addr[i]) + '</span>';
      }
      display.innerHTML = html;
    }

    function escapeHtml(c) {
      var map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
      return c.replace(/[&<>"']/g, function (m) { return map[m]; });
    }
  });

  window.copyAddress = function (addr) {
    navigator.clipboard.writeText(addr).then(function () {
      var btn = document.getElementById('copy-addr-btn');
      if (btn) { var orig = btn.textContent; btn.textContent = 'Copied!'; setTimeout(function () { btn.textContent = orig; }, 3000); }
    });
  };
})();
