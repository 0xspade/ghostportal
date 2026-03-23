// GhostPortal — External Link Interception
// Copyright (C) 2026 Spade — AGPL-3.0 License

(function () {
  'use strict';

  var BASE_URL = window.location.origin;
  var _pendingUrl = null;
  var _countdown = null;

  // Inject modal HTML once
  function _ensureModal() {
    if (document.getElementById('ext-link-modal')) return;
    var div = document.createElement('div');
    div.innerHTML = [
      '<div class="modal fade" id="ext-link-modal" tabindex="-1" aria-modal="true" role="dialog" style="z-index:1060;">',
      '  <div class="modal-dialog modal-dialog-centered">',
      '    <div class="modal-content">',
      '      <div class="modal-header">',
      '        <h5 class="modal-title fw-bold"><i class="bi bi-box-arrow-up-right me-2 text-warning"></i>Leaving GhostPortal</h5>',
      '        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>',
      '      </div>',
      '      <div class="modal-body">',
      '        <p class="mb-2 text-inverse text-opacity-75">You are about to visit an external site:</p>',
      '        <div class="p-2 rounded mb-3" style="background:rgba(255,170,0,0.08);border:1px solid rgba(255,170,0,0.25);">',
      '          <code id="ext-link-domain" class="text-warning" style="word-break:break-all;"></code>',
      '        </div>',
      '        <p class="small text-inverse text-opacity-50 mb-0">',
      '          GhostPortal is not responsible for external content. Proceed with caution.',
      '        </p>',
      '      </div>',
      '      <div class="modal-footer">',
      '        <button type="button" class="btn btn-light" data-bs-dismiss="modal">Cancel</button>',
      '        <button type="button" class="btn btn-warning" id="ext-link-proceed" disabled>',
      '          Proceed <span id="ext-link-timer">(5)</span>',
      '        </button>',
      '      </div>',
      '    </div>',
      '  </div>',
      '</div>'
    ].join('');
    document.body.appendChild(div.firstChild);

    document.getElementById('ext-link-proceed').addEventListener('click', function () {
      if (_pendingUrl) {
        window.open(_pendingUrl, '_blank', 'noopener,noreferrer');
        _pendingUrl = null;
      }
      var modal = bootstrap.Modal.getInstance(document.getElementById('ext-link-modal'));
      if (modal) modal.hide();
    });

    document.getElementById('ext-link-modal').addEventListener('hidden.bs.modal', function () {
      clearInterval(_countdown);
      _pendingUrl = null;
    });
  }

  function _showModal(url) {
    _ensureModal();
    _pendingUrl = url;

    var domain = url;
    try { domain = new URL(url).hostname; } catch (e) { /* use raw url */ }
    document.getElementById('ext-link-domain').textContent = domain;

    var proceedBtn = document.getElementById('ext-link-proceed');
    var timerSpan = document.getElementById('ext-link-timer');
    var secs = 5;
    proceedBtn.disabled = true;
    timerSpan.textContent = '(' + secs + ')';

    clearInterval(_countdown);
    _countdown = setInterval(function () {
      secs--;
      if (secs <= 0) {
        clearInterval(_countdown);
        proceedBtn.disabled = false;
        timerSpan.textContent = '';
      } else {
        timerSpan.textContent = '(' + secs + ')';
      }
    }, 1000);

    var modalEl = document.getElementById('ext-link-modal');
    var modal = bootstrap.Modal.getOrCreateInstance(modalEl);
    modal.show();
  }

  document.addEventListener('click', function (e) {
    var target = e.target.closest('a');
    if (!target) return;
    var href = target.getAttribute('href');
    if (!href) return;

    // Skip: same-origin, anchor, relative, mailto, already a /go/ link
    if (href.startsWith('/') || href.startsWith('#') || href.startsWith('mailto:')) return;
    if (href.startsWith(BASE_URL)) return;
    if (!href.match(/^https?:\/\//i)) return;
    if (href.includes('/go/')) return;

    // External link — prevent default and show modal
    e.preventDefault();

    fetch('/api/external-link', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': (document.querySelector('[name=csrf_token]') || {}).value || ''
      },
      body: JSON.stringify({ url: href })
    }).then(function (r) { return r.json(); })
      .then(function (d) {
        var goUrl = d.go_url || ('/go/' + (d.token || ''));
        _showModal(goUrl);
      })
      .catch(function () {
        // Fallback: show modal with original URL
        _showModal(href);
      });
  }, true);

})();
