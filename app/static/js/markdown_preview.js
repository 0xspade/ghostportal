// GhostPortal — Markdown Live Preview
// Copyright (C) 2026 Spade — AGPL-3.0 License

(function () {
  'use strict';

  function debounce(fn, delay) {
    var t;
    return function () { var args = arguments, ctx = this; clearTimeout(t); t = setTimeout(function () { fn.apply(ctx, args); }, delay); };
  }

  function renderPreview(textarea, preview) {
    var text = textarea.value;
    fetch('/api/preview-markdown', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrf() },
      body: JSON.stringify({ text: text })
    }).then(function (r) { return r.json(); })
      .then(function (d) { if (d.html) preview.innerHTML = d.html; })
      .catch(function () { preview.innerHTML = '<p class="text-muted">Preview unavailable</p>'; });
  }

  function getCsrf() {
    var el = document.querySelector('[name=csrf_token]');
    return el ? el.value : '';
  }

  document.addEventListener('DOMContentLoaded', function () {
    // Toggle preview panels
    document.querySelectorAll('.md-preview-toggle').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var target = this.dataset.target;
        var preview = document.getElementById(target);
        var textarea = preview ? preview.previousElementSibling : null;
        if (!preview || !textarea) return;

        var isShowing = preview.style.display !== 'none';
        preview.style.display = isShowing ? 'none' : 'block';
        if (textarea) textarea.style.display = isShowing ? 'block' : 'none';
        this.textContent = isShowing ? 'Preview' : 'Edit';

        if (!isShowing) renderPreview(textarea, preview);
      });
    });

    // Markdown toolbar
    document.querySelectorAll('.md-tool').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var action = this.dataset.action;
        var textarea = this.closest('.md-editor-wrapper').querySelector('textarea');
        if (!textarea) return;
        var sel = textarea.value.substring(textarea.selectionStart, textarea.selectionEnd);
        var map = {
          bold: '**' + (sel || 'bold text') + '**',
          code: '`' + (sel || 'code') + '`',
          codeblock: '```\n' + (sel || 'code here') + '\n```',
          link: '[' + (sel || 'link text') + '](url)'
        };
        var insert = map[action];
        if (!insert) return;
        var start = textarea.selectionStart;
        textarea.value = textarea.value.substring(0, start) + insert + textarea.value.substring(textarea.selectionEnd);
        textarea.focus();
        textarea.setSelectionRange(start + insert.length, start + insert.length);
      });
    });

    // Auto-resize textareas
    document.querySelectorAll('.md-textarea').forEach(function (ta) {
      ta.addEventListener('input', function () {
        this.style.height = 'auto';
        this.style.height = Math.max(120, this.scrollHeight) + 'px';
      });
    });
  });
})();
