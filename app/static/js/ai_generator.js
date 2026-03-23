// GhostPortal — AI Generation Polling
// Copyright (C) 2026 Spade — AGPL-3.0 License

(function () {
  'use strict';

  function getCsrf() {
    var el = document.querySelector('[name=csrf_token]');
    return el ? el.value : '';
  }

  window.triggerAIGeneration = function () {
    var provider = document.getElementById('ai-provider-select');
    var mode = document.getElementById('ai-mode-select');
    var context = document.getElementById('ai-context');
    var btn = document.getElementById('ai-generate-btn');
    var status = document.getElementById('ai-status');
    var statusText = document.getElementById('ai-status-text');
    var resultNotice = document.getElementById('ai-result-notice');
    if (!provider || !mode) return;

    btn.disabled = true;
    status.style.display = 'flex';
    resultNotice.style.display = 'none';

    var payload = {
      provider: provider.value,
      mode: mode.value,
      context: context ? context.value : '',
      current_description: (document.getElementById('description') || {}).value || '',
      current_title: (document.querySelector('[name=title]') || {}).value || '',
      cvss_vector: (document.getElementById('cvss-vector-hidden') || {}).value || '',
      cwe_id: (document.getElementById('cwe-id') || {}).value || '',
      cwe_name: (document.getElementById('cwe-name') || {}).value || ''
    };

    fetch('/ai/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrf() },
      body: JSON.stringify(payload)
    }).then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.job_id) {
          pollJob(d.job_id, mode.value, btn, status, statusText, resultNotice);
        } else {
          showError(d.error || 'Unknown error', btn, status);
        }
      })
      .catch(function (e) { showError('Request failed: ' + e.message, btn, status); });
  };

  function pollJob(jobId, mode, btn, status, statusText, resultNotice) {
    var interval = setInterval(function () {
      fetch('/ai/generate/' + jobId + '/status')
        .then(function (r) { return r.json(); })
        .then(function (d) {
          statusText.textContent = 'Generating… (' + d.status + ')';
          if (d.status === 'completed') {
            clearInterval(interval);
            fetchResult(jobId, mode, btn, status, resultNotice);
          } else if (d.status === 'failed') {
            clearInterval(interval);
            showError('AI generation failed', btn, status);
          }
        })
        .catch(function () { clearInterval(interval); showError('Polling error', btn, status); });
    }, 2000);
  }

  function fetchResult(jobId, mode, btn, status, resultNotice) {
    fetch('/ai/generate/' + jobId + '/result')
      .then(function (r) { return r.json(); })
      .then(function (d) {
        btn.disabled = false;
        status.style.display = 'none';
        if (d.output) {
          injectResult(d.output, mode);
          resultNotice.style.display = 'block';
          setTimeout(function () { resultNotice.style.display = 'none'; }, 8000);
        }
      })
      .catch(function () { showError('Could not retrieve result', btn, status); });
  }

  function injectResult(output, mode) {
    if (mode === 'suggest_cwe') {
      try {
        var cwe = JSON.parse(output);
        if (cwe.cwe_id) document.getElementById('cwe-id').value = cwe.cwe_id;
        if (cwe.cwe_name) document.getElementById('cwe-name').value = cwe.cwe_name;
      } catch (e) {}
      return;
    }
    // For full_report, improve_report: try to inject into description
    var field = document.getElementById('description');
    if (field) { field.value = output; field.dispatchEvent(new Event('input')); }
    // Mark as AI-generated
    var fields = document.querySelectorAll('.md-textarea');
    fields.forEach(function (f) { f.dataset.aiGenerated = '1'; });
  }

  function showError(msg, btn, status) {
    btn.disabled = false;
    status.style.display = 'none';
    alert('AI Error: ' + msg);
  }
})();
