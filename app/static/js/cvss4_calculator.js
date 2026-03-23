// GhostPortal — CVSS 4.0 Interactive Calculator
// Copyright (C) 2026 Spade — AGPL-3.0 License

(function () {
  'use strict';

  var metrics = {};
  var defaults = { AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N', VC: 'N', VI: 'N', VA: 'N', SC: 'N', SI: 'N', SA: 'N', E: 'X' };
  Object.assign(metrics, defaults);

  // Simplified CVSS 4.0 scoring lookup table
  // Based on CVSS 4.0 spec - simplified EQ-based calculation
  function computeScore() {
    var av = metrics.AV, ac = metrics.AC, at = metrics.AT, pr = metrics.PR, ui = metrics.UI;
    var vc = metrics.VC, vi = metrics.VI, va = metrics.VA, sc = metrics.SC, si = metrics.SI, sa = metrics.SA;

    // EQ1: 0-2
    var eq1 = 0;
    if (av === 'N' && pr === 'N' && ui === 'N') eq1 = 0;
    else if ((av === 'N' || pr === 'N' || ui === 'N') && !(av === 'N' && pr === 'N' && ui === 'N') && av !== 'P') eq1 = 1;
    else if (av === 'P' || !(av === 'N' || pr === 'N' || ui === 'N')) eq1 = 2;

    // EQ2: 0-1
    var eq2 = (ac === 'L' && at === 'N') ? 0 : 1;

    // EQ3: 0-2
    var eq3 = 0;
    if ((vc === 'H' || vi === 'H' || va === 'H') && (sc === 'H' || si === 'H' || sa === 'H')) eq3 = 0;
    else if ((vc === 'H' || vi === 'H' || va === 'H') && !(sc === 'H' || si === 'H' || sa === 'H')) eq3 = 1;
    else if (!(vc === 'H' || vi === 'H' || va === 'H') && (sc === 'H' || si === 'H' || sa === 'H')) eq3 = 1;
    else eq3 = 2;

    // EQ4: 0-2
    var eq4 = 0;
    if (sc === 'H' || si === 'H' || sa === 'H') eq4 = 0;
    else if (!(sc === 'H' || si === 'H' || sa === 'H') && (vc === 'H' || vi === 'H' || va === 'H')) eq4 = 1;
    else eq4 = 2;

    // Simplified score lookup
    var eq_sum = eq1 + eq2 + eq3 + eq4;
    var base_score = Math.max(0, 10 - eq_sum * 1.5);
    base_score = Math.min(10, Math.round(base_score * 10) / 10);

    // If all impact = N, score is 0
    if (vc === 'N' && vi === 'N' && va === 'N' && sc === 'N' && si === 'N' && sa === 'N') {
      base_score = 0;
    }

    return base_score;
  }

  function buildVector() {
    var v = 'CVSS:4.0';
    var keys = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'];
    keys.forEach(function (k) { v += '/' + k + ':' + (metrics[k] || 'X'); });
    if (metrics.E && metrics.E !== 'X') v += '/E:' + metrics.E;
    return v;
  }

  function getSeverity(score) {
    if (score === 0) return 'none';
    if (score < 4.0) return 'low';
    if (score < 7.0) return 'medium';
    if (score < 9.0) return 'high';
    return 'critical';
  }

  function updateDisplay() {
    var score = computeScore();
    var sev = getSeverity(score);
    var vector = buildVector();

    var scoreBadge = document.getElementById('cvss-score-badge');
    if (scoreBadge) {
      scoreBadge.textContent = score.toFixed(1) + ' ' + sev.toUpperCase();
      scoreBadge.className = 'cvss-score-display severity-' + sev;
    }

    var vectorDisplay = document.getElementById('cvss-vector-display');
    if (vectorDisplay) vectorDisplay.textContent = vector;

    var hiddenScore = document.getElementById('cvss-score-hidden');
    if (hiddenScore) hiddenScore.value = score.toFixed(1);

    var hiddenVector = document.getElementById('cvss-vector-hidden');
    if (hiddenVector) hiddenVector.value = vector;

    // Warn if severity inconsistent with CVSS
    checkSeverityConsistency(sev);
  }

  function checkSeverityConsistency(cvss_sev) {
    var selectedSev = document.querySelector('input[name=severity]:checked');
    var warning = document.getElementById('cvss-severity-warning');
    if (!warning || !selectedSev) return;
    if (selectedSev.value !== cvss_sev && cvss_sev !== 'none') {
      warning.textContent = '⚠ CVSS 4.0 suggests ' + cvss_sev.toUpperCase() + ' — you selected ' + selectedSev.value.toUpperCase() + '. Confirm?';
      warning.style.display = 'inline-block';
    } else {
      warning.style.display = 'none';
    }
  }

  function parseVector(vectorStr) {
    if (!vectorStr || !vectorStr.startsWith('CVSS:4.0')) return;
    var parts = vectorStr.split('/');
    parts.shift();
    parts.forEach(function (part) {
      var kv = part.split(':');
      if (kv.length === 2) metrics[kv[0]] = kv[1];
    });
  }

  // Initialize
  document.addEventListener('DOMContentLoaded', function () {
    var initVector = document.getElementById('cvss-vector-hidden');
    if (initVector && initVector.value) parseVector(initVector.value);

    document.querySelectorAll('.cvss-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var key = this.dataset.metric;
        var val = this.dataset.val;
        metrics[key] = val;

        // Update active state
        document.querySelectorAll('.cvss-btn[data-metric="' + key + '"]').forEach(function (b) {
          b.classList.remove('active');
        });
        this.classList.add('active');
        updateDisplay();
      });
    });

    // Set active buttons for initial vector
    Object.keys(metrics).forEach(function (k) {
      var btn = document.querySelector('.cvss-btn[data-metric="' + k + '"][data-val="' + metrics[k] + '"]');
      if (btn) btn.classList.add('active');
    });

    // Watch severity radio changes
    document.querySelectorAll('input[name=severity]').forEach(function (r) {
      r.addEventListener('change', function () {
        var score = computeScore();
        checkSeverityConsistency(getSeverity(score));
      });
    });

    updateDisplay();
  });
})();
