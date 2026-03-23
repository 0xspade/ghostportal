/**
 * GhostPortal — Dashboard Charts
 * Uses Chart.js with HUD Admin dark palette.
 *
 * Configuration: window.__CHART_DATA (JSON injected by dashboard template)
 */

(function () {
  'use strict';

  if (!window.Chart) return;

  const DATA = window.__CHART_DATA || {};

  // ── HUD Admin color palette ──────────────────────────────────────────────
  const COLORS = {
    green:     '#00ff88',
    cyan:      '#00d4ff',
    amber:     '#ffaa00',
    red:       '#ff4040',
    orange:    '#ff6400',
    purple:    '#9966ff',
    dim:       '#445566',
    border:    '#1e2d3d',
  };

  const SEVERITY_COLORS = {
    critical:      COLORS.red,
    high:          COLORS.orange,
    medium:        COLORS.amber,
    low:           COLORS.cyan,
    informational: COLORS.dim,
  };

  const STATUS_COLORS = {
    draft:         COLORS.dim,
    submitted:     COLORS.cyan,
    triaged:       COLORS.amber,
    duplicate:     COLORS.purple,
    informative:   '#6688aa',
    resolved:      COLORS.green,
    wont_fix:      '#885555',
  };

  // ── Chart.js Global Defaults ─────────────────────────────────────────────
  Chart.defaults.color           = '#8899aa';
  Chart.defaults.borderColor     = '#1e2d3d';
  Chart.defaults.backgroundColor = 'rgba(0, 255, 136, 0.1)';
  Chart.defaults.font.family     = "'JetBrains Mono', monospace";
  Chart.defaults.font.size       = 11;

  const GRID_OPTS = {
    color: 'rgba(30, 45, 61, 0.8)',
    borderColor: '#1e2d3d',
  };

  // ── Submissions Over Time (Line Chart) ───────────────────────────────────
  const submissionsCtx = document.getElementById('submissionsChart');
  if (submissionsCtx && DATA.submissions) {
    const submissionsChart = new Chart(submissionsCtx, {
      type: 'line',
      data: {
        labels: DATA.submissions.weekly?.labels || [],
        datasets: [{
          label: 'Submissions',
          data: DATA.submissions.weekly?.data || [],
          borderColor: COLORS.green,
          backgroundColor: 'rgba(0, 255, 136, 0.05)',
          pointBackgroundColor: COLORS.green,
          pointBorderColor: COLORS.green,
          pointRadius: 4,
          pointHoverRadius: 6,
          fill: true,
          tension: 0.3,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#0d1117',
            borderColor: '#1e2d3d',
            borderWidth: 1,
          },
        },
        scales: {
          x: { grid: GRID_OPTS, ticks: { color: '#8899aa' } },
          y: {
            grid: GRID_OPTS,
            ticks: { color: '#8899aa', stepSize: 1 },
            beginAtZero: true,
          },
        },
      },
    });

    // Toggle period
    document.querySelectorAll('.chart-toggle-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        document.querySelectorAll('.chart-toggle-btn').forEach(b => b.classList.remove('active'));
        this.classList.add('active');
        const period = this.dataset.period;
        const periodData = DATA.submissions[period] || { labels: [], data: [] };
        submissionsChart.data.labels = periodData.labels;
        submissionsChart.data.datasets[0].data = periodData.data;
        submissionsChart.update();
      });
    });
  }

  // ── Reports by Status (Donut) ────────────────────────────────────────────
  const statusCtx = document.getElementById('statusChart');
  if (statusCtx && DATA.by_status) {
    const labels = Object.keys(DATA.by_status);
    const values = Object.values(DATA.by_status);
    new Chart(statusCtx, {
      type: 'doughnut',
      data: {
        labels: labels.map(l => l.charAt(0).toUpperCase() + l.slice(1).replace('_', ' ')),
        datasets: [{
          data: values,
          backgroundColor: labels.map(l => STATUS_COLORS[l] || COLORS.dim),
          borderColor: '#0d1117',
          borderWidth: 2,
          hoverOffset: 4,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        cutout: '65%',
        plugins: {
          legend: {
            position: 'right',
            labels: { color: '#8899aa', padding: 12, font: { size: 11 } },
          },
          tooltip: {
            backgroundColor: '#0d1117',
            borderColor: '#1e2d3d',
            borderWidth: 1,
          },
        },
      },
    });
  }

  // ── Reports by Severity (Horizontal Bar) ─────────────────────────────────
  const severityCtx = document.getElementById('severityChart');
  if (severityCtx && DATA.by_severity) {
    const severityOrder = ['critical', 'high', 'medium', 'low', 'informational'];
    const labels = severityOrder.filter(s => DATA.by_severity[s] !== undefined);
    const values = labels.map(l => DATA.by_severity[l] || 0);

    new Chart(severityCtx, {
      type: 'bar',
      data: {
        labels: labels.map(l => l.charAt(0).toUpperCase() + l.slice(1)),
        datasets: [{
          data: values,
          backgroundColor: labels.map(l => SEVERITY_COLORS[l] + '33'),
          borderColor: labels.map(l => SEVERITY_COLORS[l]),
          borderWidth: 1,
        }],
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: true,
        plugins: { legend: { display: false }, tooltip: { backgroundColor: '#0d1117', borderColor: '#1e2d3d', borderWidth: 1 } },
        scales: {
          x: { grid: GRID_OPTS, ticks: { color: '#8899aa', stepSize: 1 }, beginAtZero: true },
          y: { grid: { display: false }, ticks: { color: '#8899aa' } },
        },
      },
    });
  }

  // ── CVSS Score Distribution (Histogram) ──────────────────────────────────
  const cvssCtx = document.getElementById('cvssChart');
  if (cvssCtx && DATA.cvss_distribution) {
    const cvssColors = DATA.cvss_distribution.labels.map(function (label) {
      const score = parseFloat(label);
      if (score >= 9)  return COLORS.red;
      if (score >= 7)  return COLORS.orange;
      if (score >= 4)  return COLORS.amber;
      if (score > 0)   return COLORS.cyan;
      return COLORS.dim;
    });

    new Chart(cvssCtx, {
      type: 'bar',
      data: {
        labels: DATA.cvss_distribution.labels,
        datasets: [{
          label: 'Reports',
          data: DATA.cvss_distribution.data,
          backgroundColor: cvssColors.map(c => c + '44'),
          borderColor: cvssColors,
          borderWidth: 1,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: { legend: { display: false }, tooltip: { backgroundColor: '#0d1117', borderColor: '#1e2d3d', borderWidth: 1 } },
        scales: {
          x: { grid: GRID_OPTS, ticks: { color: '#8899aa' } },
          y: { grid: GRID_OPTS, ticks: { color: '#8899aa', stepSize: 1 }, beginAtZero: true },
        },
      },
    });
  }

  // ── Top 10 CWE (Horizontal Bar) ───────────────────────────────────────────
  const cweCtx = document.getElementById('cweChart');
  if (cweCtx && DATA.top_cwe) {
    new Chart(cweCtx, {
      type: 'bar',
      data: {
        labels: DATA.top_cwe.labels,
        datasets: [{
          data: DATA.top_cwe.data,
          backgroundColor: 'rgba(0, 212, 255, 0.12)',
          borderColor: COLORS.cyan,
          borderWidth: 1,
        }],
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: true,
        plugins: { legend: { display: false }, tooltip: { backgroundColor: '#0d1117', borderColor: '#1e2d3d', borderWidth: 1 } },
        scales: {
          x: { grid: GRID_OPTS, ticks: { color: '#8899aa', stepSize: 1 }, beginAtZero: true },
          y: { grid: { display: false }, ticks: { color: '#8899aa', font: { size: 10 } } },
        },
      },
    });
  }

  // ── Bounty by Month (Bar) ─────────────────────────────────────────────────
  const bountyCtx = document.getElementById('bountyChart');
  if (bountyCtx && DATA.bounty_by_month) {
    new Chart(bountyCtx, {
      type: 'bar',
      data: {
        labels: DATA.bounty_by_month.labels,
        datasets: [{
          label: 'Bounty',
          data: DATA.bounty_by_month.data,
          backgroundColor: 'rgba(255, 170, 0, 0.12)',
          borderColor: COLORS.amber,
          borderWidth: 1,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: { legend: { display: false }, tooltip: { backgroundColor: '#0d1117', borderColor: '#1e2d3d', borderWidth: 1 } },
        scales: {
          x: { grid: GRID_OPTS, ticks: { color: '#8899aa' } },
          y: { grid: GRID_OPTS, ticks: { color: '#8899aa' }, beginAtZero: true },
        },
      },
    });
  }

})();
