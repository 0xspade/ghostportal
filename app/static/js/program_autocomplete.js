// GhostPortal — Program Name Autocomplete
// Copyright (C) 2026 Spade — AGPL-3.0 License

(function () {
  'use strict';

  function debounce(fn, delay) {
    var t;
    return function () {
      var args = arguments, ctx = this;
      clearTimeout(t);
      t = setTimeout(function () { fn.apply(ctx, args); }, delay);
    };
  }

  document.addEventListener('DOMContentLoaded', function () {
    var input = document.getElementById('program-input');
    var dropdown = document.getElementById('program-dropdown');
    if (!input || !dropdown) return;

    var fetchNames = debounce(function (q) {
      fetch('/api/programs/search?q=' + encodeURIComponent(q))
        .then(function (r) { return r.json(); })
        .then(function (data) { renderDropdown(data, q); })
        .catch(function () { dropdown.style.display = 'none'; });
    }, 200);

    input.addEventListener('input', function () {
      var q = this.value.trim();
      if (!q) { dropdown.style.display = 'none'; return; }
      fetchNames(q);
    });

    input.addEventListener('focus', function () {
      var q = this.value.trim();
      if (q) fetchNames(q);
    });

    document.addEventListener('click', function (e) {
      if (!input.contains(e.target) && !dropdown.contains(e.target)) {
        dropdown.style.display = 'none';
      }
    });

    function renderDropdown(items, query) {
      dropdown.innerHTML = '';
      items.forEach(function (item) {
        var opt = document.createElement('div');
        opt.className = 'autocomplete-option';
        opt.textContent = item.name;
        if (item.use_count) {
          var cnt = document.createElement('span');
          cnt.className = 'autocomplete-count text-muted text-sm';
          cnt.textContent = item.use_count + 'x';
          opt.appendChild(cnt);
        }
        opt.addEventListener('mousedown', function (e) {
          e.preventDefault();
          input.value = item.name;
          dropdown.style.display = 'none';
        });
        dropdown.appendChild(opt);
      });

      // Add "Add new" option if query not in results
      var hasMatch = items.some(function (i) { return i.name.toLowerCase() === query.toLowerCase(); });
      if (!hasMatch && query) {
        var addOpt = document.createElement('div');
        addOpt.className = 'autocomplete-option autocomplete-add';
        addOpt.textContent = '+ Add: "' + query + '"';
        addOpt.addEventListener('mousedown', function (e) {
          e.preventDefault();
          input.value = query;
          dropdown.style.display = 'none';
        });
        dropdown.appendChild(addOpt);
      }

      dropdown.style.display = dropdown.children.length ? 'block' : 'none';
    }
  });
})();
