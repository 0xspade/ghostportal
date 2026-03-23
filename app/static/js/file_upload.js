// GhostPortal — Drag & Drop File Upload
// Copyright (C) 2026 Spade — AGPL-3.0 License

(function () {
  'use strict';

  var ALLOWED_TYPES = ['image/png', 'image/jpeg', 'image/gif', 'video/mp4', 'video/quicktime',
    'video/webm', 'application/pdf', 'text/plain', 'application/octet-stream'];
  var ALLOWED_EXT = /\.(png|jpg|jpeg|gif|mp4|mov|webm|pdf|txt|log)$/i;
  var MAX_TOTAL_BYTES = 50 * 1024 * 1024;

  var dropZone = document.getElementById('drop-zone');
  var fileInput = document.getElementById('file-input');
  var previewGrid = document.getElementById('file-preview-grid');
  if (!dropZone || !fileInput) return;

  var selectedFiles = [];

  function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
  }

  function totalSize() {
    return selectedFiles.reduce(function (s, f) { return s + f.size; }, 0);
  }

  function validateFile(file) {
    if (!ALLOWED_EXT.test(file.name)) return 'File type not allowed: ' + file.name;
    if (file.size > 20 * 1024 * 1024) return file.name + ' exceeds 20MB';
    return null;
  }

  function addFiles(fileList) {
    for (var i = 0; i < fileList.length; i++) {
      var file = fileList[i];
      var err = validateFile(file);
      if (err) { alert(err); continue; }
      if (totalSize() + file.size > MAX_TOTAL_BYTES) { alert('Total upload size would exceed 50MB'); break; }
      selectedFiles.push(file);
    }
    renderPreviews();
    syncFileInput();
  }

  function renderPreviews() {
    if (!previewGrid) return;
    previewGrid.innerHTML = '';
    selectedFiles.forEach(function (file, idx) {
      var item = document.createElement('div');
      item.className = 'preview-item';
      if (file.type.startsWith('image/')) {
        var reader = new FileReader();
        reader.onload = function (e) {
          var img = document.createElement('img');
          img.src = e.target.result;
          img.className = 'preview-thumb';
          item.insertBefore(img, item.firstChild);
        };
        reader.readAsDataURL(file);
      } else {
        var icon = document.createElement('div');
        icon.className = 'preview-icon';
        icon.textContent = file.type === 'application/pdf' ? '📄' : file.type.startsWith('video/') ? '🎥' : '📎';
        item.appendChild(icon);
      }
      var name = document.createElement('div');
      name.className = 'preview-name text-sm';
      name.textContent = file.name.length > 20 ? file.name.substring(0, 17) + '...' : file.name;
      var size = document.createElement('div');
      size.className = 'preview-size text-sm text-muted';
      size.textContent = formatSize(file.size);
      var remove = document.createElement('button');
      remove.type = 'button';
      remove.className = 'btn btn-xs btn-danger preview-remove';
      remove.textContent = '✕';
      remove.dataset.idx = idx;
      remove.addEventListener('click', function () {
        selectedFiles.splice(parseInt(this.dataset.idx), 1);
        renderPreviews();
        syncFileInput();
      });
      item.appendChild(name);
      item.appendChild(size);
      item.appendChild(remove);
      previewGrid.appendChild(item);
    });
  }

  function syncFileInput() {
    var dt = new DataTransfer();
    selectedFiles.forEach(function (f) { dt.items.add(f); });
    fileInput.files = dt.files;
  }

  dropZone.addEventListener('dragover', function (e) {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });
  dropZone.addEventListener('dragleave', function () { dropZone.classList.remove('drag-over'); });
  dropZone.addEventListener('drop', function (e) {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    addFiles(e.dataTransfer.files);
  });
  dropZone.addEventListener('click', function (e) {
    if (e.target !== fileInput) fileInput.click();
  });
  fileInput.addEventListener('change', function () { addFiles(this.files); });
})();
