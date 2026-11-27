// DeskGuest website — progressive enhancement only. No tracking, no external calls.
(function () {
  var reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // Mobile nav
  var toggle = document.querySelector('.nav-toggle');
  var nav = document.querySelector('.main-nav');
  if (toggle && nav) {
    toggle.addEventListener('click', function () {
      var open = nav.classList.toggle('open');
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
  }

  // Reveal choreography: sections rise once, staggered children follow.
  var revealEls = document.querySelectorAll('.reveal');
  if (revealEls.length) {
    if (reduced || !('IntersectionObserver' in window)) {
      revealEls.forEach(function (el) { el.classList.add('in'); });
    } else {
      var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (e) {
          if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); }
        });
      // threshold 0, deliberately: a ratio threshold can never be met by an
      // element taller than ~8 viewports (the 7,213px comparison table and
      // the ~20,000px mobile card stack stayed at opacity:0 forever under
      // the old 0.12 — the 2026-11-25 blank-comparison fault). Any part
      // entering past the rootMargin line is the trigger.
      }, { threshold: 0, rootMargin: '0px 0px -6% 0px' });
      revealEls.forEach(function (el) { io.observe(el); });
    }
  }

  // The living session window (home hero): a session timer that counts up,
  // and the helper's Ghost travelling an eased path between points of work,
  // pausing to click. Motion depicts a state — a session in progress — and
  // stops entirely under prefers-reduced-motion.
  var screen = document.querySelector('.sw-screen');
  var ghost = document.querySelector('.ghost');
  var timerEl = document.querySelector('.timer');
  if (timerEl) {
    var secs = 252; // starts at 04:12
    var fmt = function (s) {
      var m = Math.floor(s / 60), r = s % 60;
      return (m < 10 ? '0' : '') + m + ':' + (r < 10 ? '0' : '') + r;
    };
    timerEl.textContent = fmt(secs);
    setInterval(function () { secs++; timerEl.textContent = fmt(secs); }, 1000);
  }
  if (screen && ghost && !reduced) {
    // Waypoints as fractions of the screen box: [x, y, dwellMs]
    var path = [
      [0.16, 0.52, 500], [0.60, 0.60, 1150], [0.34, 0.80, 350],
      [0.80, 0.82, 1250], [0.50, 0.50, 300]
    ];
    var seg = 0, startT = null, from = path[0], to = path[1], dwellUntil = 0;
    var DUR = 2100;
    var ease = function (t) { return t < .5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2; };
    var place = function (fx, fy) {
      var w = screen.clientWidth, h = screen.clientHeight;
      ghost.style.transform = 'translate(' + (fx * w - 18) + 'px,' + (fy * h - 18) + 'px)';
    };
    place(path[0][0], path[0][1]);
    var step = function (now) {
      if (startT === null) { startT = now; dwellUntil = now + path[0][2]; }
      if (now < dwellUntil) { requestAnimationFrame(step); return; }
      var t = (now - dwellUntil) / DUR;
      if (t >= 1) {
        place(to[0], to[1]);
        ghost.classList.remove('click'); void ghost.offsetWidth; ghost.classList.add('click');
        seg = (seg + 1) % path.length;
        from = to; to = path[(seg + 1) % path.length];
        dwellUntil = now + from[2]; startT = now;
        requestAnimationFrame(step); return;
      }
      var e = ease(t);
      place(from[0] + (to[0] - from[0]) * e, from[1] + (to[1] - from[1]) * e);
      requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  } else if (screen && ghost) {
    ghost.style.transform = 'translate(56%, 60%)';
    ghost.style.left = '56%'; ghost.style.top = '60%'; ghost.style.transform = 'translate(-18px,-18px)';
  }

  // Help search (support.html / help.html): filters the page's own topic cards —
  // the same help corpus the app carries (one corpus, two doors).
  var searchForm = document.getElementById('help-search');
  var searchInput = document.getElementById('help-search-input');
  if (searchForm && searchInput) {
    var topicCards = Array.prototype.slice.call(
      document.querySelectorAll('.cards.three .card'));
    var status = document.getElementById('help-search-status');
    var empty = document.getElementById('help-search-empty');
    var applySearch = function () {
      var q = searchInput.value.trim().toLowerCase();
      var shown = 0;
      topicCards.forEach(function (card) {
        var hit = !q || card.textContent.toLowerCase().indexOf(q) !== -1;
        card.style.display = hit ? '' : 'none';
        if (hit) shown++;
      });
      if (empty) empty.style.display = (q && shown === 0) ? '' : 'none';
      if (status) {
        status.textContent = !q ? '' :
          shown === 1 ? '1 topic matches “' + searchInput.value.trim() + '”.' :
          shown + ' topics match “' + searchInput.value.trim() + '”.';
      }
    };
    searchInput.addEventListener('input', applySearch);
    searchForm.addEventListener('submit', function (e) {
      e.preventDefault();
      applySearch();
      var first = topicCards.filter(function (c) {
        return c.style.display !== 'none';
      })[0];
      if (first) first.scrollIntoView({ block: 'nearest' });
    });
  }

  // Copy buttons for any element with data-copy="<target-id>"
  document.querySelectorAll('[data-copy]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var el = document.getElementById(btn.getAttribute('data-copy'));
      if (!el) return;
      var text = el.textContent.trim();
      if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(function () {
          var old = btn.textContent;
          btn.textContent = 'Copied';
          setTimeout(function () { btn.textContent = old; }, 1600);
        });
      }
    });
  });
})();

// Comparison matrices (Features' full table, About's short one): while
// more product columns wait off the right edge of the scroll region, a
// soft fade marks the edge; it lifts at the end of the scroll and never
// appears when nothing overflows. Purely a cue — the region is a real,
// focusable scroll container either way.
document.querySelectorAll('.matrix-wrap').forEach(function (wrap) {
  var scroller = wrap.querySelector('.matrix-scroll');
  if (!scroller) return;
  var update = function () {
    var overflows = scroller.scrollWidth > scroller.clientWidth + 4;
    wrap.classList.toggle('can-scroll', overflows);
    wrap.classList.toggle('at-end',
      !overflows || scroller.scrollLeft + scroller.clientWidth >= scroller.scrollWidth - 8);
  };
  scroller.addEventListener('scroll', update, { passive: true });
  window.addEventListener('resize', update);
  update();
});

// AI page only: a deep link to a chapter opens it on arrival.
// (Moved out of ai.html — the live CSP's script-src allows no inline
// scripts beyond the hashed class script. Guarded to the AI page by
// its body class; the code below is the page's original, unchanged.)
if (document.body.classList.contains('pg-ai')) {
// AI page only: a deep link to a chapter opens it on arrival.
(function () {
  function openFromHash() {
    var id = location.hash.replace('#', '');
    if (!id) return;
    var d = document.getElementById(id);
    if (d && d.tagName === 'DETAILS') d.open = true;
  }
  window.addEventListener('hashchange', openFromHash);
  openFromHash();
})();
}

// Verify page only: the File Check Code tool — file drop/choose, SHA-256
// computed locally via WebCrypto, compared against the pasted published
// code. (Moved out of verify.html for the same CSP reason. Guarded on
// the tool's own elements, which exist on no other page; the code below
// is the page's original, unchanged.)
if (document.getElementById('dropZone') && document.getElementById('fileInput') &&
    document.getElementById('publishedCode') && document.getElementById('compareBtn') &&
    document.getElementById('fileStatus') && document.getElementById('resultSlot')) {
(function(){
  var zone=document.getElementById('dropZone'), input=document.getElementById('fileInput'),
      pub=document.getElementById('publishedCode'), btn=document.getElementById('compareBtn'),
      status=document.getElementById('fileStatus'), slot=document.getElementById('resultSlot'),
      fileHash=null, fileName='';
  function clean(s){ return (s||'').replace(/[^0-9a-fA-F]/g,'').toLowerCase(); }
  function showResult(match){
    var div=document.createElement('div');
    div.className='result-card '+(match?'match':'mismatch');
    div.innerHTML = match
      ? '<h3><span class="mark">✓</span>Match</h3><p class="ok-line">The file matches the published File Check Code.</p><p>This matches the official release — the file you have is byte-for-byte the file that was published.</p><span class="hash">SHA-256: '+fileHash+'</span>'
      : '<h3><span class="mark">✗</span>Mismatch</h3><p class="ok-line">This does not match — do not install.</p><p>Delete the file and download again from this site or the project\u2019s releases page — nowhere else.</p><span class="hash">SHA-256: '+fileHash+'</span>';
    slot.innerHTML=''; slot.appendChild(div);
  }
  function hashFile(file){
    fileName=file.name; slot.innerHTML='';
    status.textContent='Reading '+fileName+' locally…';
    file.arrayBuffer().then(function(buf){
      return crypto.subtle.digest('SHA-256', buf);
    }).then(function(d){
      fileHash=Array.prototype.map.call(new Uint8Array(d),function(b){return ('0'+b.toString(16)).slice(-2);}).join('');
      status.innerHTML='<strong>'+fileName+'</strong> — its File Check Code:<span class="hash">SHA-256: '+fileHash+'</span>';
    }).catch(function(){
      fileHash=null; status.textContent='That file could not be read. Try choosing it again.';
    });
  }
  input.addEventListener('change',function(){ if(input.files[0]) hashFile(input.files[0]); });
  ['dragenter','dragover'].forEach(function(ev){ zone.addEventListener(ev,function(e){ e.preventDefault(); zone.classList.add('drag'); }); });
  ['dragleave','drop'].forEach(function(ev){ zone.addEventListener(ev,function(e){ e.preventDefault(); zone.classList.remove('drag'); }); });
  zone.addEventListener('drop',function(e){ var f=e.dataTransfer.files&&e.dataTransfer.files[0]; if(f) hashFile(f); });
  btn.addEventListener('click',function(){
    var want=clean(pub.value);
    if(!fileHash){ status.textContent='Choose or drop the downloaded file first — its code is computed here, on your device.'; return; }
    if(want.length!==64){ slot.innerHTML=''; status.textContent='Paste the full published File Check Code (64 characters) beside the download, then Compare.'; return; }
    showResult(want===fileHash);
  });
})();
}

// Report page only: the bug / feedback form. Guarded on the form's own
// element, which exists on no other page. Everything the visitor types
// is mirrored to a draft in this browser only, so leaving and coming
// back — or a send that fails — never loses a word.
if (document.getElementById('report-form')) {
(function () {
  var form = document.getElementById('report-form');
  var success = document.getElementById('report-success');
  var submitBtn = document.getElementById('submit-btn');
  var status = document.getElementById('submit-status');
  var errorsBox = document.getElementById('form-errors');
  var errorsList = document.getElementById('form-errors-list');
  var DRAFT_KEY = 'dg-report-draft-v1';
  var MAX_FILES = 8, MAX_FILE = 10 * 1024 * 1024, MAX_TOTAL = 25 * 1024 * 1024;
  var OK_EXT = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'txt', 'log', 'md', 'pdf', 'zip', 'mp4', 'webm'];
  var files = [];   // {file, name}
  var ghosts = [];  // {name, size} restored from a draft — names only

  var $ = function (sel) { return form.querySelector(sel); };
  var $$ = function (sel) { return Array.prototype.slice.call(form.querySelectorAll(sel)); };
  var fieldVal = function (name) {
    var el = form.elements[name];
    if (!el) return '';
    if (el.type === 'radio' || (el.length && el[0] && el[0].type === 'radio')) {
      var c = form.querySelector('input[name="' + name + '"]:checked');
      return c ? c.value : '';
    }
    return el.value || '';
  };
  var setVal = function (name, v) {
    if (v == null) return;
    var radios = $$('input[name="' + name + '"]');
    if (radios.length && radios[0].type === 'radio') {
      radios.forEach(function (r) { r.checked = r.value === v; });
    } else if (form.elements[name]) { form.elements[name].value = v; }
  };

  // --- timestamps for the time trap (refreshed after a failed send) ---
  var stampTs = function () { document.getElementById('form-ts').value = String(Date.now()); };
  stampTs();

  // --- detected device details: shown to the sender, sent only with
  //     their tick still in the box ---
  var detected = { os: '', browser: '', screen: '', from: '' };
  (function detect() {
    var ua = navigator.userAgent || '';
    var os = 'Unknown system';
    var m;
    // Test order matters: Android and ChromeOS user agents also carry
    // "Linux", and an iPad in desktop mode claims to be a Mac — check
    // them first so a phone is never labelled a Linux desktop.
    if (/CrOS/.test(ua)) os = 'ChromeOS';
    else if (/Android/.test(ua)) {
      m = /Android ([\d.]+)/.exec(ua);
      os = m ? ('Android ' + m[1]) : 'Android';
    }
    else if (/iPhone/.test(ua)) os = 'iOS (iPhone)';
    else if (/iPad/.test(ua)) os = 'iOS (iPad)';
    else if (/iPod/.test(ua)) os = 'iOS (iPod)';
    else if (/Windows NT/.test(ua)) os = 'Windows';
    else if (/Macintosh|Mac OS X/.test(ua)) {
      // A "Mac" with touch points is an iPad wearing the desktop UA.
      os = (navigator.maxTouchPoints > 0) ? 'iOS (iPad)' : 'macOS';
    }
    else if (/Linux/.test(ua)) os = 'Linux';
    var br = 'Unknown browser';
    if ((m = /Edg\/(\d+)/.exec(ua))) br = 'Edge ' + m[1];
    else if ((m = /OPR\/(\d+)/.exec(ua))) br = 'Opera ' + m[1];
    else if ((m = /Firefox\/(\d+)/.exec(ua))) br = 'Firefox ' + m[1];
    else if ((m = /Chrome\/(\d+)/.exec(ua))) br = 'Chrome ' + m[1];
    else if ((m = /Version\/(\d+).*Safari/.exec(ua))) br = 'Safari ' + m[1];
    detected.os = os; detected.browser = br;
    detected.screen = window.screen ? (screen.width + '×' + screen.height) : '';
    try {
      var ref = document.referrer ? new URL(document.referrer) : null;
      if (ref && ref.origin === location.origin) detected.from = ref.pathname;
    } catch (e) { /* no referrer is fine */ }
    var finish = function () {
      var parts = [detected.os, detected.browser, detected.screen && ('Screen ' + detected.screen)].filter(Boolean);
      document.getElementById('detected-text').textContent = parts.join(' · ') || 'We couldn’t read any details — that’s fine.';
    };
    if (navigator.userAgentData && navigator.userAgentData.getHighEntropyValues) {
      navigator.userAgentData.getHighEntropyValues(['platform', 'platformVersion']).then(function (v) {
        var pv = parseInt(v.platformVersion || '0', 10);
        if (v.platform === 'Windows') {
          if (pv >= 13) detected.os = 'Windows 11';
          else if (pv >= 1) detected.os = 'Windows 10';
        } else if (v.platform === 'Android') {
          // Client Hints can still know it's Android even when the UA
          // string has been switched to its desktop (Linux) form.
          var uaVer = /Android ([\d.]+)/.exec(ua);
          detected.os = uaVer ? ('Android ' + uaVer[1]) : (pv >= 1 ? ('Android ' + pv) : 'Android');
        } else if (v.platform === 'Chrome OS') {
          detected.os = 'ChromeOS';
        } else if (v.platform === 'macOS' && detected.os === 'Unknown system') {
          detected.os = 'macOS';
        } else if (v.platform === 'Linux' && detected.os === 'Unknown system') {
          detected.os = 'Linux';
        }
        finish();
      }).catch(finish);
    } else finish();
  })();

  // --- kind chooser: one adaptive form ---
  var summaryLabel = document.getElementById('summary-label');
  var applyKind = function () {
    var kind = fieldVal('kind') || 'bug';
    $$('.bug-only').forEach(function (el) { el.hidden = kind !== 'bug'; });
    $$('.feedback-only').forEach(function (el) { el.hidden = kind !== 'feedback'; });
    summaryLabel.textContent = kind === 'bug' ? 'In one line, what’s happening?' : 'In one line, what’s the idea?';
    submitBtn.textContent = kind === 'bug' ? 'Send report' : 'Send feedback';
  };
  $$('input[name="kind"]').forEach(function (r) { r.addEventListener('change', function () { applyKind(); saveDraft(); }); });

  // --- attachments ---
  var listEl = document.getElementById('file-list');
  var fmtSize = function (n) { return n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(n / 1024)) + ' KB'; };
  var renderFiles = function () {
    listEl.innerHTML = '';
    files.forEach(function (entry, i) {
      var li = document.createElement('li');
      var nm = document.createElement('span'); nm.className = 'fl-name'; nm.textContent = entry.name;
      var sz = document.createElement('span'); sz.className = 'fl-size'; sz.textContent = fmtSize(entry.file.size);
      var btn = document.createElement('button');
      btn.type = 'button'; btn.className = 'fl-remove'; btn.textContent = 'Remove';
      btn.setAttribute('aria-label', 'Remove ' + entry.name);
      btn.addEventListener('click', function () { files.splice(i, 1); renderFiles(); saveDraft(); });
      li.appendChild(nm); li.appendChild(sz); li.appendChild(btn);
      listEl.appendChild(li);
    });
    ghosts.forEach(function (g) {
      var li = document.createElement('li');
      var nm = document.createElement('span'); nm.className = 'fl-name'; nm.textContent = g.name;
      var sz = document.createElement('span'); sz.className = 'fl-size'; sz.textContent = fmtSize(g.size);
      var tag = document.createElement('span'); tag.className = 'fl-tag'; tag.textContent = 'Please re-attach';
      li.appendChild(nm); li.appendChild(sz); li.appendChild(tag);
      listEl.appendChild(li);
    });
  };
  var fileError = function (msg) {
    var e = document.getElementById('err-files');
    e.textContent = msg || ''; e.hidden = !msg;
  };
  var addFiles = function (incoming) {
    var problems = [];
    Array.prototype.forEach.call(incoming, function (file) {
      var name = file.webkitRelativePath || file.name;
      var ext = (name.split('.').pop() || '').toLowerCase();
      if (files.some(function (f) { return f.name === name && f.file.size === file.size; })) return;
      if (OK_EXT.indexOf(ext) === -1) { problems.push('“' + name + '” isn’t a type we can take (screenshots, text or logs, PDF, ZIP, short video).'); return; }
      if (file.size > MAX_FILE) { problems.push('“' + name + '” is over 10 MB.'); return; }
      if (files.length >= MAX_FILES) { problems.push('That’s the 8-file limit — the rest weren’t added.'); return; }
      var total = files.reduce(function (s, f) { return s + f.file.size; }, 0) + file.size;
      if (total > MAX_TOTAL) { problems.push('The files together would pass 25 MB — “' + name + '” wasn’t added.'); return; }
      files.push({ file: file, name: name });
      ghosts = ghosts.filter(function (g) { return !(g.name === name && g.size === file.size); });
    });
    fileError(problems[0] || '');
    renderFiles(); saveDraft();
  };
  var fileInput = document.getElementById('file-input');
  var folderInput = document.getElementById('folder-input');
  fileInput.addEventListener('change', function () { addFiles(fileInput.files); fileInput.value = ''; });
  folderInput.addEventListener('change', function () { addFiles(folderInput.files); folderInput.value = ''; });
  document.getElementById('pick-files').addEventListener('click', function (e) { e.stopPropagation(); fileInput.click(); });
  document.getElementById('pick-folder').addEventListener('click', function (e) { e.stopPropagation(); folderInput.click(); });
  var dz = document.getElementById('dropzone');
  dz.addEventListener('click', function () { fileInput.click(); });
  dz.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } });
  ['dragenter', 'dragover'].forEach(function (ev) {
    dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.add('drag'); });
  });
  ['dragleave', 'drop'].forEach(function (ev) {
    dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.remove('drag'); });
  });
  var readEntry = function (entry, out, done) {
    if (entry.isFile) {
      entry.file(function (f) {
        try { Object.defineProperty(f, 'webkitRelativePath', { value: entry.fullPath.replace(/^\//, '') }); } catch (e) { /* name alone still works */ }
        out.push(f); done();
      }, done);
    } else if (entry.isDirectory) {
      var reader = entry.createReader();
      var readBatch = function () {
        reader.readEntries(function (entries) {
          if (!entries.length) { done(); return; }
          var pending = entries.length;
          entries.forEach(function (en) { readEntry(en, out, function () { if (--pending === 0) readBatch(); }); });
        }, done);
      };
      readBatch();
    } else done();
  };
  dz.addEventListener('drop', function (e) {
    var items = e.dataTransfer && e.dataTransfer.items;
    var hasEntry = items && items.length && items[0].webkitGetAsEntry;
    if (!hasEntry) { addFiles(e.dataTransfer.files); return; }
    var out = [], pending = 0;
    Array.prototype.forEach.call(items, function (item) {
      if (item.kind !== 'file') return;
      var entry = item.webkitGetAsEntry();
      if (!entry) { var f = item.getAsFile(); if (f) out.push(f); return; }
      pending++;
      readEntry(entry, out, function () { if (--pending === 0) addFiles(out); });
    });
    if (pending === 0 && out.length) addFiles(out);
  });
  document.addEventListener('paste', function (e) {
    if (!e.clipboardData || !e.clipboardData.files || !e.clipboardData.files.length) return;
    e.preventDefault();
    addFiles(e.clipboardData.files);
  });

  // --- draft: never lose a word ---
  var TEXT_FIELDS = ['summary', 'trying', 'happened', 'steps', 'details', 'contact'];
  var saveTimer = null;
  function saveDraft() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(function () {
      try {
        var d = { kind: fieldVal('kind'), area: fieldVal('area'), severity: fieldVal('severity'),
          connection: fieldVal('connection'), ai: fieldVal('ai'),
          include: document.getElementById('f-include-details').checked,
          files: files.map(function (f) { return { name: f.name, size: f.file.size }; })
            .concat(ghosts) };
        TEXT_FIELDS.forEach(function (n) { d[n] = form.elements[n] ? form.elements[n].value : ''; });
        localStorage.setItem(DRAFT_KEY, JSON.stringify(d));
      } catch (e) { /* private mode: the form still works, drafts just don't persist */ }
    }, 250);
  }
  (function restoreDraft() {
    var d = null;
    try { d = JSON.parse(localStorage.getItem(DRAFT_KEY) || 'null'); } catch (e) { /* ignore */ }
    if (!d) return;
    TEXT_FIELDS.forEach(function (n) { if (d[n]) form.elements[n].value = d[n]; });
    ['kind', 'area', 'severity', 'connection', 'ai'].forEach(function (n) { if (d[n]) setVal(n, d[n]); });
    if (d.include === false) document.getElementById('f-include-details').checked = false;
    if (Array.isArray(d.files)) ghosts = d.files.filter(function (g) {
      return g && typeof g.name === 'string' && typeof g.size === 'number';
    });
    renderFiles();
  })();
  form.addEventListener('input', saveDraft);
  form.addEventListener('change', saveDraft);
  applyKind();

  // --- validation: on blur, in plain words, nothing lost ---
  var summaryCount = document.getElementById('summary-count');
  var summaryEl = document.getElementById('f-summary');
  summaryEl.addEventListener('input', function () {
    summaryCount.textContent = summaryEl.value.length ? '(' + summaryEl.value.length + ' of 150)' : '';
  });
  var showErr = function (name, msg) {
    var e = document.getElementById('err-' + name);
    if (e) { e.textContent = msg || ''; e.hidden = !msg; }
    var control = form.elements[name];
    if (control && control.setAttribute) control.setAttribute('aria-invalid', msg ? 'true' : 'false');
    return !msg;
  };
  var validateField = function (name) {
    var kind = fieldVal('kind') || 'bug';
    if (name === 'summary') return showErr('summary', fieldVal('summary').trim().length >= 3 ? '' : 'One short line is enough — what’s happening?');
    if (name === 'area') return showErr('area', fieldVal('area') ? '' : 'Please pick the closest one — “Something else” is fine.');
    if (name === 'happened') return showErr('happened', kind !== 'bug' || fieldVal('happened').trim() ? '' : 'Even a sentence helps: what did the app do, or not do?');
    if (name === 'details') return showErr('details', kind !== 'feedback' || fieldVal('details').trim() ? '' : 'A sentence or two is plenty — what would it do, and how would it help?');
    if (name === 'contact') {
      var v = fieldVal('contact').trim();
      return showErr('contact', !v || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) ? '' : 'That email doesn’t look complete — or clear it and send without one.');
    }
    return true;
  };
  ['summary', 'happened', 'details', 'contact'].forEach(function (n) {
    var el = form.elements[n];
    if (el) el.addEventListener('blur', function () { validateField(n); });
  });
  $('#area-chips').addEventListener('change', function () { validateField('area'); });

  // --- submit ---
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var kind = fieldVal('kind') || 'bug';
    var checks = [['summary', 'f-summary'], ['area', 'area-chips'], ['contact', 'f-contact']];
    if (kind === 'bug') checks.push(['happened', 'f-happened']); else checks.push(['details', 'f-details']);
    var bad = checks.filter(function (c) { return !validateField(c[0]); });
    if (bad.length) {
      errorsList.innerHTML = '';
      bad.forEach(function (c) {
        var li = document.createElement('li');
        var a = document.createElement('a');
        a.href = '#' + c[1]; a.textContent = document.getElementById('err-' + c[0]).textContent;
        a.addEventListener('click', function (ev) {
          ev.preventDefault();
          var t = document.getElementById(c[1]);
          if (t) { t.focus && t.focus(); t.scrollIntoView({ block: 'center' }); }
        });
        li.appendChild(a); errorsList.appendChild(li);
      });
      errorsBox.hidden = false;
      errorsBox.focus();
      return;
    }
    errorsBox.hidden = true;
    var fd = new FormData();
    fd.append('kind', kind);
    fd.append('summary', fieldVal('summary'));
    fd.append('area', fieldVal('area'));
    ['trying', 'happened', 'steps', 'severity', 'connection', 'ai', 'details', 'contact'].forEach(function (n) {
      var v = fieldVal(n); if (v) fd.append(n, v);
    });
    fd.append('website', fieldVal('website'));
    fd.append('form_ts', document.getElementById('form-ts').value);
    var tsInput = form.querySelector('[name="cf-turnstile-response"]');
    if (tsInput) fd.append('cf-turnstile-response', tsInput.value);
    if (document.getElementById('f-include-details').checked) {
      fd.append('include_details', 'yes');
      fd.append('detected_os', detected.os);
      fd.append('detected_browser', detected.browser);
      fd.append('detected_screen', detected.screen);
      if (detected.from) fd.append('detected_from', detected.from);
    }
    files.forEach(function (entry) { fd.append('files', entry.file, entry.name); });

    submitBtn.disabled = true;
    status.textContent = 'Sending…';
    fetch('/api/report', { method: 'POST', body: fd }).then(function (r) {
      return r.json().then(function (data) { return { ok: r.ok && data.ok, data: data }; });
    }).then(function (res) {
      submitBtn.disabled = false;
      if (res.ok) {
        try { localStorage.removeItem(DRAFT_KEY); } catch (e) { /* ignore */ }
        form.hidden = true;
        success.hidden = false;
        success.scrollIntoView({ block: 'center' });
        var h = success.querySelector('h2'); h.setAttribute('tabindex', '-1'); h.focus();
      } else {
        status.textContent = (res.data && res.data.error) || 'That didn’t send. Your answers are all still here — please try again.';
        stampTs();
        if (window.turnstile) window.turnstile.reset();
      }
    }).catch(function () {
      submitBtn.disabled = false;
      status.textContent = 'That didn’t send — your answers are all still here. Check your connection and try again.';
      stampTs();
      if (window.turnstile) window.turnstile.reset();
    });
  });

  document.getElementById('another-btn').addEventListener('click', function () {
    form.reset();
    files = []; ghosts = [];
    renderFiles(); fileError(''); status.textContent = '';
    stampTs();
    if (window.turnstile) window.turnstile.reset();
    applyKind();
    success.hidden = true;
    form.hidden = false;
    document.getElementById('report-card').scrollIntoView({ block: 'start' });
  });
})();
}
