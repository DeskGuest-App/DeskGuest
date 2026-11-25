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
      }, { threshold: 0.12, rootMargin: '0px 0px -6% 0px' });
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
