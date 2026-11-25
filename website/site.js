// DeskGuest website — small progressive enhancements only. No tracking, no external calls.
(function () {
  var toggle = document.querySelector('.nav-toggle');
  var nav = document.querySelector('.main-nav');
  if (toggle && nav) {
    toggle.addEventListener('click', function () {
      var open = nav.classList.toggle('open');
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
  }
  // Help search (support.html): filters the page's own help-topic cards —
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
  // Copy buttons for any element with data-copy-target
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
