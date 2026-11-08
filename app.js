
/* Password gate for the static site.
   The host only holds ciphertext, so locking is real: without the password
   there is nothing on disk to read. PBKDF2-HMAC-SHA256 -> AES-256-GCM, all
   in the browser's built-in Web Crypto. */
(function (g) {
  var M = null, KEY = null, SKEY = 'sitekey';

  function b64d(s) {
    var b = atob(s), a = new Uint8Array(b.length);
    for (var i = 0; i < b.length; i++) a[i] = b.charCodeAt(i);
    return a;
  }
  function b64e(buf) {
    var a = new Uint8Array(buf), s = '';
    for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
    return btoa(s);
  }

  function manifest() {
    if (M) return Promise.resolve(M);
    return fetch('enc/manifest.json').then(function (r) { return r.json(); })
      .then(function (j) { M = j; return j; });
  }

  function importKey(raw) {
    return crypto.subtle.importKey('raw', raw, 'AES-GCM', false,
                                   ['decrypt']);
  }

  function derive(pw, m) {
    var enc = new TextEncoder();
    return crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false,
                                   ['deriveBits'])
      .then(function (k) {
        return crypto.subtle.deriveBits(
          { name: 'PBKDF2', salt: b64d(m.salt), iterations: m.iter,
            hash: 'SHA-256' }, k, 256);
      });
  }

  function decrypt(key, bytes) {
    return crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: bytes.slice(0, 12) }, key, bytes.slice(12));
  }

  function restore() {
    if (KEY) return Promise.resolve(KEY);
    var raw;
    try { raw = sessionStorage.getItem(SKEY); } catch (e) { raw = null; }
    if (!raw) return Promise.resolve(null);
    return importKey(b64d(raw)).then(function (k) { KEY = k; return k; });
  }

  function unlock(pw) {
    return manifest().then(function (m) {
      return derive(pw, m).then(function (bits) {
        return importKey(bits).then(function (k) {
          return decrypt(k, b64d(m.verifier)).then(function () {
            KEY = k;
            try { sessionStorage.setItem(SKEY, b64e(bits)); } catch (e) {}
            return true;
          });
        });
      });
    }).catch(function () { return false; });
  }

  function fetchDec(url) {
    return restore().then(function (k) {
      if (!k) throw new Error('locked');
      return fetch(url).then(function (r) {
        if (!r.ok) throw new Error('missing ' + url);
        return r.arrayBuffer();
      }).then(function (buf) { return decrypt(k, new Uint8Array(buf)); });
    });
  }

  function text(url) {
    return fetchDec(url).then(function (b) {
      return new TextDecoder().decode(b);
    });
  }

  function blobURL(url, mime) {
    return fetchDec(url).then(function (b) {
      return URL.createObjectURL(new Blob([b], { type: mime || '' }));
    });
  }

  /* swap the whole document for the decrypted one, then re-create its
     scripts (importNode does not run them) and stream in its images */
  function render(html) {
    var doc = new DOMParser().parseFromString(html, 'text/html');
    var scripts = [];
    Array.prototype.forEach.call(doc.querySelectorAll('script'),
      function (s) { scripts.push({ src: s.src || s.getAttribute('src'),
                                    txt: s.textContent,
                                    type: s.getAttribute('type') });
                     s.parentNode.removeChild(s); });
    document.replaceChild(document.importNode(doc.documentElement, true),
                          document.documentElement);
    images();
    scripts.forEach(function (s) {
      var e = document.createElement('script');
      if (s.type) e.type = s.type;
      if (s.src) { e.src = s.src; e.async = false; }
      else e.textContent = s.txt;
      document.head.appendChild(e);
    });
  }

  function images() {
    manifest().then(function (m) {
      var mime = m.mime || {};
      var nodes = document.querySelectorAll('img[data-encsrc]');
      var load = function (img) {
        var n = img.getAttribute('data-encsrc');
        img.removeAttribute('data-encsrc');
        blobURL('enc/' + n + '.enc', mime[n]).then(function (u) {
          img.src = u;
        }).catch(function () {});
      };
      if (!('IntersectionObserver' in g)) {
        Array.prototype.forEach.call(nodes, load);
        return;
      }
      var io = new IntersectionObserver(function (es) {
        es.forEach(function (e) {
          if (e.isIntersecting) { io.unobserve(e.target); load(e.target); }
        });
      }, { rootMargin: '600px' });
      Array.prototype.forEach.call(nodes, function (n) { io.observe(n); });
    });
  }

  g.SiteLock = {
    unlock: unlock,
    isUnlocked: function () {
      return restore().then(function (k) { return !!k; });
    },
    lock: function () {
      KEY = null;
      try { sessionStorage.removeItem(SKEY); } catch (e) {}
    },
    openDoc: function (slug) {
      return text('enc/' + slug + '.enc').then(render);
    }
  };
})(window);
