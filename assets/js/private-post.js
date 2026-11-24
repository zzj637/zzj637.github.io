/* ==========================================================================
   private-post.js — client-side decryption for password protected posts.
   --------------------------------------------------------------------------
   The post body is encrypted at build time (AES-GCM, key derived from the
   password with PBKDF2-SHA-256) and shipped as a base64 payload. The password
   is checked by decrypting: nothing is compared against a stored hash, so a
   wrong password simply fails to authenticate the ciphertext.

   Everything happens in this browser tab. No network requests, no cookies,
   no local storage, no third-party code.
   ========================================================================== */
(function () {
  'use strict';

  var IDS = {
    root: 'lockedPost',
    payload: 'lockedPayload',
    form: 'lockedForm',
    input: 'lockedPassword',
    submit: 'lockedSubmit',
    error: 'lockedError',
    content: 'lockedContent'
  };

  function byId(id) {
    return document.getElementById(id);
  }

  /* base64 -> Uint8Array */
  function fromBase64(value) {
    var binary = window.atob(value);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function init() {
    var root = byId(IDS.root);
    if (!root) {
      return;
    }

    var payloadNode = byId(IDS.payload);
    var form = byId(IDS.form);
    var input = byId(IDS.input);
    var submit = byId(IDS.submit);
    var errorNode = byId(IDS.error);
    var contentNode = byId(IDS.content);

    if (!payloadNode || !form || !input || !submit || !errorNode || !contentNode) {
      return;
    }

    var payload = null;
    try {
      payload = JSON.parse(payloadNode.textContent.trim());
    } catch (error) {
      payload = null;
    }

    var busy = false;
    var idleLabel = submit.textContent;
    var subtle = window.crypto && window.crypto.subtle ? window.crypto.subtle : null;

    function setError(message) {
      errorNode.textContent = message;
      errorNode.hidden = !message;
      if (message) {
        root.classList.remove('is-shaking');
        /* restart the animation */
        void root.offsetWidth;
        root.classList.add('is-shaking');
      }
    }

    function setBusy(state) {
      busy = state;
      submit.disabled = state;
      input.disabled = state;
      submit.textContent = state ? '解密中…' : idleLabel;
      root.classList.toggle('is-busy', state);
    }

    function deriveKey(password, salt, iterations) {
      var encoder = new TextEncoder();
      return subtle
        .importKey('raw', encoder.encode(password), { name: 'PBKDF2' }, false, ['deriveKey'])
        .then(function (baseKey) {
          return subtle.deriveKey(
            { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
            baseKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
          );
        });
    }

    function reveal(html) {
      contentNode.innerHTML = html;
      contentNode.hidden = false;
      form.hidden = true;
      root.classList.add('is-unlocked');
      root.classList.remove('is-busy');
      setError('');
      contentNode.setAttribute('tabindex', '-1');
      try {
        contentNode.focus({ preventScroll: true });
      } catch (error) {
        contentNode.focus();
      }
    }

    function unlock(password) {
      if (!payload || !payload.salt || !payload.iv || !payload.ct) {
        return Promise.reject(new Error('missing payload'));
      }
      return deriveKey(password, fromBase64(payload.salt), payload.iter)
        .then(function (key) {
          return subtle.decrypt(
            { name: 'AES-GCM', iv: fromBase64(payload.iv) },
            key,
            fromBase64(payload.ct)
          );
        })
        .then(function (plainBuffer) {
          reveal(new TextDecoder().decode(plainBuffer));
        });
    }

    if (!subtle) {
      setBusy(false);
      submit.disabled = true;
      input.disabled = true;
      setError('当前浏览器环境不支持解密，请通过 HTTPS 打开本页。');
      return;
    }

    form.addEventListener('submit', function (event) {
      event.preventDefault();
      if (busy) {
        return;
      }

      var password = input.value;
      if (!password) {
        setError('请输入密码。');
        input.focus();
        return;
      }

      setError('');
      setBusy(true);

      unlock(password).then(
        function () {
          setBusy(false);
          input.value = '';
        },
        function (error) {
          setBusy(false);
          input.value = '';
          input.focus();
          setError(error && error.message === 'missing payload'
            ? '页面数据缺失，请刷新后重试。'
            : '密码不正确，请重试。');
        }
      );
    });

    input.focus();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
