// SecureVault login-form detector (content script, isolated from the page's own JavaScript).
// It shows a small "SecureVault: click to fill" chip next to the password box when this exact site has a
// saved login. Safety:
//  - the chip contains NO usernames or titles (the page could read them), only a generic label;
//  - clicking it never fills anything: it just opens SecureVault's popup (browser UI the page can't cover),
//    so a malicious page can't trick you into "clicking to fill" through a hidden overlay;
//  - clicks synthesised by page scripts (isTrusted === false) are ignored.
'use strict';

(() => {
  if (window.top !== window || location.protocol !== 'https:') return;

  let asked = false;
  let host = null;

  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && !el.disabled;
  };
  const findPassword = () => [...document.querySelectorAll('input[type="password"]')].find(visible) || null;

  function check() {
    if (asked) return;
    const pw = findPassword();
    if (!pw) return;
    asked = true;
    chrome.runtime.sendMessage({ type: 'login_form' }, (resp) => {
      if (chrome.runtime.lastError || !resp || !resp.count) return;
      showChip(pw);
    });
  }

  function showChip(field) {
    host = document.createElement('div');
    const root = host.attachShadow({ mode: 'closed' });
    root.innerHTML = `
      <style>
        .chip { all: initial; position: fixed; z-index: 2147483647; display: flex; gap: 6px; align-items: center;
                font: 12px system-ui, sans-serif; background: #1a7f37; color: #fff; border-radius: 6px;
                padding: 4px 8px; box-shadow: 0 2px 6px rgba(0,0,0,.25); cursor: pointer; }
        .x { cursor: pointer; opacity: .8; padding: 0 2px; }
      </style>
      <div class="chip" role="button" tabindex="-1"><span class="t">🔒 SecureVault: click to fill</span><span class="x" title="Hide">×</span></div>`;
    const chip = root.querySelector('.chip');
    const text = root.querySelector('.t');
    const place = () => {
      const r = field.getBoundingClientRect();
      if (r.width === 0) { chip.style.display = 'none'; return; }
      chip.style.display = 'flex';
      chip.style.top = Math.max(0, r.top - 30) + 'px';
      chip.style.left = Math.max(0, r.right - 210) + 'px';
    };
    root.querySelector('.x').addEventListener('click', (e) => {
      if (!e.isTrusted) return;
      e.stopPropagation();
      host.remove();
    });
    chip.addEventListener('mousedown', (e) => e.preventDefault()); // don't steal focus from the page
    chip.addEventListener('click', (e) => {
      if (!e.isTrusted) return; // ignore clicks faked by page scripts
      chrome.runtime.sendMessage({ type: 'open_popup' }, (r) => {
        if (chrome.runtime.lastError || !r || !r.ok) text.textContent = '🔒 Click the SecureVault icon in the toolbar ↗';
      });
    });
    document.documentElement.appendChild(host);
    place();
    window.addEventListener('scroll', place, true);
    window.addEventListener('resize', place);
  }

  check();
  // Single-page apps add login forms later: watch for a while, debounced.
  let timer = null;
  const obs = new MutationObserver(() => {
    if (asked) { obs.disconnect(); return; }
    clearTimeout(timer);
    timer = setTimeout(check, 400);
  });
  obs.observe(document.documentElement, { childList: true, subtree: true });
  setTimeout(() => obs.disconnect(), 60000);
})();
