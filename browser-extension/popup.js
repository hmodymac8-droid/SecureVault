// SecureVault popup: browser-drawn UI that web pages can't overlay or script.
// 1. Takes the active tab's exact https origin.
// 2. Asks SecureVault for matching logins (titles and usernames only).
// 3. On YOUR click, asks for that one login. SecureVault re-checks the site and may ask you to confirm.
// 4. Fills the top frame only, after re-checking the page is still on the same origin.
'use strict';

const HOST = 'com.securevault.host';
const $ = (id) => document.getElementById(id);

const MESSAGES = {
  not_running: 'Open SecureVault and unlock it.',
  locked: 'SecureVault is locked. Unlock it first.',
  disabled: 'Turn on browser filling in SecureVault → Security, then Save settings.',
  denied: 'The fill was denied in SecureVault.',
  no_match: 'That login doesn\'t belong to this site.',
  busy: 'Too many requests. Try again in a few seconds.',
  bad_origin: 'SecureVault only fills on https websites.',
  unsafe_environment: 'Blocked: your system environment has code-injection settings. See the SecureVault README.',
  wrong_extension: 'This extension isn\'t the official SecureVault extension.',
};

function say(text, isError) {
  $('msg').textContent = text;
  $('msg').className = isError ? 'err' : '';
}

async function ask(msg) {
  try { return await chrome.runtime.sendNativeMessage(HOST, msg); }
  catch { return { error: 'not_running' }; }
}

// Injected into the page's TOP frame in the extension's isolated world (the page's JS can't tamper with it).
function fillLogin(expectedOrigin, username, password) {
  if (location.origin !== expectedOrigin) return { ok: false, reason: 'The page changed to a different site.' };
  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && !el.disabled && !el.readOnly;
  };
  const setValue = (el, v) => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    el.focus();
    setter.call(el, v);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  };
  const isUserField = (el) => ['text', 'email', 'tel', ''].includes((el.getAttribute('type') || '').toLowerCase())
    || /user|login|email|account/i.test((el.name || '') + (el.id || '') + (el.autocomplete || ''));

  const pw = [...document.querySelectorAll('input[type="password"]')].find(visible);
  const scope = (pw && pw.form) || document;
  const inputs = [...scope.querySelectorAll('input')].filter(visible);
  let user = null;
  if (pw) {
    const idx = inputs.indexOf(pw);
    for (let i = idx - 1; i >= 0; i--) {
      const t = (inputs[i].getAttribute('type') || '').toLowerCase();
      if (['text', 'email', 'tel', ''].includes(t)) { user = inputs[i]; break; }
    }
  } else {
    // Username-first pages (e.g. "enter email" → next page asks for the password).
    user = inputs.find(isUserField) || null;
  }
  if (!pw && !user) return { ok: false, reason: 'No login box found on this page.' };
  if (user && username) setValue(user, username);
  if (pw) setValue(pw, password);
  return { ok: true, passwordFilled: !!pw };
}

async function main() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let origin = null;
  try {
    const u = new URL(tab && tab.url ? tab.url : '');
    if (u.protocol === 'https:') origin = u.origin;
  } catch { /* not a normal page */ }
  if (!origin) { say('SecureVault only fills on https websites.', true); return; }
  $('site').textContent = new URL(origin).hostname;

  const r = await ask({ type: 'list', origin });
  if (r.error) { say(MESSAGES[r.error] || 'Something went wrong.', true); return; }
  if (!r.entries || r.entries.length === 0) {
    say('No saved login for this exact site. In SecureVault, set the entry\'s URL to this site.');
    return;
  }
  say('Choose a login to fill:');
  for (const e of r.entries) {
    const li = document.createElement('li');
    const b = document.createElement('button');
    const t = document.createElement('span'); t.className = 'title'; t.textContent = e.title || '(no title)';
    const s = document.createElement('span'); s.className = 'user'; s.textContent = e.username || '';
    b.append(t, s);
    b.addEventListener('click', () => fill(tab.id, origin, e.id));
    li.append(b);
    $('list').append(li);
  }
}

async function fill(tabId, origin, id) {
  say('Waiting for SecureVault…');
  let cred = await ask({ type: 'get', origin, id });
  if (cred.error) { say(MESSAGES[cred.error] || 'Something went wrong.', true); return; }
  try {
    const [res] = await chrome.scripting.executeScript({
      target: { tabId, frameIds: [0] },
      world: 'ISOLATED',
      func: fillLogin,
      args: [origin, cred.username || '', cred.password || ''],
    });
    cred = null; // drop our copy
    const out = res && res.result;
    if (out && out.ok) {
      if (!out.passwordFilled) { say('Username filled. Continue, then click SecureVault again for the password.'); return; }
      window.close();
    } else {
      say((out && out.reason) || 'Couldn\'t fill this page.', true);
    }
  } catch (e) {
    cred = null;
    say('Couldn\'t fill this page.', true);
  }
}

main();
