// SecureVault service worker.
// Detection: when our content script finds a login form on an https page, ask the local SecureVault app
// how many saved logins match this exact site, show that number on the toolbar icon, and tell the content
// script whether to show its "click to fill" chip. Only a COUNT is ever requested here, never a password.
// No site is sent to SecureVault unless the page actually has a login form.
'use strict';

const HOST = 'com.securevault.host';

async function ask(msg) {
  try {
    return await chrome.runtime.sendNativeMessage(HOST, msg);
  } catch (e) {
    return { error: 'not_running' };
  }
}

function httpsOrigin(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' ? u.origin : null;
  } catch {
    return null;
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Only our own content scripts, only the top frame of a real tab.
  if (sender.id !== chrome.runtime.id || !sender.tab || sender.frameId !== 0) return false;
  const tabId = sender.tab.id;
  const origin = httpsOrigin(sender.url || '');

  if (msg && msg.type === 'login_form' && origin) {
    ask({ type: 'count', origin }).then((r) => {
      const count = r && typeof r.count === 'number' ? r.count : 0;
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#1a7f37' });
      chrome.action.setBadgeText({ tabId, text: count > 0 ? String(Math.min(count, 99)) : '' });
      sendResponse({ count, error: r && r.error ? r.error : null });
    });
    return true; // async response
  }

  if (msg && msg.type === 'open_popup') {
    // The password is only ever released from the browser-drawn popup, which web pages can't overlay.
    chrome.action.openPopup({ windowId: sender.tab.windowId })
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }
  return false;
});

// A new page in the tab: clear the old badge.
chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === 'loading') chrome.action.setBadgeText({ tabId, text: '' });
});
