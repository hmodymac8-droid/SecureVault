# SecureVault

A local-only, zero-knowledge password manager for Windows (C# / .NET 10 LTS, WPF). It has no network code at all: a test checks that no assembly references `System.Net`.

## Build, test, install

```powershell
dotnet test SecureVault.slnx
```

Install (elevated PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

What the installer does:
1. Copies only the source files into an **admin-only** build folder under `%ProgramData%`.
2. Restores NuGet packages into an admin-only cache in **locked mode**, so package hashes must match `packages.lock.json`.
3. Runs the tests and publishes **self-contained** (no reliance on a shared or user-set .NET runtime).
4. Installs into `C:\Program Files\SecureVault`, writable by admins only.
5. Runs the self-test of the installed copy.

Building elevated inside your user-writable checkout would let user-level malware plant build files or swap packages to get admin rights, so it builds in the admin-only folder instead. It still trusts the source you checked out.

**Why not a single .exe?** A self-extracting single-file exe unpacks `libsodium.dll` into `%TEMP%`, where any program running as you could replace it. In Program Files the DLL sits next to the exe and only admins can write there. The app also restricts DLL search to its own folder plus System32. A signed exe in a folder you can write to can still be replaced, so the install location is what matters.

**Self-test:** `SecureVault.exe --selftest report.txt` checks, inside the hardened process:
- every hardening step applied
- the diagnostics pipe is gone
- process memory reads and thread hijacking are denied
- a full create → change password → reopen cycle (with the real TPM if present) works

## How it protects your vault

| Layer | What it does |
|---|---|
| **Encryption** | XChaCha20-Poly1305 (libsodium 1.0.22 via NSec). The whole header is authenticated, so any modified byte is detected. Plaintext is padded to 4 KiB blocks. |
| **Password key** | Argon2id. Floor: 256 MiB / 3 passes, enforced on open, so a tampered header can't weaken it. Ceiling: 2 GiB / 16 passes, to limit unauthenticated DoS. New vaults start at 512 MiB / 3 passes and calibration only *raises* the passes (to about 1 s). libsodium supports only parallelism = 1. |
| **Key slots** | One random 256-bit data key, wrapped separately by each unlock method (LUKS-style). |
| **Unlock methods** | Password · Password + keyfile · Password + **TPM** (one PC) · **Recovery key** (emergency kit, any PC) |
| **Key rotation** | Changing the password, removing an unlock method, or replacing the recovery key creates a **new data key** and a new recovery key. Old backups and old credentials can't decrypt anything saved afterwards. You're offered deletion of the old backups. |
| **No silent downgrades** | Re-keying needs (and checks) the right keyfile. A TPM error aborts instead of dropping the slot. Only TPM slots belonging to *other* PCs are dropped, and they're listed. |
| **TPM** | A non-exportable RSA-2048 key in the TPM ("Microsoft Platform Crypto Provider") decrypts a 32-byte slot secret with OAEP-SHA256. The output is deterministic, checked at enrollment and tested on real hardware. |
| **Recovery key** | 160 random bits + 40-bit checksum (40 chars), typed on the secure desktop. Mandatory. If the kit window is closed before you confirm (lock, crash), a new key is issued at the next unlock. Idle and minimize auto-lock wait while the kit is open. |
| **Key commitment** | HMAC(KEK, slot context) per slot and HMAC(dataKey, …) in the header, checked in constant time first (XChaCha20-Poly1305 isn't key-committing). |
| **Anti-rollback** | A save counter, with the highest value seen stored DPAPI-protected in `%LOCALAPPDATA%\SecureVault\rollback.dat`. It warns when a file is older than that, and also when a previously saved vault has no record on this PC (new PC, or the record was deleted). |
| **Backups** | The last 5 versions (configurable) are kept encrypted in `backups\` next to the vault. |
| **Memory** | Entry passwords and notes are encrypted in RAM under a per-session key in libsodium guarded memory. They're serialised as hex between pinned, wiped buffers, so the JSON writer never escapes them through unwiped pools. Locking disposes all keys and forces a GC. |
| **Process** | It relaunches itself with a clean environment: startup hooks, profilers and `DOTNET_*`/`COR*` variables are stripped, and **diagnostics are disabled** (no debugger attach, no dump pipe). The startup-hook runtime switch is off. The **process and thread DACLs** let same-user programs only terminate or query (no memory reads, no thread hijacking; verified by the self-test). Remote and low-integrity DLLs are blocked, legacy extension points are disabled, debugger detection locks the vault, and it never runs elevated. |
| **Input** | The master password and the recovery key are typed on a **secure desktop**. It returns automatically after 60 s. A banner warns when it's turned off. |
| **Screen** | Every window is excluded from screenshots, recording and RDP capture. Passwords are hidden until you click Show. |
| **Clipboard** | Fails closed unless `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory=0` and `CanUploadToCloudClipboard=0` are all set. Cleared after 20 s if it's still our content. |
| **Auto-lock** | Idle (5 min), Windows lock, sign-out, RDP or console changes, sleep and **hibernate** (hiberfil.sys holds a RAM copy), minimize, debugger. All windows close and every field is cleared. |

### Threat model: what it does NOT protect against
- **Admin- or kernel-level malware**, `SeDebugPrivilege`, or a **hardware keylogger**.
- **Malware already running as you** has fewer options (no memory reads, no thread injection, no startup hooks), but it can still fake our window, change the non-secret `config.json` (the "secure desktop off" banner then shows), or delete the rollback record (you're then warned that the vault is unknown on this PC). The secure desktop stops ordinary keyloggers, not ones that deliberately target secure desktops.
- **A weak master password with no TPM or keyfile.** Argon2id slows guessing, but it can't save "password1" (weak master passwords are rejected). The in-app retry delay only slows guessing *inside the app*.
- **.NET strings**: anything shown in a text box (a revealed password, titles, usernames, URLs, revealed notes) becomes a string that can't be wiped. Memory wiping is **best effort**.
- **Old backups and copies** made before a re-key can still be opened with the *old* credentials, and they show the entries as they were *then*. Delete them after a re-key; the app offers to.
- **Third-party clipboard managers** may ignore the "don't record" flags. See *PCButler* below.

## PCButler and other clipboard managers
Your PC runs **PCButler**, which saves clipboard history to disk (`clipboard\history.json`). Do one of these:
1. Exclude `SecureVault.exe` in PCButler, or
2. Make PCButler skip any clipboard content carrying the standard `ExcludeClipboardContentFromMonitorProcessing` format (it's your own tool, so this is the proper fix), or
3. Disable its clipboard history.

Then delete any old `history.json` entries that may hold passwords.

## Backups (and a USB copy)
1. Lock SecureVault.
2. Copy `%LOCALAPPDATA%\SecureVault\vault.pmv` to a USB drive, ideally one encrypted with BitLocker To Go.
3. Keep the **printed emergency kit** apart from the USB drive.
4. After a password change or other re-key, **replace** the USB copy, because the old one still opens with the old credentials.

Opening an old copy triggers the rollback warning: that's expected for a restore you did yourself. TPM unlock methods only work on the PC that created them. On a new PC, open with your password slot or the recovery key, then add a TPM unlock there.

## Browser extension (Chrome / Edge)

**Setup (one time):**
1. Run `install.ps1`. It copies the extension to `C:\Program Files\SecureVault\browser-extension` and registers the browser connection.
2. Load the extension:
   - Open `chrome://extensions` (Edge: `edge://extensions`) and turn on **Developer mode**.
   - Click **Load unpacked** and choose that folder.
   - Check the ID is `mipbfgbdnkehbkfcocihjcilaflfphih`.
3. In SecureVault, open **Security**, tick **Allow the SecureVault browser extension**, and click **Save settings**.

**Using it:**
- On a site where you have a saved login, the SecureVault icon shows a number and a small **"🔒 SecureVault: click to fill"** chip appears near the password box.
- Click the chip (or the icon), then pick the login.
- SecureVault asks **Allow / Deny** (you can turn that off), then fills it in.
- The entry's **URL** must be the site's address, e.g. `github.com`.

**Why it's safe:**
| Risk | Protection |
|---|---|
| Fake or look-alike sites (phishing) | Fills only on the **exact** saved host, https only, compared in punycode (Cyrillic look-alikes never match). No subdomain wildcards. **Checked inside SecureVault**, not by the extension. |
| Hidden forms and clickjacking | Never fills automatically. The in-page chip never fills anything itself: it only opens the browser's own popup, which a page can't cover, and clicks faked by the page are ignored. Fills the top frame only, after re-checking the page's origin. |
| Web pages reading your data | The chip shows no usernames. The extension's popup and code aren't reachable from pages (no web-accessible resources, no external messaging). |
| Asking for another site's password | SecureVault refuses: `get` only works for an entry that matches the requesting site, and it answers the same whether the entry exists or not. |
| Other programs posing as the extension | Only the extension with our ID may start the helper (the native-messaging manifest is in Program Files, registered in HKLM). SecureVault accepts a connection only from its own helper exe, started by `chrome.exe` / `msedge.exe`, over a pipe ACL'd to your user and closed to the network. There's a rate limit, and you approve each fill. |
| A locked vault | The bridge only runs while the vault is unlocked **and** you've turned browser filling on. |
| Privacy | A site is sent to SecureVault (locally) only when the page has a login form, and only to get a count. Nothing goes to the internet. |

**Limits:**
- Unpacked extensions show a "developer mode" notice in Chrome.
- Malware running as you could install a look-alike extension in your browser (see the threat model).
- Once a password is filled into a page, that page has it, as with any password manager.
- Keep SecureVault open (not minimized, or turn off "Lock when minimized") while browsing.

## Importing from a browser
Use **Import CSV** (Chrome, Edge, Firefox and Bitwarden formats). Exports are **plaintext**: import, then delete the CSV. On SSDs, "secure delete" can't guarantee the data is gone, so consider changing your most important passwords afterwards.

## Two-factor codes
TOTP was left out on purpose. Keep 2FA codes in a separate authenticator app, so two factors stay two.

## Layout
- `src/Vault.Core`: crypto, file format, key slots and re-keying, recovery key, in-memory protection, generator, CSV import
- `src/Vault.App`: WPF UI, TPM, DPAPI rollback guard, secure desktop, secure clipboard, process hardening, self-test
- `tests/Vault.Core.Tests`: 40 tests:
  - published vectors (XChaCha20-Poly1305 from draft-irtf-cfrg-xchacha A.3.1, and libsodium's Argon2id vector)
  - every slot type
  - data-key rotation, and refusing downgrades
  - tamper checks on every header byte
  - random-mutation fuzzing
  - rollback counter and backups
  - the no-network static scan
  - a real-TPM determinism test

## Not done yet
Auto-type or two-part copy, a signed MSI installer, a passphrase word list.
