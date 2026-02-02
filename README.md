# TabGuard

A Chrome extension that locks specified websites behind a password. When a locked site loads, an overlay blocks access until the correct password is entered.

## How it works
- Sites are listed (one per line) in the options page.
- Passwords are stored as a PBKDF2 hash (salted) in `chrome.storage.local`.
- A content script runs at document start, checks the current host, and shows an unlock overlay when needed.

## Limitations
- This is not a security boundary. Anyone can disable/remove the extension.
- Only `http` and `https` pages can be locked.
- If you change the password, you must re-enter it on locked sites.

## Load the extension
1. Open Chrome and go to `chrome://extensions`.
2. Enable **Developer mode** (top right).
3. Click **Load unpacked** and choose this folder:
   `/Users/sarthakrawool/Documents/Programming/TabGuard`
4. Click the extension's **Details** and open **Extension options** to set a password and site list.

## Quick usage
- Add sites in the options page and toggle them on/off (e.g. `example.com` or `*.example.com`).
- Or click the extension icon to add/remove the current site from the popup.
- Use the popup to lock/unlock the current site instantly.
- Visit a locked site, enter your password, then choose a temporary unlock window (5/15/60 minutes).
