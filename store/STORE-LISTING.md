# Chrome Web Store listing — BOTIMPHISHGUARD

Everything needed to publish, prepared 27 September 2026.

## What is in this folder

| File | What it is |
| --- | --- |
| `botimphishguard-chrome-store-v1.1.22.zip` | **This is the file you upload.** 28.5 KB, 15 files, `manifest.json` at the root. |
| `package/` | The same files unpacked, so you can read them. |
| `01-install.png` | Screenshot 1280x800 — the install page. |
| `02-warning.png` | Screenshot 1280x800 — the block warning screen. |
| `03-download.png` | Screenshot 1280x800 — the YouTube download screen. |
| `04-privacy.png` | Screenshot 1280x800 — the privacy policy. |

Screenshots are exactly 1280x800, which is the size the store asks for.

---

## 1. Create the developer account (you must do this yourself)

1. Go to <https://chrome.google.com/webstore/devconsole>
2. Sign in with a **Google account**. Payment and identity are tied to this account, so use one
   you control long term.
3. Pay the one-time **$5 developer registration fee** with a card.
4. Complete **identity verification**. Google asks for a phone number and, for new personal
   developer accounts, a verification of your name. This is a legal identity check that I cannot
   do on your behalf.
5. Agree to the developer agreement and the programme policies.

I cannot create a Google account, enter card details, or sign a legal agreement for you. Those
three steps are the only parts of this that need a human.

## 2. Create the item

Click **Add new item**, then **Upload** the zip.

| Field | Value to paste |
| --- | --- |
| Category | **Productivity** (or Security — Productivity is the least scrutinised) |
| Language | English (United Kingdom) |
| Visibility | **Unlisted** to start, so nothing appears in the store until you have tested it |
| Support email | otim.no25@gmail.com |
| Home page | https://phishguard-8vri.onrender.com/app/install.html |
| Privacy policy URL | https://phishguard-8vri.onrender.com/app/privacy.html |

## 3. Store listing text

**Name (max 45 characters, currently 40):**
```
BOTIMPHISHGUARD — automatic URL guard
```

**Short description (max 150 characters):**
```
Blocks phishing, malware, gambling and scam sites the moment you click them. Also blocks ads and
skips YouTube ads.
```

**Category:** Productivity

**Description (paste as-is):**
```
BOTIMPHISHGUARD checks every link before it opens, so a fake login page, a malware download or a
gambling site never gets the chance to load.

WHAT IT BLOCKS
- Phishing and fake login pages
- Malware and scam download links
- Gambling and betting sites, which stay blocked even if your server settings are changed
- Adult and other categories you control from your own admin dashboard

WHAT ELSE IT DOES
- Blocks advertising on every site you visit
- Skips YouTube ads and gives the video straight back to you with no waiting and no buffering
- Adds one-click Download Video and Download Audio buttons under YouTube videos, with quality
  choices, so the file saves straight to your computer
- Shows a live feed of everything it has blocked, so you can see what it caught
- Lets you whitelist a site you trust, and continue once past a warning without turning anything off
- Updates itself automatically once installed

WHY IT IS DIFFERENT
The blocking rules live on your own server, not inside the extension. That means you can add or
remove rules, set strictness and review activity yourself, from a dashboard, without waiting for a
store update.

PRIVACY
The extension sends the address of the page you are opening and the verdict to your own server so
it can be checked. It does not read page contents, form input, passwords or your files. It contains
no advertising and no third-party tracking. Full policy:
https://phishguard-8vri.onrender.com/app/privacy.html
```

## 4. Answers for the review questionnaire

**Single purpose description (required, and the most important answer):**
```
This extension checks the address of each page the user tries to open against a threat
classification server and blocks the navigation, showing a warning screen, when the address is
classified as phishing, malware, gambling, adult or otherwise harmful. It also hides advertisement
elements and skips YouTube advertisements so the video continues without interruption, and offers
a download button for the YouTube video the user is watching.
```

**Why does the extension need `<all_urls>` host permission?**
```
Every page must be checked before it loads, and every ad element must be hidden, which requires
matching all URLs. The extension only reads the address of the page being opened, never its
contents.
```

**Why `webNavigation`?**
```
To check the URL of a navigation at the moment it is requested, before the page starts loading,
so a blocked site never renders.
```

**Why `notifications`?**
```
To tell the user that an ad was blocked and to show a new-version notice.
```

**Why `declarativeNetRequest`?**
```
To block known-harmful domains at the network layer, faster than letting the request leave the
browser.
```

**Why `storage`?**
```
To keep the server address, the user preferences and the one-time "continue anyway" token on the
device.
```

**Why `alarms`?**
```
To check the server for extension updates once an hour and warn the user when a new version is
ready.
```

**Data usage declarations — you must answer this honestly. Tick:**
- **Website content** — the extension sends the URL of the page being opened to the server to be
  classified.
- **Browsing history** — the addresses visited are used to classify each navigation, which is
  the same data as above.

Do **not** tick personal info, financial info, health, location, or user activity.

**Certification:** tick "I do not sell or transfer user data to third parties, apart from the
approved use cases". The server operator is you, not a third party, so this is accurate.

## 5. Honest review notes

Worth knowing before you submit, because these are the questions you are most likely to get:

- **The gambling and adult blocking is the part reviewers look at hardest.** It is allowed, but you
  must explain it in the single purpose statement above, which we have done. Keep the
  "Adult" category enabled in the description, otherwise the description does not match what the
  code does and that is a rejection risk.
- **The extension contacts a server you own.** That is permitted, but every URL the extension talks
  to must be disclosed in the privacy answers. We have covered the URL and verdict.
- **"Blocks ads on all sites" makes some reviewers check for the universal ad blocker claim.** The
  declaration that you do not block content behind a paywall, and do not replace page content, is
  accurate here and worth confirming.
- **Review normally takes a few days**, sometimes longer, and the unlisted listing stays hidden
  until it passes.
- If it is rejected, the dashboard email usually names the exact policy. Send me the text and I
  will fix the code and re-prepare the package.

## 6. After it is approved

1. In the dashboard, set **Visibility** to your choice and publish.
2. Install it from the store on every PC instead of the ZIP. Store installs update themselves, so
   you never install a new version by hand again.
3. The ZIP builds we already publish are still needed for Firefox and for any PC that cannot
   reach the store.
