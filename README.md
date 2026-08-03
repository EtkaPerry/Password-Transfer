# Password Transfer

A secure password transfer application built with a PHP backend and a web-based frontend. This tool utilizes a "reverse QR code" mechanism: rather than scanning a code to retrieve data, you scan a code on the target computer to securely transmit data from your phone.

As password managers become standard, passwords are growing longer and more complex. Entering these credentials on an untrusted or public computer poses a major security risk due to potential keyloggers and screen recorders. This application solves that problem. Simply open the app on your phone, paste your password, and scan the QR code on the target PC to instantly transfer your credentials without typing a single keystroke.

# Demo
You can test it by going [etka.co.uk/password](https://etka.co.uk/password/)
Head to website in browser on both your phone and computer. (Tip: You can open the website first in computer and show qr to phone it will open website immidiately on the phone too.)


## Environment Configuration

Required for Cloudflare Turnstile protection:

- `CF_TURNSTILE_SITE_KEY`
- `CF_TURNSTILE_SECRET_KEY`

Recommended:

- `PASSWORD_TRANSFER_ALLOWED_ORIGINS` (comma-separated)
- `PASSWORD_TRANSFER_DATA_DIR`
- `PASSWORD_TRANSFER_MAX_AGE_SECONDS`
- `PASSWORD_TRANSFER_MAX_DATA_BYTES`

If `PASSWORD_TRANSFER_DATA_DIR` points to a location under the web root on Apache, the backend will automatically create a local `.htaccess` file that denies direct HTTP access to that storage directory and its subdirectories. This is a fallback only; storing data outside the web root is still preferred.

Optional rate-limit and cleanup tuning:

- `PASSWORD_TRANSFER_STORE_RATE_LIMIT_COUNT`
- `PASSWORD_TRANSFER_STORE_RATE_LIMIT_WINDOW_SECONDS`
- `PASSWORD_TRANSFER_CHECK_RATE_LIMIT_COUNT`
- `PASSWORD_TRANSFER_CHECK_RATE_LIMIT_WINDOW_SECONDS`
- `PASSWORD_TRANSFER_CLEANUP_CHANCE_DENOMINATOR`
- `PASSWORD_TRANSFER_CLEANUP_MAX_FILES_PER_RUN`
- `PASSWORD_TRANSFER_SESSION_VERIFY_TTL_SECONDS`

## Why this exists

This project exists to make it easy and safe to transfer sensitive text (like passwords) from a mobile device to a desktop without typing. It reduces the attack surface on untrusted machines by avoiding manual entry and by performing encryption locally on the sender device.

## How it works (short)

- The receiver (desktop) generates a short-lived secret link containing a `session` and `key` in the URL fragment and renders it as a QR code.
- The sender (phone) scans the QR code, encrypts the payload locally with the `key` using AES, and posts the encrypted blob to the backend for the `session` identifier.
- The receiver polls the backend for that `session`, retrieves the encrypted blob, and decrypts it locally using the `key`. The server never sees the unencrypted payload.

### Why the key must stay in the fragment

Browsers do not transmit a URL fragment, so a key in `#session=…&key=…` never reaches the server. A query string does travel in the request line, and would be recorded in the web server access log, in Cloudflare's request logs, and in the `Referer` header of every subsequent request from the page — enough for the operator to decrypt the transfer.

Some in-app browsers rewrite a scanned link's fragment into a query string. The frontend handles that case rather than silently accepting it:

- `relocateQueryStringSecrets()` in [`web/script.js`](web/script.js) moves the pair back into the fragment on load and rewrites the address, so nothing further leaks.
- The user is shown a warning that the key already reached the server, and is offered a re-scan (which produces a fresh key) instead of continuing.
- `Referrer-Policy: strict-origin` is set in `backend-php/.htaccess`, in `api.php`, and as a `<meta name="referrer">` in the HTML, so no `Referer` ever carries a path or query string.

The initial request cannot be un-logged by any of this. Suppressing it requires server-side changes documented in [`backend-php/.htaccess`](backend-php/.htaccess) — `.htaccess` itself cannot alter Apache's log format.

## Frontend Libraries

This project uses the following JavaScript libraries (included in `web/vendor/`):

- **[Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)**: Used for client-side AES-256-GCM encryption and decryption of passwords so the server never sees the plain text. Built into all modern browsers — no external library required.
- **[html5-qrcode](https://github.com/mebjas/html5-qrcode)**: A cross-platform library for scanning QR codes using the device camera.
- **[qrcodejs](https://github.com/davidshimjs/qrcodejs)**: Used to generate QR codes on the fly representing the session URL.

## Repository

Repository: [https://github.com/EtkaPerry/Password-Transfer](https://github.com/EtkaPerry/Password-Transfer)

## License

This project is licensed under a **Custom License**. It allows commercial use, modification, distribution, and private use, but includes specific conditions for attribution, patent protection, and source disclosure for standalone or hosted primary-value services.

Key Points:
- **Permissions**: Commercial use, modification, distribution, and private use are granted.
- **Patent protection**: Patent litigation against the project or its users terminates the license rights.
- **Integration**: Attribution is required when used as a component. Source code disclosure for a larger application is **not** required when this is only one component.
- **Standalone products**: Source code disclosure is required if the primary functionality of your product is derived from this project.
- **Trademarks**: This license does not grant rights to use the "Password Transfer" name or branding.

See the [LICENSE](LICENSE) file for the full text.

## Terms of Service & Privacy Policy

The hosted service at [etka.co.uk/password](https://etka.co.uk/password/) is governed by two documents:

- [`web/terms.html`](web/terms.html) — acceptable use, the limits of the encryption guarantee, warranties and liability. Governed by the laws of England and Wales, with a carve-out preserving EEA/UK consumers' mandatory local rights.
- [`web/privacy.html`](web/privacy.html) — the UK/EU GDPR Article 13 notice: what is processed, legal bases, retention, recipients and data subject rights.

`consentNoticeHtml()` in [`web/script.js`](web/script.js) renders "By continuing you agree to the Terms of Service and confirm you have read the Privacy Policy" directly beneath the role buttons, so pressing a button is the act of agreement. It appears on the role-choice screen and, because a scanned QR link skips that screen, on the giver options screen when the session arrives prefilled.

The wording is deliberate: terms are a contract you accept, a privacy notice is information the controller must *provide*. Consent is not the legal basis for any processing here, so asking users to "agree" to the privacy policy would misstate the position.

Both documents cover **both** roles. The receiver runs the Cloudflare Turnstile challenge, so it is the receiver's IP that reaches a third party — the notice is not a giver-side concern.

These documents are **not** part of the software licence. If you self-host, you are the operator and data controller of your own instance, so you need your own versions: the sync workflow strips the operator's domain and contact address out of the published release, so both files ship as templates full of `your-domain.example`. Replace the operator name, contact address and governing law before you put an instance in front of real users.

When you change them materially, bump the version number and effective date at the top of the file you changed.

## Cookies & Privacy

This web UI uses minimal local storage to remember preferences (a single cookie-consent flag). The backend stores short-lived encrypted blobs and is designed to delete them after retrieval or expiry. IP addresses are processed transiently for rate limiting and are passed to Cloudflare Turnstile for bot protection. No analytics or third-party tracking is included by default. See [`web/privacy.html`](web/privacy.html) for the full description.

## Contributing

Contributions are welcome. Please open issues or pull requests on the GitHub repository. Keep changes focused, provide tests when possible, and document significant behavior changes.
