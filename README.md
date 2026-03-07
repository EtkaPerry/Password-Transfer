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

## Cookies & Privacy

This web UI uses minimal local storage to remember preferences (for example, cookie consent). The backend stores short-lived encrypted blobs and is designed to delete them after retrieval or expiry. No analytics or third-party tracking is included by default.

## Contributing

Contributions are welcome. Please open issues or pull requests on the GitHub repository. Keep changes focused, provide tests when possible, and document significant behavior changes.
