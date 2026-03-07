// Ensure the API URL works in dev and production
var apiUrl = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
    ? '/backend-php/api.php'
    : 'api.php';

var appRuntimeConfig = {
    turnstileSiteKey: '',
    turnstileEnabled: null,
    loaded: false
};

var runtimeConfigPromise = null;

// Generate Cryptographically Secure ID
function generateId(length) {
    var array = new Uint8Array(length);
    window.crypto.getRandomValues(array);
    return Array.from(array, function (byte) { return byte.toString(16).padStart(2, '0'); }).join('');
}

// ==========================================
// WEB CRYPTO HELPERS (AES-256-GCM)
// ==========================================
function hexToBytes(hex) {
    var bytes = new Uint8Array(hex.length / 2);
    for (var i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

async function encryptData(plaintext, keyHex) {
    var keyBytes = hexToBytes(keyHex);
    var cryptoKey = await crypto.subtle.importKey(
        'raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']
    );
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        cryptoKey,
        new TextEncoder().encode(plaintext)
    );
    var combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.length);
    return btoa(String.fromCharCode.apply(null, combined));
}

async function decryptData(encryptedBase64, keyHex) {
    var keyBytes = hexToBytes(keyHex);
    var cryptoKey = await crypto.subtle.importKey(
        'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']
    );
    var combined = Uint8Array.from(atob(encryptedBase64), function (c) { return c.charCodeAt(0); });
    var iv = combined.slice(0, 12);
    var ciphertext = combined.slice(12);
    var plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        cryptoKey,
        ciphertext
    );
    return new TextDecoder().decode(plaintext);
}

// Parse URL Fragment Hash for Session & Key
function parseHash() {
    // Some phone camera apps remove URL fragments when opening links from QR codes.
    // Support both hash (#session=...) and query string (?session=...)
    var searchParams = new URLSearchParams(window.location.search);
    var session = searchParams.get('session');
    var key = searchParams.get('key');

    if (session && key) {
        return { session: session, key: key };
    }

    var hash = window.location.hash.substring(1);
    var params = new URLSearchParams(hash);
    return {
        session: params.get('session'),
        key: params.get('key')
    };
}

function getTurnstileSiteKey() {
    if (appRuntimeConfig && appRuntimeConfig.turnstileSiteKey) {
        return appRuntimeConfig.turnstileSiteKey;
    }

    var meta = document.querySelector('meta[name="cf-turnstile-sitekey"]');
    if (!meta) return '';
    return (meta.getAttribute('content') || '').trim();
}

function isTurnstileEnabledForClient() {
    if (typeof appRuntimeConfig.turnstileEnabled === 'boolean') {
        return appRuntimeConfig.turnstileEnabled;
    }

    return getTurnstileSiteKey() !== '';
}

async function loadRuntimeConfig() {
    if (runtimeConfigPromise) {
        return runtimeConfigPromise;
    }

    runtimeConfigPromise = (async function () {
        try {
            var response = await fetch(apiUrl + '?action=config');
            if (!response.ok) return appRuntimeConfig;

            var payload = await response.json();
            if (payload && typeof payload.turnstileSiteKey === 'string') {
                appRuntimeConfig.turnstileSiteKey = payload.turnstileSiteKey.trim();
            }
            if (payload && typeof payload.turnstileEnabled === 'boolean') {
                appRuntimeConfig.turnstileEnabled = payload.turnstileEnabled;
            }
        } catch (e) {
            console.warn('Runtime config not loaded:', e);
        } finally {
            appRuntimeConfig.loaded = true;
        }

        return appRuntimeConfig;
    })();

    return runtimeConfigPromise;
}

async function ensureRuntimeConfigLoaded() {
    if (appRuntimeConfig.loaded) {
        return appRuntimeConfig;
    }

    return loadRuntimeConfig();
}

function waitForTurnstileApi(timeoutMs) {
    return new Promise(function (resolve) {
        if (window.turnstile && typeof window.turnstile.render === 'function') {
            resolve(true);
            return;
        }

        var startTime = Date.now();
        var timer = window.setInterval(function () {
            if (window.turnstile && typeof window.turnstile.render === 'function') {
                window.clearInterval(timer);
                resolve(true);
                return;
            }

            if ((Date.now() - startTime) >= timeoutMs) {
                window.clearInterval(timer);
                resolve(false);
            }
        }, 100);
    });
}

async function verifyReceiverSession(session, challengeToken) {
    if (!isTurnstileEnabledForClient()) {
        return;
    }

    if (!challengeToken) {
        throw new Error('Security check did not complete. Please try again.');
    }

    var formData = new URLSearchParams();
    formData.append('session', session);
    formData.append('cf_token', challengeToken);

    var response = await fetch(apiUrl + '?action=verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString()
    });

    var result = await response.json().catch(function () {
        return null;
    });

    if (!response.ok || !result || !result.success) {
        throw new Error(result && result.error ? result.error : 'Unable to verify the secure session.');
    }
}

async function showReceiverChallenge(container, onVerified) {
    var siteKey = getTurnstileSiteKey();
    var turnstileRequired = isTurnstileEnabledForClient();

    if (!siteKey) {
        if (turnstileRequired) {
            showError(container, 'Cloudflare Turnstile is enabled but the site key is missing.');
            return;
        }

        onVerified();
        return;
    }

    container.innerHTML = '<h1>Receive Data</h1>\n'
        + '<p>Running security check before generating your QR code.</p>\n'
        + '<div id="turnstileWidget" style="display:flex;justify-content:center;margin:1rem 0;"></div>\n'
        + '<p id="challengeStatus" class="status-msg"></p>\n'
        + '<button id="backBtnChallenge" class="secondary-btn" style="margin-top:1rem;">Back</button>\n';

    var backBtn = document.getElementById('backBtnChallenge');
    if (backBtn) {
        backBtn.addEventListener('click', function () {
            startApp();
        });
    }

    var turnstileReady = await waitForTurnstileApi(5000);
    if (!turnstileReady) {
        var fallbackStatus = document.getElementById('challengeStatus');
        if (fallbackStatus) {
            fallbackStatus.className = 'status-msg error';
            fallbackStatus.innerText = 'Security check unavailable. Please try again in a moment.';
        }
        return;
    }

    window.turnstile.render('#turnstileWidget', {
        sitekey: siteKey,
        callback: function (token) {
            onVerified(token);
        },
        'error-callback': function () {
            var status = document.getElementById('challengeStatus');
            if (status) {
                status.className = 'status-msg error';
                status.innerText = 'Challenge failed. Please try again.';
            }
        },
        'expired-callback': function () {
            var status = document.getElementById('challengeStatus');
            if (status) {
                status.className = 'status-msg';
                status.innerText = 'Challenge expired. Please verify again.';
            }
        }
    });
}

// Start Application Based on State
function startApp() {
    var container = document.getElementById('app');
    
    // Check if we arrived via a scanned QR code (direct to Giver mode)
    var hashInfo = parseHash();
    if (hashInfo.session && hashInfo.key) {
        renderGiverOptions(container, hashInfo.session, hashInfo.key);
        return;
    }

    // Initial Choice Screen
    container.innerHTML = '<h1>Password Transfer</h1>\n'
        + '<p>Select your role below to get started.</p>\n'
        + '<button id="btnReceiver" style="margin-bottom: 1rem;">I am Receiver (PC)</button>\n'
        + '<button id="btnGiver" class="secondary-btn">I am Giver (Phone)</button>\n';

    document.getElementById('btnReceiver').addEventListener('click', function() {
        renderReceiver(container);
    });

    document.getElementById('btnGiver').addEventListener('click', function() {
        renderGiverOptions(container);
    });
}

function renderGiverOptions(container, prefilledSession, prefilledKey) {
    container.innerHTML = '<h1>What to Send?</h1>\n'
        + '<p>Select the type of data you want to send.</p>\n'
        + '<button id="btnSendText" style="margin-bottom: 0.5rem;">1. Long Text</button>\n'
        + '<button id="btnSendPwd" style="margin-bottom: 0; margin-top: 0;">2. Password</button>\n'
        + '<button id="btnBackToRole" class="secondary-btn" style="margin-top: 1.5rem;">Back</button>\n';

    document.getElementById('btnSendText').addEventListener('click', function() {
        renderGiverInput(container, 'text', prefilledSession, prefilledKey);
    });

    document.getElementById('btnSendPwd').addEventListener('click', function() {
        renderGiverInput(container, 'password', prefilledSession, prefilledKey);
    });

    document.getElementById('btnBackToRole').addEventListener('click', function () {
        if (prefilledSession || prefilledKey) {
            // Clear hash so we can return to regular home screen
            try { history.replaceState(null, '', window.location.pathname + window.location.search); } 
            catch(e) { window.location.hash = ''; }
        }
        startApp();
    });
}

// ==========================================
// GIVER MODE (e.g., Mobile Phone)
// ==========================================
function renderGiverInput(container, type, prefilledSession, prefilledKey) {
    var title = type === 'text' ? 'Enter Text' : 'Enter Password';
    var placeholder = type === 'text' ? 'Enter / Paste your long text here...' : 'Enter / Paste password here...';
    var nextLabel = (prefilledSession && prefilledKey) ? 'Send Securely' : 'Next: Scan PC';

    var inputHtml = type === 'password'
        ? '<input type="password" id="dataInput" placeholder="' + placeholder + '">\n'
        : '<textarea id="dataInput" placeholder="' + placeholder + '"></textarea>\n';

    container.innerHTML = '<h1>' + title + '</h1>\n'
        + '<p>Paste the content you want to send.</p>\n'
        + inputHtml
        + '<button id="nextBtn">' + nextLabel + '</button>\n'
        + '<button id="btnBackToGiverOptions" class="secondary-btn" style="margin-top: 1rem;">Back</button>\n';

    document.getElementById('nextBtn').addEventListener('click', function () {
        var val = document.getElementById('dataInput').value.trim();
        if (!val) {
            alert('Please enter ' + (type === 'text' ? 'some text' : 'a password'));
            return;
        }
        
        if (prefilledSession && prefilledKey) {
            sendDataToBackend(container, val, type, prefilledSession, prefilledKey);
        } else {
            renderGiverCamera(container, val, type);
        }
    });

    document.getElementById('btnBackToGiverOptions').addEventListener('click', function () {
        renderGiverOptions(document.getElementById('app'), prefilledSession, prefilledKey);
    });
}

function renderGiverCamera(container, dataVal, dataType) {
    container.innerHTML = '<h1>Scan PC QR Code</h1>\n'
        + '<p>Scan the QR code shown on the Receiver screen.</p>\n'
        + '<div id="reader" style="width: 100%; max-width: 400px; margin: 0 auto 1.5rem auto;"></div>\n'
        + '<p id="statusMsg" class="status-msg"></p>\n'
        + '<button class="secondary-btn" id="cancelScanBtn">Cancel</button>\n';

    // Use Html5Qrcode directly instead of Html5QrcodeScanner to avoid UI bugs on iOS
    // particularly related to camera switching and DOM removal.
    var html5QrCode = new Html5Qrcode("reader");

    var stopScanning = function() {
        return html5QrCode.stop().then(function() {
            html5QrCode.clear();
        }).catch(function(err) {
            console.warn("Failed to stop scanning", err);
        });
    };
    
    document.getElementById('cancelScanBtn').addEventListener('click', function () {
        stopScanning().then(function() {
            renderGiverInput(container, dataType);
        });
    });

    try {
        var config = { fps: 10, qrbox: { width: 250, height: 250 } };
        
        // Prefer back camera (environment)
        html5QrCode.start({ facingMode: "environment" }, config, function onScanSuccess(decodedText, decodedResult) {
            try {
                // Defensive checks: ensure we have a string
                if (typeof decodedText !== 'string') {
                    console.warn('Scanned non-string payload, ignoring', decodedText);
                    return;
                }

                // If the scanned payload looks like HTML (e.g. starts with <), ignore it
                var trimmed = decodedText.trim();
                if (trimmed.charAt(0) === '<') {
                    console.warn('Scanned HTML content, ignoring');
                    return;
                }

                // Log the decoded text to help debugging on Safari/other browsers
                console.log('QR decoded text:', decodedText);

                // Attempt to parse the decoded text as a URL
                var url;
                try {
                    url = new URL(decodedText);
                } catch (urlError) {
                    // Not a valid URL for this flow; keep scanning
                    return;
                }

                var hash = url.hash;
                if (!hash || hash.length < 2) {
                    return; // Doesn't have our required hash
                }

                var hashParams = new URLSearchParams(hash.substring(1));
                var session = hashParams.get('session');
                var key = hashParams.get('key');

                if (!session || !key) {
                    return; // Valid URL, but not our expected format
                }

                // Stop scanning and clear UI since we found a valid code
                stopScanning().then(function() {
                     sendDataToBackend(container, dataVal, dataType, session, key);
                });
            } catch (e) {
                console.error('Scan handling error:', e);
                var status = document.getElementById('statusMsg');
                if (status) {
                    status.className = 'status-msg error';
                    status.innerText = 'Invalid scan data. Retrying...';
                }
            }
        }, function onScanFailure(error) {
            // Handle scan failure silently (happens repeatedly until success)
        }).catch(function(err) {
             console.error('QR start failed:', err);
             var s = document.getElementById('statusMsg');
             if (s) { s.className = 'status-msg error'; s.innerText = 'Camera access failed. Please ensure permission is granted.'; }
        });
    } catch (renderErr) {
        console.error('QR renderer failed to start:', renderErr);
        var s = document.getElementById('statusMsg');
        if (s) { s.className = 'status-msg error'; s.innerText = 'Camera not available in this browser.'; }
        return;
    }
}

function sendDataToBackend(container, dataVal, dataType, session, key) {
    container.innerHTML = '<h1>Sending...</h1>\n'
        + '<p>Encrypting and transferring your data.</p>\n'
        + '<p id="statusMsg" class="status-msg"></p>\n';

    var status = document.getElementById('statusMsg');

    (async function () {
        try {
            // Local Encryption (Key never leaves device)
            var payloadObj = { type: dataType, content: dataVal };
            var encrypted = await encryptData(JSON.stringify(payloadObj), key);

            var formData = new URLSearchParams();
            formData.append('session', session);
            formData.append('data', encrypted);

            var response = await fetch(apiUrl + '?action=store', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: formData.toString()
            });

            var result = null;
            var rawText = null;
            try {
                var ct = response.headers.get('content-type') || '';
                rawText = await response.text();
                if (ct.indexOf('application/json') !== -1) {
                    result = JSON.parse(rawText);
                } else {
                    try { result = JSON.parse(rawText); } catch (e) { result = null; }
                }
            } catch (readErr) {
                console.error('Error reading response body:', readErr);
            }

            if (result && result.success) {
                status.className = 'status-msg success';
                status.innerText = 'Sent successfully! It will self-destruct from server. You can close this page.';
                
                try { history.replaceState(null, '', window.location.pathname + window.location.search); } 
                catch(e) { window.location.hash = ''; }

                setTimeout(function() {
                    startApp();
                }, 10000); // Return to home after 10s
        } else {
            var msg = (result && result.error) ? result.error : ('Server rejected the request' + (rawText ? (': ' + rawText.substring(0, 300)) : ''));
            throw new Error(msg);
        }
    } catch (e) {
        status.className = 'status-msg error';
        status.innerText = 'Error: ' + e.message;
        var retryBtn = document.createElement('button');
        retryBtn.innerText = 'Try Again';
        retryBtn.style.marginTop = '1rem';
        retryBtn.onclick = function() {
            var hashInfo = parseHash();
            if (hashInfo.session && hashInfo.key) {
                sendDataToBackend(container, dataVal, dataType, hashInfo.session, hashInfo.key);
            } else {
                renderGiverCamera(container, dataVal, dataType);
            }
        };
        status.parentNode.appendChild(retryBtn);
    }
    })();
}

// ==========================================
// RECEIVER MODE (e.g., Computer Screen)
// ==========================================
function renderReceiver(container) {
    container.innerHTML = '<h1>Receive Data</h1>\n'
        + '<p>Preparing a secure session...</p>\n'
        + '<p id="challengeStatus" class="status-msg"></p>\n';

    ensureRuntimeConfigLoaded()
        .then(function () {
            return showReceiverChallenge(container, function (challengeToken) {
                startReceiverSession(container, challengeToken || '');
            });
        })
        .catch(function (e) {
            showError(container, e && e.message ? e.message : 'Unable to initialize the secure session.');
        });
}

async function startReceiverSession(container, challengeToken) {
    var session = generateId(16);
    var defaultKey = generateId(32);
    var validKeys = [defaultKey];
    var currentScanUrl = '';

    container.innerHTML = '<h1>Receive Data</h1>\n'
        + '<p>Verifying your secure session...</p>\n'
        + '<p id="challengeStatus" class="status-msg"></p>\n';

    try {
        await verifyReceiverSession(session, challengeToken);
    } catch (e) {
        showError(container, e && e.message ? e.message : 'Unable to verify the secure session.');
        return;
    }

    container.innerHTML = '<h1>Receive Data</h1>\n'
        + '<p>Scan this QR code with your phone to securely send a password or text.</p>\n'
        + '<div class="qrcode-wrapper" id="qrcode"></div>\n'
        + '<p style="font-size: 0.8rem; color: #64748b; margin: 0.5rem 0 1rem 0;">QR Code auto-updates for security</p>\n'
        + '<button id="enlargeQrBtn" class="secondary-btn" type="button">Enlarge QR</button>\n'
        + '<p>Waiting for connection...</p>\n'
        + '<button id="backBtn" class="secondary-btn" style="margin-top:1rem;">Back</button>\n';

    // Reference holders for cleanup
    var qrcodeEl = document.getElementById('qrcode');
    var pollingInterval = null;
    var keyRotationInterval = null;
    var expireTimeout = null;

    function renderActiveQrCode() {
        var url = new URL(window.location.href);
        url.hash = 'session=' + session + '&key=' + validKeys[0];
        currentScanUrl = url.href;

        if (qrcodeEl) {
            qrcodeEl.innerHTML = '';
            new QRCode(qrcodeEl, {
                text: currentScanUrl,
                width: 220,
                height: 220,
                colorDark: '#0f172a',
                colorLight: '#ffffff',
                correctLevel: QRCode.CorrectLevel.H
            });
        }

        var fsQr = document.getElementById('qrFullscreenQrContainer');
        if (fsQr) {
            fsQr.innerHTML = '';
            var maxSide = Math.min(window.innerWidth, window.innerHeight);
            var size = Math.max(320, Math.floor(maxSide * 0.82));
            new QRCode(fsQr, {
                text: currentScanUrl,
                width: size,
                height: size,
                colorDark: '#0f172a',
                colorLight: '#ffffff',
                correctLevel: QRCode.CorrectLevel.H
            });
        }
    }

    renderActiveQrCode();

    keyRotationInterval = setInterval(function() {
        validKeys.unshift(generateId(32));
        if (validKeys.length > 3) {
            validKeys.pop(); // keep last ~30 seconds worth of keys
        }
        renderActiveQrCode();
    }, 10000);

    // Enlarge QR opens fullscreen overlay with same code for easier scanning
    var enlargeBtn = document.getElementById('enlargeQrBtn');
    if (enlargeBtn) {
        enlargeBtn.addEventListener('click', function () {
            showQrFullscreen(currentScanUrl);
        });
    }

    // Back button: clear timers and return to home
    var backBtn = document.getElementById('backBtn');
    if (backBtn) {
        backBtn.addEventListener('click', function () {
            try { if (pollingInterval) clearInterval(pollingInterval); } catch (e) { console.warn(e); }
            try { if (keyRotationInterval) clearInterval(keyRotationInterval); } catch (e) { console.warn(e); }
            try { if (expireTimeout) clearTimeout(expireTimeout); } catch (e) { console.warn(e); }
            try { if (qrcodeEl) qrcodeEl.innerHTML = ''; } catch (e) { console.warn(e); }
            startApp();
        });
    }

    // Start Polling for Encrypted Data from Phone
    pollingInterval = setInterval(async function () {
        try {
            var response = await fetch(apiUrl + '?action=check&session=' + session);
            var result = await response.json();

            if (!response.ok) {
                clearInterval(pollingInterval);
                try { if (keyRotationInterval) clearInterval(keyRotationInterval); } catch (e) {}
                var errMsg = (result && result.error) ? result.error : 'Session verification failed.';
                showError(container, errMsg);
                return;
            }

            if (result && result.status === 'found') {
                clearInterval(pollingInterval);
                // If the QR is shown in fullscreen, close it so decrypted data is visible
                try {
                    var overlay = document.getElementById('qrFullscreenOverlay');
                    if (overlay) overlay.remove();
                } catch (e) { /* ignore */ }
                try { if (keyRotationInterval) clearInterval(keyRotationInterval); } catch (e) {}
                var encryptedData = result.data;

                // Local Decryption - Try all valid keys
                var decryptedValue = null;
                for (var i = 0; i < validKeys.length; i++) {
                    try {
                        var attempt = await decryptData(encryptedData, validKeys[i]);
                        if (attempt) {
                            decryptedValue = attempt;
                            break;
                        }
                    } catch (err) {
                        // Ignore and try the next valid key
                    }
                }

                // Show Decrypted Result
                if (decryptedValue) {
                    var parsedData;
                    try {
                        parsedData = JSON.parse(decryptedValue);
                        if (parsedData && parsedData.type && parsedData.content) {
                            showDecryptedData(container, parsedData.content, parsedData.type);
                        } else {
                            showDecryptedData(container, decryptedValue, 'password');
                        }
                    } catch (e) {
                         showDecryptedData(container, decryptedValue, 'password');
                    }
                } else {
                    showError(container, 'Could not decrypt data. Malformed code or expired session?');
                }
            }
        } catch (e) {
            console.error('Polling error:', e);
        }
    }, 2000); // Poll every 2 seconds

    // Session expires after 5 minutes if no one scans
    expireTimeout = setTimeout(function () {
        try { clearInterval(pollingInterval); } catch (e) { console.warn(e); }
        try { clearInterval(keyRotationInterval); } catch (e) { console.warn(e); }
        if (document.getElementById('qrcode')) {
            showError(container, 'Session timed out after 5 minutes.');
        }
    }, 5 * 60 * 1000);
}

/**
 * Shows the same session QR code in a fullscreen overlay for easier scanning on small screens.
 * @param {string} scanUrl - The URL encoded in the QR (session + key in hash)
 */
function showQrFullscreen(scanUrl) {
    var existing = document.getElementById('qrFullscreenOverlay');
    if (existing) {
        existing.remove();
    }

    var overlay = document.createElement('div');
    overlay.id = 'qrFullscreenOverlay';
    overlay.className = 'qr-fullscreen-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-label', 'QR code full screen');

    var inner = document.createElement('div');
    inner.className = 'qr-fullscreen-inner';

    var qrContainer = document.createElement('div');
    qrContainer.className = 'qr-fullscreen-qr';
    qrContainer.id = 'qrFullscreenQrContainer';

    var closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'qr-fullscreen-close';
    closeBtn.textContent = 'Close';
    closeBtn.setAttribute('aria-label', 'Close full screen QR');

    inner.appendChild(qrContainer);
    inner.appendChild(closeBtn);
    overlay.appendChild(inner);

    function closeOverlay() {
        try {
            var c = document.getElementById('qrFullscreenQrContainer');
            if (c) c.innerHTML = '';
        } catch (e) { /* ignore */ }
        overlay.remove();
        overlay = null;
    }

    overlay.addEventListener('click', function (ev) {
        if (ev.target === overlay) closeOverlay();
    });
    closeBtn.addEventListener('click', closeOverlay);

    document.body.appendChild(overlay);

    // Size QR to almost fill the viewport (leave room for Close button and padding)
    var maxSide = Math.min(window.innerWidth, window.innerHeight);
    var size = Math.max(320, Math.floor(maxSide * 0.82));

    try {
        new QRCode(qrContainer, {
            text: scanUrl,
            width: size,
            height: size,
            colorDark: '#0f172a',
            colorLight: '#ffffff',
            correctLevel: QRCode.CorrectLevel.H
        });
    } catch (e) {
        console.error('Fullscreen QR failed:', e);
        closeOverlay();
    }
}

function showDecryptedData(container, dataText, dataType) {
    if (dataType === 'password') {
        var hiddenStars = '*'.repeat(Math.max(8, dataText.length));

        container.innerHTML = '<h1>Decrypted Securely</h1>\n'
            + '<p>Password received successfully. Click to copy.</p>\n'
            + '<div class="password-display">\n'
            + '    <span id="pwdStars" class="password-text">' + hiddenStars + '</span>\n'
            + '</div>\n'
            + '<button id="copyBtn" style="margin-bottom: 1rem;">Copy Password</button>\n'
            + '<button id="startOverBtn" class="secondary-btn">Start Over</button>\n'
            + '<p id="copyStatus" class="status-msg"></p>\n'
            + '<p style="margin-top: 1.5rem; font-size: 0.8rem; color: #94a3b8;">'
            + 'This screen will automatically reset in <span id="countdown">30</span> seconds.\n'
            + '</p>';
    } else {
        container.innerHTML = '<h1>Decrypted Securely</h1>\n'
            + '<p>Text received successfully. Click to copy.</p>\n'
            + '<textarea readonly id="receivedText" style="height: 150px;">' + escapeHtml(dataText) + '</textarea>\n'
            + '<button id="copyBtn" style="margin-bottom: 1rem;">Copy Text</button>\n'
            + '<button id="startOverBtn" class="secondary-btn">Start Over</button>\n'
            + '<p id="copyStatus" class="status-msg"></p>\n'
            + '<p style="margin-top: 1.5rem; font-size: 0.8rem; color: #94a3b8;">'
            + 'This screen will automatically reset in <span id="countdown">30</span> seconds.\n'
            + '</p>';
    }

    document.getElementById('copyBtn').addEventListener('click', async function () {
        try {
            await navigator.clipboard.writeText(dataText);
            var status = document.getElementById('copyStatus');
            status.className = 'status-msg success';
            status.innerText = 'Copied to clipboard!';

            setTimeout(function () { 
                if (status) status.innerText = ''; 
            }, 3000);
        } catch (err) {
            var status = document.getElementById('copyStatus');
            if (status) {
                status.className = 'status-msg error';
                status.innerText = 'Failed to copy contents natively.';
            }
        }
    });

    document.getElementById('startOverBtn').addEventListener('click', function () {
        window.location.reload();
    });

    // Security: Auto-clear from memory within 30 seconds
    var timeLeft = 30;
    var countdownEl = document.getElementById('countdown');

    var interval = setInterval(function () {
        timeLeft--;
        if (countdownEl) countdownEl.innerText = timeLeft;
        if (timeLeft <= 0) {
            clearInterval(interval);
            showError(container, 'Session expired and cleared for security.');
        }
    }, 1000);
}

function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return '';
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

function showError(container, msg) {
    container.innerHTML = '<h1>Session Ended</h1>\n'
        + '<p id="errorMessage"></p>\n'
        + '<button id="generateNewSessionBtn" class="secondary-btn">Generate New Session</button>';

    var errorMessageEl = document.getElementById('errorMessage');
    if (errorMessageEl) {
        errorMessageEl.textContent = (typeof msg === 'string' && msg.length) ? msg : 'An unexpected error occurred.';
    }

    var generateBtn = document.getElementById('generateNewSessionBtn');
    if (generateBtn) {
        generateBtn.addEventListener('click', function () {
            window.location.reload();
        });
    }
}

/**
 * Opens a popup that fetches and displays the project license; closes on button or backdrop click.
 */
function showLicensePopup() {
    var existing = document.getElementById('licensePopupOverlay');
    if (existing) {
        existing.remove();
    }

    var overlay = document.createElement('div');
    overlay.id = 'licensePopupOverlay';
    overlay.className = 'license-popup-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-label', 'License');

    var inner = document.createElement('div');
    inner.className = 'license-popup-inner';

    var title = document.createElement('h2');
    title.className = 'license-popup-title';
    title.textContent = 'License';

    var content = document.createElement('div');
    content.className = 'license-popup-content';
    content.textContent = 'Loading…';

    var closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'license-popup-close';
    closeBtn.textContent = 'Close';
    closeBtn.setAttribute('aria-label', 'Close license');

    inner.appendChild(title);
    inner.appendChild(content);
    inner.appendChild(closeBtn);
    overlay.appendChild(inner);

    function closePopup() {
        overlay.remove();
    }

    overlay.addEventListener('click', function (ev) {
        if (ev.target === overlay) closePopup();
    });
    closeBtn.addEventListener('click', closePopup);

    document.body.appendChild(overlay);

    var licenseUrl = new URL('LICENSE', window.location.href).href;

    fetch(licenseUrl)
        .then(function (r) {
            if (!r.ok) throw new Error('Not found');
            return r.text();
        })
        .then(function (text) {
            content.textContent = '';
            var pre = document.createElement('pre');
            pre.className = 'license-popup-text';
            pre.textContent = text;
            content.appendChild(pre);
        })
        .catch(function () {
            content.textContent = 'License file could not be loaded. See the repository for the full text.';
        });
}

function initLicensePopup() {
    var link = document.getElementById('licenseLink');
    if (link) {
        link.addEventListener('click', function (ev) {
            ev.preventDefault();
            showLicensePopup();
        });
    }
}

// Start execution
window.addEventListener('DOMContentLoaded', function () {
    loadRuntimeConfig();
    startApp();
    initCookieBanner();
    initLicensePopup();
});

// Global error handler to catch uncaught errors (helps capture Safari-specific messages)
window.addEventListener('error', function (ev) {
    try {
        console.error('Uncaught error:', ev.message, ev.filename + ':' + ev.lineno + ':' + ev.colno);
    } catch (e) { /* ignore */ }
});

// Cookie banner logic
function initCookieBanner() {
    try {
        if (localStorage.getItem('pt_cookies_accepted') === '1') return;

        var placeholder = document.getElementById('cookieBannerPlaceholder') || document.body;

        var banner = document.createElement('div');
        banner.id = 'cookieBanner';

        banner.innerHTML = '<p>We use minimal local storage to remember preferences. No analytics by default. <a href="/" id="cookiePrivacyLink" style="color:var(--primary-color);">Privacy</a></p>'
            + '<div class="cookie-actions">'
            + '<button id="acceptCookies">Accept</button>'
            + '<button id="dismissCookies" class="secondary-btn">Dismiss</button>'
            + '</div>';

        // Append to placeholder (so it sits above footer)
        if (placeholder === document.body) {
            document.body.appendChild(banner);
        } else {
            placeholder.appendChild(banner);
        }

        document.getElementById('acceptCookies').addEventListener('click', function () {
            try { localStorage.setItem('pt_cookies_accepted', '1'); } catch (e) { console.warn(e); }
            banner.style.display = 'none';
        });

        document.getElementById('dismissCookies').addEventListener('click', function () {
            banner.style.display = 'none';
        });

        var pLink = document.getElementById('cookiePrivacyLink');
        if (pLink) {
            pLink.addEventListener('click', function (ev) {
                ev.preventDefault();
                alert('This app stores only ephemeral session data and your cookie consent. No tracking.');
            });
        }
    } catch (e) {
        console.warn('Cookie banner init failed', e);
    }
}
