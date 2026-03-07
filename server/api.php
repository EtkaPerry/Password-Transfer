<?php
require_once 'php-config.php';

// Security Headers
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, ALLOWED_ORIGINS, true)) {
    header("Access-Control-Allow-Origin: $origin");
}
header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

function ensureStorageDirectory($dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0700, true);
    }

    $htaccessFile = $dir . DIRECTORY_SEPARATOR . '.htaccess';
    if (!file_exists($htaccessFile)) {
        $denyRules = <<<'HTACCESS'
<IfModule mod_authz_core.c>
    Require all denied
</IfModule>
<IfModule !mod_authz_core.c>
    Deny from all
</IfModule>

Options -Indexes
HTACCESS;

        @file_put_contents($htaccessFile, $denyRules . PHP_EOL, LOCK_EX);
    }
}

$action = $_GET['action'] ?? '';

// Prefer non-web-accessible storage. Can be overridden with PASSWORD_TRANSFER_DATA_DIR.
$configuredDataDir = PASSWORD_TRANSFER_DATA_DIR;
$dataDir = $configuredDataDir
    ? rtrim($configuredDataDir, DIRECTORY_SEPARATOR)
    : rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'password-transfer-data';

ensureStorageDirectory($dataDir);

$rateLimitDir = $dataDir . DIRECTORY_SEPARATOR . 'rate-limit';
ensureStorageDirectory($rateLimitDir);

$verifiedDir = $dataDir . DIRECTORY_SEPARATOR . 'verified';
ensureStorageDirectory($verifiedDir);

// Cleanup script - randomly purges old sessions avoiding heavy disk IO for every request
// There's a 1-in-10 chance per request to run full cleanup of leftover un-fetched passwords
if (rand(1, CLEANUP_CHANCE_DENOMINATOR) === 1) {
    if ($files = glob($dataDir . '/*.json')) {
        $now = time();
        // Limit cleanup to 50 files at a time to prevent timeout during high load
        $files = array_slice($files, 0, CLEANUP_MAX_FILES_PER_RUN);
        foreach ($files as $file) {
            if ($now - filemtime($file) > MAX_AGE_SECONDS * 2) { // Give a little grace period
                @unlink($file);
            }
        }
    }
}
// (Moved into the 'store' action after reading input to avoid undefined variable)

    
// Ensure the provided session doesn't contain path traversal
function sanitizeSession($session) {
    return preg_replace('/[^a-f0-9]/', '', $session);
}

function getClientIp() {
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

function isTurnstileEnabled() {
    return defined('TURNSTILE_SECRET_KEY') && is_string(TURNSTILE_SECRET_KEY) && strlen(trim(TURNSTILE_SECRET_KEY)) > 0;
}

function verifyTurnstileToken($token, $remoteIp = '') {
    if (!isTurnstileEnabled()) {
        return ['success' => true, 'disabled' => true];
    }

    $token = trim((string)$token);
    if ($token === '') {
        return ['success' => false, 'error' => 'Missing Turnstile token'];
    }

    $postFields = [
        'secret' => TURNSTILE_SECRET_KEY,
        'response' => $token
    ];
    if (!empty($remoteIp) && $remoteIp !== 'unknown') {
        $postFields['remoteip'] = $remoteIp;
    }

    $ch = curl_init('https://challenges.cloudflare.com/turnstile/v0/siteverify');
    if ($ch === false) {
        return ['success' => false, 'error' => 'Unable to initialize verification request'];
    }

    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postFields));
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);

    $response = curl_exec($ch);
    if ($response === false) {
        $curlError = curl_error($ch);
        curl_close($ch);
        return ['success' => false, 'error' => 'Turnstile request failed: ' . $curlError];
    }

    $statusCode = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);

    if ($statusCode < 200 || $statusCode >= 300) {
        return ['success' => false, 'error' => 'Turnstile verification HTTP ' . $statusCode];
    }

    $parsed = json_decode($response, true);
    if (!is_array($parsed)) {
        return ['success' => false, 'error' => 'Invalid Turnstile response'];
    }

    if (!empty($parsed['success'])) {
        return ['success' => true, 'data' => $parsed];
    }

    $codes = '';
    if (isset($parsed['error-codes']) && is_array($parsed['error-codes'])) {
        $codes = implode(', ', $parsed['error-codes']);
    }

    return ['success' => false, 'error' => 'Turnstile verification failed' . ($codes ? (': ' . $codes) : '')];
}

function getVerifiedSessionFile($session, $verifiedDir) {
    return $verifiedDir . DIRECTORY_SEPARATOR . $session . '.json';
}

function markSessionVerified($session, $verifiedDir) {
    $file = getVerifiedSessionFile($session, $verifiedDir);
    $payload = [
        'verifiedAt' => time(),
        'expires' => time() + SESSION_VERIFY_TTL_SECONDS
    ];
    @file_put_contents($file, json_encode($payload), LOCK_EX);
}

function isSessionVerified($session, $verifiedDir) {
    if (!isTurnstileEnabled()) {
        return true;
    }

    $file = getVerifiedSessionFile($session, $verifiedDir);
    if (!file_exists($file)) {
        return false;
    }

    $raw = @file_get_contents($file);
    if ($raw === false) {
        return false;
    }

    $parsed = json_decode($raw, true);
    if (!is_array($parsed) || !isset($parsed['expires'])) {
        return false;
    }

    if ((int)$parsed['expires'] <= time()) {
        @unlink($file);
        return false;
    }

    return true;
}

function consumeSessionVerification($session, $verifiedDir) {
    $file = getVerifiedSessionFile($session, $verifiedDir);
    if (file_exists($file)) {
        @unlink($file);
    }
}

function isRateLimited($bucket, $limit, $windowSeconds, $rateLimitDir) {
    $safeBucket = preg_replace('/[^a-zA-Z0-9._-]/', '_', $bucket);
    $file = $rateLimitDir . DIRECTORY_SEPARATOR . $safeBucket . '.json';
    $now = time();

    $state = ['start' => $now, 'count' => 0];
    if (file_exists($file)) {
        $raw = @file_get_contents($file);
        if ($raw !== false) {
            $parsed = json_decode($raw, true);
            if (is_array($parsed) && isset($parsed['start']) && isset($parsed['count'])) {
                $state = [
                    'start' => (int)$parsed['start'],
                    'count' => (int)$parsed['count']
                ];
            }
        }
    }

    if (($now - $state['start']) >= $windowSeconds) {
        $state['start'] = $now;
        $state['count'] = 0;
    }

    $state['count']++;
    @file_put_contents($file, json_encode($state), LOCK_EX);

    return $state['count'] > $limit;
}

if ($action === 'verify') {
    $ip = getClientIp();
    if (isRateLimited('verify-' . $ip, CHECK_RATE_LIMIT_COUNT, CHECK_RATE_LIMIT_WINDOW_SECONDS, $rateLimitDir)) {
        echo json_encode(['error' => 'Too many requests. Please try again shortly.']);
        http_response_code(429);
        exit;
    }

    $session = sanitizeSession($_POST['session'] ?? '');
    $token = $_POST['cf_token'] ?? '';

    if (empty($session)) {
        echo json_encode(['error' => 'Missing session parameter']);
        http_response_code(400);
        exit;
    }

    if (strlen($session) !== 32) {
        echo json_encode(['error' => 'Invalid session parameter']);
        http_response_code(400);
        exit;
    }

    $verification = verifyTurnstileToken($token, $ip);
    if (!$verification['success']) {
        echo json_encode(['error' => $verification['error'] ?? 'Cloudflare challenge verification failed']);
        http_response_code(403);
        exit;
    }

    markSessionVerified($session, $verifiedDir);
    echo json_encode(['success' => true]);
    exit;
}

if ($action === 'store') {
    $ip = getClientIp();
    if (isRateLimited('store-' . $ip, STORE_RATE_LIMIT_COUNT, STORE_RATE_LIMIT_WINDOW_SECONDS, $rateLimitDir)) {
        echo json_encode(['error' => 'Too many requests. Please try again shortly.']);
        http_response_code(429);
        exit;
    }

    // We expect both session ID & the encrypted block of text
    $session = sanitizeSession($_POST['session'] ?? '');
    $data = $_POST['data'] ?? '';
    // VALIDATION: Enforce max length of 10KB to prevent abuse/attacks
    if (strlen((string)$data) > MAX_DATA_BYTES) {
        echo json_encode(['error' => 'Data too large (max ' . MAX_DATA_BYTES . ' bytes)']);
        http_response_code(413); // Payload Too Large
        exit;
    }
    
    if (empty($session) || empty($data)) {
        echo json_encode(['error' => 'Missing session or data parameters']);
        http_response_code(400);
        exit;
    }

    if (strlen($session) !== 32) {
        echo json_encode(['error' => 'Invalid session parameter']);
        http_response_code(400);
        exit;
    }

    if (!isSessionVerified($session, $verifiedDir)) {
        echo json_encode(['error' => 'Session not verified by Cloudflare challenge']);
        http_response_code(403);
        exit;
    }
    
    $file = $dataDir . '/' . $session . '.json';
    $payload = [
        'data' => $data,
        'expires' => time() + MAX_AGE_SECONDS
    ];
    
    if (file_put_contents($file, json_encode($payload))) {
        consumeSessionVerification($session, $verifiedDir);
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['error' => 'Could not save session. Check directory permissions.']);
        http_response_code(500);
    }
    exit;
}

if ($action === 'check') {
    $ip = getClientIp();
    if (isRateLimited('check-' . $ip, CHECK_RATE_LIMIT_COUNT, CHECK_RATE_LIMIT_WINDOW_SECONDS, $rateLimitDir)) {
        echo json_encode(['error' => 'Too many requests. Please try again shortly.']);
        http_response_code(429);
        exit;
    }

    // Used by the receiver to poll for returned data
    $session = sanitizeSession($_GET['session'] ?? '');
    
    if (empty($session)) {
        echo json_encode(['error' => 'Missing session parameter']);
        http_response_code(400);
        exit;
    }

    if (strlen($session) !== 32) {
        echo json_encode(['error' => 'Invalid session parameter']);
        http_response_code(400);
        exit;
    }

    $file = $dataDir . '/' . $session . '.json';
    
    if (file_exists($file)) {
        $content = json_decode(file_get_contents($file), true);
        
        // Immediately destroy data file on first read
        @unlink($file);
        
        // Check if data is still alive
        if ($content && isset($content['expires']) && $content['expires'] > time()) {
            consumeSessionVerification($session, $verifiedDir);
            echo json_encode(['status' => 'found', 'data' => $content['data']]);
            exit;
        } else {
            // Already expired
            echo json_encode(['status' => 'waiting']); // Treat it as empty
            exit;
        }
    }

    if (isTurnstileEnabled() && !isSessionVerified($session, $verifiedDir)) {
        $token = trim((string)($_GET['cf_token'] ?? ''));
        if ($token !== '') {
            $verification = verifyTurnstileToken($token, $ip);
            if (!$verification['success']) {
                echo json_encode(['error' => $verification['error'] ?? 'Cloudflare challenge verification failed']);
                http_response_code(403);
                exit;
            }
            markSessionVerified($session, $verifiedDir);
        } else {
            echo json_encode(['error' => 'Session not verified by Cloudflare challenge']);
            http_response_code(403);
            exit;
        }
    }
    
    // Default reply when waiting for the user to scan the QR
    echo json_encode(['status' => 'waiting']);
    exit;
}

if ($action === 'config') {
    echo json_encode([
        'turnstileSiteKey' => TURNSTILE_SITE_KEY,
        'turnstileEnabled' => isTurnstileEnabled()
    ]);
    exit;
}

echo json_encode(['error' => 'Invalid action requested']);
http_response_code(400);
?>