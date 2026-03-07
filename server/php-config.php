<?php
function envString($name, $default = '') {
	$value = getenv($name);
	if ($value === false) return $default;
	$trimmed = trim((string)$value);
	return $trimmed === '' ? $default : $trimmed;
}

function envInt($name, $default, $min = 1) {
	$value = getenv($name);
	if ($value === false || trim((string)$value) === '') return $default;
	$parsed = filter_var($value, FILTER_VALIDATE_INT);
	if ($parsed === false) return $default;
	return max($min, (int)$parsed);
}

function envCsv($name, $default = []) {
	$value = getenv($name);
	if ($value === false) return $default;

	$parts = array_filter(array_map('trim', explode(',', (string)$value)), function ($item) {
		return $item !== '';
	});

	return !empty($parts) ? array_values($parts) : $default;
}

define('MAX_AGE_SECONDS', envInt('PASSWORD_TRANSFER_MAX_AGE_SECONDS', 30));
define('MAX_DATA_BYTES', envInt('PASSWORD_TRANSFER_MAX_DATA_BYTES', 10240));

define('STORE_RATE_LIMIT_COUNT', envInt('PASSWORD_TRANSFER_STORE_RATE_LIMIT_COUNT', 30));
define('STORE_RATE_LIMIT_WINDOW_SECONDS', envInt('PASSWORD_TRANSFER_STORE_RATE_LIMIT_WINDOW_SECONDS', 60));
define('CHECK_RATE_LIMIT_COUNT', envInt('PASSWORD_TRANSFER_CHECK_RATE_LIMIT_COUNT', 240));
define('CHECK_RATE_LIMIT_WINDOW_SECONDS', envInt('PASSWORD_TRANSFER_CHECK_RATE_LIMIT_WINDOW_SECONDS', 60));

define('CLEANUP_CHANCE_DENOMINATOR', envInt('PASSWORD_TRANSFER_CLEANUP_CHANCE_DENOMINATOR', 20));
define('CLEANUP_MAX_FILES_PER_RUN', envInt('PASSWORD_TRANSFER_CLEANUP_MAX_FILES_PER_RUN', 50));
define('SESSION_VERIFY_TTL_SECONDS', envInt('PASSWORD_TRANSFER_SESSION_VERIFY_TTL_SECONDS', MAX_AGE_SECONDS * 2));

define('PASSWORD_TRANSFER_DATA_DIR', envString('PASSWORD_TRANSFER_DATA_DIR', ''));

define('TURNSTILE_SITE_KEY', envString('CF_TURNSTILE_SITE_KEY', ''));
define('TURNSTILE_SECRET_KEY', envString('CF_TURNSTILE_SECRET_KEY', ''));

define('ALLOWED_ORIGINS', envCsv('PASSWORD_TRANSFER_ALLOWED_ORIGINS', [
	'https://your-domain.example',
	'http://localhost',
	'http://127.0.0.1'
]));
?>