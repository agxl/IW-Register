<?php

/**
 * Developer: Andy Goldau
 * © 2026 WI-Register by PanelLayer, a brand of Subdomain LTD and managed on behalf of GoMaKe UG. All rights reserved.
 *
 * DISCLAIMER: This software is provided "as is" without any warranty of any kind.
 * WI-Register is an independent software solution and is not affiliated with,
 * endorsed by, or sponsored by Liquid Web / InterWorx or its affiliates.
 */

// Suppress PHP error output to prevent information disclosure
error_reporting(0);
ini_set('display_errors', '0');

$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
  || (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443)
  || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');

session_start([
  'cookie_httponly' => true,
  'cookie_samesite' => 'Lax',
  'cookie_secure' => $isHttps,
]);
require_once __DIR__ . '/config.php';

// ── Security Headers ───────────────────────────────────────────────────────
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
header(
  "Content-Security-Policy: default-src 'self'; "
  . "script-src 'self' 'unsafe-inline' https://js.hcaptcha.com https://www.google.com https://www.gstatic.com https://cdn.jsdelivr.net "
  . "https://challenges.cloudflare.com https://service.mtcaptcha.com https://service2.mtcaptcha.com; "
  . "frame-src 'self' https://hcaptcha.com https://*.hcaptcha.com https://www.google.com https://challenges.cloudflare.com https://service.mtcaptcha.com https://service2.mtcaptcha.com; "
  . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.bunny.net; "
  . "font-src 'self' https://fonts.gstatic.com https://fonts.bunny.net; "
  . "connect-src 'self' https://api.hcaptcha.com https://*.hcaptcha.com https://challenges.cloudflare.com https://www.google.com https://service.mtcaptcha.com https://service2.mtcaptcha.com https://api.pwnedpasswords.com; "
  . "img-src 'self' data: https://*.hcaptcha.com https://www.google.com https://www.gstatic.com https://service.mtcaptcha.com https://service2.mtcaptcha.com;"
);


// ── CSRF Token ─────────────────────────────────────────────────────────────
if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['csrf_token'];

// ── Rate Limiting (Token Bucket) ──────────────────────────────────────────
if (defined('TRUST_PROXY_HEADERS') && TRUST_PROXY_HEADERS) {
  $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
} else {
  $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}
$ip = explode(',', trim($ip))[0];

$rateLimitDir = __DIR__ . '/data/limits';
if (!is_dir($rateLimitDir))
  @mkdir($rateLimitDir, 0750, true);

$ipHash = hash('sha256', (defined('LOG_IP_SALT') ? LOG_IP_SALT : 'fallback') . $ip);
$limitFile = $rateLimitDir . '/limit_' . $ipHash . '.php';

$capacity = RATE_LIMIT_MAX;
$refillRate = $capacity / RATE_LIMIT_WINDOW;
$tokens = $capacity;
$lastUpdate = time();

$rateLimited = false;
$isPost = ($_SERVER['REQUEST_METHOD'] === 'POST');

$fp = @fopen($limitFile, 'c+');
if ($fp) {
  if (flock($fp, LOCK_EX)) {
    $raw = stream_get_contents($fp);
    if (strlen($raw) > 15) {
      $data = json_decode(substr($raw, 15), true);
      if (is_array($data)) {
        $tokens = $data['tokens'] ?? $capacity;
        $lastUpdate = $data['last_update'] ?? time();
      }
    }

    $now = time();
    $elapsed = $now - $lastUpdate;
    $tokens += $elapsed * $refillRate;
    if ($tokens > $capacity)
      $tokens = $capacity;

    if ($isPost) {
      if ($tokens >= 1) {
        $tokens -= 1;
        $rateLimited = false;
      } else {
        $rateLimited = true;
      }
    } else {
      $rateLimited = ($tokens < 1);
    }

    rewind($fp);
    ftruncate($fp, 0);
    fwrite($fp, "<?php exit; ?>\n" . json_encode([
      'tokens' => $tokens,
      'last_update' => $now
    ]));

    flock($fp, LOCK_UN);
  }
  fclose($fp);
}

// ── InterWorx XML-RPC Helpers ─────────────────────────────────────────────

/**
 * Derives the unix_user from the domain name.
 * InterWorx unix usernames must be max 8 chars, lowercase alphanumeric only.
 * e.g. example.com → example | my-great-site.org → mygreat
 */
function deriveUnixUser(string $domain): string
{
  // Strip leading "www."
  $domain = preg_replace('/^www\./i', '', strtolower(trim($domain)));
  // Take the part before the first dot (SLD)
  $sld = explode('.', $domain)[0];
  // Keep only a-z and 0-9
  $clean = preg_replace('/[^a-z0-9]/', '', $sld);
  // Ensure at least 4 chars (pad with 'user' prefix if too short)
  if (strlen($clean) < 4) {
    $clean = 'usr' . $clean;
  }
  // Truncate to max 8 chars
  return substr($clean, 0, 8);
}

/**
 * Appends a <member> node to a <struct> DOM element.
 * Used internally to construct nested XML-RPC struct types.
 */
function appendXmlRpcMember(\DOMElement $struct, string $name, \DOMNode $valueNode, \DOMDocument $doc): void
{
  $member = $doc->createElement('member');
  $nameEl = $doc->createElement('name');
  $nameEl->appendChild($doc->createTextNode($name));
  $member->appendChild($nameEl);
  $valueEl = $doc->createElement('value');
  $valueEl->appendChild($valueNode);
  $member->appendChild($valueEl);
  $struct->appendChild($member);
}

/**
 * Builds a <struct> DOM node from a flat associative array (string values only).
 */
function buildXmlRpcStruct(array $data, \DOMDocument $doc): \DOMElement
{
  $struct = $doc->createElement('struct');
  foreach ($data as $key => $value) {
    $strEl = $doc->createElement('string');
    $strEl->appendChild($doc->createTextNode((string) $value));
    appendXmlRpcMember($struct, (string) $key, $strEl, $doc);
  }
  return $struct;
}

/**
 * Builds a complete XML-RPC request body for iworx.route.
 *
 * IMPORTANT – InterWorx XML-RPC calling convention:
 *   iworx.route receives EXACTLY FOUR separate <param> nodes (positional arguments):
 *     1. auth      → <string> (API Key) OR <struct> (email + password)
 *     2. ctrl_name → <string> (e.g. '/nodeworx/siteworx')
 *     3. action    → <string> (e.g. 'add')
 *     4. input     → <struct> (action-specific input fields)
 *
 * Reference: https://www.interworx.com/support/api/
 */
function buildIwXmlRpcRequest($auth, string $ctrlName, string $action, array $input): string
{
  $doc = new \DOMDocument('1.0', 'UTF-8');
  $doc->formatOutput = false;

  $methodCall = $doc->createElement('methodCall');
  $doc->appendChild($methodCall);
  $methodCall->appendChild($doc->createElement('methodName', 'iworx.route'));

  $params = $doc->createElement('params');
  $methodCall->appendChild($params);

  // iworx.route requires FOUR separate <param> nodes (positional arguments):
  // 1. apikey struct, 2. ctrl_name string, 3. action string, 4. input struct
  // Reference: https://www.interworx.com/support/api/

  // Param 1: auth (string for API Key, struct for email/pass)
  $p1 = $doc->createElement('param');
  $v1 = $doc->createElement('value');
  if (is_array($auth)) {
    $v1->appendChild(buildXmlRpcStruct($auth, $doc));
  } else {
    $s1 = $doc->createElement('string');
    $s1->appendChild($doc->createTextNode((string)$auth));
    $v1->appendChild($s1);
  }
  $p1->appendChild($v1);
  $params->appendChild($p1);

  // Param 2: ctrl_name (string)
  $p2 = $doc->createElement('param');
  $v2 = $doc->createElement('value');
  $s2 = $doc->createElement('string');
  $s2->appendChild($doc->createTextNode($ctrlName));
  $v2->appendChild($s2);
  $p2->appendChild($v2);
  $params->appendChild($p2);

  // Param 3: action (string)
  $p3 = $doc->createElement('param');
  $v3 = $doc->createElement('value');
  $s3 = $doc->createElement('string');
  $s3->appendChild($doc->createTextNode($action));
  $v3->appendChild($s3);
  $p3->appendChild($v3);
  $params->appendChild($p3);

  // Param 4: input (struct)
  $p4 = $doc->createElement('param');
  $v4 = $doc->createElement('value');
  $v4->appendChild(buildXmlRpcStruct($input, $doc));
  $p4->appendChild($v4);
  $params->appendChild($p4);

  return $doc->saveXML();
}


/**
 * Parses an XML-RPC response and returns ['status' => int, 'payload' => string].
 * status == 0 means success in InterWorx.
 * On XML-RPC <fault>, returns status = -1 with the fault string.
 */
function parseIwXmlRpcResponse(string $xml): array
{
  if (empty(trim($xml))) {
    return ['status' => -1, 'payload' => 'Empty response from server.'];
  }

  $prev = libxml_use_internal_errors(true);
  $doc = simplexml_load_string($xml);
  libxml_clear_errors();
  libxml_use_internal_errors($prev);

  if ($doc === false) {
    return ['status' => -1, 'payload' => 'Invalid XML response from server.'];
  }

  // Check for XML-RPC fault
  if (isset($doc->fault)) {
    $faultStr = '';
    foreach ($doc->fault->value->struct->member as $member) {
      $name = (string) $member->name;
      if ($name === 'faultString') {
        $faultStr = (string) $member->value->string;
      }
    }
    return ['status' => -1, 'payload' => $faultStr ?: 'XML-RPC fault (unknown reason).'];
  }

  // Normal response: methodResponse > params > param > value > struct
  // InterWorx returns a struct with 'status' (int) and 'payload' (string or struct)
  if (!isset($doc->params->param->value->struct)) {
    // Try to grab raw text as fallback
    $raw = trim(strip_tags($xml));
    return ['status' => -1, 'payload' => $raw ?: 'Unexpected response structure.'];
  }

  $status = -1;
  $payload = '';

  foreach ($doc->params->param->value->struct->member as $member) {
    $name = (string) $member->name;
    if ($name === 'status') {
      // Status can be in <int>, <i4>, or plain <value>
      $statusVal = $member->value->int ?? $member->value->i4 ?? $member->value ?? null;
      $status = (int) (string) $statusVal;
    } elseif ($name === 'payload') {
      // Payload may be a string or another struct with 'siteworxaccount' etc.
      if (isset($member->value->string)) {
        $payload = (string) $member->value->string;
      } elseif (isset($member->value->struct)) {
        // Try to extract a human-readable message from nested struct
        foreach ($member->value->struct->member as $sub) {
          if (in_array((string) $sub->name, ['message', 'error', 'text', 'details'])) {
            $payload = (string) ($sub->value->string ?? $sub->value ?? '');
            break;
          }
        }
        if (empty($payload)) {
          $payload = 'Account processed.';
        }
      } else {
        $payload = trim(strip_tags($member->value->asXML()));
      }
    }
  }

  return ['status' => $status, 'payload' => $payload];
}

/**
 * Builds the auth struct for the XML-RPC request based on config.
 *
 * InterWorx NodeWorx API authentication always uses email + password.
 * When an API Key is configured, it is passed as the `password` value –
 * the API key functions as a password replacement for NodeWorx admin access.
 *
 * Auth struct format: { email: '...', password: '<password-or-apikey>' }
 *
 * Auth format:
 *   - API Key: raw string ('-----BEGIN INTERWORX API KEY-----...')
 *   - Password: struct { email: '...', password: '...' }
 *
 * Reference: https://www.interworx.com/support/api/
 */
function buildIwAuth()
{
  $apiKey = defined('IW_API_KEY') ? trim(IW_API_KEY) : '';
  if (!empty($apiKey)) {
    // NodeWorx API Key must be passed as a direct string.
    return $apiKey;
  }
  return [
    'email' => IW_ADMIN_EMAIL,
    'password' => IW_ADMIN_PASS,
  ];
}

/**
 * Creates a SiteWorx account via the InterWorx NodeWorx XML-RPC API.
 * Controller: /nodeworx/siteworx | Action: add
 *
 * Required input fields:
 *   master_domain, unix_user, email, password, confirm_password,
 *   package, ip, database_server
 */
function iwCreateUser(array $data): array
{
  // Sanitize host: remove trailing slash to avoid malformed URLs like https://host/:2443/xmlrpc
  $host = rtrim(IW_HOST, '/');
  $url = $host . ':' . IW_PORT . '/xmlrpc';

  $auth = buildIwAuth();
  $input = [
    // 'domain' is the primary field name used by InterWorx API for the master domain.
    // Some older InterWorx versions also accept 'master_domain' – both are listed here
    // for maximum compatibility. The API ignores unknown keys.
    'domain' => $data['domain'],
    'master_domain' => $data['domain'],
    'unix_user' => $data['unix_user'],
    'email' => $data['email'],
    'password' => $data['passwd'],
    'confirm_password' => $data['passwd'],
    'package' => IW_DEFAULT_PACKAGE,
    'ip' => IW_IP,
    'database_server' => IW_DATABASE_SERVER,
  ];

  $requestXml = buildIwXmlRpcRequest($auth, '/nodeworx/siteworx', 'add', $input);

  $ch = curl_init($url);
  $timeout = defined('IW_TIMEOUT') ? IW_TIMEOUT : 90;
  // Use mb_strlen with 8bit encoding to get byte count (safe even with mbstring.func_overload)
  $contentLength = mb_strlen($requestXml, '8bit');
  curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => $requestXml,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_SSL_VERIFYPEER => IW_SSL_VERIFY,
    CURLOPT_SSL_VERIFYHOST => IW_SSL_VERIFY ? 2 : 0,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_TIMEOUT => $timeout,
    CURLOPT_HTTPHEADER => ['Content-Type: text/xml', 'Content-Length: ' . $contentLength],
  ]);

  $response = curl_exec($ch);
  $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  $errno = curl_errno($ch);
  $errorMsg = curl_error($ch);
  curl_close($ch);

  if ($errno) {
    return ['success' => false, 'message' => 'Connection to InterWorx server failed: ' . htmlspecialchars($errorMsg)];
  }

  if ($httpCode === 401) {
    return ['success' => false, 'message' => 'Authentication failed (401). Please check your IW_API_KEY or IW_ADMIN_EMAIL / IW_ADMIN_PASS in config.php.'];
  }

  if ($httpCode === 403) {
    return ['success' => false, 'message' => 'Access forbidden (403). Your credentials lack the required NodeWorx permissions.'];
  }

  if ($httpCode !== 200 && empty($response)) {
    return ['success' => false, 'message' => 'Unexpected HTTP response from server (HTTP ' . $httpCode . ').'];
  }

  $parsed = parseIwXmlRpcResponse((string) $response);

  if ($parsed['status'] === 0) {
    return ['success' => true, 'message' => 'Account successfully created!'];
  }

  // Provide specific user-facing messages for known InterWorx status codes
  $statusCode = $parsed['status'];
  $apiPayload = !empty($parsed['payload']) ? htmlspecialchars($parsed['payload']) : '';

  $knownErrors = [
    99 => 'Invalid input fields. Please check your domain and username.',
    100 => 'Access denied. The API credentials lack the required NodeWorx permissions.',
    401 => 'Authentication failed. Please check IW_ADMIN_EMAIL and IW_ADMIN_PASS (or IW_API_KEY) in config.php.',
    902 => 'This domain already exists on the server. Please use a different domain.',
    914 => 'The configured hosting package does not exist. Please check IW_DEFAULT_PACKAGE in config.php.',
  ];

  if (isset($knownErrors[$statusCode])) {
    $errMsg = $knownErrors[$statusCode];
    // Append raw API payload for additional context if available
    if ($apiPayload && $apiPayload !== $errMsg) {
      $errMsg .= ' (API: ' . $apiPayload . ')';
    }
  } else {
    $errMsg = $apiPayload ?: ('An error occurred (status ' . $statusCode . ').');
  }

  return ['success' => false, 'message' => $errMsg];
}

// ── Audit Log ──────────────────────────────────────────────────────────────
/**
 * Writes a GDPR-compliant, JSON-Lines audit entry to the log file.
 * IPs are pseudonymized via a salted SHA-256 hash (not reversible without the salt).
 * Email addresses are masked to protect PII (e.g. j***@gmail.com).
 * The log file is rotated when it exceeds AUDIT_LOG_MAX_SIZE bytes.
 */
function auditLog(string $username, string $email, string $domain, string $result, string $reason): void
{
  if (!defined('AUDIT_LOG_ENABLED') || !AUDIT_LOG_ENABLED)
    return;

  $logPath = AUDIT_LOG_PATH;
  $logDir = dirname($logPath);
  if (!is_dir($logDir))
    @mkdir($logDir, 0750, true);

  // Rotate if over size limit
  if (file_exists($logPath) && filesize($logPath) > AUDIT_LOG_MAX_SIZE) {
    @rename($logPath, $logPath . '.' . date('Ymd-His'));
  }

  // Pseudonymize IP (GDPR: no plaintext personal data)
  $rawIp = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
  $anonIp = substr(hash('sha256', $rawIp . LOG_IP_SALT), 0, 16);

  // Mask email (keep first char + domain for debugging)
  $maskedEmail = '';
  if ($email && strpos($email, '@') !== false) {
    [$local, $dom] = explode('@', $email, 2);
    $maskedEmail = substr($local, 0, 1) . '***@' . $dom;
  }

  $entry = json_encode([
    't' => date('c'),
    'ip' => $anonIp,
    'user' => $username,
    'domain' => $domain,
    'email' => $maskedEmail,
    'result' => $result,
    'reason' => $reason ?: null,
  ], JSON_UNESCAPED_UNICODE);

  $fp = @fopen($logPath, 'a');
  if ($fp) {
    flock($fp, LOCK_EX);
    if (filesize($logPath) === 0) {
      fwrite($fp, "<?php exit; ?>\n");
    }
    fwrite($fp, $entry . "\n");
    flock($fp, LOCK_UN);
    fclose($fp);
  }
}

// ── DNS MX Check ───────────────────────────────────────────────────────────
/**
 * Checks if a domain has valid MX records.
 * Results are cached in the session for 60s to prevent DNS flooding on retries.
 * Fail-open: returns true if DNS resolution itself fails.
 */
function checkEmailMx(string $domain): bool
{
  if (!defined('ENABLE_MX_CHECK') || !ENABLE_MX_CHECK)
    return true;
  if (!$domain)
    return false;

  $cacheKey = 'mx_' . md5($domain);
  if (isset($_SESSION[$cacheKey]) && (time() - $_SESSION[$cacheKey]['ts']) < 60) {
    return $_SESSION[$cacheKey]['result'];
  }

  // checkdnsrr returns false on both "no MX" and "resolution failure"
  // Use dns_get_record for more control; fall back to true on error (fail-open)
  set_error_handler(function () {}, E_WARNING);
  $records = dns_get_record($domain, DNS_MX | DNS_A);
  restore_error_handler();

  // Fail-open: if dns_get_record returns false (DNS unavailable), allow registration
  if ($records === false) {
    $_SESSION[$cacheKey] = ['result' => true, 'ts' => time()];
    return true;
  }

  $hasMx = !empty($records);
  $_SESSION[$cacheKey] = ['result' => $hasMx, 'ts' => time()];
  return $hasMx;
}

// ── Invite Code Validation ─────────────────────────────────────────────────
/**
 * Validates an invite code and marks it as used if INVITE_SINGLE_USE is true.
 * Uses exclusive file locking to prevent race conditions.
 */
function validateInviteCode(string $code): bool
{
  if (!defined('INVITE_ONLY_MODE') || !INVITE_ONLY_MODE)
    return true;

  $code = strtoupper(preg_replace('/[^A-Z0-9\-]/', '', strtoupper(trim($code))));
  if (!$code)
    return false;

  // Check against configured valid codes (timing-safe loop)
  $isValid = false;
  foreach (INVITE_CODES as $validCode) {
    if (hash_equals(strtoupper(trim($validCode)), $code)) {
      $isValid = true;
      break;
    }
  }
  if (!$isValid)
    return false;

  if (!defined('INVITE_SINGLE_USE') || !INVITE_SINGLE_USE)
    return true;

  // Check and mark as used via flat file with exclusive lock
  $file = INVITE_CODES_FILE;
  $dir = dirname($file);
  if (!is_dir($dir))
    @mkdir($dir, 0750, true);
  if (!file_exists($file))
    file_put_contents($file, "<?php exit; ?>\n" . json_encode(['used' => []]));

  $fp = @fopen($file, 'r+');
  if (!$fp)
    return false; // Cannot acquire file handle → deny

  $result = false;
  if (flock($fp, LOCK_EX)) {
    $raw = stream_get_contents($fp);
    $jsonStr = substr($raw, 15) ?: '{}';
    $data = json_decode($jsonStr, true) ?? ['used' => []];
    if (!in_array($code, (array) ($data['used'] ?? []), true)) {
      $data['used'][] = $code;
      rewind($fp);
      ftruncate($fp, 0);
      fwrite($fp, "<?php exit; ?>\n" . json_encode($data, JSON_PRETTY_PRINT));
      $result = true;
    }
    flock($fp, LOCK_UN);
  }
  fclose($fp);
  return $result;
}



/**
 * Sends a POST request to a CAPTCHA verification API and returns decoded JSON.
 */
function captchaCurl(string $url, array $data): array
{
  $ch = curl_init($url);
  curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => http_build_query($data),
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_SSL_VERIFYPEER => IW_SSL_VERIFY,
    CURLOPT_SSL_VERIFYHOST => IW_SSL_VERIFY ? 2 : 0,
    CURLOPT_TIMEOUT => 10,
  ]);
  $res = curl_exec($ch);
  curl_close($ch);
  return json_decode((string) $res, true) ?? [];
}

/**
 * Verifies an ALTCHA proof-of-work payload without any external API call.
 * Steps: decode base64-JSON → check algorithm → verify PoW hash → verify HMAC signature → check expiry.
 */
function verifyAltchaPayload(string $payload): bool
{
  if (!$payload)
    return false;
  $data = json_decode(base64_decode($payload), true);
  if (!is_array($data))
    return false;

  $alg = $data['algorithm'] ?? '';
  $challenge = $data['challenge'] ?? '';
  $salt = $data['salt'] ?? '';
  $number = (string) ($data['number'] ?? '');
  $signature = $data['signature'] ?? '';

  // Only SHA-256 is supported
  if ($alg !== 'SHA-256')
    return false;

  // Check expiry embedded in salt params (e.g. "abc123?expires=1234567890")
  $query = parse_url($salt, PHP_URL_QUERY) ?? '';
  parse_str($query, $saltParams);
  if (isset($saltParams['expires']) && time() > (int) $saltParams['expires'])
    return false;

  // Verify Proof-of-Work: hash(salt + number) must equal challenge
  if (hash('sha256', $salt . $number) !== $challenge)
    return false;

  // Verify HMAC signature: prevents crafted challenges
  $expected = hash_hmac('sha256', $challenge, ALTCHA_HMAC_KEY);
  return hash_equals($expected, $signature);
}

/**
 * Dispatches to the configured CAPTCHA provider and returns true on success.
 */
function verifyCaptcha(): bool
{
  $provider = CAPTCHA_PROVIDER;
  if ($provider === 'none')
    return true;

  if ($provider === 'hcaptcha') {
    $token = $_POST['h-captcha-response'] ?? '';
    if (!$token)
      return false;
    $r = captchaCurl('https://api.hcaptcha.com/siteverify', [
      'secret' => HCAPTCHA_SECRET_KEY,
      'response' => $token,
      'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '',
    ]);
    return ($r['success'] ?? false) === true;
  }

  if ($provider === 'recaptcha') {
    $token = $_POST['g-recaptcha-response'] ?? '';
    if (!$token)
      return false;
    $r = captchaCurl('https://www.google.com/recaptcha/api/siteverify', [
      'secret' => RECAPTCHA_SECRET_KEY,
      'response' => $token,
      'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '',
    ]);
    return ($r['success'] ?? false) === true;
  }

  if ($provider === 'altcha') {
    return verifyAltchaPayload($_POST['altcha'] ?? '');
  }

  if ($provider === 'turnstile') {
    $token = $_POST['cf-turnstile-response'] ?? '';
    if (!$token)
      return false;
    $r = captchaCurl('https://challenges.cloudflare.com/turnstile/v0/siteverify', [
      'secret' => TURNSTILE_SECRET_KEY,
      'response' => $token,
      'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '',
    ]);
    return ($r['success'] ?? false) === true;
  }

  if ($provider === 'mtcaptcha') {
    $token = $_POST['mtcaptcha-verifiedtoken'] ?? '';
    if (!$token)
      return false;
    // MTCaptcha uses GET for verification
    $url = 'https://service.mtcaptcha.com/mtcv1/api/checktoken'
      . '?privatekey=' . urlencode(MTCAPTCHA_PRIVATE_KEY)
      . '&token=' . urlencode($token);
    $ch = curl_init($url);
    curl_setopt_array($ch, [
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_SSL_VERIFYPEER => IW_SSL_VERIFY,
      CURLOPT_SSL_VERIFYHOST => IW_SSL_VERIFY ? 2 : 0,
      CURLOPT_TIMEOUT => 10,
    ]);
    $res = curl_exec($ch);
    $errno = curl_errno($ch);
    curl_close($ch);
    if ($errno || !$res)
      return false;
    $parsed = json_decode($res, true);
    return ($parsed['success'] ?? false) === true;
  }

  return false;
}

// ── Process Form ───────────────────────────────────────────────────────────
$result = null;
if ($rateLimited && $_SERVER['REQUEST_METHOD'] !== 'POST') {
  $result = ['success' => false, 'message' => 'Too many registration attempts. Please wait a few minutes before trying again.'];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // Honeypot check
  if (!empty($_POST['website_hp'])) {
    // Silently drop bot registration but pretend it succeeded
    $result = ['success' => true, 'message' => 'Account successfully created!'];
  } elseif (!hash_equals($csrf, $_POST['csrf_token'] ?? '')) {
    $result = ['success' => false, 'message' => 'Invalid security token. Please refresh the page.'];
  } elseif ($rateLimited) {
    $result = ['success' => false, 'message' => 'Too many registrations. Please wait a few minutes.'];
  } elseif (CAPTCHA_PROVIDER !== 'none' && !verifyCaptcha()) {
    $result = ['success' => false, 'message' => 'CAPTCHA verification failed. Please try again.'];
  } else {
    $domain = trim($_POST['domain'] ?? '');
    $email = filter_var(trim($_POST['email'] ?? ''), FILTER_VALIDATE_EMAIL);
    $passwd = $_POST['passwd'] ?? '';
    $passwd2 = $_POST['passwd2'] ?? '';
    $emailDomain = $email ? substr(strrchr($email, "@"), 1) : '';

    // Derive unix_user automatically from domain (Option A from plan)
    $unix_user = deriveUnixUser($domain);

    // Reserved Names Check
    $isReservedDomain = false;
    if (!empty($domain)) {
      $lowerDomain = strtolower($domain);
      $blockSub = defined('BLOCK_RESERVED_SUBDOMAINS') && BLOCK_RESERVED_SUBDOMAINS;
      foreach (RESERVED_DOMAINS as $rd) {
        $lowerRd = strtolower($rd);
        if ($lowerDomain === $lowerRd) {
          $isReservedDomain = true;
          break;
        }
        if ($blockSub && str_ends_with($lowerDomain, '.' . $lowerRd)) {
          $isReservedDomain = true;
          break;
        }
      }
    }

    if (MAINTENANCE_MODE) {
      $result = ['success' => false, 'message' => 'Registrations are currently paused.'];
      auditLog($unix_user ?? '', $email ?: '', $domain ?? '', 'fail', 'maintenance_mode');
    } elseif ((!empty(TOS_URL) || !empty(PRIVACY_URL)) && empty($_POST['tos_agree'])) {
      $result = ['success' => false, 'message' => 'You must agree to the Terms of Service and Privacy Policy.'];
      auditLog($unix_user ?? '', $email ?: '', $domain ?? '', 'fail', 'tos_not_agreed');
    } elseif (INVITE_ONLY_MODE && !validateInviteCode($_POST['invite_code'] ?? '')) {
      $result = ['success' => false, 'message' => 'invite_invalid'];
      auditLog($unix_user ?? '', $email ?: '', $domain ?? '', 'fail', 'invite_invalid');
    } elseif (!$email) {
      $result = ['success' => false, 'message' => 'Please enter a valid email address.'];
      auditLog($unix_user ?? '', '', $domain ?? '', 'fail', 'email_invalid');
    } elseif ($emailDomain && in_array(strtolower($emailDomain), BLOCKED_EMAIL_DOMAINS)) {
      $result = ['success' => false, 'message' => 'This email provider is not allowed. Please use a valid email address.'];
      auditLog($unix_user ?? '', $email, $domain ?? '', 'fail', 'email_domain_blocked');
    } elseif ($emailDomain && !checkEmailMx($emailDomain)) {
      $result = ['success' => false, 'message' => 'email_mx_invalid'];
      auditLog($unix_user ?? '', $email, $domain ?? '', 'fail', 'email_mx_no_records');
    } elseif (empty($domain) || !filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) || strpos($domain, '.') === false) {
      $result = ['success' => false, 'message' => 'Please enter a valid domain (e.g. example.com).'];
      auditLog($unix_user ?? '', $email ?: '', $domain ?? '', 'fail', 'domain_invalid');
    } elseif ($isReservedDomain) {
      $result = ['success' => false, 'message' => 'This domain is reserved and cannot be registered.'];
      auditLog($unix_user ?? '', $email ?: '', $domain, 'fail', 'domain_reserved');
    } elseif (in_array(strtolower($unix_user), RESERVED_USERNAMES)) {
      $result = ['success' => false, 'message' => 'The derived system username for this domain is reserved. Please use a different domain.'];
      auditLog($unix_user, $email ?: '', $domain ?? '', 'fail', 'username_reserved');
    } elseif (strlen($passwd) < PASSWD_MIN_LENGTH) {
      $result = ['success' => false, 'message' => 'Password must be at least ' . PASSWD_MIN_LENGTH . ' characters long.'];
      auditLog($unix_user ?? '', $email ?: '', $domain ?? '', 'fail', 'password_too_short');
    } elseif (PASSWD_REQUIRE_COMPLEXITY && (!preg_match('/[A-Z]/', $passwd) || !preg_match('/[a-z]/', $passwd) || !preg_match('/[0-9]/', $passwd))) {
      $result = ['success' => false, 'message' => 'Password must contain at least one uppercase letter, one lowercase letter, and one number.'];
      auditLog($unix_user ?? '', $email ?: '', $domain ?? '', 'fail', 'password_complexity');
    } elseif ($passwd !== $passwd2) {
      $result = ['success' => false, 'message' => 'Passwords do not match.'];
      auditLog($unix_user ?? '', $email ?: '', $domain ?? '', 'fail', 'password_mismatch');
    } else {
      // Allow up to 120 seconds for slow InterWorx server responses
      @set_time_limit(120);

      // Release PHP session lock so session file is not locked during long InterWorx cURL request
      if (session_status() === PHP_SESSION_ACTIVE) {
        session_write_close();
      }

      $result = iwCreateUser([
        'domain' => $domain,
        'unix_user' => $unix_user,
        'email' => $email,
        'passwd' => $passwd,
      ]);

      auditLog($unix_user, $email ?: '', $domain, $result['success'] ? 'success' : 'fail', $result['success'] ? '' : 'iw_api_error');

      if ($result['success']) {
        if (WEBHOOK_ENABLED && !empty(WEBHOOK_URL)) {
          $payload = json_encode(['content' => "🔔 **New Registration**\nUser: `{$unix_user}`\nDomain: `{$domain}`\nEmail: `{$email}`"]);
          $ch = curl_init(WEBHOOK_URL);
          curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
          curl_setopt($ch, CURLOPT_POST, 1);
          curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
          curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
          curl_setopt($ch, CURLOPT_TIMEOUT, 3);
          curl_exec($ch);
          curl_close($ch);
        }

        if (!empty(ADMIN_EMAIL)) {
          $subject = "New Registration: $unix_user";
          $msg = "A new user has registered.\n\nUsername: $unix_user\nDomain: $domain\nEmail: $email\nDate: " . date('Y-m-d H:i:s') . "\nIP: " . ($_SERVER['REMOTE_ADDR'] ?? 'Unknown');
          $rawHost = $_SERVER['HTTP_HOST'] ?? 'localhost';
          $host = preg_replace('/[^a-zA-Z0-9\.\-]/', '', $rawHost) ?: 'localhost';
          $headers = "From: no-reply@" . $host . "\r\n" .
            "Reply-To: " . filter_var($email, FILTER_SANITIZE_EMAIL) . "\r\n" .
            "X-Mailer: PHP/" . phpversion();
          @mail(ADMIN_EMAIL, $subject, $msg, $headers);
        }

        // ── Demo Mode: Track account for scheduled deletion ─────────────────
        if (defined('DEMO_MODE') && DEMO_MODE) {
          $demoFile = defined('DEMO_ACCOUNTS_FILE') ? DEMO_ACCOUNTS_FILE : (__DIR__ . '/data/demo_accounts.json');
          $demoDir = dirname($demoFile);
          if (!is_dir($demoDir)) {
            @mkdir($demoDir, 0750, true);
          }
          $accounts = [];
          if (is_file($demoFile)) {
            $raw = file_get_contents($demoFile);
            $accounts = json_decode($raw, true) ?: [];
          }
          $accounts[$unix_user] = [
            'domain' => $domain,
            'email' => $email,
            'created_at' => time(),
            'delete_after' => time() + (defined('DEMO_LIFETIME_HOURS') ? (int) DEMO_LIFETIME_HOURS : 2) * 3600,
          ];
          file_put_contents($demoFile, json_encode($accounts, JSON_PRETTY_PRINT), LOCK_EX);
        }
      }
    }
  }

  // Re-open session if closed to safely update CSRF token on success
  if (session_status() !== PHP_SESSION_ACTIVE) {
    @session_start([
      'cookie_httponly' => true,
      'cookie_samesite' => 'Lax',
      'cookie_secure' => $isHttps,
    ]);
  }

  if ($result && $result['success']) {
    // Regenerate CSRF token only on successful account creation
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    $csrf = $_SESSION['csrf_token'];
  } else {
    // Keep existing CSRF token intact on form re-display / validation error
    $csrf = $_SESSION['csrf_token'] ?? $csrf;
  }
}

$now = date('j.n.Y, H:i');
?>
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title><?= SITE_TITLE ?></title>
  <meta name="description" content="InterWorx Account Registration" />
  <meta name="robots" content="noindex, nofollow, noarchive, nosnippet" />
  <meta name="googlebot" content="noindex, nofollow" />
  <link rel="icon" type="image/svg+xml"
    href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 42 42'%3E%3Crect width='42' height='42' rx='10' fill='%23159f85'/%3E%3Cpath d='M8 21L16 13L24 21L16 29L8 21Z' fill='%23ffffff'/%3E%3Cpath d='M18 21L26 13L34 21L26 29L18 21Z' fill='%23ffffff' opacity='.6'/%3E%3C/svg%3E" />
  <?php
  $fontProvider = defined('FONT_PROVIDER') ? FONT_PROVIDER : 'bunny';
  if ($fontProvider === 'bunny'): ?>
    <link rel="preconnect" href="https://fonts.bunny.net" />
    <link href="https://fonts.bunny.net/css?family=inter:300,400,500,600&amp;display=swap" rel="stylesheet" />
  <?php elseif ($fontProvider === 'google'): ?>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&amp;display=swap" rel="stylesheet" />
  <?php endif; ?>
  <?php if (CAPTCHA_PROVIDER === 'hcaptcha'): ?>
    <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
  <?php elseif (CAPTCHA_PROVIDER === 'recaptcha'): ?>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
  <?php elseif (CAPTCHA_PROVIDER === 'altcha'): ?>
    <script type="module" src="https://cdn.jsdelivr.net/npm/altcha/dist/altcha.min.js"></script>
  <?php elseif (CAPTCHA_PROVIDER === 'turnstile'): ?>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <?php elseif (CAPTCHA_PROVIDER === 'mtcaptcha'): ?>
    <script>
      var mtcaptchaConfig = { "sitekey": "<?= htmlspecialchars(MTCAPTCHA_SITE_KEY) ?>" };
      (function () {
        var mt_service = document.createElement('script');
        mt_service.async = true;
        mt_service.src = 'https://service.mtcaptcha.com/mtcv1/client/mtcaptcha.min.js';
        (document.getElementsByTagName('head')[0] || document.getElementsByTagName('body')[0]).appendChild(mt_service);
        var mt_service2 = document.createElement('script');
        mt_service2.async = true;
        mt_service2.src = 'https://service2.mtcaptcha.com/mtcv1/client/mtcaptcha2.min.js';
        (document.getElementsByTagName('head')[0] || document.getElementsByTagName('body')[0]).appendChild(mt_service2);
      })();
    </script>
  <?php endif; ?>
  <style>
    :root {
      --bg: linear-gradient(150deg, #3b2260 0%, #58398b 30%, #896ec9 50%, #58398b 70%, #341d57 100%);
      --poly: transparent;
      --card: #ffffff;
      --card-b: rgba(0, 0, 0, 0.1);
      --input-bg: #ffffff;
      --input-icon-bg: #f5f7f9;
      --input-b: #d1d5dc;
      --input-bh: #5d4a99;
      --text: #333333;
      --sub: #6b7280;
      --btn: #67549c;
      --btn-h: #54447d;
      --btn-text: #ffffff;
      --err-bg: rgba(220, 53, 69, 0.08);
      --err-b: rgba(220, 53, 69, 0.3);
      --err-text: #c0392b;
      --ok-bg: rgba(25, 185, 84, 0.08);
      --ok-b: rgba(25, 185, 84, 0.3);
      --ok-text: #1a8a44;
      --time: rgba(255, 255, 255, 0.6);
      --icon-btn: rgba(255, 255, 255, 0.15);
      --icon-bth: rgba(255, 255, 255, 0.3);
      --sb-track: rgba(0, 0, 0, 0.05);
      --sb-thumb: rgba(0, 0, 0, 0.2);
      --sb-thumb-h: rgba(0, 0, 0, 0.35);
      --accent: #159f85;
      --accent-glow: rgba(21, 159, 133, 0.3);
    }

    *,
    *::before,
    *::after {
      box-sizing: border-box;
      margin: 0;
      padding: 0
    }

    * {
      scrollbar-width: thin;
      scrollbar-color: var(--sb-thumb) var(--sb-track)
    }

    ::-webkit-scrollbar {
      width: 8px;
      height: 8px
    }

    ::-webkit-scrollbar-track {
      background: var(--sb-track);
      border-radius: 4px
    }

    ::-webkit-scrollbar-thumb {
      background: var(--sb-thumb);
      border-radius: 4px;
      transition: background .2s
    }

    ::-webkit-scrollbar-thumb:hover {
      background: var(--sb-thumb-h)
    }

    body {
      font-family: 'Inter', sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      transition: background .35s, color .35s;
      position: relative;
      overflow-x: hidden;
      overflow-y: auto;
    }

    /* Preloader */
    #preloader {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: var(--bg);
      z-index: 9999;
      display: grid;
      place-content: center;
      transition: opacity 0.5s ease, visibility 0.5s ease;
    }

    #preloader.hidden {
      opacity: 0;
      visibility: hidden;
    }

    #preloader-spinner {
      color: #0066cc;
      display: inline-block;
      position: relative;
      width: 80px;
      height: 80px;
    }

    #preloader-spinner div {
      box-sizing: border-box;
      display: block;
      position: absolute;
      width: 96px;
      height: 96px;
      margin: 8px;
      border: 8px solid currentColor;
      border-radius: 50%;
      animation: lds-ring 1.2s cubic-bezier(0.5, 0, 0.5, 1) infinite;
      border-color: currentColor transparent transparent transparent;
    }

    #preloader-spinner div:nth-child(1) {
      animation-delay: -0.45s;
    }

    #preloader-spinner div:nth-child(2) {
      animation-delay: -0.3s;
    }

    #preloader-spinner div:nth-child(3) {
      animation-delay: -0.15s;
    }

    @keyframes lds-ring {
      0% {
        transform: rotate(0deg);
      }

      100% {
        transform: rotate(360deg);
      }
    }

    .bg-poly {
      position: fixed;
      inset: 0;
      z-index: 0;
      overflow: hidden;
      pointer-events: none;
    }

    .bg-poly svg {
      width: 100%;
      height: 100%;
      opacity: .3
    }

    /* Top-Right Controls */
    .top-controls {
      position: fixed;
      top: 16px;
      right: 20px;
      display: flex;
      gap: 10px;
      align-items: center;
      z-index: 100;
    }

    .icon-btn {
      width: 36px;
      height: 36px;
      border-radius: 50%;
      background: var(--icon-btn);
      border: 1px solid var(--card-b);
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      transition: background .2s;
      color: var(--text);
    }

    .icon-btn:hover {
      background: var(--icon-bth)
    }

    .icon-btn svg {
      width: 18px;
      height: 18px
    }

    /* Language Dropdown */
    .lang-dropdown-wrap {
      position: relative
    }

    .lang-btn {
      display: flex;
      align-items: center;
      gap: 6px;
      background: var(--icon-btn);
      border: 1px solid var(--card-b);
      border-radius: 18px;
      padding: 6px 14px;
      color: var(--text);
      font-family: inherit;
      font-size: .82rem;
      font-weight: 500;
      cursor: pointer;
      transition: background .2s;
    }

    .lang-btn:hover {
      background: var(--icon-bth)
    }

    .lang-btn svg {
      width: 15px;
      height: 15px;
      opacity: .85
    }

    .lang-dropdown {
      position: absolute;
      top: calc(100% + 6px);
      right: 0;
      background: var(--card);
      border: 1px solid var(--card-b);
      border-radius: 12px;
      padding: 6px;
      width: 170px;
      max-height: 260px;
      overflow-y: auto;
      box-shadow: 0 12px 32px rgba(0, 0, 0, .35);
      display: none;
      z-index: 200;
    }

    .lang-dropdown.show {
      display: block
    }

    .lang-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      width: 100%;
      padding: 7px 10px;
      border: none;
      background: transparent;
      color: var(--text);
      font-family: inherit;
      font-size: .82rem;
      border-radius: 6px;
      cursor: pointer;
      text-align: left;
      transition: background .15s;
    }

    .lang-item:hover {
      background: var(--input-bg)
    }

    .lang-item.active {
      color: var(--btn);
      font-weight: 600
    }

    /* Card */
    .card {
      position: relative;
      z-index: 1;
      background: var(--card);
      border: 1px solid var(--card-b);
      border-radius: 20px;
      padding: 40px 44px 36px;
      width: 100%;
      max-width: 480px;
      box-shadow: 0 12px 40px rgba(0, 0, 0, .15);
      transition: background .35s, border-color .35s, box-shadow .35s;
    }

    /* Logo */
    .logo {
      display: flex;
      align-items: center;
      gap: 12px;
      justify-content: center;
      margin-bottom: 28px
    }

    .logo-icon {
      width: 42px;
      height: 42px
    }

    .logo-text h1 {
      font-size: 1.45rem;
      font-weight: 600;
      letter-spacing: -.02em;
      color: var(--text)
    }

    .logo-text p {
      font-size: .72rem;
      letter-spacing: .22em;
      color: var(--sub);
      text-transform: uppercase;
      margin-top: 1px
    }

    /* Alert */
    .alert {
      border-radius: 10px;
      padding: 12px 14px;
      font-size: .85rem;
      margin-bottom: 20px;
      border: 1px solid;
      line-height: 1.5;
    }

    .alert-error {
      background: var(--err-bg);
      border-color: var(--err-b);
      color: var(--err-text)
    }

    .alert-success {
      background: var(--ok-bg);
      border-color: var(--ok-b);
      color: var(--ok-text)
    }

    .alert a {
      color: inherit;
      font-weight: 600
    }

    /* Form */
    .field {
      margin-bottom: 18px
    }

    label {
      display: none;
      /* Hidden visually, input placeholders act as labels */
    }

    .iw-input-group {
      display: flex;
      align-items: stretch;
      background: var(--input-bg);
      border: 1px solid var(--input-b);
      border-radius: 20px;
      overflow: hidden;
      transition: border-color 0.2s, box-shadow 0.2s;
      position: relative;
    }

    .iw-input-group:focus-within {
      border-color: var(--input-bh);
      box-shadow: 0 0 0 2px rgba(93, 74, 153, 0.15);
    }

    .iw-input-group .input-icon {
      background: var(--input-icon-bg);
      padding: 0 16px;
      border-right: 1px solid var(--input-b);
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--sub);
    }

    .iw-input-group .input-icon svg {
      width: 16px;
      height: 16px;
    }

    .iw-input-group input[type=text],
    .iw-input-group input[type=email],
    .iw-input-group input[type=password] {
      flex: 1;
      width: 100%;
      background: transparent;
      border: none;
      color: var(--text);
      font-family: inherit;
      font-size: 0.9rem;
      padding: 12px 16px;
      outline: none;
    }

    .iw-input-group input::placeholder {
      color: var(--sub);
      opacity: 0.8;
    }

    .eye-btn {
      position: absolute;
      right: 12px;
      top: 50%;
      transform: translateY(-50%);
      background: none;
      border: none;
      cursor: pointer;
      color: var(--sub);
      display: flex;
      padding: 4px;
      transition: color .2s;
    }

    .eye-btn:hover {
      color: var(--btn)
    }

    .eye-btn svg.hide-icon {
      display: none
    }

    .pw-field {
      padding-right: 42px !important
    }

    .copy-pw-btn {
      background: none;
      border: 1px solid var(--input-b);
      border-radius: 6px;
      cursor: pointer;
      color: var(--sub);
      font-size: 0.78rem;
      padding: 4px 10px;
      display: flex;
      align-items: center;
      gap: 5px;
      transition: all .2s;
      white-space: nowrap;
    }

    .copy-pw-btn:hover {
      color: var(--text);
      border-color: var(--btn)
    }

    .copy-pw-btn.copied {
      color: #2ecc71;
      border-color: #2ecc71
    }

    /* Row */
    .field-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px
    }

    /* Submit */
    .btn {
      width: 100%;
      max-width: 160px;
      margin: 24px auto 0;
      padding: 11px;
      background: var(--btn);
      color: var(--btn-text);
      border: none;
      border-radius: 24px;
      font-family: inherit;
      font-size: .95rem;
      font-weight: 500;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      transition: background .2s, transform .1s, opacity .2s;
    }

    .btn:hover {
      background: var(--btn-h)
    }

    .btn:active {
      transform: scale(.98)
    }

    .btn:disabled {
      opacity: .6;
      cursor: not-allowed
    }

    .spinner {
      width: 18px;
      height: 18px;
      border: 2px solid rgba(255, 255, 255, .4);
      border-top-color: #fff;
      border-radius: 50%;
      animation: spin .7s linear infinite;
      display: none;
    }

    @keyframes spin {
      to {
        transform: rotate(360deg)
      }
    }

    /* Password Strength Meter */
    .pw-meter {
      margin-top: 10px;
    }

    .pw-meter-bar {
      height: 4px;
      background: var(--input-bg);
      border-radius: 2px;
      overflow: hidden;
      border: 1px solid var(--input-b);
    }

    .pw-meter-fill {
      height: 100%;
      width: 0%;
      transition: width 0.3s ease, background-color 0.3s ease;
    }

    .pw-meter-text {
      font-size: 0.75rem;
      margin-top: 4px;
      color: var(--sub);
      display: flex;
      justify-content: space-between;
    }

    /* Password Checklist */
    .pw-checklist {
      list-style: none;
      margin-top: 10px;
      padding: 0;
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 6px 10px;
    }

    .pw-check-item {
      display: flex;
      align-items: center;
      gap: 5px;
      font-size: 0.74rem;
      color: var(--sub);
      transition: color 0.2s;
    }

    .pw-check-item .check-icon {
      width: 15px;
      height: 15px;
      border-radius: 50%;
      border: 1.5px solid var(--sub);
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      transition: background 0.2s, border-color 0.2s;
      font-size: 0.65rem;
    }

    .pw-check-item.ok {
      color: var(--ok-text);
    }

    .pw-check-item.ok .check-icon {
      background: var(--ok-text);
      border-color: var(--ok-text);
      color: #fff;
    }

    /* HIBP Status */
    .hibp-status {
      font-size: 0.78rem;
      margin-top: 8px;
      padding: 6px 10px;
      border-radius: 6px;
      display: none;
    }

    .hibp-status.checking {
      display: block;
      color: var(--sub);
    }

    .hibp-status.warning {
      display: block;
      color: var(--err-text);
      background: var(--err-bg);
      border: 1px solid var(--err-b);
    }

    .hibp-status.ok {
      display: block;
      color: var(--ok-text);
      background: var(--ok-bg);
      border: 1px solid var(--ok-b);
    }

    /* Unix User Hint Badge */
    .unix-user-hint {
      display: none;
      margin-top: 6px;
      font-size: 0.78rem;
      color: var(--sub);
      background: var(--input-bg);
      border: 1px solid var(--input-b);
      border-radius: 6px;
      padding: 5px 10px;
    }

    .unix-user-hint strong {
      color: var(--accent);
      font-family: 'Courier New', monospace;
    }

    .help-fab-wrap {
      position: fixed;
      bottom: 20px;
      left: 20px;
      z-index: 100;
    }

    .help-fab {
      display: flex;
      align-items: center;
      gap: 8px;
      background: var(--icon-btn);
      border: 1px solid var(--card-b);
      border-radius: 20px;
      padding: 8px 16px;
      color: var(--text);
      font-family: inherit;
      font-size: 0.85rem;
      font-weight: 500;
      cursor: pointer;
      transition: background 0.2s;
    }

    .help-fab:hover {
      background: var(--icon-bth);
    }

    .help-fab svg {
      color: var(--btn);
    }

    .help-menu {
      position: absolute;
      bottom: calc(100% + 10px);
      left: 0;
      background: var(--card);
      border: 1px solid var(--card-b);
      border-radius: 12px;
      padding: 6px;
      width: 180px;
      box-shadow: 0 12px 32px rgba(0, 0, 0, .35);
      display: none;
      flex-direction: column;
      z-index: 200;
    }

    .help-menu.show {
      display: flex;
      animation: fadeIn 0.2s ease-out;
    }

    .help-menu a {
      padding: 8px 12px;
      color: var(--text);
      text-decoration: none;
      font-size: 0.85rem;
      border-radius: 6px;
      transition: background 0.15s;
    }

    .help-menu a:hover {
      background: var(--input-bg);
    }

    /* Bottom time */
    .bottom-time {
      position: fixed;
      bottom: 18px;
      font-size: .78rem;
      color: var(--time);
      z-index: 1;
      transition: color .35s;
    }

    .login-link {
      text-align: center;
      margin-top: 16px;
      font-size: .82rem;
      color: var(--sub)
    }

    .login-link a {
      color: var(--btn);
      text-decoration: none;
      font-weight: 500
    }

    .login-link a:hover {
      text-decoration: underline
    }

    /* ALTCHA Widget Theming */
    altcha-widget {
      --altcha-color-border: var(--input-b);
      --altcha-color-border-focus: var(--input-bh);
      --altcha-color-background: var(--input-bg);
      --altcha-color-text: var(--text);
      --altcha-color-text-secondary: var(--sub);
      --altcha-border-radius: 8px;
      width: 100%;
      margin-top: 18px;
      display: block;
    }

    /* ── Cookie Banner ──────────────────────────────────────────────────────── */
    #cookieBanner {
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      z-index: 9998;
      background: rgba(255, 255, 255, 0.98);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border-top: 1px solid rgba(0, 0, 0, 0.08);
      box-shadow: 0 -4px 24px rgba(0, 0, 0, 0.1);
      padding: 16px 24px;
      display: flex;
      align-items: center;
      gap: 16px;
      flex-wrap: wrap;
      justify-content: space-between;
      transform: translateY(100%);
      transition: transform 0.4s cubic-bezier(0.16, 1, 0.3, 1);
    }

    #cookieBanner.visible {
      transform: translateY(0);
    }

    #cookieBanner p {
      font-size: 0.88rem;
      color: #111111;
      line-height: 1.5;
      margin: 0;
      flex: 1;
      min-width: 200px;
      font-weight: 500;
    }

    #cookieAcceptBtn {
      background: var(--btn);
      color: #fff;
      border: none;
      border-radius: 20px;
      padding: 9px 24px;
      font-family: inherit;
      font-size: 0.85rem;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s, transform 0.1s;
      white-space: nowrap;
      flex-shrink: 0;
    }

    #cookieAcceptBtn:hover {
      background: var(--btn-h);
    }

    #cookieAcceptBtn:active {
      transform: scale(0.97);
    }

    /* ── Accessibility Widget ───────────────────────────────────────────────── */
    #a11yWidget {
      position: fixed;
      bottom: 20px;
      right: 20px;
      z-index: 500;
      display: flex;
      flex-direction: column;
      align-items: flex-end;
      gap: 8px;
    }

    #a11yToggleBtn {
      width: 40px;
      height: 40px;
      border-radius: 50%;
      background: var(--btn);
      border: none;
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      box-shadow: 0 4px 16px var(--accent-glow);
      transition: background 0.2s, transform 0.2s, box-shadow 0.2s;
    }

    #a11yToggleBtn:hover {
      background: var(--btn-h);
      transform: scale(1.08);
      box-shadow: 0 6px 20px var(--accent-glow);
    }

    #a11yToggleBtn svg {
      width: 20px;
      height: 20px;
    }

    #a11yPanel {
      background: var(--card);
      border: 1px solid var(--card-b);
      border-radius: 14px;
      padding: 14px 16px;
      width: 210px;
      box-shadow: 0 16px 40px rgba(0, 0, 0, 0.35);
      display: none;
      flex-direction: column;
      gap: 10px;
      animation: fadeIn 0.2s ease-out;
    }

    #a11yPanel.open {
      display: flex;
    }

    #a11yPanel h4 {
      font-size: 0.78rem;
      font-weight: 600;
      color: var(--sub);
      text-transform: uppercase;
      letter-spacing: 0.1em;
      margin: 0 0 4px;
      border-bottom: 1px solid var(--card-b);
      padding-bottom: 8px;
    }

    .a11y-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }

    .a11y-label {
      font-size: 0.82rem;
      color: var(--text);
    }

    .a11y-controls {
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .a11y-btn {
      width: 28px;
      height: 28px;
      border-radius: 6px;
      background: var(--input-bg);
      border: 1px solid var(--input-b);
      color: var(--text);
      font-size: 0.9rem;
      font-family: inherit;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: background 0.15s;
    }

    .a11y-btn:hover {
      background: var(--icon-bth);
    }

    .a11y-toggle-switch {
      position: relative;
      width: 36px;
      height: 20px;
      cursor: pointer;
    }

    .a11y-toggle-switch input {
      opacity: 0;
      width: 0;
      height: 0;
      position: absolute;
    }

    .a11y-slider {
      position: absolute;
      inset: 0;
      background: var(--input-bg);
      border: 1px solid var(--input-b);
      border-radius: 10px;
      transition: background 0.2s;
    }

    .a11y-slider::before {
      content: '';
      position: absolute;
      width: 14px;
      height: 14px;
      left: 2px;
      top: 2px;
      background: var(--sub);
      border-radius: 50%;
      transition: transform 0.2s, background 0.2s;
    }

    .a11y-toggle-switch input:checked+.a11y-slider {
      background: var(--btn);
      border-color: var(--btn);
    }

    .a11y-toggle-switch input:checked+.a11y-slider::before {
      transform: translateX(16px);
      background: #fff;
    }

    #a11yFontSize {
      font-size: 0.78rem;
      color: var(--sub);
      min-width: 22px;
      text-align: center;
    }

    @keyframes fadeIn {
      from {
        opacity: 0;
        transform: translateY(6px);
      }

      to {
        opacity: 1;
        transform: translateY(0);
      }
    }
  </style>
</head>

<body>

  <!-- Preloader -->
  <div id="preloader">
    <div id="preloader-spinner">
      <div></div>
      <div></div>
      <div></div>
    </div>
  </div>

  <!-- Polygon Background -->
  <div class="bg-poly" aria-hidden="true" style="display:none">
    <svg viewBox="0 0 1440 900" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice">
      <defs>
        <linearGradient id="g1" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#0a1530" />
          <stop offset="100%" stop-color="#050a18" />
        </linearGradient>
      </defs>
      <polygon points="0,0 480,0 240,300" fill="#0f1e3d" opacity=".6" />
      <polygon points="480,0 960,0 720,240" fill="#0d1a33" opacity=".5" />
      <polygon points="960,0 1440,0 1200,200" fill="#071020" opacity=".7" />
      <polygon points="0,300 240,300 0,600" fill="#0a1528" opacity=".5" />
      <polygon points="240,300 600,150 480,450" fill="#112040" opacity=".4" />
      <polygon points="600,150 960,0 720,240" fill="#0d1a33" opacity=".4" />
      <polygon points="1200,200 1440,0 1440,400" fill="#091220" opacity=".6" />
      <polygon points="0,600 0,900 300,900" fill="#0e1c35" opacity=".5" />
      <polygon points="300,900 600,700 900,900" fill="#081420" opacity=".4" />
      <polygon points="900,900 1440,700 1440,900" fill="#0c1828" opacity=".6" />
      <polygon points="600,700 900,500 1200,700" fill="#122240" opacity=".35" />
      <polygon points="0,600 300,900 600,700 480,450" fill="#091520" opacity=".3" />
      <polygon points="1200,200 1440,400 1200,700 900,500" fill="#071018" opacity=".4" />
    </svg>
  </div>

  <!-- Theme Toggle & Language Selector -->
  <div class="top-controls" role="toolbar" aria-label="Settings">

    <div class="lang-dropdown-wrap" id="langWrap">
      <button type="button" class="lang-btn" id="langBtn" aria-label="Select language" aria-expanded="false">
        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10" />
          <path
            d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
        </svg>
        <span id="currentLangLabel">English</span>
      </button>
      <div class="lang-dropdown" id="langDropdown" role="menu"></div>
    </div>
  </div>

  <!-- Card -->
  <div class="card">
    <!-- Logo -->
    <div class="logo" style="margin-bottom: 40px;">
      <!-- Original SVG Icon with color #159f85 -->
      <svg class="logo-icon" viewBox="0 0 42 42" fill="none" xmlns="http://www.w3.org/2000/svg"
        style="width:48px; height:48px;">
        <rect width="42" height="42" rx="10" fill="#159f85" opacity=".15" />
        <path d="M8 21L16 13L24 21L16 29L8 21Z" fill="#159f85" />
        <path d="M18 21L26 13L34 21L26 29L18 21Z" fill="#159f85" opacity=".6" />
      </svg>
      <div class="logo-text" style="text-align: left; margin-left: 4px;">
        <h1 style="font-size: 1.7rem; color: var(--text); margin: 0; padding: 0; font-weight: 600;"><?= htmlspecialchars(CARD_HEADING) ?></h1>
        <p
          style="font-size: 0.68rem; color: var(--sub); margin: 0; padding: 0; letter-spacing: 0.22em; text-transform: uppercase;">
          <?= htmlspecialchars(CARD_SUBHEADING) ?></p>
      </div>
    </div>

    <?php if (MAINTENANCE_MODE): ?>
      <div style="text-align:center; padding: 40px 10px 20px;">
        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="var(--sub)" stroke-width="2"
          stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:20px; display:inline-block;">
          <path
            d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z">
          </path>
        </svg>
        <h2 style="margin-bottom:12px; font-weight:600; font-size:1.5rem; color:var(--text);"
          data-i18n="maintenance_heading">Maintenance Mode</h2>
        <p style="color:var(--sub); margin-bottom:20px; font-size: 1rem; line-height:1.5;" data-i18n="maintenance_text">
          New registrations are currently paused for maintenance. Please check back later.
        </p>
      </div>
    <?php elseif ($result && $result['success']): ?>
      <div style="text-align:center; padding: 30px 10px 10px; animation: fadeIn 0.4s ease-out;">
        <svg width="72" height="72" viewBox="0 0 24 24" fill="none" stroke="var(--ok-text)" stroke-width="2"
          stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:20px; display:inline-block;">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
          <polyline points="22 4 12 14.01 9 11.01"></polyline>
        </svg>
        <h2 style="margin-bottom:12px; font-weight:600; font-size:1.6rem; color:var(--text);" data-i18n="success_heading">
          Account Created!</h2>
        <p style="color:var(--sub); margin-bottom:15px; font-size: 1rem; line-height:1.5;">
          <?= htmlspecialchars($result['message']) ?>
        </p>
        <div
          style="background: rgba(21, 159, 133, 0.1); border: 1px solid rgba(21, 159, 133, 0.3); border-radius: 16px; padding: 12px; margin-bottom: <?= (defined('DEMO_MODE') && DEMO_MODE) ? '15' : '25' ?>px;">
          <p style="color: var(--accent); font-size: 0.85rem; margin: 0; line-height: 1.4;" data-i18n="setup_2fa">
            We recommend enabling Two-Factor Authentication (2FA) in the panel.
          </p>
        </div>
        <?php if (defined('DEMO_MODE') && DEMO_MODE): ?>
          <p style="background:rgba(255,108,47,0.12); border:1px solid rgba(255,108,47,0.4); border-radius:16px; padding:12px 16px; margin-bottom:25px; font-size:0.9rem; line-height:1.5; color:var(--text);"
            data-i18n-demo-hours="<?= (int) (defined('DEMO_LIFETIME_HOURS') ? DEMO_LIFETIME_HOURS : 2) ?>"
            data-i18n="demo_notice">
            ⏱ This is a demo account and will be automatically deleted after
            <?= (int) (defined('DEMO_LIFETIME_HOURS') ? DEMO_LIFETIME_HOURS : 2) ?> hour(s).
          </p>
        <?php endif; ?>
        <a href="<?= htmlspecialchars(PANEL_URL) ?>" class="btn"
          style="text-decoration:none; display:inline-flex; width:auto; padding:0 32px;" data-i18n="to_login">To Login</a>
      </div>
    <?php else: ?>
      <?php if ($result && !$result['success']): ?>
        <div class="alert alert-error">
          <?= htmlspecialchars($result['message']) ?>
        </div>
      <?php endif; ?>

      <form method="POST" action="" id="regForm" novalidate autocomplete="off">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>" />
        <input type="text" name="website_hp" style="display:none" tabindex="-1" autocomplete="off">

        <div class="field">
          <div class="iw-input-group">
            <div class="input-icon">
              <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"
                stroke-width="2">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="2" y1="12" x2="22" y2="12"></line>
                <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z">
                </path>
              </svg>
            </div>
            <input type="text" id="domain" name="domain" data-i18n-ph="domain_ph" placeholder="Domain (e.g. example.com)"
              value="<?= htmlspecialchars($_POST['domain'] ?? '') ?>" autocomplete="off" required>
          </div>
          <!-- Unix user hint: shown dynamically as user types -->
          <div class="unix-user-hint" id="unixUserHint">
            <span data-i18n="unix_user_hint">System username</span>: <strong id="unixUserPreview"></strong>
          </div>
        </div>

        <div class="field">
          <div class="iw-input-group">
            <div class="input-icon">
              <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"
                stroke-width="2">
                <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path>
                <polyline points="22,6 12,13 2,6"></polyline>
              </svg>
            </div>
            <input type="email" id="email" name="email" data-i18n-ph="email_ph" placeholder="Email Address"
              value="<?= htmlspecialchars($_POST['email'] ?? '') ?>" autocomplete="email" required>
          </div>
          <div id="emailSuggestion" style="display:none; font-size: 0.85rem; margin-top: 6px; color: var(--sub);">
            <span data-i18n="did_you_mean">Did you mean</span> <a href="#" id="emailSuggestionLink"
              style="color: var(--btn); text-decoration: none; font-weight: 500;"></a>?
          </div>
        </div>

        <div class="field">
          <div style="display:flex; justify-content:flex-end; align-items:center; margin-bottom:6px; gap:12px;">
            <button type="button" id="copyPwBtn" title="Copy password"
              style="background:none; border:none; cursor:pointer; color:var(--sub); font-size:0.75rem; display:flex; align-items:center; gap:4px; padding:0; transition: color 0.2s;">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
              </svg>
              <span data-i18n="copy_pw">Copy</span>
            </button>
            <button type="button" id="generatePwBtn" title="Generate secure password"
              style="background:none; border:none; cursor:pointer; color:var(--sub); font-size:0.75rem; display:flex; align-items:center; gap:4px; padding:0; transition: color 0.2s;">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                stroke-linecap="round" stroke-linejoin="round">
                <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
              </svg>
              <span data-i18n="generate">Generate</span>
            </button>
          </div>
          <div class="iw-input-group">
            <div class="input-icon">
              <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"
                stroke-width="2">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
              </svg>
            </div>
            <input type="password" id="passwd" name="passwd" class="pw-field" data-i18n-ph="password_ph"
              placeholder="Password (Min. <?= PASSWD_MIN_LENGTH ?> chars)" autocomplete="new-password" required>
            <button type="button" class="eye-btn" data-target="passwd" aria-label="Show password">
              <svg class="show-icon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="none"
                viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                <circle cx="12" cy="12" r="3" />
              </svg>
              <svg class="hide-icon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="none"
                viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="display:none">
                <path
                  d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                <line x1="1" y1="1" x2="23" y2="23" />
              </svg>
            </button>
          </div>
        </div>

        <div class="field">
          <div class="iw-input-group">
            <div class="input-icon" style="opacity: 0.6;">
              <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"
                stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
              </svg>
            </div>
            <input type="password" id="passwd2" name="passwd2" class="pw-field" data-i18n-ph="confirm_ph"
              placeholder="Confirm Password" autocomplete="new-password" required>
            <button type="button" class="eye-btn" data-target="passwd2" aria-label="Show password">
              <svg class="show-icon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="none"
                viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                <circle cx="12" cy="12" r="3" />
              </svg>
              <svg class="hide-icon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="none"
                viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="display:none">
                <path
                  d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                <line x1="1" y1="1" x2="23" y2="23" />
              </svg>
            </button>
          </div>
        </div>

        <div class="pw-meter" id="pwMeter">
          <div class="pw-meter-bar">
            <div class="pw-meter-fill" id="pwMeterFill"></div>
          </div>
          <div class="pw-meter-text">
            <span id="pwHint" data-i18n="pw_hint">A-Z, a-z, 0-9</span>
            <div style="display:flex; align-items:center; gap:10px;">
              <span id="pwMeterText"></span>
              <button type="button" id="copyPwBtn" class="copy-pw-btn" style="display:none;" title="Copy password">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                  stroke-linecap="round" stroke-linejoin="round">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
                <span id="copyPwLabel" data-i18n="copy_pw">Copy</span>
              </button>
            </div>
          </div>
        </div>

        <?php if (defined('PASSWD_SHOW_CHECKLIST') && PASSWD_SHOW_CHECKLIST): ?>
          <ul class="pw-checklist" id="pwChecklist" data-min="<?= PASSWD_MIN_LENGTH ?>"
            data-complexity="<?= PASSWD_REQUIRE_COMPLEXITY ? '1' : '0' ?>">
            <li class="pw-check-item" id="chk-length">
              <span class="check-icon">✓</span>
              <span data-i18n-min="pw_req_length">At least <?= PASSWD_MIN_LENGTH ?> characters</span>
            </li>
            <?php if (PASSWD_REQUIRE_COMPLEXITY): ?>
              <li class="pw-check-item" id="chk-upper">
                <span class="check-icon">✓</span>
                <span data-i18n="pw_req_upper">One uppercase letter (A-Z)</span>
              </li>
              <li class="pw-check-item" id="chk-lower">
                <span class="check-icon">✓</span>
                <span data-i18n="pw_req_lower">One lowercase letter (a-z)</span>
              </li>
              <li class="pw-check-item" id="chk-number">
                <span class="check-icon">✓</span>
                <span data-i18n="pw_req_number">One number (0-9)</span>
              </li>
            <?php endif; ?>
          </ul>
        <?php endif; ?>

        <?php if (defined('ENABLE_HIBP_CHECK') && ENABLE_HIBP_CHECK): ?>
          <div class="hibp-status" id="hibpStatus"></div>
        <?php endif; ?>

        <?php if (defined('INVITE_ONLY_MODE') && INVITE_ONLY_MODE): ?>
          <div class="field">
            <label for="invite_code" data-i18n="invite_code">Invitation Code</label>
            <input type="text" id="invite_code" name="invite_code" data-i18n-ph="invite_code_ph"
              placeholder="Enter your invite code" maxlength="32" autocomplete="off" spellcheck="false"
              style="text-transform:uppercase; letter-spacing:0.05em;">
          </div>
        <?php endif; ?>

        <?php if (!empty(TOS_URL) || !empty(PRIVACY_URL)): ?>
          <div class="field" style="margin-top: 15px; display: flex; align-items: flex-start; gap: 8px;">
            <input type="checkbox" id="tos_agree" name="tos_agree" value="1" required
              style="margin-top: 3px; cursor: pointer; width: auto;">
            <label for="tos_agree"
              style="display: inline-block; font-size: 0.85rem; color: var(--text); line-height: 1.4; font-weight: normal; cursor: pointer;">
              <span data-i18n="tos_prefix">I agree to the</span>
              <?php if (!empty(TOS_URL)): ?>
                <a href="<?= htmlspecialchars(TOS_URL) ?>" target="_blank" data-i18n="tos_link"
                  style="color: var(--btn);">Terms of Service</a>
              <?php endif; ?>
              <?php if (!empty(TOS_URL) && !empty(PRIVACY_URL)): ?>
                <span data-i18n="tos_and">and</span>
              <?php endif; ?>
              <?php if (!empty(PRIVACY_URL)): ?>
                <a href="<?= htmlspecialchars(PRIVACY_URL) ?>" target="_blank" data-i18n="privacy_link"
                  style="color: var(--btn);">Privacy Policy</a>
              <?php endif; ?>
            </label>
          </div>
        <?php endif; ?>

        <div class="captcha-wrapper" style="margin-top: 18px; display: flex; justify-content: center; width: 100%;">
          <?php if (CAPTCHA_PROVIDER === 'hcaptcha'): ?>
            <div class="h-captcha" data-sitekey="<?= htmlspecialchars(HCAPTCHA_SITE_KEY) ?>"></div>
          <?php elseif (CAPTCHA_PROVIDER === 'recaptcha'): ?>
            <div class="g-recaptcha" data-sitekey="<?= htmlspecialchars(RECAPTCHA_SITE_KEY) ?>"></div>
          <?php elseif (CAPTCHA_PROVIDER === 'altcha'): ?>
            <altcha-widget challengeurl="altcha-challenge.php"></altcha-widget>
          <?php elseif (CAPTCHA_PROVIDER === 'turnstile'): ?>
            <div class="cf-turnstile" data-sitekey="<?= htmlspecialchars(TURNSTILE_SITE_KEY) ?>" <?= $rateLimited ? 'data-execution="execute"' : '' ?>></div>
          <?php elseif (CAPTCHA_PROVIDER === 'mtcaptcha'): ?>
            <div class="mtcaptcha"></div>
          <?php endif; ?>
        </div>

        <button type="submit" class="btn" id="submitBtn" <?= $rateLimited ? 'disabled' : '' ?>>
          <div class="spinner" id="spinner"></div>
          <span id="submitLabel" data-i18n="register">Register</span>
        </button>
      </form>

      <p class="login-link">
        <span data-i18n="already_registered">Already registered?</span> <a href="<?= htmlspecialchars(PANEL_URL) ?>"
          target="_blank" data-i18n="to_login">To Login</a>
      </p>
    <?php endif; ?>
  </div>



  <?php if (defined('COOKIE_BANNER_ENABLED') && COOKIE_BANNER_ENABLED): ?>
    <!-- Cookie Consent Banner -->
    <div id="cookieBanner" role="dialog" aria-label="Cookie consent" data-i18n-attr="aria-label:cookie_banner_label" aria-live="polite">
      <p id="cookieBannerText" data-i18n="cookie_banner_text"><?= htmlspecialchars(COOKIE_BANNER_TEXT) ?></p>
      <button id="cookieAcceptBtn" type="button" data-i18n="cookie_banner_btn"><?= htmlspecialchars(COOKIE_BANNER_BTN) ?></button>
    </div>
  <?php endif; ?>

  <?php if (defined('ACCESSIBILITY_WIDGET_ENABLED') && ACCESSIBILITY_WIDGET_ENABLED): ?>
    <!-- Accessibility Widget -->
    <div id="a11yWidget" role="complementary" aria-label="Accessibility tools" data-i18n-attr="aria-label:a11y_widget_label">
      <div id="a11yPanel" role="region" aria-label="Accessibility options" data-i18n-attr="aria-label:a11y_panel_label">
        <h4 data-i18n="a11y_title">Accessibility</h4>
        <div class="a11y-row">
          <span class="a11y-label" data-i18n="a11y_font_size">Font Size</span>
          <div class="a11y-controls">
            <button class="a11y-btn" id="a11yFontDec" aria-label="Decrease font size"
              title="Decrease font size" data-i18n-attr="aria-label:a11y_font_dec|title:a11y_font_dec">A−</button>
            <span id="a11yFontSize">100%</span>
            <button class="a11y-btn" id="a11yFontInc" aria-label="Increase font size"
              title="Increase font size" data-i18n-attr="aria-label:a11y_font_inc|title:a11y_font_inc">A+</button>
          </div>
        </div>
        <div class="a11y-row">
          <span class="a11y-label" data-i18n="a11y_high_contrast">High Contrast</span>
          <label class="a11y-toggle-switch" aria-label="Toggle high contrast" data-i18n-attr="aria-label:a11y_high_contrast">
            <input type="checkbox" id="a11yContrast">
            <span class="a11y-slider"></span>
          </label>
        </div>
        <div class="a11y-row">
          <span class="a11y-label" data-i18n="a11y_grayscale">Grayscale</span>
          <label class="a11y-toggle-switch" aria-label="Toggle grayscale" data-i18n-attr="aria-label:a11y_grayscale">
            <input type="checkbox" id="a11yGrayscale">
            <span class="a11y-slider"></span>
          </label>
        </div>
        <div class="a11y-row">
          <span class="a11y-label" data-i18n="a11y_reduce_motion">Reduce Motion</span>
          <label class="a11y-toggle-switch" aria-label="Toggle reduce motion" data-i18n-attr="aria-label:a11y_reduce_motion">
            <input type="checkbox" id="a11yMotion">
            <span class="a11y-slider"></span>
          </label>
        </div>
      </div>
      <button id="a11yToggleBtn" aria-label="Open accessibility tools" aria-expanded="false" aria-controls="a11yPanel" data-i18n-attr="aria-label:a11y_toggle_btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
          stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10" />
          <path d="M12 8v4l2 2" />
          <circle cx="12" cy="7" r="1" fill="currentColor" stroke="none" />
          <path d="M9 17l1.5-4.5M15 17l-1.5-4.5M9 12.5h6" />
        </svg>
      </button>
    </div>
  <?php endif; ?>

  <?php if (!empty(SUPPORT_EMAIL) || !empty(SUPPORT_URL)): ?>
    <div class="help-fab-wrap" id="helpFabWrap">
      <button class="help-fab" type="button" id="helpFabBtn">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
          stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"></circle>
          <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path>
          <line x1="12" y1="17" x2="12.01" y2="17"></line>
        </svg>
        <span data-i18n="need_help">Need help?</span>
      </button>
      <div class="help-menu" id="helpMenu">
        <a href="<?= !empty(SUPPORT_URL) ? htmlspecialchars(SUPPORT_URL) : 'mailto:' . htmlspecialchars(SUPPORT_EMAIL) ?>"
          target="_blank" data-i18n="contact_support">Contact Support</a>
        <a href="<?php
        $resetMail = !empty(SUPPORT_RESET_EMAIL) ? SUPPORT_RESET_EMAIL : SUPPORT_EMAIL;
        echo 'mailto:' . htmlspecialchars($resetMail)
          . '?subject=' . rawurlencode('Password Reset Request')
          . '&body=' . rawurlencode("Hello,\n\nI would like to request a password reset for my account.\n\nRegistered domain: \n\nThank you.");
        ?>" data-i18n="forgot_password">Forgot Password?</a>
      </div>
    </div>
  <?php endif; ?>

  <script>

    // ── Unix User Preview (derived from domain) ────────────────────────────────
    function deriveUnixUserJs(domain) {
      domain = domain.replace(/^www\./i, '').toLowerCase().trim();
      const sld = domain.split('.')[0] || '';
      let clean = sld.replace(/[^a-z0-9]/g, '');
      if (clean.length < 4) clean = 'usr' + clean;
      return clean.substring(0, 8);
    }

    const domainInput = document.getElementById('domain');
    const unixUserHint = document.getElementById('unixUserHint');
    const unixUserPreview = document.getElementById('unixUserPreview');

    if (domainInput && unixUserHint && unixUserPreview) {
      domainInput.addEventListener('input', function () {
        const val = this.value.trim();
        if (val.length > 0 && val.includes('.')) {
          const u = deriveUnixUserJs(val);
          unixUserPreview.textContent = u;
          unixUserHint.style.display = 'block';
        } else {
          unixUserHint.style.display = 'none';
        }
      });
    }

    // ── Password Strength Meter ───────────────────────────────────────────────
    const pwInput = document.getElementById('passwd');
    const pwMeterFill = document.getElementById('pwMeterFill');
    const pwMeterText = document.getElementById('pwMeterText');

    if (pwInput) {
      pwInput.addEventListener('input', function () {
        const val = this.value;
        if (!val) {
          pwMeterFill.style.width = '0%';
          pwMeterText.textContent = '';
          return;
        }
        let score = 0;
        if (val.length >= <?= PASSWD_MIN_LENGTH ?>) score++;
        if (/[A-Z]/.test(val)) score++;
        if (/[a-z]/.test(val)) score++;
        if (/[0-9]/.test(val)) score++;
        if (/[^A-Za-z0-9]/.test(val)) score++;

        const langCode = localStorage.getItem('iw_lang') || 'en';
        const curDict = I18N[langCode] || I18N['en'];
        let width = '25%', color = '#ff4d4d', label = curDict.pw_weak || 'Weak';
        if (score >= 4) {
          width = '100%'; color = '#2ecc71'; label = curDict.pw_strong || 'Strong';
        } else if (score >= 3) {
          width = '66%'; color = '#ffa64d'; label = curDict.pw_medium || 'Medium';
        } else if (score >= 2) {
          width = '33%'; color = '#ff4d4d'; label = curDict.pw_weak || 'Weak';
        }

        pwMeterFill.style.width = width;
        pwMeterFill.style.backgroundColor = color;
        pwMeterText.textContent = label;
        pwMeterText.style.color = color;
      });
    }

    // ── Multi-Language (i18n) Engine ───────────────────────────────────────────
    const I18N = {
      "en": {
        "name": "English",
        "subtitle": "web control panel",
        "email": "Email Address",
        "email_ph": "user@example.com",
        "domain": "Domain",
        "domain_ph": "example.com",
        "unix_user_hint": "System username (auto-derived)",
        "password": "Password",
        "password_ph": "Min. 8 chars",
        "confirm": "Confirm",
        "confirm_ph": "Repeat",
        "register": "Register",
        "already_registered": "Already registered?",
        "to_login": "To Login",
        "to_panel": "Go to Panel",
        "pw_hint": "A-Z, a-z, 0-9",
        "pw_weak": "Weak",
        "pw_medium": "Medium",
        "pw_strong": "Strong",
        "please_wait": "Please wait...",
        "success_heading": "Account Created!",
        "generate": "Generate",
        "maintenance_heading": "Maintenance Mode",
        "maintenance_text": "New registrations are temporarily paused for maintenance. Please check back later.",
        "tos_prefix": "I agree to the",
        "tos_link": "Terms of Service",
        "tos_and": "and",
        "privacy_link": "Privacy Policy",
        "did_you_mean": "Did you mean",
        "setup_2fa": "We recommend enabling Two-Factor Authentication (2FA) in the panel.",
        "copy_pw": "Copy",
        "need_help": "Need Help?",
        "contact_support": "Contact Support",
        "forgot_password": "Forgot Password?",
        "pw_req_length": "At least {n} characters",
        "pw_req_upper": "One uppercase letter (A-Z)",
        "pw_req_lower": "One lowercase letter (a-z)",
        "pw_req_number": "One number (0-9)",
        "email_mx_invalid": "The email domain does not appear to accept mail.",
        "pw_hibp_warning": "⚠️ This password appeared in {n} data breach(es).",
        "pw_hibp_ok": "✓ Password not found in known data breaches.",
        "pw_hibp_checking": "Checking password security...",
        "invite_code": "Invitation Code",
        "invite_code_ph": "Enter your invitation code",
        "invite_required": "An invitation code is required to register.",
        "invite_invalid": "Invalid or already used invitation code.",
        "demo_notice": "⏱ This is a demo account and will be automatically deleted after {n} hour(s).",
        "cookie_banner_text": "We use essential cookies for security (CSRF, session). By continuing, you agree to our cookie usage.",
        "cookie_banner_btn": "Accept & Continue",
        "cookie_banner_label": "Cookie consent",
        "a11y_widget_label": "Accessibility tools",
        "a11y_panel_label": "Accessibility options",
        "a11y_title": "Accessibility",
        "a11y_font_size": "Font Size",
        "a11y_font_dec": "Decrease font size",
        "a11y_font_inc": "Increase font size",
        "a11y_high_contrast": "High Contrast",
        "a11y_grayscale": "Grayscale",
        "a11y_reduce_motion": "Reduce Motion",
        "a11y_toggle_btn": "Open accessibility tools"
      },
      "uz": {
        "name": "Oʻzbekcha",
        "subtitle": "veb boshqaruv paneli",
        "email": "E-pochta manzili",
        "email_ph": "foydalanuvchi@namuna.uz",
        "domain": "Domen",
        "domain_ph": "namuna.uz",
        "unix_user_hint": "Tizim foydalanuvchisi (avtomatik)",
        "password": "Parol",
        "password_ph": "Kamida 8 belgi",
        "confirm": "Tasdiqlash",
        "confirm_ph": "Takrorlang",
        "register": "Roʻyxatdan oʻtish",
        "already_registered": "Roʻyxatdan oʻtganmisiz?",
        "to_login": "Kirish",
        "to_panel": "Panelga oʻtish",
        "pw_hint": "A-Z, a-z, 0-9",
        "pw_weak": "Zarif",
        "pw_medium": "Oʻrtacha",
        "pw_strong": "Kuchli",
        "please_wait": "Kuting...",
        "success_heading": "Hisob yaratildi!",
        "generate": "Yaratish",
        "maintenance_heading": "Profilaktika rejimi",
        "maintenance_text": "Yangi roʻyxatdan oʻtishlar profilaktika ishlari sababli vaqtincha toʻxtatilgan. Keyinroq qayta urinib koʻring.",
        "tos_prefix": "Men",
        "tos_link": "Xizmat koʻrsatish shartlari",
        "tos_and": "va",
        "privacy_link": "Maxfiylik siyosatiga roziman",
        "did_you_mean": "Buni nazarda tutdingizmi:",
        "setup_2fa": "Panelda Ikki faktorli autentifikatsiyani (2FA) yoqishingizni tavsiya qilamiz.",
        "copy_pw": "Nusxalash",
        "need_help": "Yordam kerakmi?",
        "contact_support": "Qo'llab-quvvatlash bilan bog'lanish",
        "forgot_password": "Parolni unutdingizmi?",
        "pw_req_length": "Kamida {n} ta belgi",
        "pw_req_upper": "Bitta bosh harf (A-Z)",
        "pw_req_lower": "Bitta kichik harf (a-z)",
        "pw_req_number": "Bitta raqam (0-9)",
        "email_mx_invalid": "Elektron pochta domeni xatlarni qabul qilmayotganga o‘xshaydi.",
        "pw_hibp_warning": "⚠️ Ushbu parol {n} ta ma'lumotlar sizib chiqishida paydo bo'lgan.",
        "pw_hibp_ok": "✓ Parol ma'lum bo'lgan ma'lumotlar sizib chiqishida topilmadi.",
        "pw_hibp_checking": "Parol xavfsizligi tekshirilmoqda...",
        "invite_code": "Taklif kodi",
        "invite_code_ph": "Taklif kodini kiriting",
        "invite_required": "Ro'yxatdan o'tish uchun taklif kodi kerak.",
        "invite_invalid": "Yaroqsiz yoki oldin ishlatilgan taklif kodi.",
        "demo_notice": "⏱ Bu demo hisob va {n} soatdan keyin avtomatik o'chiriladi.",
        "cookie_banner_text": "Xavfsizlik (CSRF, sessiya) uchun zaruriy kukilardan foydalanamiz. Davom etish orqali kukilardan foydalanishimizga rozilik bildirasiz.",
        "cookie_banner_btn": "Qabul qilish va davom etish",
        "cookie_banner_label": "Kuki roziligi",
        "a11y_widget_label": "Maxsus imkoniyatlar vositalari",
        "a11y_panel_label": "Maxsus imkoniyatlar opsiyalari",
        "a11y_title": "Maxsus imkoniyatlar",
        "a11y_font_size": "Shrift hajmi",
        "a11y_font_dec": "Shrift hajmini kamaytirish",
        "a11y_font_inc": "Shrift hajmini oshirish",
        "a11y_high_contrast": "Yuqori kontrast",
        "a11y_grayscale": "Kulrang tuslar",
        "a11y_reduce_motion": "Harakatni kamaytirish",
        "a11y_toggle_btn": "Maxsus imkoniyatlar vositalarini ochish"
      },
      cs: { name: 'Čeština', subtitle: 'webový ovládací panel', username: 'Uivatelské jméno', username_ph: '4–8 znaků, a-z 0-9', email: 'E-mailová adresa', email_ph: 'uzivatel@priklad.cz', domain: 'Doména', domain_ph: 'priklad.cz', password: 'Heslo', password_ph: 'Min. <?= PASSWD_MIN_LENGTH ?> znaků', confirm: 'Potvrdit', confirm_ph: 'Opakovat', register: 'Registrovat', already_registered: 'Již máte účet?', to_login: 'Přihlásit se', to_panel: 'Do panelu', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Slabé', pw_medium: 'Střední', pw_strong: 'Silné', please_wait: 'Čekejte prosím...', success_heading: 'Účet byl vytvořen!', generate: 'Generovat', maintenance_heading: 'Režim údržby', maintenance_text: 'Nové registrace jsou z důvodu údržby pozastaveny. Zkuste to prosím později.', tos_prefix: 'Souhlasím s', tos_link: 'obchodními podmínkami', tos_and: 'a', privacy_link: 'zásadami ochrany osobních údajů', did_you_mean: 'Měli jste na mysli', setup_2fa: 'Doporučujeme v panelu zapnout dvojfázové ověření (2FA).', copy_pw: 'Kopírovat', need_help: 'Potřebujete pomoc?', contact_support: 'Kontaktovat podporu', forgot_password: 'Zapomenuté heslo?', pw_req_length: 'Alespoň {n} znaků', pw_req_upper: 'Jedno velké písmeno (A-Z)', pw_req_lower: 'Jedno malé písmeno (a-z)', pw_req_number: 'Jedna číslice (0-9)', email_mx_invalid: 'Zdá se, že doména e-mailu nepřijímá poštu.', pw_hibp_warning: '⚠️ Toto heslo se objevilo v {n} úniku dat.', pw_hibp_ok: '✓ Heslo nebylo nalezeno ve známých únicích dat.', pw_hibp_checking: 'Kontrola bezpečnosti hesla...', invite_code: 'Zvací kód', invite_code_ph: 'Zadejte svůj zvací kód', invite_required: 'K registraci je vyžadován zvací kód.', invite_invalid: 'Neplatný nebo již použitý zvací kód.', cookie_banner_text: 'Používáme nezbytné soubory cookie pro bezpečnost (CSRF, relace). Pokračováním souhlasíte s používáním souborů cookie.', cookie_banner_btn: 'Přijmout a pokračovat', cookie_banner_label: 'Souhlas s cookies', a11y_widget_label: 'Nástroje přístupnosti', a11y_panel_label: 'Možnosti přístupnosti', a11y_title: 'Přístupnost', a11y_font_size: 'Velikost písma', a11y_font_dec: 'Zmenšit písmo', a11y_font_inc: 'Zvětšit písmo', a11y_high_contrast: 'Vysoký kontrast', a11y_grayscale: 'Stupně šedi', a11y_reduce_motion: 'Omezit pohyb', a11y_toggle_btn: 'Otevřít nástroje přístupnosti' },
      de: { name: 'Deutsch', subtitle: 'Web-Control-Panel', username: 'Benutzername', username_ph: '4–8 Zeichen, a-z 0-9', email: 'E-Mail-Adresse', email_ph: 'user@example.com', domain: 'Domain', domain_ph: 'beispiel.de', password: 'Passwort', password_ph: 'Mind. <?= PASSWD_MIN_LENGTH ?> Zeichen', confirm: 'Bestätigen', confirm_ph: 'Wiederholen', register: 'Registrieren', already_registered: 'Bereits registriert?', to_login: 'Zum Login', to_panel: 'Zum Panel', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Schwach', pw_medium: 'Mittel', pw_strong: 'Stark', please_wait: 'Bitte warten...', success_heading: 'Konto erstellt!', generate: 'Generieren', maintenance_heading: 'Wartungsmodus', maintenance_text: 'Neue Registrierungen sind wegen Wartungsarbeiten derzeit pausiert. Bitte versuchen Sie es später erneut.', tos_prefix: 'Ich stimme den', tos_link: 'AGB', tos_and: 'und der', privacy_link: 'Datenschutzerklärung zu', did_you_mean: 'Meinten Sie', setup_2fa: 'Wir empfehlen, im Panel die Zwei-Faktor-Authentifizierung (2FA) zu aktivieren.', copy_pw: 'Kopieren', need_help: 'Brauchen Sie Hilfe?', contact_support: 'Support kontaktieren', forgot_password: 'Passwort vergessen?', pw_req_length: 'Mind. {n} Zeichen', pw_req_upper: 'Ein Großbuchstabe (A-Z)', pw_req_lower: 'Ein Kleinbuchstabe (a-z)', pw_req_number: 'Eine Zahl (0-9)', email_mx_invalid: 'Die E-Mail-Domain hat keine Mailserver.', pw_hibp_warning: '⚠️ Dieses Passwort taucht in {n} Datenleck(s) auf.', pw_hibp_ok: '✓ Passwort nicht in bekannten Datenlecks gefunden.', pw_hibp_checking: 'Passwortsicherheit wird geprüft...', invite_code: 'Einladungscode', invite_code_ph: 'Code eingeben', invite_required: 'Zur Registrierung ist ein Einladungscode erforderlich.', invite_invalid: 'Ungültiger oder bereits verwendeter Einladungscode.', cookie_banner_text: 'Wir verwenden essenzielle Cookies für die Sicherheit (CSRF, Sitzung). Durch die Fortsetzung stimmen Sie unserer Cookie-Nutzung zu.', cookie_banner_btn: 'Akzeptieren & Fortfahren', cookie_banner_label: 'Cookie-Einwilligung', a11y_widget_label: 'Barrierefreiheit-Tools', a11y_panel_label: 'Barrierefreiheit-Optionen', a11y_title: 'Barrierefreiheit', a11y_font_size: 'Schriftgröße', a11y_font_dec: 'Schriftgröße verkleinern', a11y_font_inc: 'Schriftgröße vergrößern', a11y_high_contrast: 'Hoher Kontrast', a11y_grayscale: 'Graustufen', a11y_reduce_motion: 'Bewegung reduzieren', a11y_toggle_btn: 'Barrierefreiheit-Tools öffnen' },
      fr: { name: 'Français', subtitle: 'panneau de contrôle web', username: 'Nom d\'utilisateur', username_ph: '4–8 caract., a-z 0-9', email: 'Adresse e-mail', email_ph: 'user@example.com', domain: 'Domaine', domain_ph: 'exemple.com', password: 'Mot de passe', password_ph: 'Min. <?= PASSWD_MIN_LENGTH ?> caract.', confirm: 'Confirmer', confirm_ph: 'Répéter', register: 'S\'inscrire', already_registered: 'Déjà inscrit ?', to_login: 'Connexion', to_panel: 'Au panneau', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Faible', pw_medium: 'Moyen', pw_strong: 'Fort', please_wait: 'Veuillez patienter...', success_heading: 'Compte créé !', generate: 'Générer', maintenance_heading: 'Mode maintenance', maintenance_text: 'Les nouvelles inscriptions sont actuellement suspendues pour maintenance. Veuillez réessayer plus tard.', tos_prefix: 'J\'accepte les', tos_link: 'conditions d\'utilisation', tos_and: 'et la', privacy_link: 'politique de confidentialité', did_you_mean: 'Vouliez-vous dire', setup_2fa: 'Nous recommandons d\'activer l\'authentification à deux facteurs (2FA) dans le panneau.', copy_pw: 'Copier', need_help: 'Besoin d\'aide ?', contact_support: 'Contacter le support', forgot_password: 'Mot de passe oublié ?', pw_req_length: 'Au moins {n} caractères', pw_req_upper: 'Une majuscule (A-Z)', pw_req_lower: 'Une minuscule (a-z)', pw_req_number: 'Un chiffre (0-9)', email_mx_invalid: 'Le domaine de messagerie ne semble pas accepter de courrier.', pw_hibp_warning: '⚠️ Ce mot de passe est apparu dans {n} fuite(s) de données.', pw_hibp_ok: '✓ Mot de passe introuvable dans les fuites de données connues.', pw_hibp_checking: 'Vérification de la sécurité du mot de passe...', invite_code: 'Code d\'invitation', invite_code_ph: 'Entrez votre code d\'invitation', invite_required: 'Un code d\'invitation est requis pour s\'inscrire.', invite_invalid: 'Code d\'invitation invalide ou déjà utilisé.', cookie_banner_text: 'Nous utilisons des cookies essentiels pour la sécurité (CSRF, session). En continuant, vous acceptez notre utilisation des cookies.', cookie_banner_btn: 'Accepter et continuer', cookie_banner_label: 'Consentement aux cookies', a11y_widget_label: 'Outils d\'accessibilité', a11y_panel_label: 'Options d\'accessibilité', a11y_title: 'Accessibilité', a11y_font_size: 'Taille de police', a11y_font_dec: 'Réduire la taille de la police', a11y_font_inc: 'Augmenter la taille de la police', a11y_high_contrast: 'Contraste élevé', a11y_grayscale: 'Niveaux de gris', a11y_reduce_motion: 'Réduire les mouvements', a11y_toggle_btn: 'Ouvrir les outils d\'accessibilité' },
      hu: { name: 'Magyar', subtitle: 'webes vezérlőpult', username: 'Felhasználónév', username_ph: '4–8 karakter, a-z 0-9', email: 'E-mail cím', email_ph: 'felhasznalo@pelda.hu', domain: 'Domain', domain_ph: 'pelda.hu', password: 'Jelszó', password_ph: 'Min. <?= PASSWD_MIN_LENGTH ?> karakter', confirm: 'Megerősítés', confirm_ph: 'Ismétlés', register: 'Regisztráció', already_registered: 'Már regisztrált?', to_login: 'Bejelentkezés', to_panel: 'A panelre', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Gyenge', pw_medium: 'Közepes', pw_strong: 'Erős', please_wait: 'Kérjük várjon...', success_heading: 'Fiók létrehozva!', generate: 'Generálás', maintenance_heading: 'Karbantartási mód', maintenance_text: 'Új regisztrációk karbantartás miatt jelenleg szünetelnek. Kérjük, próbálja újra később.', tos_prefix: 'Elfogadom az', tos_link: 'Általános Szerződési Feltételeket', tos_and: 'és az', privacy_link: 'Adatvédelmi Nyilatkozatot', did_you_mean: 'Erre gondolt:', setup_2fa: 'Javasoljuk, hogy engedélyezze a kétlépcsős azonosítást (2FA) a panelen.', copy_pw: 'Másolás', need_help: 'Segítségre van szüksége?', contact_support: 'Kapcsolat a támogatással', forgot_password: 'Elfelejtett jelszó?', pw_req_length: 'Legalább {n} karakter', pw_req_upper: 'Egy nagybetű (A-Z)', pw_req_lower: 'Egy kisbetű (a-z)', pw_req_number: 'Egy szám (0-9)', email_mx_invalid: 'Úgy tűnik, hogy az e-mail domain nem fogad leveleket.', pw_hibp_warning: '⚠️ Ez a jelszó {n} adatszivárgásban szerepelt.', pw_hibp_ok: '✓ A jelszó nem található az ismert adatszivárgásokban.', pw_hibp_checking: 'Jelszó biztonságának ellenőrzése...', invite_code: 'Meghívó kód', invite_code_ph: 'Adja meg a meghívó kódját', invite_required: 'A regisztrációhoz meghívó kód szükséges.', invite_invalid: 'Érvénytelen vagy már felhasznált meghívó kód.', cookie_banner_text: 'Alapvető sütiket használunk a biztonság érdekében (CSRF, munkamenet). A folytatással elfogadja a sütik használatát.', cookie_banner_btn: 'Elfogadás és folytatás', cookie_banner_label: 'Süti hozzájárulás', a11y_widget_label: 'Akadálymentesítési eszközök', a11y_panel_label: 'Akadálymentesítési beállítások', a11y_title: 'Akadálymentesítés', a11y_font_size: 'Betűméret', a11y_font_dec: 'Betűméret csökkentése', a11y_font_inc: 'Betűméret növelése', a11y_high_contrast: 'Magas kontraszt', a11y_grayscale: 'Fekete-fehér', a11y_reduce_motion: 'Mozgás csökkentése', a11y_toggle_btn: 'Akadálymentesítési eszközök megnyitása' },
      it: { name: 'Italiano', subtitle: 'pannello di controllo web', username: 'Nome utente', username_ph: '4–8 caratt., a-z 0-9', email: 'Indirizzo e-mail', email_ph: 'utente@esempio.it', domain: 'Dominio', domain_ph: 'esempio.it', password: 'Password', password_ph: 'Min. <?= PASSWD_MIN_LENGTH ?> caratt.', confirm: 'Conferma', confirm_ph: 'Ripeti', register: 'Registrati', already_registered: 'Già registrato?', to_login: 'Accedi', to_panel: 'Al pannello', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Debole', pw_medium: 'Media', pw_strong: 'Forte', please_wait: 'Attendere prego...', success_heading: 'Account creato!', generate: 'Genera', maintenance_heading: 'Modalità di manutenzione', maintenance_text: 'Le nuove registrazioni sono momentaneamente sospese per manutenzione. Si prega di riprovare più tardi.', tos_prefix: 'Accetto i', tos_link: 'Termini di Servizio', tos_and: 'e la', privacy_link: 'Informativa sulla Privacy', did_you_mean: 'Intendevi', setup_2fa: 'Ti consigliamo di abilitare l\'autenticazione a due fattori (2FA) nel pannello.', copy_pw: 'Copia', need_help: 'Hai bisogno di aiuto?', contact_support: 'Contatta il supporto', forgot_password: 'Password dimenticata?', pw_req_length: 'Almeno {n} caratteri', pw_req_upper: 'Una lettera maiuscola (A-Z)', pw_req_lower: 'Una lettera minuscola (a-z)', pw_req_number: 'Un numero (0-9)', email_mx_invalid: 'Il dominio email non sembra accettare posta.', pw_hibp_warning: '⚠️ Questa password è apparsa in {n} violazioni di dati.', pw_hibp_ok: '✓ Password non trovata in violazioni di dati note.', pw_hibp_checking: 'Controllo della sicurezza della password...', invite_code: 'Codice di invito', invite_code_ph: 'Inserisci il tuo codice di invito', invite_required: 'È richiesto un codice di invito per registrarsi.', invite_invalid: 'Codice di invito non valido o già utilizzato.', cookie_banner_text: 'Utilizziamo cookie essenziali per la sicurezza (CSRF, sessione). Continuando, accetti l\'uso dei cookie.', cookie_banner_btn: 'Accetta e continua', cookie_banner_label: 'Consenso sui cookie', a11y_widget_label: 'Strumenti di accessibilità', a11y_panel_label: 'Opzioni di accessibilità', a11y_title: 'Accessibilità', a11y_font_size: 'Dimensione testo', a11y_font_dec: 'Riduci dimensione testo', a11y_font_inc: 'Aumenta dimensione testo', a11y_high_contrast: 'Alto contrasto', a11y_grayscale: 'Scala di grigi', a11y_reduce_motion: 'Riduci movimento', a11y_toggle_btn: 'Apri strumenti di accessibilità' },
      ko: { name: '한국어', subtitle: '웹 제어판', username: '사용자 이름', username_ph: '4–8자, a-z 0-9', email: '이메일 주소', email_ph: 'user@example.com', domain: '도메인', domain_ph: 'example.com', password: '비밀번호', password_ph: '최소 <?= PASSWD_MIN_LENGTH ?>자', confirm: '비밀번호 확인', confirm_ph: '재입력', register: '회원가입', already_registered: '이미 계정이 있으신가요?', to_login: '로그인', to_panel: '패널로 이동', pw_hint: 'A-Z, a-z, 0-9', pw_weak: '약함', pw_medium: '보통', pw_strong: '강함', please_wait: '잠시만 기다려 주세요...', success_heading: '계정이 생성되었습니다!', generate: '자동 생성', maintenance_heading: '점검 모드', maintenance_text: '유지 보수를 위해 신규 회원가입이 일시 중단되었습니다. 나중에 다시 시도해 주세요.', tos_prefix: '본인은', tos_link: '이용약관', tos_and: '및', privacy_link: '개인정보 처리방침에 동의합니다', did_you_mean: '다음을 입력하셨나요:', setup_2fa: '패널에서 2단계 인증(2FA)을 활성화하는 것을 권장합니다.', copy_pw: '복사', need_help: '도움이 필요하신가요?', contact_support: '고객지원 문의', forgot_password: '비밀번호 찾기', pw_req_length: '최소 {n}자', pw_req_upper: '대문자 1개 이상 (A-Z)', pw_req_lower: '소문자 1개 이상 (a-z)', pw_req_number: '숫자 1개 이상 (0-9)', email_mx_invalid: '이메일 도메인이 메일을 수신하지 않는 것 같습니다.', pw_hibp_warning: '⚠️ 이 비밀번호는 {n}건의 데이터 유출에서 발견되었습니다.', pw_hibp_ok: '✓ 알려진 데이터 유출에서 비밀번호를 찾을 수 없습니다.', pw_hibp_checking: '비밀번호 보안 검사 중...', invite_code: '초대 코드', invite_code_ph: '초대 코드 입력', invite_required: '등록하려면 초대 코드가 필요합니다.', invite_invalid: '유효하지 않거나 이미 사용된 초대 코드입니다.', cookie_banner_text: '보안(CSRF, 세션)을 위해 필수 쿠키를 사용합니다. 계속 진행하면 쿠키 사용에 동의하게 됩니다.', cookie_banner_btn: '동의 및 계속', cookie_banner_label: '쿠키 동의', a11y_widget_label: '접근성 도구', a11y_panel_label: '접근성 옵션', a11y_title: '접근성', a11y_font_size: '글자 크기', a11y_font_dec: '글자 크기 축소', a11y_font_inc: '글자 크기 확대', a11y_high_contrast: '고대비', a11y_grayscale: '흑백', a11y_reduce_motion: '동작 줄이기', a11y_toggle_btn: '접근성 도구 열기' },
      lt: { name: 'Lietuvių', subtitle: 'valdymo skydas', username: 'Vartotojo vardas', username_ph: '4–8 simboliai, a-z 0-9', email: 'El. pašto adresas', email_ph: 'vartotojas@pavyzdys.lt', domain: 'Domenas', domain_ph: 'pavyzdys.lt', password: 'Slaptažodis', password_ph: 'Ne mažiau <?= PASSWD_MIN_LENGTH ?> simp.', confirm: 'Patvirtinti', confirm_ph: 'Pakartoti', register: 'Registruotis', already_registered: 'Jau užsiregistravę?', to_login: 'Prisijungti', to_panel: 'Į valdymo skydą', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Silpnas', pw_medium: 'Vidutinis', pw_strong: 'Stiprus', please_wait: 'Prašome palaukti...', success_heading: 'Paskyra sukurta!', generate: 'Generuoti', maintenance_heading: 'Priežiūros režimas', maintenance_text: 'Naujos registracijos laikinai sustabdytos dėl profilaktikos darbų. Bandykite vėliau.', tos_prefix: 'Sutinku su', tos_link: 'paslaugų teikimo sąlygomis', tos_and: 'ir', privacy_link: 'privatumo politika', did_you_mean: 'Ar turėjote omenyje', setup_2fa: 'Rekomenduojame skydelyje įjungti dviejų veiksnių autentifikavimą (2FA).', copy_pw: 'Kopijuoti', need_help: 'Reikia pagalbos?', contact_support: 'Susisiekti su palaikymu', forgot_password: 'Pamiršote slaptažodį?', pw_req_length: 'Bent {n} simbolių', pw_req_upper: 'Viena didžioji raidė (A-Z)', pw_req_lower: 'Viena mažoji raidė (a-z)', pw_req_number: 'Vienas skaičius (0-9)', email_mx_invalid: 'Atrodo, kad el. pašto domenas nepriima pašto.', pw_hibp_warning: '⚠️ Šis slaptažodis pasirodė {n} duomenų nutekėjimuose.', pw_hibp_ok: '✓ Slaptažodis nerastas žinomuose duomenų nutekėjimuose.', pw_hibp_checking: 'Tikrinamas slaptažodžio saugumas...', invite_code: 'Kvietimo kodas', invite_code_ph: 'Įveskite kvietimo kodą', invite_required: 'Norint užsiregistruoti reikalingas kvietimo kodas.', invite_invalid: 'Neteisingas arba jau panaudotas kvietimo kodas.', cookie_banner_text: 'Naudojame būtinus slapukus saugumui (CSRF, seansas). Tęsdami sutinkate su slapukų naudojimu.', cookie_banner_btn: 'Sutikti ir tęsti', cookie_banner_label: 'Slapukų sutikimas', a11y_widget_label: 'Prieinamumo įrankiai', a11y_panel_label: 'Prieinamumo parinktys', a11y_title: 'Prieinamumas', a11y_font_size: 'Šrifto dydis', a11y_font_dec: 'Sumažinti šriftą', a11y_font_inc: 'Padidinti šriftą', a11y_high_contrast: 'Didelis kontrastas', a11y_grayscale: 'Pilkumo tonai', a11y_reduce_motion: 'Sumažinti judėjimą', a11y_toggle_btn: 'Atidaryti prieinamumo įrankius' },
      nl: { name: 'Nederlands', subtitle: 'webbeheerpaneel', username: 'Gebruikersnaam', username_ph: '4–8 tekens, a-z 0-9', email: 'E-mailadres', email_ph: 'gebruiker@voorbeeld.nl', domain: 'Domein', domain_ph: 'voorbeeld.nl', password: 'Wachtwoord', password_ph: 'Min. <?= PASSWD_MIN_LENGTH ?> tekens', confirm: 'Bevestigen', confirm_ph: 'Herhalen', register: 'Registreren', already_registered: 'Al geregistreerd?', to_login: 'Inloggen', to_panel: 'Naar paneel', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Zwak', pw_medium: 'Gemiddeld', pw_strong: 'Sterk', please_wait: 'Even geduld...', success_heading: 'Account aangemaakt!', generate: 'Genereren', maintenance_heading: 'Onderhoudsmodus', maintenance_text: 'Nieuwe registraties zijn tijdelijk onderbroken voor onderhoud. Probeer het later opnieuw.', tos_prefix: 'Ik ga akkoord met de', tos_link: 'Algemene Voorwaarden', tos_and: 'en het', privacy_link: 'Privacybeleid', did_you_mean: 'Bedoelde u', setup_2fa: 'We raden aan om Tweestapsverificatie (2FA) in te schakelen in het paneel.', copy_pw: 'Kopiëren', need_help: 'Hulp nodig?', contact_support: 'Neem contact op met support', forgot_password: 'Wachtwoord vergeten?', pw_req_length: 'Minimaal {n} tekens', pw_req_upper: 'Eén hoofdletter (A-Z)', pw_req_lower: 'Eén kleine letter (a-z)', pw_req_number: 'Eén cijfer (0-9)', email_mx_invalid: 'Het e-maildomein lijkt geen e-mail te accepteren.', pw_hibp_warning: '⚠️ Dit wachtwoord verscheen in {n} datalekken.', pw_hibp_ok: '✓ Wachtwoord niet gevonden in bekende datalekken.', pw_hibp_checking: 'Wachtwoordbeveiliging controleren...', invite_code: 'Uitnodigingscode', invite_code_ph: 'Voer uw uitnodigingscode in', invite_required: 'Een uitnodigingscode is vereist om te registreren.', invite_invalid: 'Ongeldige of reeds gebruikte uitnodigingscode.', cookie_banner_text: 'Wij gebruiken essentiële cookies voor de veiligheid (CSRF, sessie). Door verder te gaan, gaat u akkoord met ons cookiegebruik.', cookie_banner_btn: 'Accepteren & doorgaan', cookie_banner_label: 'Cookie toestemming', a11y_widget_label: 'Toegankelijkheidshulpmiddelen', a11y_panel_label: 'Toegankelijkheidsopties', a11y_title: 'Toegankelijkheid', a11y_font_size: 'Lettergrootte', a11y_font_dec: 'Lettergrootte verkleinen', a11y_font_inc: 'Lettergrootte vergroten', a11y_high_contrast: 'Hoog contrast', a11y_grayscale: 'Grijswaarden', a11y_reduce_motion: 'Minder beweging', a11y_toggle_btn: 'Toegankelijkheidshulpmiddelen openen' },
      pl: { name: 'Polski', subtitle: 'panel sterowania web', username: 'Nazwa użytkownika', username_ph: '4–8 znaków, a-z 0-9', email: 'Adres e-mail', email_ph: 'uzytkownik@przyklad.pl', domain: 'Domena', domain_ph: 'przyklad.pl', password: 'Hasło', password_ph: 'Min. <?= PASSWD_MIN_LENGTH ?> znaków', confirm: 'Potwierdź', confirm_ph: 'Powtórz', register: 'Zarejestruj się', already_registered: 'Masz już konto?', to_login: 'Zaloguj się', to_panel: 'Do panelu', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Słabe', pw_medium: 'Średnio', pw_strong: 'Mocne', please_wait: 'Proszę czekać...', success_heading: 'Konto utworzone!', generate: 'Generuj', maintenance_heading: 'Tryb konserwacji', maintenance_text: 'Nowe rejestracje są obecnie wstrzymane z powodu prac konserwacyjnych. Prosimy spróbować później.', tos_prefix: 'Akceptuję', tos_link: 'Regulamin', tos_and: 'oraz', privacy_link: 'Politykę Prywatności', did_you_mean: 'Czy chodziło ci o', setup_2fa: 'Zalecamy włączenie uwierzytelniania dwuskładnikowego (2FA) w panelu.', copy_pw: 'Kopiuj', need_help: 'Potrzebujesz pomocy?', contact_support: 'Skontaktuj się ze wsparciem', forgot_password: 'Zapomniałeś hasła?', pw_req_length: 'Co najmniej {n} znaków', pw_req_upper: 'Jedna wielka litera (A-Z)', pw_req_lower: 'Jedna mała litera (a-z)', pw_req_number: 'Jedna cyfra (0-9)', email_mx_invalid: 'Wydaje się, że domena e-mail nie przyjmuje poczty.', pw_hibp_warning: '⚠️ To hasło pojawiło się w {n} wyciekach danych.', pw_hibp_ok: '✓ Hasło nie zostało znalezione w znanych wyciekach danych.', pw_hibp_checking: 'Sprawdzanie bezpieczeństwa hasła...', invite_code: 'Kod zaproszenia', invite_code_ph: 'Wprowadź swój kod zaproszenia', invite_required: 'Do rejestracji wymagany jest kod zaproszenia.', invite_invalid: 'Nieprawidłowy lub już użyty kod zaproszenia.', cookie_banner_text: 'Używamy niezbędnych plików cookie w celach bezpieczeństwa (CSRF, sesja). Kontynuując, zgadzasz się na używanie plików cookie.', cookie_banner_btn: 'Akceptuj i kontynuuj', cookie_banner_label: 'Zgoda na pliki cookie', a11y_widget_label: 'Narzędzia dostępności', a11y_panel_label: 'Opcje dostępności', a11y_title: 'Dostępność', a11y_font_size: 'Rozmiar czcionki', a11y_font_dec: 'Zmniejsz czcionkę', a11y_font_inc: 'Zwiększ czcionkę', a11y_high_contrast: 'Wysoki kontrast', a11y_grayscale: 'Skala szarości', a11y_reduce_motion: 'Redukcja ruchu', a11y_toggle_btn: 'Otwórz narzędzia dostępności' },
      es: { name: 'Español', subtitle: 'panel de control web', username: 'Nombre de usuario', username_ph: '4–8 caráct., a-z 0-9', email: 'Correo electrónico', email_ph: 'usuario@ejemplo.com', domain: 'Dominio', domain_ph: 'ejemplo.com', password: 'Contraseña', password_ph: 'Mín. <?= PASSWD_MIN_LENGTH ?> caráct.', confirm: 'Confirmar', confirm_ph: 'Repetir', register: 'Registrarse', already_registered: '¿Ya tienes cuenta?', to_login: 'Iniciar sesión', to_panel: 'Al panel', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Débil', pw_medium: 'Media', pw_strong: 'Fuerte', please_wait: 'Por favor espere...', success_heading: '¡Cuenta creada!', generate: 'Generar', maintenance_heading: 'Modo de mantenimiento', maintenance_text: 'Las nuevas inscripciones están pausadas temporalmente por mantenimiento. Por favor, vuelva a intentarlo más tarde.', tos_prefix: 'Acepto los', tos_link: 'Términos del Servicio', tos_and: 'y la', privacy_link: 'Política de Privacidad', did_you_mean: '¿Quisiste decir', setup_2fa: 'Recomendamos activar la autenticación de dos factores (2FA) en el panel.', copy_pw: 'Copiar', need_help: '¿Necesitas ayuda?', contact_support: 'Contactar soporte', forgot_password: '¿Olvidaste tu contraseña?', pw_req_length: 'Al menos {n} caracteres', pw_req_upper: 'Una letra mayúscula (A-Z)', pw_req_lower: 'Una letra minúscula (a-z)', pw_req_number: 'Un número (0-9)', email_mx_invalid: 'El dominio de correo electrónico no parece aceptar correo.', pw_hibp_warning: '⚠️ Esta contraseña apareció en {n} filtración(es) de datos.', pw_hibp_ok: '✓ Contraseña no encontrada en filtraciones de datos conocidas.', pw_hibp_checking: 'Comprobando seguridad de la contraseña...', invite_code: 'Código de invitación', invite_code_ph: 'Ingresa tu código de invitación', invite_required: 'Se requiere un código de invitación para registrarse.', invite_invalid: 'Código de invitación no válido o ya utilizado.', cookie_banner_text: 'Utilizamos cookies esenciales para la seguridad (CSRF, sesión). Al continuar, aceptas nuestro uso de cookies.', cookie_banner_btn: 'Aceptar y continuar', cookie_banner_label: 'Consentimiento de cookies', a11y_widget_label: 'Herramientas de accesibilidad', a11y_panel_label: 'Opciones de accesibilidad', a11y_title: 'Accesibilidad', a11y_font_size: 'Tamaño de fuente', a11y_font_dec: 'Disminuir tamaño de fuente', a11y_font_inc: 'Aumentar tamaño de fuente', a11y_high_contrast: 'Alto contraste', a11y_grayscale: 'Escala de grises', a11y_reduce_motion: 'Reducir movimiento', a11y_toggle_btn: 'Abrir herramientas de accesibilidad' },
      ru: { name: 'Русский', subtitle: 'панель управления web', username: 'Имя пользователя', username_ph: '4–8 симв., a-z 0-9', email: 'Электронная почта', email_ph: 'user@example.com', domain: 'Домен', domain_ph: 'example.com', password: 'Пароль', password_ph: 'Мин. <?= PASSWD_MIN_LENGTH ?> симв.', confirm: 'Подтверждение', confirm_ph: 'Повторите', register: 'Зарегистрироваться', already_registered: 'Уже зарегистрированы?', to_login: 'Войти', to_panel: 'В панель', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Слабый', pw_medium: 'Средний', pw_strong: 'Надежный', please_wait: 'Пожалуйста, подождите...', success_heading: 'Аккаунт создан!', generate: 'Сгенерировать', maintenance_heading: 'Режим обслуживания', maintenance_text: 'Новые регистрации временно приостановлены для проведения технических работ. Пожалуйста, зайдите позже.', tos_prefix: 'Я согласен с', tos_link: 'Условиями обслуживания', tos_and: 'и', privacy_link: 'Политикой конфиденциальности', did_you_mean: 'Возможно, вы имели в виду', setup_2fa: 'Мы рекомендуем включить двухфакторную аутентификацию (2FA) в панели.', copy_pw: 'Копировать', need_help: 'Нужна помощь?', contact_support: 'Связаться с поддержкой', forgot_password: 'Забыли пароль?', pw_req_length: 'Мин. {n} символов', pw_req_upper: 'Одна заглавная буква (A-Z)', pw_req_lower: 'Одна строчная буква (a-z)', pw_req_number: 'Одна цифра (0-9)', email_mx_invalid: 'Похоже, почтовый домен не принимает почту.', pw_hibp_warning: '⚠️ Этот пароль был найден в {n} утечках данных.', pw_hibp_ok: '✓ Пароль не найден в известных утечках данных.', pw_hibp_checking: 'Проверка безопасности пароля...', invite_code: 'Код приглашения', invite_code_ph: 'Введите код приглашения', invite_required: 'Для регистрации требуется код приглашения.', invite_invalid: 'Недействительный или уже использованный код приглашения.', cookie_banner_text: 'Мы используем необходимые файлы cookie для безопасности (CSRF, сессия). Продолжая, вы соглашаетесь с использованием cookie.', cookie_banner_btn: 'Принять и продолжить', cookie_banner_label: 'Согласие на куки', a11y_widget_label: 'Инструменты доступности', a11y_panel_label: 'Параметры доступности', a11y_title: 'Доступность', a11y_font_size: 'Размер шрифта', a11y_font_dec: 'Уменьшить шрифт', a11y_font_inc: 'Увеличить шрифт', a11y_high_contrast: 'Высокий контраст', a11y_grayscale: 'Оттенки серого', a11y_reduce_motion: 'Уменьшение движения', a11y_toggle_btn: 'Открыть инструменты доступности' },
      sl: { name: 'Slovenščina', subtitle: 'spletna nadzorna plošča', username: 'Uporabniško ime', username_ph: '4–8 znakov, a-z 0-9', email: 'E-poštni naslov', email_ph: 'uporabnik@primer.si', domain: 'Domena', domain_ph: 'primer.si', password: 'Geslo', password_ph: 'Najmanj <?= PASSWD_MIN_LENGTH ?> znakov', confirm: 'Potrdi', confirm_ph: 'Ponovi', register: 'Registracija', already_registered: 'Že registrirani?', to_login: 'Prijava', to_panel: 'V nadzorno ploščo', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Šibko', pw_medium: 'Srednje', pw_strong: 'Močno', please_wait: 'Prosimo, počakajte...', success_heading: 'Račun ustvarjen!', generate: 'Generiraj', maintenance_heading: 'Vzdrževalni način', maintenance_text: 'Nove registracije so trenutno zaustavljene zaradi vzdrževanja. Prosimo, poskusite znova pozneje.', tos_prefix: 'Strinjam se s', tos_link: 'pogoji storitve', tos_and: 'in', privacy_link: 'politiko zasebnosti', did_you_mean: 'Ali ste mislili', setup_2fa: 'Priporočamo, da v nadzorni plošči omogočite dvostopenjsko preverjanje (2FA).', copy_pw: 'Kopiraj', need_help: 'Potrebujete pomoč?', contact_support: 'Obrnite se na podporo', forgot_password: 'Ste pozabili geslo?', pw_req_length: 'Vsaj {n} znakov', pw_req_upper: 'Ena velika črka (A-Z)', pw_req_lower: 'Ena mala črka (a-z)', pw_req_number: 'Ena številka (0-9)', email_mx_invalid: 'Zdi se, da e-poštna domena ne sprejema pošte.', pw_hibp_warning: '⚠️ To geslo se je pojavilo v {n} kršitvah podatkov.', pw_hibp_ok: '✓ Geslo ni bilo najdeno v znanih kršitvah podatkov.', pw_hibp_checking: 'Preverjanje varnosti gesla...', invite_code: 'Koda povabila', invite_code_ph: 'Vnesite kodo povabila', invite_required: 'Za registracijo je potrebna koda povabila.', invite_invalid: 'Neveljavna ali že uporabljena koda povabila.', cookie_banner_text: 'Uporabljamo nujne piškotke za varnost (CSRF, seja). Z nadaljevanjem se strinjate z uporabo piškotkov.', cookie_banner_btn: 'Sprejmi in nadaljuj', cookie_banner_label: 'Soglasje za piškotke', a11y_widget_label: 'Orodja za dostopnost', a11y_panel_label: 'Možnosti dostopnosti', a11y_title: 'Dostopnost', a11y_font_size: 'Velikost pisave', a11y_font_dec: 'Zmanjšaj pisavo', a11y_font_inc: 'Povečaj pisavo', a11y_high_contrast: 'Visok kontrast', a11y_grayscale: 'Sivine', a11y_reduce_motion: 'Zmanjšaj gibanje', a11y_toggle_btn: 'Odpri orodja za dostopnost' },
      sk: { name: 'Slovenčina', subtitle: 'webový ovládací panel', username: 'Používateľské meno', username_ph: '4–8 znakov, a-z 0-9', email: 'E-mailová adresa', email_ph: 'pouzivatel@priklad.sk', domain: 'Doména', domain_ph: 'priklad.sk', password: 'Heslo', password_ph: 'Min. <?= PASSWD_MIN_LENGTH ?> znakov', confirm: 'Potvrdiť', confirm_ph: 'Opakovať', register: 'Registrovať', already_registered: 'Už máte účet?', to_login: 'Prihlásiť sa', to_panel: 'Do panela', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Slabé', pw_medium: 'Stredné', pw_strong: 'Silné', please_wait: 'Čakajte prosím...', success_heading: 'Účet bol vytvorený!', generate: 'Generovať', maintenance_heading: 'Režim údržby', maintenance_text: 'Nové registrácie sú z dôvodu údržby pozastavené. Skúste to prosím neskôr.', tos_prefix: 'Súhlasím s', tos_link: 'obchodnými podmienkami', tos_and: 'a', privacy_link: 'zásadami ochrany osobných údajov', did_you_mean: 'Mali ste na mysli', setup_2fa: 'Odporúčame v paneli zapnúť dvojfázové overenie (2FA).', copy_pw: 'Kopírovať', need_help: 'Potrebujete pomoc?', contact_support: 'Kontaktovať podporu', forgot_password: 'Zabudnuté heslo?', pw_req_length: 'Aspoň {n} znakov', pw_req_upper: 'Jedno veľké písmeno (A-Z)', pw_req_lower: 'Jedno malé písmeno (a-z)', pw_req_number: 'Jedna číslica (0-9)', email_mx_invalid: 'Zdá sa, že doména e-mailu neprijíma poštu.', pw_hibp_warning: '⚠️ Toto heslo sa objavilo v {n} úniku dát.', pw_hibp_ok: '✓ Heslo nebolo nájdené v známych únikoch dát.', pw_hibp_checking: 'Kontrola bezpečnosti hesla...', invite_code: 'Pozývací kód', invite_code_ph: 'Zadajte svoj pozývací kód', invite_required: 'Na registráciu je potrebný pozývací kód.', invite_invalid: 'Neplatný alebo už použitý pozývací kód.', cookie_banner_text: 'Používame nevyhnutné súbory cookie pre bezpečnosť (CSRF, relácia). Pokračovaním súhlasíte s používaním súborov cookie.', cookie_banner_btn: 'Prijať a pokračovať', cookie_banner_label: 'Súhlas s cookies', a11y_widget_label: 'Nástroje prístupnosti', a11y_panel_label: 'Možnosti prístupnosti', a11y_title: 'Prístupnosť', a11y_font_size: 'Veľkosť písma', a11y_font_dec: 'Zmenšiť písmo', a11y_font_inc: 'Zväčšiť písmo', a11y_high_contrast: 'Vysoký kontrast', a11y_grayscale: 'Stupne sivej', a11y_reduce_motion: 'Obmedziť pohyb', a11y_toggle_btn: 'Otvoriť nástroje prístupnosti' },
      sv: { name: 'Svenska', subtitle: 'webbkontrollpanel', username: 'Användarnamn', username_ph: '4–8 tecken, a-z 0-9', email: 'E-postadress', email_ph: 'anvandare@exempel.se', domain: 'Domän', domain_ph: 'exempel.se', password: 'Lösenord', password_ph: 'Minst <?= PASSWD_MIN_LENGTH ?> tecken', confirm: 'Bekräfta', confirm_ph: 'Upprepa', register: 'Registrera', already_registered: 'Redan registrerad?', to_login: 'Till inloggning', to_panel: 'Till panelen', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Svagt', pw_medium: 'Medel', pw_strong: 'Starkt', please_wait: 'Vänligen vänta...', success_heading: 'Konto skapat!', generate: 'Generera', maintenance_heading: 'Underhållsläge', maintenance_text: 'Nya registreringar är för närvarande pausade för underhåll. Vänligen återkom senare.', tos_prefix: 'Jag godkänner', tos_link: 'Användarvillkoren', tos_and: 'och', privacy_link: 'Integritetspolicyn', did_you_mean: 'Menade du', setup_2fa: 'Vi rekommenderar att du aktiverar tvåfaktorsautentisering (2FA) i panelen.', copy_pw: 'Kopiera', need_help: 'Behöver du hjälp?', contact_support: 'Kontakta support', forgot_password: 'Glömt lösenord?', pw_req_length: 'Minst {n} tecken', pw_req_upper: 'En stor bokstav (A-Z)', pw_req_lower: 'En liten bokstav (a-z)', pw_req_number: 'En siffra (0-9)', email_mx_invalid: 'E-postdomänen verkar inte acceptera e-post.', pw_hibp_warning: '⚠️ Detta lösenord dök upp i {n} dataläckor.', pw_hibp_ok: '✓ Lösenord hittades inte i kända dataläckor.', pw_hibp_checking: 'Kontrollerar lösenordssäkerhet...', invite_code: 'Inbjudningskod', invite_code_ph: 'Ange din inbjudningskod', invite_required: 'En inbjudningskod krävs för att registrera.', invite_invalid: 'Ogiltig eller redan använd inbjudningskod.', cookie_banner_text: 'Vi använder nödvändiga kakor för säkerhet (CSRF, session). Genom att fortsätta godkänner du vår användning av kakor.', cookie_banner_btn: 'Acceptera & fortsätt', cookie_banner_label: 'Samtycke till kakor', a11y_widget_label: 'Tillgänglighetsverktyg', a11y_panel_label: 'Tillgänglighetsalternativ', a11y_title: 'Tillgänglighet', a11y_font_size: 'Textstorlek', a11y_font_dec: 'Minska textstorlek', a11y_font_inc: 'Öka textstorlek', a11y_high_contrast: 'Hög kontrast', a11y_grayscale: 'Gråskala', a11y_reduce_motion: 'Minska rörelse', a11y_toggle_btn: 'Öppna tillgänglighetsverktyg' },
      tr: { name: 'Türkçe', subtitle: 'web kontrol paneli', username: 'Kullanıcı adı', username_ph: '4–8 karak., a-z 0-9', email: 'E-posta adresi', email_ph: 'kullanici@ornek.com', domain: 'Alan adı', domain_ph: 'ornek.com', password: 'Şifre', password_ph: 'Min. <?= PASSWD_MIN_LENGTH ?> karak.', confirm: 'Doğrula', confirm_ph: 'Tekrar', register: 'Kayıt Ol', already_registered: 'Zaten kayıtlı mısınız?', to_login: 'Giriş Yap', to_panel: 'Panele Git', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Zayıf', pw_medium: 'Orta', pw_strong: 'Güçlü', please_wait: 'Lütfen bekleyin...', success_heading: 'Hesap Oluşturuldu!', generate: 'Oluştur', maintenance_heading: 'Bakım Modu', maintenance_text: 'Yeni kayıtlar bakım nedeniyle geçici olarak durdurulmuştur. Lütfen daha sonra tekrar deneyin.', tos_prefix: '', tos_link: 'Kullanım Koşullarını', tos_and: 've', privacy_link: 'Gizlilik Politikasını kabul ediyorum', did_you_mean: 'Bunu mu demek istediniz:', setup_2fa: 'Panelden İki Faktörlü Kimlik Doğrulamayı (2FA) etkinleştirmenizi öneririz.', copy_pw: 'Kopyala', need_help: 'Yardıma mı ihtiyacınız var?', contact_support: 'Destekle iletişime geç', forgot_password: 'Şifremi Unuttum?', pw_req_length: 'En az {n} karakter', pw_req_upper: 'Bir büyük harf (A-Z)', pw_req_lower: 'Bir küçük harf (a-z)', pw_req_number: 'Bir rakam (0-9)', email_mx_invalid: 'E-posta etki alanı posta kabul etmiyor gibi görünüyor.', pw_hibp_warning: '⚠️ Bu şifre {n} veri ihlalinde göründü.', pw_hibp_ok: '✓ Şifre bilinen veri ihlallerinde bulunamadı.', pw_hibp_checking: 'Şifre güvenliği kontrol ediliyor...', invite_code: 'Davet Kodu', invite_code_ph: 'Davet kodunuzu girin', invite_required: 'Kayıt olmak için davet kodu gereklidir.', invite_invalid: 'Geçersiz veya zaten kullanılmış davet kodu.', cookie_banner_text: 'Güvenlik (CSRF, oturum) için gerekli çerezleri kullanıyoruz. Devam ederek çerez kullanımımızı kabul etmiş olursunuz.', cookie_banner_btn: 'Kabul Et ve Devam Et', cookie_banner_label: 'Çerez onayı', a11y_widget_label: 'Erişilebilirlik araçları', a11y_panel_label: 'Erişilebilirlik seçenekleri', a11y_title: 'Erişilebilirlik', a11y_font_size: 'Yazı Boyutu', a11y_font_dec: 'Yazı boyutunu küçült', a11y_font_inc: 'Yazı boyutunu büyüt', a11y_high_contrast: 'Yüksek Kontrast', a11y_grayscale: 'Gri Tonlamalı', a11y_reduce_motion: 'Hareketi Azalt', a11y_toggle_btn: 'Erişilebilirlik araçlarını aç' },
      uk: { name: 'Українська', subtitle: 'панель керування web', username: 'Ім\'я користувача', username_ph: '4–8 симв., a-z 0-9', email: 'Електронна пошта', email_ph: 'user@example.com', domain: 'Домен', domain_ph: 'example.com', password: 'Пароль', password_ph: 'Мін. <?= PASSWD_MIN_LENGTH ?> симв.', confirm: 'Підтвердження', confirm_ph: 'Повторіть', register: 'Зареєструватися', already_registered: 'Вже маєте акаунт?', to_login: 'Увійти', to_panel: 'До панелі', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Слабкий', pw_medium: 'Середній', pw_strong: 'Надійний', please_wait: 'Будь ласка, зачекайте...', success_heading: 'Акаунт створено!', generate: 'Згенерувати', maintenance_heading: 'Режим обслуговування', maintenance_text: 'Нові реєстрації тимчасово призупинено через технічні роботи. Будь ласка, спробуйте пізніше.', tos_prefix: 'Я погоджуюся з', tos_link: 'Умовами обслуговування', tos_and: 'та', privacy_link: 'Політикою конфіденційності', did_you_mean: 'Можливо, ви мали на увазі', setup_2fa: 'Ми рекомендуємо ввімкнути двофакторну автентифікацію (2FA) у панелі.', copy_pw: 'Копіювати', need_help: 'Потрібна допомога?', contact_support: 'Зв\'язатися з підтримкою', forgot_password: 'Забули пароль?', pw_req_length: 'Мін. {n} символів', pw_req_upper: 'Одна велика літера (A-Z)', pw_req_lower: 'Одна мала літера (a-z)', pw_req_number: 'Одна цифра (0-9)', email_mx_invalid: 'Схоже, поштовий домен не приймає пошту.', pw_hibp_warning: '⚠️ Цей пароль знайдено у {n} витоках даних.', pw_hibp_ok: '✓ Пароль не знайдено у відомих витоках даних.', pw_hibp_checking: 'Перевірка безпеки пароля...', invite_code: 'Код запрошення', invite_code_ph: 'Введіть код запрошення', invite_required: 'Для реєстрації потрібен код запрошення.', invite_invalid: 'Недійсний або вже використаний код запрошення.', cookie_banner_text: 'Ми використовуємо необхідні файли cookie для безпеки (CSRF, сесія). Продовжуючи, ви погоджуєтеся з використанням файлів cookie.', cookie_banner_btn: 'Прийняти та продовжити', cookie_banner_label: 'Згода на файли cookie', a11y_widget_label: 'Інструменти доступності', a11y_panel_label: 'Параметри доступності', a11y_title: 'Доступність', a11y_font_size: 'Розмір шрифту', a11y_font_dec: 'Зменшити шрифт', a11y_font_inc: 'Збільшити шрифт', a11y_high_contrast: 'Високий контраст', a11y_grayscale: 'Відтінки сірого', a11y_reduce_motion: 'Зменшити рух', a11y_toggle_btn: 'Відкрити інструменти доступності' },
      uz: { name: 'Oʻzbekcha', subtitle: 'veb boshqaruv paneli', username: 'Foydalanuvchi nomi', username_ph: '4–8 belgi, a-z 0-9', email: 'E-pochta manzili', email_ph: 'foydalanuvchi@namuna.uz', domain: 'Domen', domain_ph: 'namuna.uz', password: 'Parol', password_ph: 'Kamida <?= PASSWD_MIN_LENGTH ?> belgi', confirm: 'Tasdiqlash', confirm_ph: 'Takrorlang', register: 'Roʻyxatdan oʻtish', already_registered: 'Roʻyxatdan oʻtganmisiz?', to_login: 'Kirish', to_panel: 'Panelga oʻtish', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'Zarif', pw_medium: 'Oʻrtacha', pw_strong: 'Kuchli', please_wait: 'Kuting...', success_heading: 'Hisob yaratildi!', generate: 'Yaratish', maintenance_heading: 'Profilaktika rejimi', maintenance_text: 'Yangi roʻyxatdan oʻtishlar profilaktika ishlari sababli vaqtincha toʻxtatilgan. Keyinroq qayta urinib koʻring.', tos_prefix: 'Men', tos_link: 'Xizmat koʻrsatish shartlari', tos_and: 'va', privacy_link: 'Maxfiylik siyosatiga roziman', did_you_mean: 'Buni nazarda tutdingizmi:', setup_2fa: 'Panelda Ikki faktorli autentifikatsiyani (2FA) yoqishingizni tavsiya qilamiz.', copy_pw: 'Nusxalash', need_help: 'Yordam kerakmi?', contact_support: 'Qo\'llab-quvvatlash bilan bog\'lanish', forgot_password: 'Parolni unutdingizmi?', pw_req_length: 'Kamida {n} ta belgi', pw_req_upper: 'Bitta bosh harf (A-Z)', pw_req_lower: 'Bitta kichik harf (a-z)', pw_req_number: 'Bitta raqam (0-9)', email_mx_invalid: 'Elektron pochta domeni xatlarni qabul qilmayotganga o‘xshaydi.', pw_hibp_warning: '⚠️ Ushbu parol {n} ta ma\'lumotlar sizib chiqishida paydo bo\'lgan.', pw_hibp_ok: '✓ Parol ma\'lum bo\'lgan ma\'lumotlar sizib chiqishida topilmadi.', pw_hibp_checking: 'Parol xavfsizligi tekshirilmoqda...', invite_code: 'Taklif kodi', invite_code_ph: 'Taklif kodini kiriting', invite_required: 'Ro\'yxatdan o\'tish uchun taklif kodi kerak.', invite_invalid: 'Yaroqsiz yoki oldin ishlatilgan taklif kodi.', cookie_banner_text: 'Xavfsizlik (CSRF, sessiya) uchun zaruriy kukilardan foydalanamiz. Davom etish orqali kukilardan foydalanishimizga rozilik bildirasiz.', cookie_banner_btn: 'Qabul qilish va davom etish', cookie_banner_label: 'Kuki roziligi', a11y_widget_label: 'Maxsus imkoniyatlar vositalari', a11y_panel_label: 'Maxsus imkoniyatlar opsiyalari', a11y_title: 'Maxsus imkoniyatlar', a11y_font_size: 'Shrift hajmi', a11y_font_dec: 'Shrift hajmini kamaytirish', a11y_font_inc: 'Shrift hajmini oshirish', a11y_high_contrast: 'Yuqori kontrast', a11y_grayscale: 'Kulrang tuslar', a11y_reduce_motion: 'Harakatni kamaytirish', a11y_toggle_btn: 'Maxsus imkoniyatlar vositalarini ochish' },
      th: { name: 'ไทย', subtitle: 'แผงควบคุมเว็บ', username: 'ชื่อผู้ใช้', username_ph: '4–8 ตัวอักษร, a-z 0-9', email: 'อีเมล', email_ph: 'user@example.com', domain: 'โดเมน', domain_ph: 'example.com', password: 'รหัสผ่าน', password_ph: 'อย่างน้อย <?= PASSWD_MIN_LENGTH ?> ตัวอักษร', confirm: 'ยืนยันรหัสผ่าน', confirm_ph: 'ป้อนอีกครั้ง', register: 'ลงทะเบียน', already_registered: 'มีบัญชีอยู่แล้ว?', to_login: 'เข้าสู่ระบบ', to_panel: 'ไปที่พาเนล', pw_hint: 'A-Z, a-z, 0-9', pw_weak: 'อ่อน', pw_medium: 'ปานกลาง', pw_strong: 'แข็งแกร่ง', please_wait: 'โปรดรอสักครู่...', success_heading: 'สร้างบัญชีแล้ว!', generate: 'สร้างรหัส', maintenance_heading: 'โหมดปรับปรุงระบบ', maintenance_text: 'เปิดปิดการลงทะเบียนใหม่ชั่วคราวเพื่อปรับปรุงระบบ โปรดลองอีกครั้งในภายหลัง', tos_prefix: 'ฉันยอมรับ', tos_link: 'ข้อตกลงการใช้บริการ', tos_and: 'และ', privacy_link: 'นโยบายความเป็นส่วนตัว', did_you_mean: 'คุณหมายถึง', setup_2fa: 'เราขอแนะนำให้เปิดใช้งานการยืนยันแบบสองขั้นตอน (2FA) ในแผงควบคุม', need_help: 'ต้องการความช่วยเหลือ?', contact_support: 'ติดต่อฝ่ายสนับสนุน', forgot_password: 'ลืมรหัสผ่าน?', pw_req_length: 'อย่างน้อย {n} ตัวอักษร', pw_req_upper: 'ตัวพิมพ์ใหญ่ 1 ตัว (A-Z)', pw_req_lower: 'ตัวพิมพ์เล็ก 1 ตัว (a-z)', pw_req_number: 'ตัวเลข 1 ตัว (0-9)', email_mx_invalid: 'โดเมนอีเมลดูเหมือนจะไม่รับเมล', pw_hibp_warning: '⚠️ รหัสผ่านนี้ปรากฏในข้อมูลรั่วไหล {n} ครั้ง', pw_hibp_ok: '✓ ไม่พบรหัสผ่านในข้อมูลรั่วไหลที่ทราบ', pw_hibp_checking: 'กำลังตรวจสอบความปลอดภัยของรหัสผ่าน...', invite_code: 'รหัสคำเชิญ', invite_code_ph: 'ใส่รหัสคำเชิญของคุณ', invite_required: 'ต้องใช้รหัสคำเชิญในการลงทะเบียน', invite_invalid: 'รหัสคำเชิญไม่ถูกต้องหรือถูกใช้ไปแล้ว', cookie_banner_text: 'เราใช้คุกกี้ที่จำเป็นเพื่อความปลอดภัย (CSRF, เซสชัน) การดำเนินการต่อแสดงว่าคุณยินยอมให้เราใช้คุกกี้', cookie_banner_btn: 'ยอมรับและดำเนินการต่อ', cookie_banner_label: 'การยินยอมใช้คุกกี้', a11y_widget_label: 'เครื่องมือการเข้าถึง', a11y_panel_label: 'ตัวเลือกการเข้าถึง', a11y_title: 'การเข้าถึง', a11y_font_size: 'ขนาดตัวอักษร', a11y_font_dec: 'ลดขนาดตัวอักษร', a11y_font_inc: 'เพิ่มขนาดตัวอักษร', a11y_high_contrast: 'ความคมชัดสูง', a11y_grayscale: 'โหมดขาวดำ', a11y_reduce_motion: 'ลดการเคลื่อนไหว', a11y_toggle_btn: 'เปิดเครื่องมือการเข้าถึง' },
      zh: { name: '简体中文', subtitle: 'Web 控制面板', username: '用户名', username_ph: '4–8个字符, a-z 0-9', email: '电子邮件', email_ph: 'user@example.com', domain: '域名', domain_ph: 'example.com', password: '密码', password_ph: '至少 <?= PASSWD_MIN_LENGTH ?> 个字符', confirm: '确认密码', confirm_ph: '重复密码', register: '注册', already_registered: '已有账号？', to_login: '去登录', to_panel: '前往控制面板', pw_hint: 'A-Z, a-z, 0-9', pw_weak: '弱', pw_medium: '中', pw_strong: '强', please_wait: '请稍候...', success_heading: '账号已创建！', generate: '生成密码', maintenance_heading: '维护模式', maintenance_text: '由于系统维护，新用户注册已暂停。请稍后再试。', tos_prefix: '我同意', tos_link: '服务条款', tos_and: '和', privacy_link: '隐私政策', did_you_mean: '您是说', setup_2fa: '我们建议您在面板中启用双因素身份验证 (2FA)。', copy_pw: '复制', need_help: '需要帮助吗？', contact_support: '联系支持', forgot_password: '忘记密码？', pw_req_length: '至少 {n} 个字符', pw_req_upper: '一个大写字母 (A-Z)', pw_req_lower: '一个小写字母 (a-z)', pw_req_number: '一个数字 (0-9)', email_mx_invalid: '该电子邮件域名似乎不接收邮件。', pw_hibp_warning: '⚠️ 此密码已在 {n} 次数据泄露中出现。', pw_hibp_ok: '✓ 在已知数据泄露中未找到此密码。', pw_hibp_checking: '正在检查密码安全性...', invite_code: '邀请码', invite_code_ph: '请输入您的邀请码', invite_required: '注册需要邀请码。', invite_invalid: '邀请码无效或已使用。', cookie_banner_text: '我们使用必要的 Cookie 以确保安全（CSRF、会话）。继续操作即表示您同意我们使用 Cookie。', cookie_banner_btn: '接受并继续', cookie_banner_label: 'Cookie 同意', a11y_widget_label: '无障碍工具', a11y_panel_label: '无障碍选项', a11y_title: '无障碍', a11y_font_size: '字号', a11y_font_dec: '减小字号', a11y_font_inc: '增大字号', a11y_high_contrast: '高对比度', a11y_grayscale: '灰度', a11y_reduce_motion: '减少动画', a11y_toggle_btn: '打开无障碍工具' },
      pt: {
        name: 'Português',
        subtitle: 'painel de controlo web',
        username: 'Nome de utilizador',
        username_ph: '4–8 caracteres, a-z 0-9',
        email: 'Endereço de e-mail',
        email_ph: 'utilizador@exemplo.pt',
        domain: 'Domínio',
        domain_ph: 'exemplo.pt',
        password: 'Palavra-passe',
        password_ph: 'Mín. <?= PASSWD_MIN_LENGTH ?> caracteres',
        confirm: 'Confirmar',
        confirm_ph: 'Repetir',
        register: 'Registar',
        already_registered: 'Já registado?',
        to_login: 'Entrar',
        to_panel: 'Ir para o painel',
        pw_hint: 'A-Z, a-z, 0-9',
        pw_weak: 'Fraca',
        pw_medium: 'Média',
        pw_strong: 'Forte',
        please_wait: 'Por favor, aguarde...',
        success_heading: 'Conta criada!',
        generate: 'Gerar',
        maintenance_heading: 'Modo de manutenção',
        maintenance_text: 'Novos registos estão temporariamente suspensos para manutenção. Por favor, tente mais tarde.',
        tos_prefix: 'Aceito os',
        tos_link: 'Termos de Serviço',
        tos_and: 'e a',
        privacy_link: 'Política de Privacidade',
        did_you_mean: 'Queria dizer',
        setup_2fa: 'Recomendamos a ativação da autenticação de dois fatores (2FA) no painel.',
        copy_pw: 'Copiar',
        need_help: 'Precisa de ajuda?',
        contact_support: 'Contactar o Suporte',
        forgot_password: 'Esqueceu-se da palavra-passe?',
        pw_req_length: 'Pelo menos {n} caracteres',
        pw_req_upper: 'Uma letra maiúscula (A-Z)',
        pw_req_lower: 'Uma letra minúscula (a-z)',
        pw_req_number: 'Um número (0-9)',
        email_mx_invalid: 'O domínio do e-mail parece não aceitar mensagens.',
        pw_hibp_warning: '⚠️ Esta palavra-passe foi encontrada em {n} fugas de dados.',
        pw_hibp_ok: '✓ Palavra-passe não encontrada em fugas de dados conhecidas.',
        pw_hibp_checking: 'A verificar a segurança da palavra-passe...',
        invite_code: 'Código de convite',
        invite_code_ph: 'Introduza o seu código de convite',
        invite_required: 'É necessário um código de convite para se registar.',
        invite_invalid: 'Código de convite inválido ou já utilizado.',
        cookie_banner_text: 'Utilizamos cookies essenciais para a segurança (CSRF, sessão). Ao continuar, concorda com a nossa utilização de cookies.',
        cookie_banner_btn: 'Aceitar e continuar',
        cookie_banner_label: 'Consentimento de cookies',
        a11y_widget_label: 'Ferramentas de acessibilidade',
        a11y_panel_label: 'Opções de acessibilidade',
        a11y_title: 'Acessibilidade',
        a11y_font_size: 'Tamanho da letra',
        a11y_font_dec: 'Diminuir tamanho da letra',
        a11y_font_inc: 'Aumentar tamanho da letra',
        a11y_high_contrast: 'Alto contraste',
        a11y_grayscale: 'Escala de cinzentos',
        a11y_reduce_motion: 'Reduzir movimento',
        a11y_toggle_btn: 'Abrir ferramentas de acessibilidade'
      },
      pt_br: {
        name: 'Português (Brasil)',
        subtitle: 'painel de controle web',
        username: 'Nome de usuário',
        username_ph: '4–8 caracteres, a-z 0-9',
        email: 'Endereço de e-mail',
        email_ph: 'usuario@exemplo.com.br',
        domain: 'Domínio',
        domain_ph: 'exemplo.com.br',
        password: 'Senha',
        password_ph: 'Mín. <?= PASSWD_MIN_LENGTH ?> caracteres',
        confirm: 'Confirmar',
        confirm_ph: 'Repetir',
        register: 'Cadastrar',
        already_registered: 'Já cadastrado?',
        to_login: 'Entrar',
        to_panel: 'Ir para o painel',
        pw_hint: 'A-Z, a-z, 0-9',
        pw_weak: 'Fraca',
        pw_medium: 'Média',
        pw_strong: 'Forte',
        please_wait: 'Por favor, aguarde...',
        success_heading: 'Conta criada!',
        generate: 'Gerar',
        maintenance_heading: 'Modo de manutenção',
        maintenance_text: 'Novos cadastros estão temporariamente suspensos para manutenção. Por favor, tente mais tarde.',
        tos_prefix: 'Aceito os',
        tos_link: 'Termos de Serviço',
        tos_and: 'e a',
        privacy_link: 'Política de Privacidade',
        did_you_mean: 'Você quis dizer',
        setup_2fa: 'Recomendamos a ativação da autenticação de dois fatores (2FA) no painel.',
        copy_pw: 'Copiar',
        need_help: 'Precisa de ajuda?',
        contact_support: 'Contatar o Suporte',
        forgot_password: 'Esqueceu a senha?',
        pw_req_length: 'Pelo menos {n} caracteres',
        pw_req_upper: 'Uma letra maiúscula (A-Z)',
        pw_req_lower: 'Uma letra minúscula (a-z)',
        pw_req_number: 'Um número (0-9)',
        email_mx_invalid: 'O domínio do e-mail parece não aceitar mensagens.',
        pw_hibp_warning: '⚠️ Esta senha foi encontrada em {n} vazamentos de dados.',
        pw_hibp_ok: '✓ Senha não encontrada em vazamentos de dados conhecidos.',
        pw_hibp_checking: 'Verificando a segurança da senha...',
        invite_code: 'Código de convite',
        invite_code_ph: 'Digite seu código de convite',
        invite_required: 'É necessário um código de convite para se cadastrar.',
        invite_invalid: 'Código de convite inválido ou já utilizado.',
        cookie_banner_text: 'Utilizamos cookies essenciais para segurança (CSRF, sessão). Ao continuar, você concorda com o uso de cookies.',
        cookie_banner_btn: 'Aceitar e continuar',
        cookie_banner_label: 'Consentimento de cookies',
        a11y_widget_label: 'Ferramentas de acessibilidade',
        a11y_panel_label: 'Opções de acessibilidade',
        a11y_title: 'Acessibilidade',
        a11y_font_size: 'Tamanho da fonte',
        a11y_font_dec: 'Diminuir tamanho da fonte',
        a11y_font_inc: 'Aumentar tamanho da fonte',
        a11y_high_contrast: 'Alto contraste',
        a11y_grayscale: 'Escala de cinza',
        a11y_reduce_motion: 'Reduzir movimento',
        a11y_toggle_btn: 'Abrir ferramentas de acessibilidade'
      },
      ja: {
        name: '日本語',
        subtitle: 'Web コントロールパネル',
        username: 'ユーザー名',
        username_ph: '4–8文字、a-z 0-9',
        email: 'メールアドレス',
        email_ph: 'user@example.jp',
        domain: 'ドメイン',
        domain_ph: 'example.jp',
        password: 'パスワード',
        password_ph: '最小 <?= PASSWD_MIN_LENGTH ?> 文字',
        confirm: 'パスワード確認',
        confirm_ph: 'もう一度入力',
        register: '登録する',
        already_registered: '既に登録されていますか？',
        to_login: 'ログイン',
        to_panel: 'パネルへ',
        pw_hint: 'A-Z, a-z, 0-9',
        pw_weak: '弱い',
        pw_medium: '普通',
        pw_strong: '強い',
        please_wait: '少々お待ちください...',
        success_heading: 'アカウントが作成されました！',
        generate: '自動生成',
        maintenance_heading: 'メンテナンスモード',
        maintenance_text: '現在、メンテナンスのため新規登録を一時的に停止しています。後ほどもう一度お試しください。',
        tos_prefix: '私は',
        tos_link: '利用規約',
        tos_and: 'および',
        privacy_link: 'プライバシーポリシーに同意します',
        did_you_mean: 'もしかして',
        setup_2fa: 'パネル内で2要素認証 (2FA) を有効にすることをお勧めします。',
        copy_pw: 'コピー',
        need_help: 'ヘルプが必要ですか？',
        contact_support: 'サポートに連絡',
        forgot_password: 'パスワードをお忘れですか？',
        pw_req_length: '最小 {n} 文字以上',
        pw_req_upper: '大文字1文字以上 (A-Z)',
        pw_req_lower: '小文字1文字以上 (a-z)',
        pw_req_number: '数字1文字以上 (0-9)',
        email_mx_invalid: 'メールのドメインがメールを受信できない状態のようです。',
        pw_hibp_warning: '⚠️ このパスワードは過去に {n} 件のデータ漏洩で確認されています。',
        pw_hibp_ok: '✓ このパスワードは既知のデータ漏洩では見つかりませんでした。',
        pw_hibp_checking: 'パスワードの安全性を確認中...',
        invite_code: '招待コード',
        invite_code_ph: '招待コードを入力してください',
        invite_required: '登録には招待コードが必要です。',
        invite_invalid: '招待コードが無効か、または既に使用されています。',
        cookie_banner_text: 'セキュリティ（CSRF、セッション）のために必須のCookieを使用しています。続行することで、Cookieの使用に同意したことになります。',
        cookie_banner_btn: '同意して続行',
        cookie_banner_label: 'Cookieの同意',
        a11y_widget_label: 'アクセシビリティツール',
        a11y_panel_label: 'アクセシビリティオプション',
        a11y_title: 'アクセシビリティ',
        a11y_font_size: 'フォントサイズ',
        a11y_font_dec: 'フォントサイズを縮小',
        a11y_font_inc: 'フォントサイズを拡大',
        a11y_high_contrast: 'ハイコントラスト',
        a11y_grayscale: 'グレースケール',
        a11y_reduce_motion: '視差効果を減らす',
        a11y_toggle_btn: 'アクセシビリティツールを開く'
      }
    };
    let currentLang = 'en';
    function setLanguage(langCode) {
      if (!I18N[langCode]) langCode = 'en';
      currentLang = langCode;
      const dict = I18N[langCode] || I18N['en'];
      localStorage.setItem('iw_lang', langCode);
      const langLabel = document.getElementById('currentLangLabel');
      if (langLabel) langLabel.textContent = dict.name;

      document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.dataset.i18n;
        if (dict[key]) {
          let text = dict[key];
          if (key === 'demo_notice' && el.dataset.i18nDemoHours) {
            text = text.replace('{n}', el.dataset.i18nDemoHours);
          }
          el.textContent = text;
        }
      });

      document.querySelectorAll('[data-i18n-ph]').forEach(el => {
        const key = el.dataset.i18nPh;
        if (dict[key]) el.placeholder = dict[key];
      });

      document.querySelectorAll('[data-i18n-min]').forEach(el => {
        const key = el.dataset.i18nMin;
        const checklist = document.getElementById('pwChecklist');
        const minLen = checklist ? checklist.dataset.min : 8;
        if (dict[key]) el.textContent = dict[key].replace('{n}', minLen);
      });

      document.querySelectorAll('.lang-item').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.lang === langCode);
      });
    }

    if (langDropdown && langBtn) {
      Object.keys(I18N).forEach(code => {
        const item = document.createElement('button');
        item.type = 'button';
        item.className = 'lang-item';
        item.dataset.lang = code;
        item.textContent = I18N[code].name;
        item.addEventListener('click', () => {
          setLanguage(code);
          langDropdown.classList.remove('show');
        });
        langDropdown.appendChild(item);
      });

      langBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        langDropdown.classList.toggle('show');
      });

      document.addEventListener('click', (e) => {
        const langWrap = document.getElementById('langWrap');
        if (langWrap && !langWrap.contains(e.target)) {
          langDropdown.classList.remove('show');
        }
      });

      // Init language from localStorage or browser settings
      const savedLang = localStorage.getItem('iw_lang') || navigator.language.slice(0, 2);
      setLanguage(I18N[savedLang] ? savedLang : 'en');
    }

    // ── Client-Side Validation & Submit Spinner ───────────────────────────────
    const regForm = document.getElementById('regForm');
    if (regForm) {
      regForm.addEventListener('submit', function (e) {
        const email = document.getElementById('email').value.trim();
        const domain = document.getElementById('domain').value.trim();
        const pw = document.getElementById('passwd').value;
        const pw2 = document.getElementById('passwd2').value;

        if (!email.includes('@')) {
          e.preventDefault();
          alert('Please enter a valid email address.');
          return;
        }
        if (!domain.match(/^[a-z0-9][a-z0-9\-\.]+\.[a-z]{2,}$/i)) {
          e.preventDefault();
          alert('Please enter a valid domain (e.g. example.com).');
          return;
        }
        if (pw.length < <?= PASSWD_MIN_LENGTH ?>) {
          e.preventDefault();
          alert('Password must be at least <?= PASSWD_MIN_LENGTH ?> characters long.');
          return;
        }
        <?php if (PASSWD_REQUIRE_COMPLEXITY): ?>
          if (!/[A-Z]/.test(pw) || !/[a-z]/.test(pw) || !/[0-9]/.test(pw)) {
            e.preventDefault();
            alert('Password must contain at least one uppercase letter, one lowercase letter, and one number.');
            return;
          }
        <?php endif; ?>
        if (pw !== pw2) {
          e.preventDefault();
          alert('Passwords do not match.');
          return;
        }

        const btn = document.getElementById('submitBtn');
        const spinner = document.getElementById('spinner');
        const label = document.getElementById('submitLabel');
        if (spinner) spinner.style.display = 'block';
        const curLang = localStorage.getItem('iw_lang') || 'en';
        if (label) label.textContent = (I18N[curLang] || I18N['en']).please_wait || 'Please wait...';
        setTimeout(() => { if (btn) btn.disabled = true; }, 10);
      });
    }

    // ── Hide Preloader after page load ────────────────────────────────────────
    window.addEventListener('load', () => {
      const preloader = document.getElementById('preloader');
      if (preloader) {
        preloader.classList.add('hidden');
        // Remove from DOM after transition to free resources
        preloader.addEventListener('transitionend', () => preloader.remove(), { once: true });
      }
    });

    // ── Email Typo Detection ──────────────────────────────────────────────────
    const emailInput = document.getElementById('email');
    const emailSuggestion = document.getElementById('emailSuggestion');
    const emailSuggestionLink = document.getElementById('emailSuggestionLink');

    if (emailInput && emailSuggestion && emailSuggestionLink) {
      const commonDomains = [
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com', 'me.com', 'mac.com',
        'gmx.de', 'gmx.net', 'gmx.at', 'gmx.ch', 'web.de', 't-online.de', 'freenet.de', 'posteo.de', 'mailbox.org',
        'yandex.ru', 'mail.ru', 'inbox.ru', 'bk.ru', 'list.ru', 'rambler.ru',
        'proton.me', 'protonmail.com', 'tuta.com', 'tutamail.com',
        'live.com', 'msn.com', 'zoho.com'
      ];

      function calculateDistance(a, b) {
        if (a.length === 0) return b.length;
        if (b.length === 0) return a.length;
        const matrix = [];
        for (let i = 0; i <= b.length; i++) matrix[i] = [i];
        for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
        for (let i = 1; i <= b.length; i++) {
          for (let j = 1; j <= a.length; j++) {
            if (b.charAt(i - 1) === a.charAt(j - 1)) {
              matrix[i][j] = matrix[i - 1][j - 1];
            } else {
              matrix[i][j] = Math.min(matrix[i - 1][j - 1] + 1, Math.min(matrix[i][j - 1] + 1, matrix[i - 1][j] + 1));
            }
          }
        }
        return matrix[b.length][a.length];
      }

      emailInput.addEventListener('blur', function () {
        const val = this.value.trim().toLowerCase();
        const parts = val.split('@');
        if (parts.length === 2 && parts[1].length > 0) {
          const user = parts[0];
          const domain = parts[1];
          let bestMatch = null;
          let minDistance = 3;

          if (commonDomains.includes(domain)) {
            emailSuggestion.style.display = 'none';
            return;
          }

          for (const cd of commonDomains) {
            const d = calculateDistance(domain, cd);
            if (d < minDistance) {
              minDistance = d;
              bestMatch = cd;
            }
          }

          if (bestMatch && bestMatch !== domain) {
            const suggestedEmail = user + '@' + bestMatch;
            emailSuggestionLink.textContent = suggestedEmail;
            emailSuggestion.style.display = 'block';

            emailSuggestionLink.onclick = function (e) {
              e.preventDefault();
              emailInput.value = suggestedEmail;
              emailSuggestion.style.display = 'none';
              emailInput.focus();
            };
          } else {
            emailSuggestion.style.display = 'none';
          }
        } else {
          emailSuggestion.style.display = 'none';
        }
      });
    }

    // Close help menu on outside click
    window.addEventListener('click', function (e) {
      const hm = document.getElementById('helpMenu');
      if (hm && hm.classList.contains('show') && !e.target.closest('#helpFabWrap')) {
        hm.classList.remove('show');
      }
    });

    // Help FAB toggle
    const helpFabBtn = document.getElementById('helpFabBtn');
    if (helpFabBtn) {
      helpFabBtn.addEventListener('click', function (e) {
        e.stopPropagation();
        document.getElementById('helpMenu').classList.toggle('show');
      });
    }

    // ── Password Checklist ──────────────────────────────────────────────────
    (function () {
      const checklist = document.getElementById('pwChecklist');
      if (!checklist) return;

      const minLen = parseInt(checklist.dataset.min, 10) || 8;
      const complexity = checklist.dataset.complexity === '1';
      const pwInput = document.getElementById('passwd');
      if (!pwInput) return;

      const chkLength = document.getElementById('chk-length');
      const chkUpper = document.getElementById('chk-upper');
      const chkLower = document.getElementById('chk-lower');
      const chkNumber = document.getElementById('chk-number');

      function setCheck(el, ok) {
        if (!el) return;
        el.classList.toggle('ok', ok);
        el.querySelector('.check-icon').textContent = ok ? '✓' : '';
      }

      function updateChecklist() {
        const val = pwInput.value;
        setCheck(chkLength, val.length >= minLen);
        if (complexity) {
          setCheck(chkUpper, /[A-Z]/.test(val));
          setCheck(chkLower, /[a-z]/.test(val));
          setCheck(chkNumber, /[0-9]/.test(val));
        }
        // Update i18n placeholder for min-length text
        if (chkLength) {
          const span = chkLength.querySelector('[data-i18n-min]');
          if (span) {
            const key = span.dataset.i18nMin;
            const lang = I18N[currentLang] || I18N['en'] || {};
            const tpl = lang[key] || `At least ${minLen} characters`;
            span.textContent = tpl.replace('{n}', minLen);
          }
        }
      }

      pwInput.addEventListener('input', updateChecklist);
      updateChecklist();
    })();

    // ── Password Generator ────────────────────────────────────────────────────
    (function () {
      const btn = document.getElementById('generatePwBtn');
      const pwInput = document.getElementById('passwd');
      const pwInput2 = document.getElementById('passwd2');
      const copyBtn = document.getElementById('copyPwBtn');
      if (!btn || !pwInput || !pwInput2) return;

      if (copyBtn) {
        copyBtn.addEventListener('click', function () {
          if (pwInput.value) {
            navigator.clipboard.writeText(pwInput.value).then(() => {
              const originalColor = copyBtn.style.color;
              copyBtn.style.color = 'var(--ok-text)';
              setTimeout(() => copyBtn.style.color = originalColor, 1500);
            }).catch(err => console.error('Could not copy text: ', err));
          }
        });
      }

      btn.addEventListener('click', function () {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+~-';
        let pw = '';
        const minLen = Math.max(16, <?= PASSWD_MIN_LENGTH ?>);
        
        <?php if (PASSWD_REQUIRE_COMPLEXITY): ?>
          pw += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random() * 26)];
          pw += 'abcdefghijklmnopqrstuvwxyz'[Math.floor(Math.random() * 26)];
          pw += '0123456789'[Math.floor(Math.random() * 10)];
          pw += '!@#$%^&*()_+~-'[Math.floor(Math.random() * 14)];
        <?php endif; ?>
        
        while (pw.length < minLen) {
          pw += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        
        pw = pw.split('').sort(() => 0.5 - Math.random()).join('');
        pwInput.value = pw;
        pwInput2.value = pw;
        
        pwInput.dispatchEvent(new Event('input', { bubbles: true }));
        pwInput2.dispatchEvent(new Event('input', { bubbles: true }));
      });
    })();

    // ── HaveIBeenPwned Check ────────────────────────────────────────────────
    <?php if (defined('ENABLE_HIBP_CHECK') && ENABLE_HIBP_CHECK): ?>
        (function () {
          const pwInput = document.getElementById('passwd');
          const hibpStatus = document.getElementById('hibpStatus');
          const form = document.getElementById('regForm');
          if (!pwInput || !hibpStatus) return;

          const blockOnBreach = <?= defined('HIBP_BLOCK_ON_BREACH') && HIBP_BLOCK_ON_BREACH ? 'true' : 'false' ?>;
          let hibpTimer = null;
          let lastBreach = false;

          // Compute SHA-1 using Web Crypto API (no external lib needed)
          async function sha1(str) {
            const buf = new TextEncoder().encode(str);
            const hash = await crypto.subtle.digest('SHA-1', buf);
            return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
          }

          async function checkHibp(password) {
            if (password.length < 4) {
              hibpStatus.className = 'hibp-status';
              lastBreach = false;
              return;
            }

            const lang = I18N[currentLang] || I18N['en'] || {};
            hibpStatus.className = 'hibp-status checking';
            hibpStatus.textContent = lang.pw_hibp_checking || 'Checking password security...';

            try {
              const hash = await sha1(password);
              const prefix = hash.substring(0, 5);
              const suffix = hash.substring(5);

              const resp = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
                headers: { 'Add-Padding': 'true' }
              });
              if (!resp.ok) throw new Error('HIBP API error');

              const text = await resp.text();
              let count = 0;
              for (const line of text.split('\n')) {
                const [s, c] = line.trim().split(':');
                if (s && s.toUpperCase() === suffix) {
                  count = parseInt(c, 10) || 1;
                  break;
                }
              }

              if (count > 0) {
                lastBreach = true;
                hibpStatus.className = 'hibp-status warning';
                const tpl = lang.pw_hibp_warning || '⚠️ This password appeared in {n} data breach(es).';
                hibpStatus.textContent = tpl.replace('{n}', count.toLocaleString());
              } else {
                lastBreach = false;
                hibpStatus.className = 'hibp-status ok';
                hibpStatus.textContent = lang.pw_hibp_ok || '✓ Password not found in known data breaches.';
              }
            } catch (e) {
              // Fail-silent: do not block on API unavailability
              hibpStatus.className = 'hibp-status';
              lastBreach = false;
            }
          }

          pwInput.addEventListener('input', function () {
            clearTimeout(hibpTimer);
            hibpTimer = setTimeout(() => checkHibp(pwInput.value), 800);
          });

          // Block form submission if breach found and HIBP_BLOCK_ON_BREACH is enabled
          if (blockOnBreach && form) {
            form.addEventListener('submit', function (e) {
              if (lastBreach) {
                e.preventDefault();
                const lang = I18N[currentLang] || I18N['en'] || {};
                hibpStatus.className = 'hibp-status warning';
                hibpStatus.textContent = lang.pw_hibp_warning
                  ? lang.pw_hibp_warning.replace('{n}', '?')
                  : '⚠️ Please choose a different password.';
                pwInput.focus();
              }
            }, true);
          }
        })();
    <?php endif; ?>

  </script>

  <?php if (defined('COOKIE_BANNER_ENABLED') && COOKIE_BANNER_ENABLED): ?>
    <script>
        // ── Cookie Consent Banner ──────────────────────────────────────────────────
        (function () {
          const banner = document.getElementById('cookieBanner');
          if (!banner) return;
          const COOKIE_KEY = 'iw_cookie_consent';

          if (localStorage.getItem(COOKIE_KEY) !== '1') {
            // Slide in after a short delay so the page settles first
            setTimeout(() => banner.classList.add('visible'), 400);
          }

          const acceptBtn = document.getElementById('cookieAcceptBtn');
          if (acceptBtn) {
            acceptBtn.addEventListener('click', function () {
              localStorage.setItem(COOKIE_KEY, '1');
              banner.classList.remove('visible');
              banner.addEventListener('transitionend', () => banner.remove(), { once: true });
            });
          }
        })();
    </script>
  <?php endif; ?>

  <?php if (defined('ACCESSIBILITY_WIDGET_ENABLED') && ACCESSIBILITY_WIDGET_ENABLED): ?>
    <script>
      // ── Accessibility Widget ───────────────────────────────────────────────────
      (function () {
        const toggleBtn = document.getElementById('a11yToggleBtn');
        const panel = document.getElementById('a11yPanel');
        const fontDecBtn = document.getElementById('a11yFontDec');
        const fontIncBtn = document.getElementById('a11yFontInc');
        const fontLabel = document.getElementById('a11yFontSize');
        const contrastCb = document.getElementById('a11yContrast');
        const grayscaleCb = document.getElementById('a11yGrayscale');
        const motionCb = document.getElementById('a11yMotion');

        const STORE = 'iw_a11y';
        let state = { font: 100, contrast: false, grayscale: false, motion: false };

        try {
          const saved = JSON.parse(localStorage.getItem(STORE) || 'null');
          if (saved) state = { ...state, ...saved };
        } catch (e) { }

        function save() {
          try { localStorage.setItem(STORE, JSON.stringify(state)); } catch (e) { }
        }

        function applyAll() {
          document.documentElement.style.fontSize = state.font + '%';
          fontLabel.textContent = state.font + '%';
          document.documentElement.classList.toggle('a11y-contrast', state.contrast);
          document.documentElement.classList.toggle('a11y-grayscale', state.grayscale);
          document.documentElement.classList.toggle('a11y-motion', state.motion);
          contrastCb.checked = state.contrast;
          grayscaleCb.checked = state.grayscale;
          motionCb.checked = state.motion;
        }

        // Inject global a11y CSS rules once
        if (!document.getElementById('a11y-rules')) {
          const style = document.createElement('style');
          style.id = 'a11y-rules';
          style.textContent = [
            '.a11y-contrast { filter: contrast(1.6) brightness(1.05); }',
            '.a11y-grayscale { filter: grayscale(1); }',
            '.a11y-contrast.a11y-grayscale { filter: contrast(1.6) brightness(1.05) grayscale(1); }',
            '.a11y-motion *, .a11y-motion *::before, .a11y-motion *::after { animation-duration: 0.001ms !important; transition-duration: 0.001ms !important; }'
          ].join('\n');
          document.head.appendChild(style);
        }

        applyAll();

        // Toggle panel
        toggleBtn.addEventListener('click', function (e) {
          e.stopPropagation();
          const open = panel.classList.toggle('open');
          toggleBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
        });

        // Close on outside click
        document.addEventListener('click', function (e) {
          const widget = document.getElementById('a11yWidget');
          if (widget && !widget.contains(e.target)) {
            panel.classList.remove('open');
            toggleBtn.setAttribute('aria-expanded', 'false');
          }
        });

        // Font size
        fontDecBtn.addEventListener('click', function () {
          state.font = Math.max(80, state.font - 10);
          applyAll(); save();
        });
        fontIncBtn.addEventListener('click', function () {
          state.font = Math.min(150, state.font + 10);
          applyAll(); save();
        });

        // Toggles
        contrastCb.addEventListener('change', function () {
          state.contrast = this.checked;
          applyAll(); save();
        });
        grayscaleCb.addEventListener('change', function () {
          state.grayscale = this.checked;
          applyAll(); save();
        });
        motionCb.addEventListener('change', function () {
          state.motion = this.checked;
          applyAll(); save();
        });
      })();
    </script>
  <?php endif; ?>
</body>

</html>