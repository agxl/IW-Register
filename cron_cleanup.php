<?php

/**
 * Developer: Andy Goldau
 * © 2026 WI-Register by PanelLayer, a brand of Subdomain LTD and managed on behalf of GoMaKe UG. All rights reserved.
 *
 * DISCLAIMER: This software is provided "as is" without any warranty of any kind.
 * WI-Register is an independent software solution and is not affiliated with,
 * endorsed by, or sponsored by Liquid Web / InterWorx or its affiliates.
 */

/**
 * Demo Mode Account Cleanup Script (Cronjob)
 * --------------------------------------------------
 * Deletes expired demo InterWorx SiteWorx accounts created by WI-Register
 * via the InterWorx NodeWorx XML-RPC API (/nodeworx/siteworx action: delete).
 *
 * Setup (add to crontab on your server):
 *   crontab -e
 *   Add the following line (runs every 30 minutes):
 *   [asterisk]/30 * * * * php /home/YOUR_IW_USER/public_html/cron_cleanup.php >> /dev/null 2>&1
 */

// Prevent unauthorized direct HTTP access unless running via CLI
if (php_sapi_name() !== 'cli' && !defined('CRON_ALLOWED')) {
    header('HTTP/1.1 403 Forbidden');
    echo "Access denied. This script is intended to be run via command line (CLI cronjob).\n";
    exit(1);
}

// Set maximum execution time for batch account deletions
@set_time_limit(300);

// Load main configuration
$configPath = __DIR__ . '/config.php';
if (!is_file($configPath)) {
    echo "[" . date('Y-m-d H:i:s') . "] ERROR: Configuration file not found at $configPath\n";
    exit(1);
}
require_once $configPath;

// Check if Demo Mode is enabled
if (!defined('DEMO_MODE') || !DEMO_MODE) {
    echo "[" . date('Y-m-d H:i:s') . "] DEMO MODE IS DISABLED in config.php. Exiting.\n";
    exit(0);
}

$dataFile = defined('DEMO_ACCOUNTS_FILE') ? DEMO_ACCOUNTS_FILE : (__DIR__ . '/data/demo_accounts.json');

if (!is_file($dataFile)) {
    echo "[" . date('Y-m-d H:i:s') . "] No demo accounts file found ($dataFile). Nothing to clean up.\n";
    exit(0);
}

$raw      = file_get_contents($dataFile);
$accounts = json_decode((string) $raw, true);

if (!is_array($accounts) || empty($accounts)) {
    echo "[" . date('Y-m-d H:i:s') . "] Demo accounts list is empty. Nothing to clean up.\n";
    exit(0);
}

// ── InterWorx XML-RPC helpers (self-contained, no require of index.php) ─────

/**
 * Appends a <member> to a <struct> DOM element.
 */
function cron_appendMember(\DOMElement $struct, string $name, \DOMNode $valueNode, \DOMDocument $doc): void
{
    $member  = $doc->createElement('member');
    $nameEl  = $doc->createElement('name');
    $nameEl->appendChild($doc->createTextNode($name));
    $member->appendChild($nameEl);
    $valueEl = $doc->createElement('value');
    $valueEl->appendChild($valueNode);
    $member->appendChild($valueEl);
    $struct->appendChild($member);
}

/**
 * Builds a flat <struct> DOM node from an associative string array.
 */
function cron_buildStruct(array $data, \DOMDocument $doc): \DOMElement
{
    $struct = $doc->createElement('struct');
    foreach ($data as $key => $value) {
        $strEl = $doc->createElement('string');
        $strEl->appendChild($doc->createTextNode((string)$value));
        cron_appendMember($struct, (string)$key, $strEl, $doc);
    }
    return $struct;
}

/**
 * Builds an iworx.route XML-RPC request (single-struct convention).
 */
function cron_buildRequest(array $auth, string $ctrl, string $action, array $input): string
{
    $doc = new \DOMDocument('1.0', 'UTF-8');
    $doc->formatOutput = false;

    $mc = $doc->createElement('methodCall');
    $doc->appendChild($mc);
    $mc->appendChild($doc->createElement('methodName', 'iworx.route'));

    $params      = $doc->createElement('params');
    $outerParam  = $doc->createElement('param');
    $outerValue  = $doc->createElement('value');
    $outerStruct = $doc->createElement('struct');

    // Member 1: apikey (auth struct: email + password)
    cron_appendMember($outerStruct, 'apikey', cron_buildStruct($auth, $doc), $doc);

    // Member 2: ctrl_name
    $ctrlEl = $doc->createElement('string');
    $ctrlEl->appendChild($doc->createTextNode($ctrl));
    cron_appendMember($outerStruct, 'ctrl_name', $ctrlEl, $doc);

    // Member 3: action
    $actionEl = $doc->createElement('string');
    $actionEl->appendChild($doc->createTextNode($action));
    cron_appendMember($outerStruct, 'action', $actionEl, $doc);

    // Member 4: input
    cron_appendMember($outerStruct, 'input', cron_buildStruct($input, $doc), $doc);

    $outerValue->appendChild($outerStruct);
    $outerParam->appendChild($outerValue);
    $params->appendChild($outerParam);
    $mc->appendChild($params);

    return $doc->saveXML();
}

/**
 * Sends an iworx.route XML-RPC request and returns true on success (status == 0).
 */
function cron_sendRequest(string $requestXml): array
{
    $host = rtrim(IW_HOST, '/');
    $url  = $host . ':' . IW_PORT . '/xmlrpc';

    $ch      = curl_init($url);
    $timeout = defined('IW_TIMEOUT') ? IW_TIMEOUT : 90;
    $byteLen = mb_strlen($requestXml, '8bit');

    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $requestXml,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYPEER => IW_SSL_VERIFY,
        CURLOPT_SSL_VERIFYHOST => IW_SSL_VERIFY ? 2 : 0,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_HTTPHEADER     => ['Content-Type: text/xml', 'Content-Length: ' . $byteLen],
    ]);

    $response = curl_exec($ch);
    $errno    = curl_errno($ch);
    $errStr   = curl_error($ch);
    curl_close($ch);

    if ($errno) {
        return ['success' => false, 'message' => 'cURL error: ' . $errStr];
    }

    // Parse XML-RPC response
    $prev = libxml_use_internal_errors(true);
    $doc  = simplexml_load_string((string)$response);
    libxml_clear_errors();
    libxml_use_internal_errors($prev);

    if ($doc === false) {
        return ['success' => false, 'message' => 'Invalid XML response'];
    }

    if (isset($doc->fault)) {
        return ['success' => false, 'message' => 'XML-RPC fault'];
    }

    $status = -1;
    if (isset($doc->params->param->value->struct)) {
        foreach ($doc->params->param->value->struct->member as $member) {
            if ((string)$member->name === 'status') {
                $status = (int)(string)($member->value->int ?? $member->value->i4 ?? $member->value ?? -1);
                break;
            }
        }
    }

    return ['success' => ($status === 0), 'message' => 'API status: ' . $status];
}

/**
 * Returns the auth struct for the API request.
 * API Key (if set) is passed as the password field for NodeWorx admin auth.
 */
function cron_buildAuth(): array
{
    $apiKey = defined('IW_API_KEY') ? trim(IW_API_KEY) : '';
    if (!empty($apiKey)) {
        return ['email' => IW_ADMIN_EMAIL, 'password' => $apiKey];
    }
    return ['email' => IW_ADMIN_EMAIL, 'password' => IW_ADMIN_PASS];
}

/**
 * Deletes a SiteWorx account via NodeWorx XML-RPC API.
 * Controller: /nodeworx/siteworx | Action: delete
 * Required input: domain (master domain of the account)
 */
function iwDeleteAccount(string $domain): array
{
    $auth    = cron_buildAuth();
    $input   = ['domain' => $domain];
    $reqXml  = cron_buildRequest($auth, '/nodeworx/siteworx', 'delete', $input);
    return cron_sendRequest($reqXml);
}

// ── Main cleanup loop ─────────────────────────────────────────────────────────

$now          = time();
$deletedCount = 0;
$keptCount    = 0;

echo "[" . date('Y-m-d H:i:s') . "] Starting demo accounts cleanup scan (" . count($accounts) . " accounts tracked)...\n";

foreach ($accounts as $username => $info) {
    $deleteAfter = (int) ($info['delete_after'] ?? 0);
    $domain      = $info['domain'] ?? '';

    if ($now >= $deleteAfter) {
        if (empty($domain)) {
            echo "[" . date('Y-m-d H:i:s') . "] SKIP: Account '$username' has no domain recorded – removing from list.\n";
            unset($accounts[$username]);
            $deletedCount++;
            continue;
        }

        echo "[" . date('Y-m-d H:i:s') . "] Account '$username' (domain: $domain) expired (Created: "
            . date('Y-m-d H:i:s', $info['created_at'] ?? 0)
            . "). Terminating via InterWorx API...\n";

        $result = iwDeleteAccount($domain);

        if ($result['success']) {
            echo "[" . date('Y-m-d H:i:s') . "] SUCCESS: Account '$username' (domain: $domain) deleted from InterWorx.\n";
            unset($accounts[$username]);
            $deletedCount++;
        } else {
            echo "[" . date('Y-m-d H:i:s') . "] ERROR: Failed to delete '$username' (domain: $domain): " . $result['message'] . "\n";
            // Keep account in list and retry on next run
        }
    } else {
        $remainingMin = ceil(($deleteAfter - $now) / 60);
        echo "[" . date('Y-m-d H:i:s') . "] Account '$username' active ($remainingMin minutes remaining).\n";
        $keptCount++;
    }
}

// Save updated accounts list
file_put_contents($dataFile, json_encode($accounts, JSON_PRETTY_PRINT), LOCK_EX);

echo "[" . date('Y-m-d H:i:s') . "] Cleanup complete. Deleted: $deletedCount account(s), Active: $keptCount account(s).\n";
