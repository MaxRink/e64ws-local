<?php
	/*
	 * E64 Local Owner API v1 - dev-gated REST module
	 *
	 * Deploy to /usr/local/www/dev/rest_api_dev.php on a dev-mode device.
	 * Requires isDev() == true (first token of /etc/issue == "development").
	 *
	 * All routes require:
	 *   1. A valid vendor REST session (handled by rest_api.php before calling here)
	 *   2. Owner token in /db/e64local/token, passed via X-E64-Local-Token header or
	 *      "token" key in JSON POST body.
	 *
	 * Routes (POST /rest_api/<name>):
	 *   capabilities - API version, route list, limits and feature flags
	 *   machine      - model, variant, firmware, dev mode, hashed serial
	 *   grind_log    - grind_log rows (newest first; limit/offset/since/until)
	 *   service_log  - event_log rows joined with event_types (same filters)
	 *   alert_log    - alert_log rows joined with alert_types (same filters)
	 *   portafilters - portafilter table rows
	 *   recipes      - recipe_entries + recipe_data joined with enum tables
	 *   settings     - settings table, with redaction of sensitive keys
	 *   config       - machine config JSON from /db/<Variant>Config.json, redacted
	 *   file         - read an allowlisted file (base64 or text)
	 *   ws_token     - mint a fresh WSS token for wss://<host>:9997/?token=...
	 *
	 * Gated action routes (only when /db/e64local/actions.json is valid):
	 *   action_prepare - validate an action, return a single-use HMAC token
	 *   action_execute - verify the token, run one bounded action, audit it
	 *   action_status  - read the persisted state/result of one action
	 *   action_cancel  - idempotent cancel/stop for one action
	 *   action_audit   - read the action audit log (newest first)
	 *
	 * Action identifiers (action_grind_start_gbw, action_recipe_update, ...)
	 * are values of the action_prepare "route" field, NOT HTTP paths: a bare
	 * POST to an action identifier never actuates anything.
	 *
	 * The log routes accept limit (default 20/500/500), offset (default 0,
	 * max 1000000), and since/until (YYYY-MM-DD, YYYY-MM-DD HH:MM:SS or Unix
	 * seconds).  They return rows in a stable newest-first order by row id.
	 *
	 * DB-backed row values are strings: they come from the sqlite3 CLI's CSV
	 * output.  The simulator mirrors that representation.
	 *
	 * Redaction rules:
	 *   - keys whose (case-insensitive) name ends with password, passwd, secret,
	 *     token, logindata, apikey, api_key or credential
	 *     (covers Role.*.LoginData, Wifi.StaPassword, productionWifiPassword)
	 *   - keys named productionWifiSsid, cloudBaseUrl, mobileAppPairingUrl or
	 *     M2m.CoffeeMachinesConfig (case-insensitive, any nesting depth for config)
	 *   - free-text log columns (grind_debug_data, event_details, alert_details)
	 *     and allowlisted text files via _redactText(): password/secret key/value,
	 *     SN*, MAC and IPv4 patterns
	 *
	 * Deliberately excluded, at every layer:
	 *   - ESP reset/flash/erase/OTA, ESP NVS, WiFi provisioning, pairing,
	 *     eFuse/OTP and bootloader entry.  Those command names are absent from
	 *     the module catalog and from the root-owned runner allowlist.
	 *   - The ESP-side nozzle-light driver: it has no host-side surface, so no
	 *     catalog entry exists for it at all.
	 *   - Role password set/clear (owner decision: no credential writes).  The
	 *     names are absent from the catalog; a request is refused as
	 *     credential-bearing rather than reported as an unavailable action.
	 *   - Caller-supplied SQL, table names, column names or shell fragments.
	 *
	 * Time domains: rate-limit events are monotonic milliseconds (hrtime), so a
	 * wall-clock step cannot reset a window; an unusable bucket is refused, not
	 * pruned.  Confirm tokens and records are bound to
	 * /proc/sys/kernel/random/boot_id, so a reboot invalidates every prepared
	 * action.
	 *
	 * Database reads are read-only: sqlite3 runs with -readonly and the SQL is
	 * passed through escapeshellarg(), never interpolated into the shell string.
	 * Database writes only happen inside the root-owned runner, with a fixed
	 * statement per allowlisted kind and a pre-write backup.
	 *
	 * Owner-authorized use only.  No vendor keys, signed updates, or cloud
	 * credentials are included or required.
	 */

	require_once( "sessionHelper.php" );
	require_once( "constants.php" );
	require_once( "systemInfo.php" );

	// --- Dev gate ----------------------------------------------------------------
	// Fail closed and check before any request handling. rest_api.php only
	// requires this file in dev mode, but the module must not depend on that.
	if ( !function_exists( "isDev" ) || !isDev() )
	{
		http_response_code( 403 );
		echo json_encode(
			array( "error" => "dev mode required", "success" => false, "errorCode" => 403 ),
			JSON_PRETTY_PRINT
		);
		exit;
	}

	// Local API v1 constants
	define( "E64LOCAL_API_VERSION", "1" );
	define( "E64LOCAL_TOKEN_FILE", "/db/e64local/token" );
	define( "E64LOCAL_TOKEN_DIR", "/db/e64local" );

	// Maximum rows returned by list endpoints
	define( "MAX_ROWS_GRIND_LOG", 5000 );
	define( "MAX_ROWS_SERVICE_LOG", 5000 );
	define( "MAX_ROWS_ALERT_LOG", 5000 );
	define( "DEFAULT_ROWS_GRIND_LOG", 20 );
	define( "DEFAULT_ROWS_SERVICE_LOG", 500 );
	define( "DEFAULT_ROWS_ALERT_LOG", 500 );

	// Maximum file size for the file and config routes (bytes)
	define( "MAX_FILE_BYTES", 1048576 );  // 1 MiB

	// Maximum JSON request body size (bytes).  Every read-only request is small.
	define( "MAX_REQUEST_BYTES", 16384 );

	// Maximum pagination offset accepted by the log routes.
	define( "MAX_OFFSET", 1000000 );

	// Routes handled by this module.  Keep in sync with
	// docs/openapi/local-api.yaml and tools/e64ws_simulator.py.
	$E64LOCAL_ROUTES = array(
		"alert_log",
		"capabilities",
		"config",
		"file",
		"grind_log",
		"machine",
		"portafilters",
		"recipes",
		"service_log",
		"settings",
		"ws_token",
	);

	// systemInfo.php grinderType mapping (API_REFERENCE.md 1.4.6).
	$E64LOCAL_GRINDER_TYPE_NAMES = array(
		0 => "E64 WS",
		1 => "E65T GbS",
		2 => "E65W GbS",
		3 => "E80T GbS",
		4 => "E80W GbS",
		5 => "E64 WS",
		6 => "E64 TS",
	);

	// Exact realpath allowlist for the file route
	$E64LOCAL_FILE_ALLOWLIST = array(
		"/etc/issue",
		"/tmp/FirmwareUpdateState.json",
	);

	// Directories whose regular files may be read by the file route
	$E64LOCAL_FILE_ALLOWED_DIRS = array(
		"/log",
	);

	// Case-insensitive key-name suffixes that must never be returned
	$E64LOCAL_REDACT_KEY_SUFFIXES = array(
		"password",
		"passwd",
		"secret",
		"token",
		"logindata",
		"apikey",
		"api_key",
		"credential",
	);

	// Case-insensitive exact key names that must never be returned
	$E64LOCAL_REDACT_KEY_EXACT = array(
		"m2m.coffeemachinesconfig",
		"productionwifissid",
		"cloudbaseurl",
		"mobileapppairingurl",
		"grindersn",
		"serialnumber",
		"machineserial",
		"machineserialnumber",
		"serial",
	);

	// --- Helpers -------------------------------------------------------------------

	/** Return the database path for the current variant. */
	function _dbPath()
	{
		global $systemVariantCc;
		return "/db/{$systemVariantCc}Sqlite.db";
	}

	/** Return the machine config JSON path for the current variant. */
	function _configPath()
	{
		global $machineInfoFile;
		return $machineInfoFile;
	}

	/** Decode a JSON request body into an array (never a scalar). */
	function _decodeBody( $postContent )
	{
		$body = json_decode( (string)$postContent, true );
		return is_array( $body ) ? $body : array();
	}

	/** Write the standard success envelope. */
	function _okResponse( &$returnJson, &$success, &$returnVal, $data )
	{
		$returnJson["data"] = $data;
		$returnJson["success"] = true;
		$returnJson["errorCode"] = 0;
		$success = true;
		$returnVal = 0;
	}

	/** Write the standard failure envelope. */
	function _failResponse( &$returnJson, &$success, &$returnVal, $errorCode, $message, $console = null )
	{
		$returnJson["error"] = $message;
		if ( $console !== null )
		{
			$returnJson["console"] = $console;
		}
		$returnJson["success"] = false;
		$returnJson["errorCode"] = (int)$errorCode;
		$success = false;
		$returnVal = (int)$errorCode;
	}

	/** Clamp a caller-supplied row limit to the documented range. */
	function _limitFromBody( $body, $default, $max )
	{
		$limit = isset( $body["limit"] ) ? (int)$body["limit"] : $default;
		if ( $limit <= 0 )
		{
			$limit = $default;
		}
		if ( $limit > $max )
		{
			$limit = $max;
		}
		return $limit;
	}

	/** Clamp a caller-supplied pagination offset to the documented range. */
	function _offsetFromBody( $body )
	{
		$offset = isset( $body["offset"] ) ? (int)$body["offset"] : 0;
		if ( $offset < 0 )
		{
			$offset = 0;
		}
		if ( $offset > MAX_OFFSET )
		{
			$offset = MAX_OFFSET;
		}
		return $offset;
	}

	/** Normalize one since/until value.  null = absent, false = invalid. */
	function _normalizeTimeValue( $value, $isUntil )
	{
		if ( $value === null || $value === "" )
		{
			return null;
		}

		// Unix seconds, as a JSON number or a decimal string.
		if ( is_int( $value ) || ( is_string( $value ) && preg_match( '/^[0-9]{1,10}$/', $value ) ) )
		{
			$epoch = (int)$value;
			if ( $epoch < 0 || $epoch > 4102444800 )  // 2100-01-01
			{
				return false;
			}
			return date( "Y-m-d H:i:s", $epoch );
		}

		if ( !is_string( $value ) )
		{
			return false;
		}

		if ( !preg_match( '/^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2}):(\d{2}))?$/', $value, $matches ) )
		{
			return false;
		}

		$year = (int)$matches[1];
		$month = (int)$matches[2];
		$day = (int)$matches[3];
		if ( !checkdate( $month, $day, $year ) )
		{
			return false;
		}

		if ( isset( $matches[4] ) && $matches[4] !== "" )
		{
			$hour = (int)$matches[4];
			$minute = (int)$matches[5];
			$second = (int)$matches[6];
			if ( $hour > 23 || $minute > 59 || $second > 59 )
			{
				return false;
			}
			$time = sprintf( "%02d:%02d:%02d", $hour, $minute, $second );
		}
		else
		{
			// A bare date covers the whole day for until.
			$time = $isUntil ? "23:59:59" : "00:00:00";
		}

		return sprintf( "%04d-%02d-%02d %s", $year, $month, $day, $time );
	}

	/** Build a validated SQL WHERE fragment for the since/until filters. */
	function _timeFilters( $body, $column, &$error = null )
	{
		$error = null;
		$since = _normalizeTimeValue( isset( $body["since"] ) ? $body["since"] : null, false );
		$until = _normalizeTimeValue( isset( $body["until"] ) ? $body["until"] : null, true );

		if ( $since === false )
		{
			$error = "invalid since (use YYYY-MM-DD, YYYY-MM-DD HH:MM:SS or Unix seconds)";
			return null;
		}
		if ( $until === false )
		{
			$error = "invalid until (use YYYY-MM-DD, YYYY-MM-DD HH:MM:SS or Unix seconds)";
			return null;
		}
		if ( $since !== null && $until !== null && strcmp( $since, $until ) > 0 )
		{
			$error = "since must not be after until";
			return null;
		}

		// The normalized values contain only digits, '-', ' ', ':'.
		$parts = array();
		if ( $since !== null )
		{
			$parts[] = $column . " >= '" . $since . "'";
		}
		if ( $until !== null )
		{
			$parts[] = $column . " <= '" . $until . "'";
		}

		return array(
			"clause" => count( $parts ) > 0 ? " WHERE " . implode( " AND ", $parts ) : "",
			"since" => $since,
			"until" => $until,
		);
	}

	/** Run a read-only SQLite query and return CSV rows as associative arrays. */
	function _sqliteQuery( $query, $limit = null, $offset = null )
	{
		$dbFile = _dbPath();

		if ( !is_file( $dbFile ) || !is_readable( $dbFile ) )
		{
			return array( "rows" => array(), "count" => 0, "returnVal" => 1 );
		}

		$fullQuery = $query;
		if ( $limit !== null )
		{
			$fullQuery .= " LIMIT " . (int)$limit;
			if ( $offset !== null && (int)$offset > 0 )
			{
				$fullQuery .= " OFFSET " . (int)$offset;
			}
		}

		// -readonly: this module never writes to the database, so no WAL
		// checkpoint and no permission changes are performed here.
		// escapeshellarg() keeps the SQL in a single argv entry.
		// sudo -n: never wait for a password prompt that a web request cannot answer.
		if ( !function_exists( "exec" ) )
		{
			return array( "rows" => array(), "count" => 0, "returnVal" => 1 );
		}

		$cmd = "sudo -n /usr/bin/sqlite3 -readonly -header -csv "
			. escapeshellarg( $dbFile ) . " " . escapeshellarg( $fullQuery );

		$lines = array();
		$returnVal = 0;
		exec( $cmd, $lines, $returnVal );

		if ( $returnVal !== 0 )
		{
			return array( "rows" => array(), "count" => 0, "returnVal" => $returnVal );
		}

		// Parse the CSV with fgetcsv so quoted separators/newlines survive.
		$rows = array();
		$stream = fopen( "php://temp", "w+" );
		if ( $stream === false )
		{
			return array( "rows" => array(), "count" => 0, "returnVal" => 1 );
		}
		fwrite( $stream, implode( "\n", $lines ) );
		rewind( $stream );

		$headers = fgetcsv( $stream, 0, ",", '"', "\\" );
		if ( $headers === false || $headers === array( null ) )
		{
			fclose( $stream );
			return array( "rows" => array(), "count" => 0, "returnVal" => 0 );
		}
		$headers = array_map( "trim", $headers );

		while ( ( $values = fgetcsv( $stream, 0, ",", '"', "\\" ) ) !== false )
		{
			if ( $values === array( null ) || count( $values ) !== count( $headers ) )
			{
				continue;
			}
			$row = array();
			foreach ( $headers as $idx => $header )
			{
				$row[$header] = $values[$idx] !== null ? $values[$idx] : "";
			}
			$rows[] = $row;
		}
		fclose( $stream );

		return array( "rows" => $rows, "count" => count( $rows ), "returnVal" => 0 );
	}

	/** Return true/false for table presence, or null when the DB is unusable. */
	function _tableExists( $table )
	{
		$query = "SELECT name FROM sqlite_master WHERE type = 'table' AND name = '"
			. str_replace( "'", "''", (string)$table ) . "'";
		$result = _sqliteQuery( $query, 1 );
		if ( $result["returnVal"] !== 0 )
		{
			return null;
		}
		return $result["count"] > 0;
	}

	/** Read and decode the machine config JSON. */
	function _loadConfig( &$error = null, &$errorCode = null )
	{
		$error = null;
		$errorCode = 500;

		$configPath = _configPath();
		if ( !is_string( $configPath ) || !is_file( $configPath ) || !is_readable( $configPath ) )
		{
			$error = "config file not found";
			return null;
		}

		$size = filesize( $configPath );
		if ( $size === false || $size > MAX_FILE_BYTES )
		{
			$error = "config file too large (max " . MAX_FILE_BYTES . " bytes)";
			return null;
		}

		$configJson = file_get_contents( $configPath );
		if ( !is_string( $configJson ) )
		{
			$error = "failed to read config file";
			return null;
		}

		$config = json_decode( $configJson, true );
		if ( !is_array( $config ) )
		{
			$error = "config file is not valid JSON";
			return null;
		}

		return $config;
	}

	/** Find a serial-number value in the config without returning the raw value. */
	function _findSerial( $value, $depth = 0 )
	{
		if ( !is_array( $value ) || $depth > 8 )
		{
			return null;
		}

		// Prefer known identity keys at this level before descending, so a
		// nested "serial" in an unrelated object cannot win.
		$priority = array( "grindersn", "serialnumber", "machineserial", "machineserialnumber", "serial" );
		foreach ( $priority as $wanted )
		{
			foreach ( $value as $key => $child )
			{
				if ( is_string( $key ) && strtolower( $key ) === $wanted )
				{
					if ( is_string( $child ) && trim( $child ) !== "" )
					{
						return trim( $child );
					}
					if ( is_int( $child ) )
					{
						return (string)$child;
					}
				}
			}
		}

		foreach ( $value as $child )
		{
			$found = _findSerial( $child, $depth + 1 );
			if ( $found !== null )
			{
				return $found;
			}
		}

		return null;
	}

	/** Map the systemInfo grinderType value to its name. */
	function _grinderTypeName( $type )
	{
		global $E64LOCAL_GRINDER_TYPE_NAMES;
		return isset( $E64LOCAL_GRINDER_TYPE_NAMES[$type] )
			? $E64LOCAL_GRINDER_TYPE_NAMES[$type]
			: "unknown";
	}

	/** Build the capabilities document used for client handshakes. */
	function _capabilitiesData()
	{
		global $E64LOCAL_ROUTES, $E64LOCAL_ACTION_META_ROUTES;

		$actionData = _actionCapabilities();
		$routes = $E64LOCAL_ROUTES;
		if ( $actionData["enabled"] )
		{
			$routes = array_merge( $routes, $E64LOCAL_ACTION_META_ROUTES );
		}

		return array(
			"schema" => "e64local-api-v" . E64LOCAL_API_VERSION,
			"route" => "capabilities",
			"apiVersion" => E64LOCAL_API_VERSION,
			"routes" => $routes,
			// The catalog is always reported so an operator can see why an
			// action is absent; only a valid policy makes the routes usable.
			"actions" => $actionData,
			"features" => array(
				"pagination" => true,
				"timeFilters" => true,
				"logRowTypes" => "strings",
				"recipeExport" => "json",
				"csvExport" => false,
				"singleRecipe" => false,
				"machineIdentity" => "serial-sha256",
				"wssToken" => true,
				"actions" => (bool)$actionData["enabled"],
				"destructiveActions" => (bool)$actionData["destructiveEnabled"],
			),
			"limits" => array(
				"maxRows" => MAX_ROWS_GRIND_LOG,
				"defaultRows" => array(
					"alert_log" => DEFAULT_ROWS_ALERT_LOG,
					"grind_log" => DEFAULT_ROWS_GRIND_LOG,
					"service_log" => DEFAULT_ROWS_SERVICE_LOG,
				),
				"maxOffset" => MAX_OFFSET,
				"maxFileBytes" => MAX_FILE_BYTES,
				"maxRequestBytes" => MAX_REQUEST_BYTES,
			),
			"serverTime" => time(),
			"devMode" => true,
		);
	}

	/** Build the machine-identity document without exposing the raw serial. */
	function _machineData( &$error = null, &$errorCode = null )
	{
		global $systemVariantCc;

		$config = _loadConfig( $error, $errorCode );
		if ( $config === null )
		{
			return null;
		}

		$type = isset( $config["grinderType"] ) && is_numeric( $config["grinderType"] )
			? (int)$config["grinderType"]
			: null;
		$subType = isset( $config["grinderSubType"] ) && is_numeric( $config["grinderSubType"] )
			? (int)$config["grinderSubType"]
			: null;
		$serial = _findSerial( $config );

		$issue = "";
		if ( is_readable( "/etc/issue" ) )
		{
			$rawIssue = file_get_contents( "/etc/issue" );
			if ( is_string( $rawIssue ) )
			{
				$line = strtok( $rawIssue, "\r\n" );
				$issue = _redactText( substr( (string)$line, 0, 512 ) );
			}
		}

		return array(
			"schema" => "e64local-api-v" . E64LOCAL_API_VERSION,
			"route" => "machine",
			"variant" => isset( $systemVariantCc ) ? (string)$systemVariantCc : "unknown",
			"model" => $type !== null ? _grinderTypeName( $type ) : "unknown",
			"grinderType" => $type,
			"grinderTypeName" => $type !== null ? _grinderTypeName( $type ) : "unknown",
			"grinderSubType" => $subType,
			"firmware" => $issue,
			"devMode" => true,
			"serialPresent" => $serial !== null,
			"serialSha256" => $serial !== null ? hash( "sha256", $serial ) : null,
			"serialNote" => "the raw serial number is never returned by this API",
		);
	}

	/** Check if the owner token is valid. Fails closed on any read problem. */
	function _checkOwnerToken( $postContent, &$error = null )
	{
		// Get token from header first, then from the JSON POST body
		$token = null;
		if ( isset( $_SERVER["HTTP_X_E64_LOCAL_TOKEN"] ) )
		{
			$token = $_SERVER["HTTP_X_E64_LOCAL_TOKEN"];
		}
		else
		{
			$post = _decodeBody( $postContent );
			if ( isset( $post["token"] ) )
			{
				$token = $post["token"];
			}
		}

		// Tokens are strings; anything else is malformed input.
		if ( !is_string( $token ) || $token === "" )
		{
			$error = "owner token required";
			return false;
		}

		if ( !is_file( E64LOCAL_TOKEN_FILE ) || !is_readable( E64LOCAL_TOKEN_FILE ) )
		{
			$error = "local API not configured (token file missing)";
			return false;
		}

		$rawToken = file_get_contents( E64LOCAL_TOKEN_FILE );
		if ( !is_string( $rawToken ) )
		{
			$error = "local API not configured (token file unreadable)";
			return false;
		}

		$expectedToken = trim( $rawToken );
		if ( $expectedToken === "" )
		{
			$error = "local API not configured (token file empty)";
			return false;
		}

		// Constant-time comparison
		if ( !hash_equals( $expectedToken, $token ) )
		{
			$error = "invalid owner token";
			return false;
		}

		return true;
	}

	/** True when a settings/config key name must be redacted. */
	function _isSensitiveKey( $key )
	{
		global $E64LOCAL_REDACT_KEY_SUFFIXES, $E64LOCAL_REDACT_KEY_EXACT;

		if ( !is_string( $key ) || $key === "" )
		{
			return false;
		}

		$lower = strtolower( $key );

		foreach ( $E64LOCAL_REDACT_KEY_EXACT as $exact )
		{
			if ( $lower === $exact )
			{
				return true;
			}
		}

		foreach ( $E64LOCAL_REDACT_KEY_SUFFIXES as $suffix )
		{
			$len = strlen( $suffix );
			if ( strlen( $lower ) >= $len && substr( $lower, -$len ) === $suffix )
			{
				return true;
			}
		}

		return false;
	}

	/** Redact sensitive settings keys from an associative array. */
	function _redactSettings( $settings )
	{
		$redacted = array();
		$result = array();

		foreach ( $settings as $key => $value )
		{
			if ( _isSensitiveKey( $key ) )
			{
				$redacted[] = $key;
				// Omit the value entirely
			}
			else
			{
				$result[$key] = $value;
			}
		}

		return array( "rows" => $result, "redacted" => $redacted );
	}

	/** Recursively replace sensitive config values with "<redacted>". */
	function _redactConfigValue( $value, $prefix, &$redacted )
	{
		if ( !is_array( $value ) )
		{
			return $value;
		}

		$result = array();
		foreach ( $value as $key => $child )
		{
			$path = $prefix === "" ? (string)$key : $prefix . "." . $key;
			if ( _isSensitiveKey( (string)$key ) )
			{
				$redacted[] = $path;
				$result[$key] = "<redacted>";
				continue;
			}
			$result[$key] = _redactConfigValue( $child, $path, $redacted );
		}
		return $result;
	}

	/** Redact sensitive config keys from a decoded config array. */
	function _redactConfig( $config )
	{
		$redacted = array();

		if ( !is_array( $config ) )
		{
			return array( "config" => $config, "redacted" => $redacted );
		}

		return array( "config" => _redactConfigValue( $config, "", $redacted ), "redacted" => $redacted );
	}

	/** Redact sensitive patterns from free-text content. */
	function _redactText( $text )
	{
		if ( !is_string( $text ) || $text === "" )
		{
			return $text;
		}

		$patterns = array(
			'/(\bpassword\b|\bpasswd\b|\bpwd\b|\bpsk\b|\bpass\b|\bsecret\b|\btoken\b|\bbearer\b|\bsession\b|\bssid\b)\s*(?::|=|\s)\s*["\']?[^\s"\'&\n]{4,}["\']?/i',
			'/\bSN[\s:#=_-]*[A-Za-z0-9-]{4,}/',
			'/\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b/i',  // MAC addresses
			'/\b\d{1,3}(?:\.\d{1,3}){3}\b/',             // IPv4 addresses
		);

		$redacted = $text;
		foreach ( $patterns as $pattern )
		{
			$next = preg_replace( $pattern, "<redacted>", $redacted );
			if ( $next === null )
			{
				// A broken pattern must never leak the original text.
				return "<redacted>";
			}
			$redacted = $next;
		}

		return $redacted;
	}

	/** Apply the text redaction to the free-text columns of log rows. */
	function _redactLogRows( $rows, $fields )
	{
		foreach ( $rows as $idx => $row )
		{
			foreach ( $fields as $field )
			{
				if ( isset( $row[$field] ) && is_string( $row[$field] ) )
				{
					$rows[$idx][$field] = _redactText( $row[$field] );
				}
			}
		}
		return $rows;
	}

	/** Check if a file path is allowed for the file route. */
	function _isAllowedFile( $path )
	{
		global $E64LOCAL_FILE_ALLOWLIST, $E64LOCAL_FILE_ALLOWED_DIRS;

		if ( !is_string( $path ) || $path === "" || $path[0] !== "/" || strpos( $path, "\0" ) !== false )
		{
			return false;
		}

		// Reject symlinks and hard links outright, then work with the resolved
		// path only.  A hard link inside /log must not expose /db or /etc.
		if ( is_link( $path ) )
		{
			return false;
		}
		$linkStat = @lstat( $path );
		if ( $linkStat === false || ( isset( $linkStat["nlink"] ) && $linkStat["nlink"] > 1 ) )
		{
			return false;
		}

		$realPath = realpath( $path );
		if ( $realPath === false || !is_file( $realPath ) )
		{
			return false;
		}

		// Exact allowlist (resolved path equality, no prefix matching).
		foreach ( $E64LOCAL_FILE_ALLOWLIST as $allowed )
		{
			if ( $realPath === $allowed )
			{
				return true;
			}
		}

		// Directory allowlist: walk the resolved parent chain and compare each
		// directory by exact path equality.
		$dir = realpath( dirname( $realPath ) );
		$depth = 0;
		while ( $dir !== false && $dir !== "/" && $depth < 32 )
		{
			foreach ( $E64LOCAL_FILE_ALLOWED_DIRS as $allowedDir )
			{
				$realAllowedDir = realpath( $allowedDir );
				if ( $realAllowedDir !== false && $dir === $realAllowedDir )
				{
					return true;
				}
			}
			$parent = realpath( dirname( $dir ) );
			if ( $parent === false || $parent === $dir )
			{
				break;
			}
			$dir = $parent;
			$depth++;
		}

		return false;
	}

	/** Read a file and return its content (text or base64). */
	function _readFile( $path, &$error = null, &$errorCode = null )
	{
		$errorCode = 0;

		if ( !_isAllowedFile( $path ) )
		{
			$error = "file not in allowlist";
			$errorCode = 400;
			return null;
		}

		$realPath = realpath( $path );
		if ( $realPath === false )
		{
			$error = "file not found";
			$errorCode = 400;
			return null;
		}

		if ( !is_readable( $realPath ) )
		{
			$error = "file not readable";
			$errorCode = 500;
			return null;
		}

		// Bounded read: never buffer more than the cap plus one byte.
		$handle = fopen( $realPath, "rb" );
		if ( $handle === false )
		{
			$error = "failed to open file";
			$errorCode = 500;
			return null;
		}

		$content = "";
		$readFailed = false;
		while ( strlen( $content ) <= MAX_FILE_BYTES )
		{
			$chunk = fread( $handle, MAX_FILE_BYTES + 1 - strlen( $content ) );
			if ( $chunk === false )
			{
				$readFailed = true;
				break;
			}
			if ( $chunk === "" )
			{
				break;
			}
			$content .= $chunk;
		}
		fclose( $handle );

		if ( $readFailed )
		{
			$error = "failed to read file";
			$errorCode = 500;
			return null;
		}

		if ( strlen( $content ) > MAX_FILE_BYTES )
		{
			$error = "file too large (max " . MAX_FILE_BYTES . " bytes)";
			$errorCode = 400;
			return null;
		}

		// Strip a UTF-8 BOM before the text check
		if ( preg_match( '/^\xEF\xBB\xBF/', $content ) )
		{
			$content = substr( $content, 3 );
		}

		// Try to detect if it's text (printable ASCII + common UTF-8)
		if ( preg_match( '/^[\x09\x0A\x0D\x20-\x7E\x80-\xFF]*$/s', $content ) )
		{
			// Apply text redaction
			$content = _redactText( $content );
			return array( "encoding" => "text", "content" => $content );
		}

		// Binary or non-UTF-8: return as base64
		return array( "encoding" => "base64", "content" => base64_encode( $content ) );
	}

	/** Mint a fresh WSS token using the vendor's createToken(). */
	function _mintWsToken()
	{
		if ( !function_exists( "createToken" ) )
		{
			return null;
		}

		// Call the vendor's createToken which writes /tmp/tok_<token>
		// and sets $_SESSION['token'] and $sessionToken global
		createToken();

		global $sessionToken;

		if ( !is_string( $sessionToken ) || $sessionToken === "" )
		{
			return null;
		}

		// The token becomes part of a path below; refuse anything unusual.
		if ( !preg_match( '/^[A-Za-z0-9._-]+$/', $sessionToken ) )
		{
			return null;
		}

		$tokenFile = "/tmp/tok_" . $sessionToken;
		if ( !is_file( $tokenFile ) || !is_readable( $tokenFile ) )
		{
			return null;
		}

		$rawToken = file_get_contents( $tokenFile );
		$tokenData = is_string( $rawToken ) ? json_decode( $rawToken, true ) : null;
		$expires = ( is_array( $tokenData ) && isset( $tokenData["expires"] ) )
			? (int)$tokenData["expires"]
			: ( time() + 300 );

		return array(
			"token" => $sessionToken,
			"expires" => $expires,
		);
	}

	// --- Route handlers --------------------------------------------------------------

	/** Handle grind_log route. */
	function _handleGrindLog( $postContent, &$returnJson, &$success, &$returnVal )
	{
		$body = _decodeBody( $postContent );
		$limit = _limitFromBody( $body, DEFAULT_ROWS_GRIND_LOG, MAX_ROWS_GRIND_LOG );
		$offset = _offsetFromBody( $body );

		$timeError = null;
		$filters = _timeFilters( $body, "grind_log.grind_date_time", $timeError );
		if ( $filters === null )
		{
			_failResponse( $returnJson, $success, $returnVal, 400, $timeError );
			return;
		}

		$query = "" .
			"SELECT " .
			"  grind_log.grind_id, grind_log.grind_uuid, grind_log.grind_date_time, " .
			"  grind_log.recipe_index, grind_log.recipe_cpr_id, grind_log.recipe_data_id, " .
			"  grind_log.grind_ddd, grind_log.grind_duration, grind_log.grind_duration_noload, " .
			"  grind_log.grind_weight, grind_log.grind_successfull, " .
			"  grind_log.grind_trigger_id, grind_trigger_modes.grind_trigger_name AS grind_trigger, " .
			"  grind_log.recipe_gbs_enabled, grind_log.grind_debug_data, " .
			"  recipe_data.recipe_uuid AS recipe_uuid, recipe_data.recipe_mode_id, " .
			"  recipe_modes.recipe_mode_name AS recipe_mode, " .
			"  recipe_data.recipe_amount, recipe_data.recipe_type_id, " .
			"  recipe_types.recipe_type_name AS recipe_type, " .
			"  recipe_data.recipe_icon_id, recipe_icons.recipe_icon_name AS recipe_icon, " .
			"  recipe_data.recipe_coarseness, recipe_data.recipe_brew_time, " .
			"  recipe_data.recipe_brew_weight " .
			"FROM grind_log " .
			"LEFT JOIN recipe_data ON grind_log.recipe_data_id = recipe_data.recipe_data_id " .
			"LEFT JOIN recipe_modes ON recipe_data.recipe_mode_id = recipe_modes.recipe_mode_id " .
			"LEFT JOIN recipe_types ON recipe_data.recipe_type_id = recipe_types.recipe_type_id " .
			"LEFT JOIN recipe_icons ON recipe_data.recipe_icon_id = recipe_icons.recipe_icon_id " .
			"LEFT JOIN grind_trigger_modes ON grind_log.grind_trigger_id = grind_trigger_modes.grind_trigger_id " .
			$filters["clause"] .
			"ORDER BY grind_log.grind_id DESC";

		$result = _sqliteQuery( $query, $limit, $offset );

		if ( $result["returnVal"] !== 0 )
		{
			_failResponse(
				$returnJson,
				$success,
				$returnVal,
				500,
				"database query failed",
				"sqlite3 exit code: " . $result["returnVal"]
			);
			return;
		}

		_okResponse( $returnJson, $success, $returnVal, array(
			"schema" => "e64local-api-v" . E64LOCAL_API_VERSION,
			"route" => "grind_log",
			"rows" => _redactLogRows( $result["rows"], array( "grind_debug_data" ) ),
			"count" => $result["count"],
			"limit" => $limit,
			"offset" => $offset,
			"since" => $filters["since"],
			"until" => $filters["until"],
			"hasMore" => $result["count"] === $limit,
		) );
	}

	/** Handle service_log route. */
	function _handleServiceLog( $postContent, &$returnJson, &$success, &$returnVal )
	{
		$body = _decodeBody( $postContent );
		$limit = _limitFromBody( $body, DEFAULT_ROWS_SERVICE_LOG, MAX_ROWS_SERVICE_LOG );
		$offset = _offsetFromBody( $body );

		$timeError = null;
		$filters = _timeFilters( $body, "event_log.event_date_time", $timeError );
		if ( $filters === null )
		{
			_failResponse( $returnJson, $success, $returnVal, 400, $timeError );
			return;
		}

		$query = "" .
			"SELECT " .
			"  event_log.event_id, event_log.event_type_id, " .
			"  event_types.event_type_name AS event_type, " .
			"  event_log.event_date_time, event_log.event_details " .
			"FROM event_log " .
			"LEFT JOIN event_types ON event_log.event_type_id = event_types.event_type_id " .
			$filters["clause"] .
			"ORDER BY event_log.event_id DESC";

		$result = _sqliteQuery( $query, $limit, $offset );

		if ( $result["returnVal"] !== 0 )
		{
			_failResponse(
				$returnJson,
				$success,
				$returnVal,
				500,
				"database query failed",
				"sqlite3 exit code: " . $result["returnVal"]
			);
			return;
		}

		_okResponse( $returnJson, $success, $returnVal, array(
			"schema" => "e64local-api-v" . E64LOCAL_API_VERSION,
			"route" => "service_log",
			"rows" => _redactLogRows( $result["rows"], array( "event_details" ) ),
			"count" => $result["count"],
			"limit" => $limit,
			"offset" => $offset,
			"since" => $filters["since"],
			"until" => $filters["until"],
			"hasMore" => $result["count"] === $limit,
		) );
	}

	/** Handle alert_log route. */
	function _handleAlertLog( $postContent, &$returnJson, &$success, &$returnVal )
	{
		$body = _decodeBody( $postContent );
		$limit = _limitFromBody( $body, DEFAULT_ROWS_ALERT_LOG, MAX_ROWS_ALERT_LOG );
		$offset = _offsetFromBody( $body );

		$timeError = null;
		$filters = _timeFilters( $body, "alert_log.alert_date_time", $timeError );
		if ( $filters === null )
		{
			_failResponse( $returnJson, $success, $returnVal, 400, $timeError );
			return;
		}

		$exists = _tableExists( "alert_log" );
		if ( $exists === null )
		{
			_failResponse( $returnJson, $success, $returnVal, 500, "database query failed" );
			return;
		}
		if ( $exists === false )
		{
			// alert_log is absent on some firmware generations.  This is a
			// schema difference, not a query error, so clients can poll it.
			_okResponse( $returnJson, $success, $returnVal, array(
				"schema" => "e64local-api-v" . E64LOCAL_API_VERSION,
				"route" => "alert_log",
				"rows" => array(),
				"count" => 0,
				"limit" => $limit,
				"offset" => $offset,
				"since" => $filters["since"],
				"until" => $filters["until"],
				"hasMore" => false,
				"note" => "alert_log table not present on this firmware",
			) );
			return;
		}

		$query = "" .
			"SELECT " .
			"  alert_log.alert_id, alert_log.alert_type_id, " .
			"  alert_types.alert_type_name AS alert_type, " .
			"  alert_log.alert_date_time, alert_log.alert_details, alert_log.alert_active " .
			"FROM alert_log " .
			"LEFT JOIN alert_types ON alert_log.alert_type_id = alert_types.alert_type_id " .
			$filters["clause"] .
			"ORDER BY alert_log.alert_id DESC";

		$result = _sqliteQuery( $query, $limit, $offset );

		if ( $result["returnVal"] !== 0 )
		{
			_failResponse(
				$returnJson,
				$success,
				$returnVal,
				500,
				"database query failed",
				"sqlite3 exit code: " . $result["returnVal"]
			);
			return;
		}

		_okResponse( $returnJson, $success, $returnVal, array(
			"schema" => "e64local-api-v" . E64LOCAL_API_VERSION,
			"route" => "alert_log",
			"rows" => _redactLogRows( $result["rows"], array( "alert_details" ) ),
			"count" => $result["count"],
			"limit" => $limit,
			"offset" => $offset,
			"since" => $filters["since"],
			"until" => $filters["until"],
			"hasMore" => $result["count"] === $limit,
		) );
	}

	/** Handle portafilters route. */
	function _handlePortafilters( $postContent, &$returnJson, &$success, &$returnVal )
	{
		$query = "SELECT portafilter_id, weight, weight_tolerance, recipe_index FROM portafilters ORDER BY portafilter_id";

		$result = _sqliteQuery( $query, null );

		if ( $result["returnVal"] !== 0 )
		{
			_failResponse(
				$returnJson,
				$success,
				$returnVal,
				500,
				"database query failed",
				"sqlite3 exit code: " . $result["returnVal"]
			);
			return;
		}

		_okResponse( $returnJson, $success, $returnVal, array(
			"schema" => "e64local-api-v" . E64LOCAL_API_VERSION,
			"route" => "portafilters",
			"rows" => $result["rows"],
			"count" => $result["count"],
		) );
	}

	/** Handle recipes route. */
	function _handleRecipes( $postContent, &$returnJson, &$success, &$returnVal )
	{
		$query = "" .
			"SELECT " .
			"  recipe_entries.recipe_index, recipe_entries.recipe_data_id, " .
			"  recipe_entries.recipe_active, recipe_entries.recipe_cpr_id, " .
			"  recipe_data.recipe_uuid, recipe_data.recipe_mode_id, " .
			"  recipe_modes.recipe_mode_name AS recipe_mode, " .
			"  recipe_data.recipe_amount, recipe_data.recipe_type_id, " .
			"  recipe_types.recipe_type_name AS recipe_type, " .
			"  recipe_data.recipe_icon_id, recipe_icons.recipe_icon_name AS recipe_icon, " .
			"  recipe_data.recipe_coarseness, recipe_data.recipe_brew_time, " .
			"  recipe_data.recipe_brew_weight " .
			"FROM recipe_entries " .
			"LEFT JOIN recipe_data ON recipe_entries.recipe_data_id = recipe_data.recipe_data_id " .
			"LEFT JOIN recipe_modes ON recipe_data.recipe_mode_id = recipe_modes.recipe_mode_id " .
			"LEFT JOIN recipe_types ON recipe_data.recipe_type_id = recipe_types.recipe_type_id " .
			"LEFT JOIN recipe_icons ON recipe_data.recipe_icon_id = recipe_icons.recipe_icon_id " .
			"ORDER BY recipe_entries.recipe_index";

		$result = _sqliteQuery( $query, null );

		if ( $result["returnVal"] !== 0 )
		{
			_failResponse(
				$returnJson,
				$success,
				$returnVal,
				500,
				"database query failed",
				"sqlite3 exit code: " . $result["returnVal"]
			);
			return;
		}

		_okResponse( $returnJson, $success, $returnVal, array(
			"schema" => "e64local-api-v" . E64LOCAL_API_VERSION,
			"route" => "recipes",
			"rows" => $result["rows"],
			"count" => $result["count"],
		) );
	}

	/** Handle settings route. */
	function _handleSettings( $postContent, &$returnJson, &$success, &$returnVal )
	{
		$query = "SELECT key, value FROM settings ORDER BY key";

		$result = _sqliteQuery( $query, null );

		if ( $result["returnVal"] !== 0 )
		{
			_failResponse(
				$returnJson,
				$success,
				$returnVal,
				500,
				"database query failed",
				"sqlite3 exit code: " . $result["returnVal"]
			);
			return;
		}

		// Build key-value pairs.  Values stay strings: the settings table is
		// untyped text and the API does not guess types.
		$settings = array();
		foreach ( $result["rows"] as $row )
		{
			$key = isset( $row["key"] ) ? $row["key"] : "";
			$value = isset( $row["value"] ) ? $row["value"] : "";
			if ( $key !== "" )
			{
				$settings[$key] = $value;
			}
		}

		// Apply redaction
		$redacted = _redactSettings( $settings );

		_okResponse( $returnJson, $success, $returnVal, array(
			"schema" => "e64local-api-v" . E64LOCAL_API_VERSION,
			"route" => "settings",
			"settings" => (object)$redacted["rows"],
			"redacted" => $redacted["redacted"],
			"count" => count( $redacted["rows"] ),
		) );
	}

	/** Handle config route. */
	function _handleConfig( $postContent, &$returnJson, &$success, &$returnVal )
	{
		$error = null;
		$errorCode = 500;
		$config = _loadConfig( $error, $errorCode );

		if ( $config === null )
		{
			_failResponse( $returnJson, $success, $returnVal, $errorCode, $error );
			return;
		}

		// Apply redaction
		$redacted = _redactConfig( $config );

		// Add metadata
		$redacted["config"]["_e64local_schema"] = "e64local-api-v" . E64LOCAL_API_VERSION;
		$redacted["config"]["_e64local_route"] = "config";

		_okResponse( $returnJson, $success, $returnVal, array(
			"schema" => "e64local-api-v" . E64LOCAL_API_VERSION,
			"route" => "config",
			"config" => $redacted["config"],
			"redacted" => $redacted["redacted"],
		) );
	}

	/** Handle machine route. */
	function _handleMachine( $postContent, &$returnJson, &$success, &$returnVal )
	{
		$error = null;
		$errorCode = 500;
		$data = _machineData( $error, $errorCode );

		if ( $data === null )
		{
			_failResponse( $returnJson, $success, $returnVal, $errorCode, $error );
			return;
		}

		_okResponse( $returnJson, $success, $returnVal, $data );
	}

	/** Handle capabilities route. */
	function _handleCapabilities( $postContent, &$returnJson, &$success, &$returnVal )
	{
		_okResponse( $returnJson, $success, $returnVal, _capabilitiesData() );
	}

	/** Handle file route. */
	function _handleFile( $postContent, &$returnJson, &$success, &$returnVal )
	{
		$body = _decodeBody( $postContent );
		if ( !isset( $body["path"] ) || !is_string( $body["path"] ) )
		{
			_failResponse( $returnJson, $success, $returnVal, 400, "path parameter required" );
			return;
		}

		$path = $body["path"];
		$error = null;
		$errorCode = 400;
		$fileData = _readFile( $path, $error, $errorCode );

		if ( $fileData === null )
		{
			_failResponse( $returnJson, $success, $returnVal, $errorCode, $error );
			return;
		}

		_okResponse( $returnJson, $success, $returnVal, array(
			"schema" => "e64local-api-v" . E64LOCAL_API_VERSION,
			"route" => "file",
			"path" => $path,
			"encoding" => $fileData["encoding"],
			"content" => $fileData["content"],
		) );
	}

	/** Handle ws_token route. */
	function _handleWsToken( $postContent, &$returnJson, &$success, &$returnVal )
	{
		$tokenData = _mintWsToken();

		if ( $tokenData === null )
		{
			_failResponse( $returnJson, $success, $returnVal, 500, "failed to mint WSS token" );
			return;
		}

		_okResponse( $returnJson, $success, $returnVal, array(
			"schema" => "e64local-api-v" . E64LOCAL_API_VERSION,
			"route" => "ws_token",
			"token" => $tokenData["token"],
			"expires" => $tokenData["expires"],
			"warning" => "this token authorises WSS commands; it is not a read-only data credential",
		) );
	}

	// --- Gated action layer ----------------------------------------------------------
	//
	// Everything below is reachable only when /db/e64local/actions.json exists,
	// is well formed, and says enabled=true.  Without that file every action
	// meta route fails closed with errorCode 403; the read-only routes above
	// keep working unchanged.  See docs/LOCAL_API.md §12 for the contract.

	define( "E64LOCAL_POLICY_FILE", "/db/e64local/actions.json" );
	define( "E64LOCAL_ACTION_DIR", "/db/e64local/actions" );
	define( "E64LOCAL_AUDIT_FILE", "/db/e64local/audit.jsonl" );
	define( "E64LOCAL_RATE_DIR", "/db/e64local/rate" );
	define( "E64LOCAL_ACTION_BACKUP_DIR", "/db/e64local/backup" );
	define( "E64LOCAL_ACTION_RUNNER", "/usr/local/bin/e64local-action-run" );
	define( "E64LOCAL_SQLITE3", "/usr/bin/sqlite3" );
	define( "E64LOCAL_ACTION_JOB_SCHEMA", "e64local-action-job-v1" );
	define( "E64LOCAL_ACTION_KEEP_SEC", 604800 );         // 7 days of records
	define( "E64LOCAL_ACTION_MAX_RECORDS", 500 );
	define( "E64LOCAL_ACTION_AUDIT_MAX_BYTES", 1048576 );
	define( "E64LOCAL_ACTION_AUDIT_KEEP", 3 );
	define( "E64LOCAL_ACTION_MAX_AUDIT_PAGE", 1000 );
	define( "E64LOCAL_ACTION_MIN_TIMEOUT_MS", 3000 );
	define( "E64LOCAL_ACTION_MAX_TIMEOUT_MS", 60000 );
	define( "E64LOCAL_BOOT_ID_FILE", "/proc/sys/kernel/random/boot_id" );
	define( "E64LOCAL_ACTION_RATE_SCHEMA", "e64local-action-rate-v2" );
	define( "E64LOCAL_ACTION_RATE_MINUTE_MS", 60000 );
	define( "E64LOCAL_ACTION_RATE_HOUR_MS", 3600000 );

	/*
	 * Action identifiers are NOT HTTP routes.  A client posts the identifier in
	 * the "route" field of action_prepare; action_execute then runs exactly the
	 * prepared action.  These five meta routes are the only action paths in the
	 * dispatch table, so a single POST can never start a motor.
	 */
	$E64LOCAL_ACTION_META_ROUTES = array(
		"action_audit",
		"action_cancel",
		"action_execute",
		"action_prepare",
		"action_status",
	);

	// Absolute code-side caps.  A policy may narrow these; it can never widen
	// them, so a hand-edited policy file cannot remove a safety bound.
	$E64LOCAL_ACTION_ABSOLUTE_BOUNDS = array(
		"targetWeightGr" => array( "min" => 0.1, "max" => 50.0 ),
		"grindTimeSec" => array( "min" => 0.5, "max" => 60.0 ),
		"manualGrindMs" => array( "min" => 100, "max" => 5000 ),
		"purgeMs" => array( "min" => 100, "max" => 10000 ),
		"agsaStepDd" => array( "min" => 1, "max" => 300 ),
		"fanDuty" => array( "min" => 0, "max" => 100 ),
		"brightness" => array( "min" => 0, "max" => 100 ),
		"brewTimeMs" => array( "min" => 0, "max" => 120000 ),
		"brewWeightMg" => array( "min" => 0, "max" => 200000 ),
		"recipeAmountMg" => array( "min" => 100, "max" => 100000 ),
		"recipeCoarseness" => array( "min" => 0, "max" => 10000 ),
		"standbySec" => array( "min" => 0, "max" => 86400 ),
		"settingsEntries" => array( "min" => 1, "max" => 8 ),
	);

	// Default per-bucket rate limits.  A policy may tighten a bucket; values
	// above these defaults are clamped.
	$E64LOCAL_ACTION_DEFAULT_RATES = array(
		"grind_start" => array( "perMinute" => 6, "perHour" => 30 ),
		"grind_stop" => array( "perMinute" => 60, "perHour" => 600 ),
		"agsa" => array( "perMinute" => 10, "perHour" => 120 ),
		"fan" => array( "perMinute" => 10, "perHour" => 120 ),
		"display" => array( "perMinute" => 30, "perHour" => 300 ),
		"settings_write" => array( "perMinute" => 30, "perHour" => 300 ),
		"recipe_write" => array( "perMinute" => 30, "perHour" => 300 ),
		"brew" => array( "perMinute" => 30, "perHour" => 300 ),
		"calibration" => array( "perMinute" => 2, "perHour" => 2 ),
		"destructive" => array( "perMinute" => 1, "perHour" => 1 ),
		"execute" => array( "perMinute" => 60, "perHour" => 600 ),
		"default" => array( "perMinute" => 30, "perHour" => 300 ),
	);

	/**
	 * The action catalog.
	 *
	 * "implemented" entries are dispatchable through prepare/execute.
	 * "unavailable" entries are reported to the client with the reason they are
	 * not dispatchable.  No entry in this array is an HTTP route.
	 *
	 * Evidence anchors point at the recovered vendor surface in this repository
	 * (docs/API_REFERENCE.md, docs/GRINDER_FEATURE_MAP.md, docs/SQLITE_SCHEMA.md,
	 * docs/API_REFERENCE.md §1247 for the ESP-side nozzle light).
	 */
	function _actionCatalog()
	{
		static $catalog = null;
		if ( $catalog !== null )
		{
			return $catalog;
		}

		$catalog = array(
			// --- Grinding ------------------------------------------------------
			"action_grind_start_gbw" => array(
				"risk" => "actuator",
				"status" => "implemented",
				"surface" => "wss",
				"command" => "StartGrindGbw",
				"bucket" => "grind_start",
				"destructive" => false,
				"timeoutMs" => 15000,
				"summary" => "Start a grind to a target weight in grams",
				"evidence" => "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 16 StartGrindGbw targetWeightGr:double); docs/DEV_MODE_AND_LOCAL_CONTROL.md#what-this-enables",
				"preconditions" => array( "update", "state", "wizard", "calibration", "portafilter" ),
			),
			"action_grind_start_gbt" => array(
				"risk" => "actuator",
				"status" => "implemented",
				"surface" => "wss",
				"command" => "StartGrindGbt",
				"bucket" => "grind_start",
				"destructive" => false,
				"timeoutMs" => 15000,
				"summary" => "Start a timed grind in seconds",
				"evidence" => "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 17 StartGrindGbt grindTimeSec:double)",
				"preconditions" => array( "update", "state", "wizard", "portafilter" ),
			),
			"action_grind_start_manual" => array(
				"risk" => "actuator",
				"status" => "implemented",
				"surface" => "wss",
				"command" => "StartGrindManual",
				"followUp" => array( "command" => "Stop", "afterMsParam" => "durationMs" ),
				"bucket" => "grind_start",
				"destructive" => false,
				"timeoutMs" => 12000,
				"summary" => "Run the motor for a bounded manual burst, then stop",
				"evidence" => "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 15 StartGrindManual, row 14 Stop); docs/GRINDER_FEATURE_MAP.md#3-grinding",
				"preconditions" => array( "update", "state", "wizard", "portafilter" ),
			),
			"action_grind_stop" => array(
				"risk" => "actuator",
				"status" => "implemented",
				"surface" => "wss",
				"command" => "Stop",
				"bucket" => "grind_stop",
				"destructive" => false,
				"timeoutMs" => 10000,
				"summary" => "Stop the current grind immediately",
				"evidence" => "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 14 Stop)",
				"preconditions" => array( "update" ),
			),
			"action_grind_purge" => array(
				"risk" => "actuator",
				"status" => "implemented",
				"surface" => "wss",
				"command" => "StartGrindGbt",
				"bucket" => "grind_start",
				"destructive" => false,
				"timeoutMs" => 15000,
				"summary" => "Run a short timed purge dose",
				"evidence" => "docs/GRINDER_FEATURE_MAP.md#3-grinding (Purge: Grinding.PurgeValueMs; GbT approximates); docs/SQLITE_SCHEMA.md (Grinding.PurgeValueMs default 200 ms); docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 17)",
				"preconditions" => array( "update", "state", "wizard", "portafilter" ),
			),

			// --- AGSA ----------------------------------------------------------
			"action_agsa_move" => array(
				"risk" => "actuator",
				"status" => "implemented",
				"surface" => "wss",
				"command" => "SetAgsaTargetDdValue",
				"bucket" => "agsa",
				"destructive" => false,
				"timeoutMs" => 15000,
				"summary" => "Move the AGSA to a disc-distance value near the current one",
				"evidence" => "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 35 SetAgsaTargetDdValue targetDdValue:int); docs/GRINDER_FEATURE_MAP.md#4-motor-and-mechanism",
				"preconditions" => array( "update", "state", "wizard" ),
			),
			"action_agsa_stop" => array(
				"risk" => "actuator",
				"status" => "implemented",
				"surface" => "wss",
				"command" => "StopAgsa",
				"bucket" => "agsa",
				"destructive" => false,
				"timeoutMs" => 10000,
				"summary" => "Stop AGSA motion",
				"evidence" => "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 36 StopAgsa)",
				"preconditions" => array( "update" ),
			),
			"action_agsa_configure" => array(
				"risk" => "state-changing",
				"status" => "implemented",
				"surface" => "sqlite",
				"sqlKind" => "settings_set_bulk",
				"bucket" => "settings_write",
				"destructive" => false,
				"timeoutMs" => 30000,
				"summary" => "Enable AGSA and set its allowlisted parameters",
				"evidence" => "docs/SQLITE_SCHEMA.md#complete-persistent-key-inventory (Agsa.AgsaUponRecipeChange, Agsa.AgsaStartWithRecipeDd, Agsa.ShowRecipeDdEnabled, Agsa.BlockageWarningThreshold); docs/SQLITE_SCHEMA.md#settings-and-configuration (INSERT OR REPLACE INTO settings)",
				"preconditions" => array( "update" ),
			),

			// --- Fan and display ----------------------------------------------
			"action_fan_set" => array(
				"risk" => "actuator",
				"status" => "implemented",
				"surface" => "wss",
				"command" => "SetFan1Duty",
				"bucket" => "fan",
				"destructive" => false,
				"timeoutMs" => 15000,
				"summary" => "Set fan duty and optional temperature control",
				"evidence" => "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (rows 22-24 SetFanTemperatureCtrlEnabled, SetFan1Duty, SetFan2Duty)",
				"preconditions" => array( "update" ),
			),
			"action_display_backlight" => array(
				"risk" => "state-changing",
				"status" => "implemented",
				"surface" => "wss",
				"command" => "SetBacklightBrightness",
				"bucket" => "display",
				"destructive" => false,
				"timeoutMs" => 15000,
				"summary" => "Set display brightness and backlight power",
				"evidence" => "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (rows 27-28 ToggleBacklightPower, SetBacklightBrightness)",
				"preconditions" => array( "update" ),
			),
			"action_led_set" => array(
				"risk" => "state-changing",
				"status" => "implemented",
				"surface" => "sqlite",
				"sqlKind" => "settings_set_bulk",
				"bucket" => "settings_write",
				"destructive" => false,
				"timeoutMs" => 30000,
				"summary" => "Set standby/permanent LED colour and enable flags",
				"evidence" => "docs/SQLITE_SCHEMA.md#settings-and-configuration (Standby.LedColorRgb = #7F7F7F); docs/GRINDER_FEATURE_MAP.md#7-settings (Brightness / LED)",
				"preconditions" => array( "update" ),
			),
			"action_language_set" => array(
				"risk" => "state-changing",
				"status" => "implemented",
				"surface" => "wss",
				"command" => "SetLanguage",
				"bucket" => "settings_write",
				"destructive" => false,
				"timeoutMs" => 15000,
				"summary" => "Set the UI language through the vendor ConfigManager",
				"evidence" => "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 40 SetLanguage language:string); docs/SQLITE_SCHEMA.md#settings-and-configuration (System.Language = en_US)",
				"preconditions" => array( "update" ),
			),
			"action_standby_configure" => array(
				"risk" => "state-changing",
				"status" => "implemented",
				"surface" => "sqlite",
				"sqlKind" => "settings_set_bulk",
				"bucket" => "settings_write",
				"destructive" => false,
				"timeoutMs" => 30000,
				"summary" => "Set standby timer, LED and shift-window settings",
				"evidence" => "docs/SQLITE_SCHEMA.md#complete-persistent-key-inventory (Standby.ActivationTimeSec, Standby.LedEnabled, Standby.ShiftTimesEnabled, Standby.ShiftTimeBegin/End)",
				"preconditions" => array( "update" ),
			),

			// --- Settings ------------------------------------------------------
			"action_settings_set" => array(
				"risk" => "state-changing",
				"status" => "implemented",
				"surface" => "sqlite",
				"sqlKind" => "settings_set_bulk",
				"bucket" => "settings_write",
				"destructive" => false,
				"timeoutMs" => 30000,
				"summary" => "Write 1..8 allowlisted machine settings",
				"evidence" => "docs/SQLITE_SCHEMA.md#settings-and-configuration (INSERT OR REPLACE INTO settings VALUES (:key, :value)); docs/GRINDER_FEATURE_MAP.md#7-settings",
				"preconditions" => array( "update" ),
			),

			// --- Recipes -------------------------------------------------------
			"action_recipe_activate" => array(
				"risk" => "state-changing",
				"status" => "implemented",
				"surface" => "sqlite",
				"sqlKind" => "recipe_activate",
				"bucket" => "recipe_write",
				"destructive" => false,
				"timeoutMs" => 30000,
				"summary" => "Select the active recipe slot",
				"evidence" => "docs/SQLITE_SCHEMA.md (recipe_entries.recipe_active; RecipeEntrySql::updateActive 0x004288a4)",
				"preconditions" => array( "update" ),
			),
			"action_recipe_create" => array(
				"risk" => "state-changing",
				"status" => "implemented",
				"surface" => "sqlite",
				"sqlKind" => "recipe_create",
				"bucket" => "recipe_write",
				"destructive" => false,
				"timeoutMs" => 30000,
				"summary" => "Create a recipe in a free slot",
				"evidence" => "docs/SQLITE_SCHEMA.md (recipe_data/recipe_entries columns; RecipeDataSql::insert 0x004269cc, RecipeEntrySql::update 0x00428248)",
				"preconditions" => array( "update" ),
			),
			"action_recipe_update" => array(
				"risk" => "state-changing",
				"status" => "implemented",
				"surface" => "sqlite",
				"sqlKind" => "recipe_update",
				"bucket" => "recipe_write",
				"destructive" => false,
				"timeoutMs" => 30000,
				"summary" => "Update the dose/time/DD fields of an existing recipe",
				"evidence" => "docs/SQLITE_SCHEMA.md (recipe_data columns; RecipeEntrySql::update 0x00428248)",
				"preconditions" => array( "update" ),
			),
			"action_recipe_delete" => array(
				"risk" => "destructive",
				"status" => "implemented",
				"surface" => "sqlite",
				"sqlKind" => "recipe_delete",
				"bucket" => "destructive",
				"destructive" => true,
				"timeoutMs" => 30000,
				"summary" => "Delete a non-active recipe slot",
				"evidence" => "docs/SQLITE_SCHEMA.md (recipe_data/recipe_entries); docs/GRINDER_FEATURE_MAP.md#5-recipes-and-presets (delete is destructive)",
				"preconditions" => array( "update" ),
			),

			// --- Calibration (owner decision: destructive gate) ----------------
			"action_calibration_loadcell" => array(
				"risk" => "destructive",
				"status" => "implemented",
				"surface" => "wss",
				"command" => "StartCalibration",
				"bucket" => "calibration",
				"destructive" => true,
				"timeoutMs" => 20000,
				"summary" => "Start the load-cell calibration sequence",
				"evidence" => "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 18 StartCalibration); docs/GRINDER_FEATURE_MAP.md#6-calibration",
				"preconditions" => array( "update", "state", "wizard", "role-limitation" ),
			),
			"action_calibration_tare" => array(
				"risk" => "destructive",
				"status" => "implemented",
				"surface" => "wss",
				"command" => "StartTara",
				"bucket" => "calibration",
				"destructive" => true,
				"timeoutMs" => 20000,
				"summary" => "Tare the scale",
				"evidence" => "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 19 StartTara); docs/GRINDER_FEATURE_MAP.md#6-calibration",
				"preconditions" => array( "update", "state", "wizard", "role-limitation" ),
			),
			"action_calibration_dd" => array(
				"risk" => "destructive",
				"status" => "implemented",
				"surface" => "wss",
				"command" => "CalibrateDdSensor",
				"bucket" => "calibration",
				"destructive" => true,
				"timeoutMs" => 20000,
				"summary" => "Calibrate the disc-distance sensor",
				"evidence" => "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 37 CalibrateDdSensor); docs/GRINDER_FEATURE_MAP.md#6-calibration",
				"preconditions" => array( "update", "state", "wizard", "role-limitation" ),
			),

			// --- Destructive maintenance ---------------------------------------
			"action_logs_clear" => array(
				"risk" => "destructive",
				"status" => "implemented",
				"surface" => "wss",
				"command" => "ResetLog",
				"bucket" => "destructive",
				"destructive" => true,
				"timeoutMs" => 15000,
				"summary" => "Clear the device logs",
				"evidence" => "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 21 ResetLog); docs/GRINDER_FEATURE_MAP.md#10-data-and-logs",
				"preconditions" => array( "update" ),
			),
			"action_statistics_reset" => array(
				"risk" => "destructive",
				"status" => "implemented",
				"surface" => "sqlite",
				"sqlKind" => "statistics_reset",
				"bucket" => "destructive",
				"destructive" => true,
				"timeoutMs" => 30000,
				"summary" => "Reset the statistics timestamps",
				"evidence" => "docs/SQLITE_SCHEMA.md (Statistics.Reset.TimeStamp, Statistics.Reset.Today.TimeStamp); docs/GRINDER_FEATURE_MAP.md#7-settings",
				"preconditions" => array( "update" ),
			),
			"action_driver_reset" => array(
				"risk" => "destructive",
				"status" => "implemented",
				"surface" => "wss",
				"command" => "ResetDriverConfig",
				"bucket" => "destructive",
				"destructive" => true,
				"timeoutMs" => 15000,
				"summary" => "Restore the driver configuration defaults",
				"evidence" => "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 34 ResetDriverConfig); docs/GRINDER_FEATURE_MAP.md#6-calibration",
				"preconditions" => array( "update" ),
			),

			// --- Brew events ----------------------------------------------------
			"action_brew_event_add" => array(
				"risk" => "state-changing",
				"status" => "implemented",
				"surface" => "wss",
				"command" => "AddBrewEvent",
				"bucket" => "brew",
				"destructive" => false,
				"timeoutMs" => 15000,
				"summary" => "Attach a brew event to a grind UUID",
				"evidence" => "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 38 AddBrewEvent); docs/GRINDER_FEATURE_MAP.md#10-data-and-logs",
				"preconditions" => array( "update" ),
			),

			// --- Reported as unavailable ---------------------------------------
			"action_fan_calibrate" => array(
				"risk" => "actuator",
				"status" => "unavailable",
				"code" => 422,
				"reason" => "CalibrateFan1/CalibrateFan2 has no recovered completion signal or duration bound, so a hard timeout cannot be guaranteed",
				"evidence" => "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (rows 25-26)",
			),
			"action_endurance_start" => array(
				"risk" => "actuator",
				"status" => "unavailable",
				"code" => 422,
				"reason" => "StartEnduranceTest is an unbounded loop and no host-side watchdog is installed that could guarantee a stop",
				"evidence" => "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 50); docs/LOCAL_API.md#129-owner-decisions (watchdog)",
			),
			"action_endurance_stop" => array(
				"risk" => "actuator",
				"status" => "unavailable",
				"code" => 422,
				"reason" => "no endurance run can be started through this API, so its stop primitive has nothing to stop",
				"evidence" => "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 51)",
			),
			"action_rc_input" => array(
				"risk" => "actuator",
				"status" => "unavailable",
				"code" => 422,
				"reason" => "the Rc* surface includes press/release pairs and long presses; a dropped release cannot be bounded or undone",
				"evidence" => "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (rows 41-49)",
			),
			"action_gbs_report" => array(
				"risk" => "state-changing",
				"status" => "unavailable",
				"code" => 422,
				"reason" => "GbsCreateReport replies with a non-standard envelope (or JSON null) instead of GrinderActionResult, so success cannot be verified",
				"evidence" => "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 39)",
			),
			"action_recipe_clone" => array(
				"risk" => "state-changing",
				"status" => "unavailable",
				"code" => 422,
				"reason" => "no vendor surface; clone is a compound read+create and is deferred until the create/update pair has field use",
				"evidence" => "docs/GRINDER_FEATURE_MAP.md#5-recipes-and-presets",
			),
			"action_recipe_import" => array(
				"risk" => "state-changing",
				"status" => "unavailable",
				"code" => 422,
				"reason" => "no vendor route; bulk import needs a schema-validated payload contract that this release does not define",
				"evidence" => "docs/GRINDER_FEATURE_MAP.md#5-recipes-and-presets",
			),
			"action_factory_reset" => array(
				"risk" => "destructive",
				"status" => "unavailable",
				"code" => 422,
				"reason" => "no REST/WSS factory-reset surface exists; the only recovered path is the physical emergency script that deletes sqlite_master, which is out of scope",
				"evidence" => "docs/SQLITE_SCHEMA.md#corruption-reset-retention-and-export (PRAGMA writable_schema; DELETE FROM sqlite_master); docs/GRINDER_FEATURE_MAP.md#15-features-impossible-or-unsafe-through-any-exposed-surface",
			),
		);

		return $catalog;
	}

	/**
	 * Return the gate state and the validated policy, failing closed.
	 *
	 * The policy is read on every call.  A PHP request is a fresh process in
	 * production, and re-reading keeps a mid-request policy change (or a test
	 * harness that flips the file) honest instead of serving a stale gate.
	 */
	function _actionGate( &$reason = null )
	{
		$state = array(
			"enabled" => false,
			"destructive" => false,
			"policy" => null,
			"reason" => null,
		);
		$reason = null;

		if ( !is_file( E64LOCAL_POLICY_FILE ) || !is_readable( E64LOCAL_POLICY_FILE ) )
		{
			$state["reason"] = "actions are not enabled (policy file missing)";
			$reason = $state["reason"];
			return $state;
		}

		$raw = @file_get_contents( E64LOCAL_POLICY_FILE );
		$policy = is_string( $raw ) ? json_decode( $raw, true ) : null;
		if ( !is_array( $policy ) )
		{
			$state["reason"] = "actions are not enabled (policy file is not valid JSON)";
			$reason = $state["reason"];
			return $state;
		}

		$enabled = isset( $policy["enabled"] ) && $policy["enabled"] === true;
		$version = isset( $policy["version"] ) ? $policy["version"] : null;
		$secret = isset( $policy["secret"] ) && is_string( $policy["secret"] ) ? $policy["secret"] : "";
		if ( !$enabled || $version !== 1 || preg_match( '/^[0-9a-f]{64}$/', $secret ) !== 1
			|| !isset( $policy["bounds"] ) || !is_array( $policy["bounds"] ) )
		{
			$state["reason"] = "actions are not enabled (policy file is invalid or unsupported)";
			$reason = $state["reason"];
			return $state;
		}

		$state["enabled"] = true;
		$state["destructive"] = isset( $policy["destructiveEnabled"] ) && $policy["destructiveEnabled"] === true;
		$state["policy"] = $policy;
		return $state;
	}

	/** Clamp a policy bound to the absolute code-side range. */
	function _actionBound( $policy, $name, $fallbackMin, $fallbackMax )
	{
		global $E64LOCAL_ACTION_ABSOLUTE_BOUNDS;
		$absolute = isset( $E64LOCAL_ACTION_ABSOLUTE_BOUNDS[$name] )
			? $E64LOCAL_ACTION_ABSOLUTE_BOUNDS[$name]
			: array( "min" => $fallbackMin, "max" => $fallbackMax );
		$min = $absolute["min"];
		$max = $absolute["max"];

		if ( isset( $policy["bounds"][$name] ) && is_array( $policy["bounds"][$name] ) )
		{
			$entry = $policy["bounds"][$name];
			if ( isset( $entry["min"] ) && is_numeric( $entry["min"] ) )
			{
				$min = max( $min, (float)$entry["min"] );
			}
			if ( isset( $entry["max"] ) && is_numeric( $entry["max"] ) )
			{
				$max = min( $max, (float)$entry["max"] );
			}
		}
		// Both ends are clamped into the absolute range again.  Without this a
		// policy whose min sits above the absolute max (or whose max sits below
		// the absolute min) would invert the range and hand out a bound wider
		// than the code allows; the clamp is module-side, never policy-side.
		$min = min( max( $min, $absolute["min"] ), $absolute["max"] );
		$max = min( max( $max, $absolute["min"] ), $absolute["max"] );
		// A policy that clamps to a single point is not a usable range; fall
		// back to the absolute range instead of refusing every value.  The
		// fallback can only be the wider absolute range, never a policy one.
		if ( $max <= $min )
		{
			$min = $absolute["min"];
			$max = $absolute["max"];
		}
		return array( "min" => $min, "max" => $max );
	}

	/** Deterministic, language-neutral canonical form of the normalized params. */
	function _actionCanonical( $value )
	{
		if ( is_array( $value ) )
		{
			$keys = array_keys( $value );
			sort( $keys, SORT_STRING );
			$parts = array();
			foreach ( $keys as $key )
			{
				$parts[] = "k" . strlen( (string)$key ) . ":" . (string)$key . "=" . _actionCanonical( $value[$key] );
			}
			return "a" . count( $parts ) . "{" . implode( ",", $parts ) . "}";
		}
		if ( is_bool( $value ) )
		{
			return "b:" . ( $value ? "1" : "0" );
		}
		if ( is_int( $value ) )
		{
			return "i:" . $value;
		}
		if ( is_float( $value ) )
		{
			return "d:" . number_format( $value, 6, ".", "" );
		}
		$text = (string)$value;
		return "s:" . strlen( $text ) . ":" . $text;
	}

	/** SHA-256 of the canonical params; the audit log records only this. */
	function _actionParamsHash( $params )
	{
		return hash( "sha256", _actionCanonical( $params ) );
	}

	/** Build a confirm token bound to action, params, expiry and request. */
	function _actionToken( $secret, $actionId, $route, $paramsHash, $expires, $requestId )
	{
		return hash_hmac(
			"sha256",
			$actionId . "|" . $route . "|" . $paramsHash . "|" . $expires . "|" . $requestId,
			$secret
		);
	}

	/** Generate a random UUID v4. */
	function _actionUuid()
	{
		$bytes = random_bytes( 16 );
		$bytes[6] = chr( ( ord( $bytes[6] ) & 0x0f ) | 0x40 );
		$bytes[8] = chr( ( ord( $bytes[8] ) & 0x3f ) | 0x80 );
		return vsprintf( "%s%s-%s-%s-%s-%s%s%s", str_split( bin2hex( $bytes ), 4 ) );
	}

	/** Validate a caller-supplied request id. */
	function _actionValidRequestId( $value )
	{
		return is_string( $value ) && preg_match( '/^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$/', $value ) === 1;
	}

	/**
	 * Call an optional test hook, or run $fallback.
	 *
	 * The offline PHP harness sets $E64LOCAL_ACTION_HOOKS to model a monotonic
	 * clock that steps backwards, a different boot id, or an unreadable boot
	 * id.  Nothing in this module writes that array and no request field can
	 * reach it, so in production the seams below always take their fallback.
	 */
	function _actionHook( $name, $fallback )
	{
		global $E64LOCAL_ACTION_HOOKS;
		if ( is_array( $E64LOCAL_ACTION_HOOKS ) && isset( $E64LOCAL_ACTION_HOOKS[$name] )
			&& is_callable( $E64LOCAL_ACTION_HOOKS[$name] ) )
		{
			return call_user_func( $E64LOCAL_ACTION_HOOKS[$name] );
		}
		return $fallback();
	}

	/**
	 * Monotonic milliseconds, the domain of the rate-limit timestamps.
	 *
	 * hrtime() is CLOCK_MONOTONIC on Linux: it never steps with NTP or the
	 * wall clock and is shared by every worker on the host.  It is the seam
	 * the PHP harness overrides to model a clock that steps backwards.
	 */
	function _actionMonotonicNow()
	{
		$value = _actionHook( "monotonicNow", function () {
			if ( !function_exists( "hrtime" ) )
			{
				return null;
			}
			$nanoseconds = hrtime( true );
			if ( !is_int( $nanoseconds ) || $nanoseconds < 0 )
			{
				return null;
			}
			return intdiv( $nanoseconds, 1000000 );
		} );
		return is_int( $value ) && $value >= 0 ? $value : null;
	}

	/**
	 * The boot identity a prepared action is bound to.
	 *
	 * A confirm token must not survive a reboot: the wall clock may have moved
	 * either way, so expiry alone is not a reliable bound.  Returns null when
	 * the kernel does not expose a usable id, and the caller fails closed.
	 */
	function _actionBootId()
	{
		$value = _actionHook( "bootId", function () {
			if ( !is_file( E64LOCAL_BOOT_ID_FILE ) || !is_readable( E64LOCAL_BOOT_ID_FILE ) )
			{
				return null;
			}
			$raw = @file_get_contents( E64LOCAL_BOOT_ID_FILE );
			if ( !is_string( $raw ) )
			{
				return null;
			}
			$id = trim( $raw );
			if ( preg_match( '/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/', $id ) !== 1 )
			{
				return null;
			}
			return $id;
		} );
		return is_string( $value ) && $value !== "" ? $value : null;
	}

	/**
	 * Compare a prepared record's boot binding with the live boot id.
	 *
	 * Returns true when the record may execute.  A different boot is a 409 (the
	 * token cannot survive a reboot); an unreadable boot id is a 503, and the
	 * record is left untouched so a transient read failure does not spend it.
	 */
	function _actionBootMatchesRecord( $record, &$error, &$code )
	{
		$error = null;
		$code = 500;
		$bootId = _actionBootId();
		if ( $bootId === null )
		{
			$error = "the kernel boot id is unavailable; refusing to execute a prepared action";
			$code = 503;
			return false;
		}
		if ( !isset( $record["bootId"] ) || !is_string( $record["bootId"] ) || $record["bootId"] === "" )
		{
			$error = "the prepared action carries no boot id; refusing to execute it";
			$code = 409;
			return false;
		}
		if ( $record["bootId"] !== $bootId )
		{
			$error = "the device has rebooted since this action was prepared";
			$code = 409;
			return false;
		}
		return true;
	}

	/** Return the client tuple recorded in the audit log. */
	function _actionClient()
	{
		$address = isset( $_SERVER["REMOTE_ADDR"] ) ? (string)$_SERVER["REMOTE_ADDR"] : "unknown";
		$agent = isset( $_SERVER["HTTP_USER_AGENT"] ) ? (string)$_SERVER["HTTP_USER_AGENT"] : "";
		return array(
			"addr" => $address,
			"uaSha256" => $agent === "" ? null : hash( "sha256", $agent ),
		);
	}

	/**
	 * Settings the generic action_settings_set route accepts.
	 *
	 * Credential keys (Role.*), WiFi/ESP keys (Wifi.*), cloud keys (Cloud.*),
	 * M2M keys (M2m.*), production/factory keys and any key ending in
	 * password/secret/token/logindata are absent by construction.  Keys owned
	 * by action_agsa_configure, action_led_set, action_standby_configure and
	 * action_language_set are also absent so there is exactly one write path
	 * per key.  Types and ranges follow docs/SQLITE_SCHEMA.md.
	 */
	function _actionSettingSpecs()
	{
		return array(
			"System.WelcomeName" => array( "type" => "text", "max" => 64 ),
			"System.Name" => array( "type" => "text", "max" => 64 ),
			"System.UseAmPm" => array( "type" => "bool" ),
			"System.Brightness.Backlight" => array( "type" => "int", "min" => 0, "max" => 100 ),
			"System.Gbw3PointCalibrationEnabled" => array( "type" => "bool" ),
			"Temperature.Unit" => array( "type" => "enum", "values" => array( "C", "F" ) ),
			"Temperature.ShowOnMainScreen" => array( "type" => "bool" ),
			"Grinding.OvershootWeight" => array( "type" => "int", "min" => 0, "max" => 2000000 ),
			"Grinding.PurgeValueMs" => array( "type" => "int", "min" => 100, "max" => 10000 ),
			"Grinding.Portafilter.DetectionEnabled" => array( "type" => "bool" ),
			"Grinding.PortafilterSwitch.Disabled" => array( "type" => "bool" ),
			"Grinding.LoadCell.Disabled" => array( "type" => "bool" ),
			"Grinding.BreakFunctionEnabled" => array( "type" => "bool" ),
			"Gbw.CalibrationCustomWeight" => array( "type" => "int", "min" => 0, "max" => 5000000 ),
			"Gbw.CalibrationCustomWeightEnable" => array( "type" => "bool" ),
			"Gbw.CalibrationReminderInterval" => array( "type" => "int", "min" => 0, "max" => 3650 ),
			"Gbs.Algo.PreventAgsaBrewtimeRange_ms" => array( "type" => "int", "min" => 0, "max" => 600000 ),
		);
	}

	/** Validate and normalize one settings value for the write adapter. */
	function _actionSettingValue( $key, $value, $spec, &$error )
	{
		switch ( $spec["type"] )
		{
			case "bool":
				if ( !is_bool( $value ) )
				{
					$error = $key . " expects a JSON boolean";
					return null;
				}
				return $value;
			case "int":
				if ( is_bool( $value ) || !is_int( $value ) )
				{
					$error = $key . " expects a JSON integer";
					return null;
				}
				if ( $value < $spec["min"] || $value > $spec["max"] )
				{
					$error = $key . " is outside " . $spec["min"] . ".." . $spec["max"];
					return null;
				}
				return $value;
			case "enum":
				if ( !is_string( $value ) || !in_array( $value, $spec["values"], true ) )
				{
					$error = $key . " has an unsupported value";
					return null;
				}
				return $value;
			case "clock":
				if ( !is_string( $value ) || preg_match( '/^([01][0-9]|2[0-3]):[0-5][0-9]$/', $value ) !== 1 )
				{
					$error = $key . " expects HH:MM";
					return null;
				}
				return $value;
			case "color":
				if ( !is_string( $value ) || preg_match( '/^#[0-9A-Fa-f]{6}$/', $value ) !== 1 )
				{
					$error = $key . " expects #RRGGBB";
					return null;
				}
				return strtoupper( $value );
			case "text":
				if ( !is_string( $value ) || strlen( $value ) > $spec["max"]
					|| preg_match( '/^[\p{L}\p{N} ._\-]*$/u', $value ) !== 1 )
				{
					$error = $key . " contains unsupported characters";
					return null;
				}
				return $value;
		}
		$error = $key . " has an unsupported type";
		return null;
	}

	function _actionReadSetting( $key )
	{
		$result = _sqliteQuery(
			"SELECT value FROM settings WHERE key = '" . str_replace( "'", "''", $key ) . "'",
			1
		);
		if ( $result["returnVal"] !== 0 || $result["count"] === 0 )
		{
			return null;
		}
		return isset( $result["rows"][0]["value"] ) ? (string)$result["rows"][0]["value"] : null;
	}

	function _actionParamInt( $params, $key, $min, $max, $required, &$error )
	{
		if ( !array_key_exists( $key, $params ) )
		{
			if ( $required )
			{
				$error = $key . " is required";
			}
			return null;
		}
		$value = $params[$key];
		if ( is_bool( $value ) || !is_int( $value ) )
		{
			$error = $key . " must be a JSON integer";
			return null;
		}
		if ( $value < $min || $value > $max )
		{
			$error = $key . " must be between " . $min . " and " . $max;
			return null;
		}
		return $value;
	}

	function _actionParamNumber( $params, $key, $min, $max, $required, &$error )
	{
		if ( !array_key_exists( $key, $params ) )
		{
			if ( $required )
			{
				$error = $key . " is required";
			}
			return null;
		}
		$value = $params[$key];
		if ( is_bool( $value ) || !( is_int( $value ) || is_float( $value ) ) )
		{
			$error = $key . " must be a JSON number";
			return null;
		}
		if ( is_float( $value ) && ( is_nan( $value ) || is_infinite( $value ) ) )
		{
			$error = $key . " must be finite";
			return null;
		}
		if ( $value < $min || $value > $max )
		{
			$error = $key . " must be between " . $min . " and " . $max;
			return null;
		}
		return (float)$value;
	}

	function _actionParamBool( $params, $key, $required, &$error )
	{
		if ( !array_key_exists( $key, $params ) )
		{
			if ( $required )
			{
				$error = $key . " is required";
			}
			return null;
		}
		if ( !is_bool( $params[$key] ) )
		{
			$error = $key . " must be a JSON boolean";
			return null;
		}
		return $params[$key];
	}

	function _actionParamEnum( $params, $key, $values, $required, &$error )
	{
		if ( !array_key_exists( $key, $params ) )
		{
			if ( $required )
			{
				$error = $key . " is required";
			}
			return null;
		}
		if ( !is_string( $params[$key] ) || !in_array( $params[$key], $values, true ) )
		{
			$error = $key . " must be one of " . implode( ", ", $values );
			return null;
		}
		return $params[$key];
	}

	function _actionParamUuid( $params, $key, $required, &$error )
	{
		if ( !array_key_exists( $key, $params ) )
		{
			if ( $required )
			{
				$error = $key . " is required";
			}
			return null;
		}
		if ( !is_string( $params[$key] )
			|| preg_match( '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $params[$key] ) !== 1 )
		{
			$error = $key . " must be a lowercase UUID";
			return null;
		}
		return $params[$key];
	}

	/** Reject a params object that is not an object or has unknown keys. */
	function _actionOnlyKeys( $params, $allowed, &$error )
	{
		if ( !is_array( $params ) )
		{
			$error = "params must be a JSON object";
			return false;
		}
		foreach ( $params as $key => $unused )
		{
			if ( !is_string( $key ) || !in_array( $key, $allowed, true ) )
			{
				$error = "unknown parameter " . (string)$key;
				return false;
			}
		}
		return true;
	}

	/** Build a sorted [{"key":..,"value":..}] list for a settings write. */
	function _actionSettingsEntries( $values )
	{
		$keys = array_keys( $values );
		sort( $keys, SORT_STRING );
		$entries = array();
		foreach ( $keys as $key )
		{
			$entries[] = array( "key" => $key, "value" => $values[$key] );
		}
		return $entries;
	}

	/**
	 * Validate and normalize the params for one action.
	 *
	 * Returns the normalized array (only known keys, canonical types) or null
	 * with $error/$code set.  Nothing here touches the actuator surface; the
	 * only reads are the recipe row needed to fill an update and the purge
	 * default.
	 */
	function _actionNormalizeParams( $route, $params, $policy, &$error, &$code )
	{
		$error = null;
		$code = 422;
		$normalized = array();

		switch ( $route )
		{
			case "action_grind_start_gbw":
				if ( !_actionOnlyKeys( $params, array( "targetWeightGr" ), $error ) )
				{
					return null;
				}
				$bound = _actionBound( $policy, "targetWeightGr", 0.1, 50.0 );
				$weight = _actionParamNumber( $params, "targetWeightGr", $bound["min"], $bound["max"], true, $error );
				if ( $weight === null )
				{
					return null;
				}
				$normalized = array( "targetWeightGr" => $weight );
				break;

			case "action_grind_start_gbt":
				if ( !_actionOnlyKeys( $params, array( "grindTimeSec" ), $error ) )
				{
					return null;
				}
				$bound = _actionBound( $policy, "grindTimeSec", 0.5, 60.0 );
				$seconds = _actionParamNumber( $params, "grindTimeSec", $bound["min"], $bound["max"], true, $error );
				if ( $seconds === null )
				{
					return null;
				}
				$normalized = array( "grindTimeSec" => $seconds );
				break;

			case "action_grind_start_manual":
				if ( !_actionOnlyKeys( $params, array( "durationMs" ), $error ) )
				{
					return null;
				}
				$bound = _actionBound( $policy, "manualGrindMs", 100, 5000 );
				$duration = _actionParamInt( $params, "durationMs", (int)$bound["min"], (int)$bound["max"], false, $error );
				if ( $error !== null )
				{
					return null;
				}
				$normalized = array( "durationMs" => $duration === null ? 1500 : $duration );
				break;

			case "action_grind_stop":
			case "action_agsa_stop":
			case "action_calibration_loadcell":
			case "action_calibration_tare":
			case "action_calibration_dd":
			case "action_logs_clear":
			case "action_statistics_reset":
			case "action_driver_reset":
				if ( !_actionOnlyKeys( $params, array(), $error ) )
				{
					return null;
				}
				$normalized = array();
				break;

			case "action_grind_purge":
				if ( !_actionOnlyKeys( $params, array( "durationMs" ), $error ) )
				{
					return null;
				}
				$bound = _actionBound( $policy, "purgeMs", 100, 10000 );
				$duration = _actionParamInt( $params, "durationMs", (int)$bound["min"], (int)$bound["max"], false, $error );
				if ( $error !== null )
				{
					return null;
				}
				if ( $duration === null )
				{
					$configured = _actionReadSetting( "Grinding.PurgeValueMs" );
					$duration = 200;
					if ( $configured !== null && preg_match( '/^[0-9]{1,5}$/', $configured ) )
					{
						$duration = (int)$configured;
					}
					if ( $duration < (int)$bound["min"] )
					{
						$duration = (int)$bound["min"];
					}
					if ( $duration > (int)$bound["max"] )
					{
						$duration = (int)$bound["max"];
					}
				}
				$normalized = array( "durationMs" => $duration );
				break;

			case "action_agsa_move":
				if ( !_actionOnlyKeys( $params, array( "targetDdValue" ), $error ) )
				{
					return null;
				}
				$target = _actionParamInt( $params, "targetDdValue", 0, 10000, true, $error );
				if ( $target === null )
				{
					return null;
				}
				$normalized = array( "targetDdValue" => $target );
				break;

			case "action_agsa_configure":
			{
				$allowed = array( "enabled", "startWithRecipeDd", "showRecipeDd", "blockageWarningThreshold" );
				if ( !_actionOnlyKeys( $params, $allowed, $error ) )
				{
					return null;
				}
				$values = array();
				$enabled = _actionParamBool( $params, "enabled", true, $error );
				if ( $error !== null )
				{
					return null;
				}
				$values["Agsa.AgsaUponRecipeChange"] = $enabled;
				if ( array_key_exists( "startWithRecipeDd", $params ) )
				{
					$value = _actionParamBool( $params, "startWithRecipeDd", true, $error );
					if ( $error !== null )
					{
						return null;
					}
					$values["Agsa.AgsaStartWithRecipeDd"] = $value;
				}
				if ( array_key_exists( "showRecipeDd", $params ) )
				{
					$value = _actionParamBool( $params, "showRecipeDd", true, $error );
					if ( $error !== null )
					{
						return null;
					}
					$values["Agsa.ShowRecipeDdEnabled"] = $value;
				}
				if ( array_key_exists( "blockageWarningThreshold", $params ) )
				{
					$value = _actionParamInt( $params, "blockageWarningThreshold", 0, 10000, true, $error );
					if ( $error !== null )
					{
						return null;
					}
					$values["Agsa.BlockageWarningThreshold"] = $value;
				}
				$normalized = array( "entries" => _actionSettingsEntries( $values ) );
				break;
			}

			case "action_fan_set":
			{
				if ( !_actionOnlyKeys( $params, array( "fan", "dutyPercent", "temperatureCtrlEnabled" ), $error ) )
				{
					return null;
				}
				$fan = _actionParamInt( $params, "fan", 1, 2, true, $error );
				if ( $fan === null )
				{
					return null;
				}
				$bound = _actionBound( $policy, "fanDuty", 0, 100 );
				$duty = _actionParamInt( $params, "dutyPercent", (int)$bound["min"], (int)$bound["max"], true, $error );
				if ( $duty === null )
				{
					return null;
				}
				$normalized = array( "fan" => $fan, "dutyPercent" => $duty );
				if ( array_key_exists( "temperatureCtrlEnabled", $params ) )
				{
					$enabled = _actionParamBool( $params, "temperatureCtrlEnabled", true, $error );
					if ( $error !== null )
					{
						return null;
					}
					$normalized["temperatureCtrlEnabled"] = $enabled;
				}
				break;
			}

			case "action_display_backlight":
			{
				if ( !_actionOnlyKeys( $params, array( "brightness", "power" ), $error ) )
				{
					return null;
				}
				if ( !array_key_exists( "brightness", $params ) && !array_key_exists( "power", $params ) )
				{
					$error = "brightness or power is required";
					return null;
				}
				$bound = _actionBound( $policy, "brightness", 0, 100 );
				$brightness = _actionParamInt( $params, "brightness", (int)$bound["min"], (int)$bound["max"], false, $error );
				if ( $error !== null )
				{
					return null;
				}
				// The vendor command is a bare toggle with no state read-back, so
				// only an explicit toggle is accepted: on/off would be a guess.
				$power = _actionParamEnum( $params, "power", array( "toggle" ), false, $error );
				if ( $error !== null )
				{
					return null;
				}
				$normalized = array();
				if ( $brightness !== null )
				{
					$normalized["brightness"] = $brightness;
				}
				if ( $power !== null )
				{
					$normalized["power"] = $power;
				}
				break;
			}

			case "action_led_set":
			{
				$allowed = array( "enabled", "colorRgb", "permanentLighting", "colorFading", "permanentColorRgb" );
				if ( !_actionOnlyKeys( $params, $allowed, $error ) )
				{
					return null;
				}
				if ( count( $params ) === 0 )
				{
					$error = "at least one LED field is required";
					return null;
				}
				$values = array();
				$map = array(
					"enabled" => array( "Standby.LedEnabled", "bool" ),
					"colorRgb" => array( "Standby.LedColorRgb", "color" ),
					"permanentLighting" => array( "System.PermanentLedLightingEnabled", "bool" ),
					"colorFading" => array( "System.PermanentLedColorFadingEnabled", "bool" ),
					"permanentColorRgb" => array( "System.PermanentLedColorRgb", "color" ),
				);
				foreach ( $map as $param => $target )
				{
					if ( !array_key_exists( $param, $params ) )
					{
						continue;
					}
					$spec = array( "type" => $target[1] );
					$value = _actionSettingValue( $target[0], $params[$param], $spec, $error );
					if ( $value === null )
					{
						return null;
					}
					$values[$target[0]] = $value;
				}
				$normalized = array( "entries" => _actionSettingsEntries( $values ) );
				break;
			}

			case "action_language_set":
				if ( !_actionOnlyKeys( $params, array( "language" ), $error ) )
				{
					return null;
				}
				$language = _actionParamEnum(
					$params,
					"language",
					array( "de", "en", "en_US", "es", "fr", "it", "nl", "pl", "pt", "tr" ),
					true,
					$error
				);
				if ( $language === null )
				{
					return null;
				}
				$normalized = array( "language" => $language );
				break;

			case "action_standby_configure":
			{
				$allowed = array( "activationTimeSec", "ledEnabled", "shiftTimesEnabled", "shiftTimeBegin", "shiftTimeEnd" );
				if ( !_actionOnlyKeys( $params, $allowed, $error ) )
				{
					return null;
				}
				if ( count( $params ) === 0 )
				{
					$error = "at least one standby field is required";
					return null;
				}
				$values = array();
				if ( array_key_exists( "activationTimeSec", $params ) )
				{
					$bound = _actionBound( $policy, "standbySec", 0, 86400 );
					$value = _actionParamInt( $params, "activationTimeSec", (int)$bound["min"], (int)$bound["max"], true, $error );
					if ( $error !== null )
					{
						return null;
					}
					$values["Standby.ActivationTimeSec"] = $value;
				}
				if ( array_key_exists( "ledEnabled", $params ) )
				{
					$value = _actionParamBool( $params, "ledEnabled", true, $error );
					if ( $error !== null )
					{
						return null;
					}
					$values["Standby.LedEnabled"] = $value;
				}
				$shift = _actionParamBool( $params, "shiftTimesEnabled", false, $error );
				if ( $error !== null )
				{
					return null;
				}
				if ( $shift !== null )
				{
					$values["Standby.ShiftTimesEnabled"] = $shift;
				}
				foreach ( array( "shiftTimeBegin" => "Standby.ShiftTimeBegin", "shiftTimeEnd" => "Standby.ShiftTimeEnd" ) as $param => $key )
				{
					if ( !array_key_exists( $param, $params ) )
					{
						continue;
					}
					$value = _actionSettingValue( $key, $params[$param], array( "type" => "clock" ), $error );
					if ( $value === null )
					{
						return null;
					}
					$values[$key] = $value;
				}
				if ( $shift === true )
				{
					$begin = array_key_exists( "shiftTimeBegin", $params ) ? $params["shiftTimeBegin"] : _actionReadSetting( "Standby.ShiftTimeBegin" );
					$end = array_key_exists( "shiftTimeEnd", $params ) ? $params["shiftTimeEnd"] : _actionReadSetting( "Standby.ShiftTimeEnd" );
					if ( !is_string( $begin ) || !is_string( $end ) || $begin === "" || $end === "" )
					{
						$error = "enabling shift times requires shiftTimeBegin and shiftTimeEnd";
						return null;
					}
				}
				$normalized = array( "entries" => _actionSettingsEntries( $values ) );
				break;
			}

			case "action_settings_set":
			{
				if ( !_actionOnlyKeys( $params, array( "settings" ), $error ) )
				{
					return null;
				}
				if ( !isset( $params["settings"] ) || !is_array( $params["settings"] ) )
				{
					$error = "settings must be a JSON object";
					return null;
				}
				$countBound = _actionBound( $policy, "settingsEntries", 1, 8 );
				$minEntries = (int)$countBound["min"];
				$maxEntries = (int)$countBound["max"];
				if ( count( $params["settings"] ) < $minEntries || count( $params["settings"] ) > $maxEntries )
				{
					$error = "settings must contain between " . $minEntries . " and " . $maxEntries . " entries";
					return null;
				}
				$specs = _actionSettingSpecs();
				$values = array();
				foreach ( $params["settings"] as $key => $value )
				{
					if ( !is_string( $key ) || !isset( $specs[$key] ) )
					{
						$error = "setting key is not allowlisted: " . (string)$key;
						return null;
					}
					$normalizedValue = _actionSettingValue( $key, $value, $specs[$key], $error );
					if ( $error !== null )
					{
						return null;
					}
					$values[$key] = $normalizedValue;
				}
				$normalized = array( "entries" => _actionSettingsEntries( $values ) );
				break;
			}

			case "action_recipe_activate":
				if ( !_actionOnlyKeys( $params, array( "recipeIndex" ), $error ) )
				{
					return null;
				}
				$index = _actionParamInt( $params, "recipeIndex", 1, 1000, true, $error );
				if ( $index === null )
				{
					return null;
				}
				$normalized = array( "recipeIndex" => $index );
				break;

			case "action_recipe_create":
			{
				$allowed = array( "recipeIndex", "modeId", "amountMg", "typeId", "iconId", "coarseness", "brewTimeMs", "brewWeightMg" );
				if ( !_actionOnlyKeys( $params, $allowed, $error ) )
				{
					return null;
				}
				$bound = _actionBound( $policy, "recipeAmountMg", 100, 100000 );
				$index = _actionParamInt( $params, "recipeIndex", 1, 1000, true, $error );
				$modeId = _actionParamInt( $params, "modeId", 1, 1000, true, $error );
				$amount = _actionParamInt( $params, "amountMg", (int)$bound["min"], (int)$bound["max"], true, $error );
				$typeId = _actionParamInt( $params, "typeId", 1, 1000, true, $error );
				$iconId = _actionParamInt( $params, "iconId", 1, 1000, true, $error );
				$coarsenessBound = _actionBound( $policy, "recipeCoarseness", 0, 10000 );
				$coarseness = _actionParamInt( $params, "coarseness", (int)$coarsenessBound["min"], (int)$coarsenessBound["max"], true, $error );
				$brewTimeBound = _actionBound( $policy, "brewTimeMs", 0, 120000 );
				$brewTime = _actionParamInt( $params, "brewTimeMs", (int)$brewTimeBound["min"], (int)$brewTimeBound["max"], true, $error );
				$brewWeightBound = _actionBound( $policy, "brewWeightMg", 0, 200000 );
				$brewWeight = _actionParamInt( $params, "brewWeightMg", (int)$brewWeightBound["min"], (int)$brewWeightBound["max"], true, $error );
				if ( $error !== null )
				{
					return null;
				}
				$normalized = array(
					"recipeIndex" => $index,
					"modeId" => $modeId,
					"amountMg" => $amount,
					"typeId" => $typeId,
					"iconId" => $iconId,
					"coarseness" => $coarseness,
					"brewTimeMs" => $brewTime,
					"brewWeightMg" => $brewWeight,
					"uuid" => _actionUuid(),
				);
				break;
			}

			case "action_recipe_update":
			{
				$allowed = array( "recipeIndex", "modeId", "amountMg", "typeId", "iconId", "coarseness", "brewTimeMs", "brewWeightMg" );
				if ( !_actionOnlyKeys( $params, $allowed, $error ) )
				{
					return null;
				}
				$index = _actionParamInt( $params, "recipeIndex", 1, 1000, true, $error );
				if ( $index === null )
				{
					return null;
				}
				$fields = array( "modeId", "amountMg", "typeId", "iconId", "coarseness", "brewTimeMs", "brewWeightMg" );
				$provided = 0;
				foreach ( $fields as $field )
				{
					if ( array_key_exists( $field, $params ) )
					{
						$provided++;
					}
				}
				if ( $provided === 0 )
				{
					$error = "at least one recipe field is required";
					return null;
				}

				$result = _sqliteQuery(
					"SELECT recipe_data.recipe_mode_id, recipe_data.recipe_amount, recipe_data.recipe_type_id, "
					. "recipe_data.recipe_icon_id, recipe_data.recipe_coarseness, recipe_data.recipe_brew_time, "
					. "recipe_data.recipe_brew_weight FROM recipe_entries "
					. "LEFT JOIN recipe_data ON recipe_entries.recipe_data_id = recipe_data.recipe_data_id "
					. "WHERE recipe_entries.recipe_index = " . (int)$index,
					1
				);
				if ( $result["returnVal"] !== 0 )
				{
					$error = "database query failed";
					$code = 500;
					return null;
				}
				if ( $result["count"] === 0 )
				{
					$error = "recipe slot does not exist";
					$code = 404;
					return null;
				}
				$row = $result["rows"][0];
				$current = array(
					"modeId" => isset( $row["recipe_mode_id"] ) && $row["recipe_mode_id"] !== "" ? (int)$row["recipe_mode_id"] : null,
					"amountMg" => isset( $row["recipe_amount"] ) && $row["recipe_amount"] !== "" ? (int)$row["recipe_amount"] : null,
					"typeId" => isset( $row["recipe_type_id"] ) && $row["recipe_type_id"] !== "" ? (int)$row["recipe_type_id"] : null,
					"iconId" => isset( $row["recipe_icon_id"] ) && $row["recipe_icon_id"] !== "" ? (int)$row["recipe_icon_id"] : null,
					"coarseness" => isset( $row["recipe_coarseness"] ) && $row["recipe_coarseness"] !== "" ? (int)$row["recipe_coarseness"] : null,
					"brewTimeMs" => isset( $row["recipe_brew_time"] ) && $row["recipe_brew_time"] !== "" ? (int)$row["recipe_brew_time"] : null,
					"brewWeightMg" => isset( $row["recipe_brew_weight"] ) && $row["recipe_brew_weight"] !== "" ? (int)$row["recipe_brew_weight"] : null,
				);
				foreach ( $current as $field => $value )
				{
					if ( $value === null )
					{
						$error = "recipe row is incomplete (" . $field . ")";
						$code = 500;
						return null;
					}
				}

				$amountBound = _actionBound( $policy, "recipeAmountMg", 100, 100000 );
				$coarsenessBound = _actionBound( $policy, "recipeCoarseness", 0, 10000 );
				$brewTimeBound = _actionBound( $policy, "brewTimeMs", 0, 120000 );
				$brewWeightBound = _actionBound( $policy, "brewWeightMg", 0, 200000 );
				$limits = array(
					"modeId" => array( 1, 1000 ),
					"amountMg" => array( (int)$amountBound["min"], (int)$amountBound["max"] ),
					"typeId" => array( 1, 1000 ),
					"iconId" => array( 1, 1000 ),
					"coarseness" => array( (int)$coarsenessBound["min"], (int)$coarsenessBound["max"] ),
					"brewTimeMs" => array( (int)$brewTimeBound["min"], (int)$brewTimeBound["max"] ),
					"brewWeightMg" => array( (int)$brewWeightBound["min"], (int)$brewWeightBound["max"] ),
				);
				$merged = array();
				foreach ( $fields as $field )
				{
					if ( array_key_exists( $field, $params ) )
					{
						$value = _actionParamInt( $params, $field, $limits[$field][0], $limits[$field][1], true, $error );
						if ( $error !== null )
						{
							return null;
						}
						$merged[$field] = $value;
					}
					else
					{
						$merged[$field] = $current[$field];
					}
				}
				$normalized = array_merge( array( "recipeIndex" => $index ), $merged );
				break;
			}

			case "action_recipe_delete":
				if ( !_actionOnlyKeys( $params, array( "recipeIndex" ), $error ) )
				{
					return null;
				}
				$index = _actionParamInt( $params, "recipeIndex", 1, 1000, true, $error );
				if ( $index === null )
				{
					return null;
				}
				$normalized = array( "recipeIndex" => $index );
				break;

			case "action_brew_event_add":
			{
				$allowed = array( "grindUuid", "doseIndex", "validity", "brewTimeMs", "brewWeightMg", "machineName", "groupHead" );
				if ( !_actionOnlyKeys( $params, $allowed, $error ) )
				{
					return null;
				}
				$uuid = _actionParamUuid( $params, "grindUuid", true, $error );
				if ( $uuid === null )
				{
					return null;
				}
				$doseIndex = _actionParamInt( $params, "doseIndex", 0, 1000, false, $error );
				$validity = _actionParamBool( $params, "validity", true, $error );
				$brewTimeBound = _actionBound( $policy, "brewTimeMs", 0, 120000 );
				$brewTime = _actionParamInt( $params, "brewTimeMs", (int)$brewTimeBound["min"], (int)$brewTimeBound["max"], true, $error );
				$brewWeightBound = _actionBound( $policy, "brewWeightMg", 0, 200000 );
				$brewWeight = _actionParamInt( $params, "brewWeightMg", (int)$brewWeightBound["min"], (int)$brewWeightBound["max"], true, $error );
				if ( $error !== null )
				{
					return null;
				}
				$normalized = array(
					"grindUuid" => $uuid,
					"doseIndex" => $doseIndex === null ? 0 : $doseIndex,
					"validity" => $validity,
					"brewTimeMs" => $brewTime,
					"brewWeightMg" => $brewWeight,
				);
				if ( array_key_exists( "machineName", $params ) )
				{
					if ( !is_string( $params["machineName"] ) || strlen( $params["machineName"] ) > 64
						|| preg_match( '/^[\p{L}\p{N} ._\-]+$/u', $params["machineName"] ) !== 1 )
					{
						$error = "machineName must be 1..64 safe characters";
						return null;
					}
					$normalized["machineName"] = $params["machineName"];
				}
				if ( array_key_exists( "groupHead", $params ) )
				{
					if ( !is_string( $params["groupHead"] ) || strlen( $params["groupHead"] ) > 64
						|| preg_match( '/^[\p{L}\p{N} ._\-]+$/u', $params["groupHead"] ) !== 1 )
					{
						$error = "groupHead must be 1..64 safe characters";
						return null;
					}
					$normalized["groupHead"] = $params["groupHead"];
				}
				break;
			}

			default:
				$error = "unknown action";
				$code = 404;
				return null;
		}

		ksort( $normalized, SORT_STRING );
		return $normalized;
	}

	// --- Rate limiting, audit and action records ------------------------------------

	/**
	 * Sliding-window rate limit persisted under /db/e64local/rate/.
	 *
	 * Timestamps live in the monotonic-millisecond domain (hrtime), never the
	 * wall clock, so an NTP step cannot wipe or double-count a window.  A
	 * bucket whose stored state is unusable (unknown schema, a timestamp in the
	 * future, or a value that looks like an old wall-clock epoch) fails closed.
	 *
	 * Returns true when the request may proceed, false when limited (with
	 * $retryAfter), and null when the state cannot be trusted ($ioError set) so
	 * the caller can fail closed with errorCode 503.
	 */
	function _actionRateLimit( $bucket, $policy, &$retryAfter, &$ioError )
	{
		global $E64LOCAL_ACTION_DEFAULT_RATES;

		$retryAfter = 0;
		$ioError = null;

		$safeBucket = preg_replace( '/[^a-z_]/', '', strtolower( (string)$bucket ) );
		if ( $safeBucket === "" )
		{
			$safeBucket = "default";
		}
		$defaults = isset( $E64LOCAL_ACTION_DEFAULT_RATES[$safeBucket] )
			? $E64LOCAL_ACTION_DEFAULT_RATES[$safeBucket]
			: $E64LOCAL_ACTION_DEFAULT_RATES["default"];
		$perMinute = $defaults["perMinute"];
		$perHour = $defaults["perHour"];
		if ( isset( $policy["rateLimits"][$safeBucket] ) && is_array( $policy["rateLimits"][$safeBucket] ) )
		{
			$entry = $policy["rateLimits"][$safeBucket];
			if ( isset( $entry["perMinute"] ) && is_int( $entry["perMinute"] ) )
			{
				$perMinute = min( $perMinute, max( 0, $entry["perMinute"] ) );
			}
			if ( isset( $entry["perHour"] ) && is_int( $entry["perHour"] ) )
			{
				$perHour = min( $perHour, max( 0, $entry["perHour"] ) );
			}
		}

		if ( !is_dir( E64LOCAL_RATE_DIR ) && !@mkdir( E64LOCAL_RATE_DIR, 0700, true ) )
		{
			$ioError = "rate-limit directory is not writable";
			return null;
		}

		$now = _actionMonotonicNow();
		if ( $now === null )
		{
			// Without a monotonic clock there is no safe timestamp domain.
			$ioError = "monotonic clock is unavailable";
			return null;
		}
		$path = E64LOCAL_RATE_DIR . "/" . $safeBucket . ".json";
		$handle = @fopen( $path, "c+" );
		if ( $handle === false )
		{
			$ioError = "rate-limit file is not writable";
			return null;
		}
		if ( !flock( $handle, LOCK_EX ) )
		{
			fclose( $handle );
			$ioError = "rate-limit lock failed";
			return null;
		}

		// The monotonic domain is per boot: a bucket written before a reboot is
		// not comparable, so the boot id is stored with it and a different one
		// starts a fresh window instead of being pruned or mis-read.  Anything
		// else that does not decode as this schema is refused, not reset.
		$bootId = _actionBootId();
		$raw = stream_get_contents( $handle );
		$state = json_decode( is_string( $raw ) ? $raw : "", true );
		$events = array();
		$unusable = false;
		if ( trim( (string)$raw ) !== "" )
		{
			if ( !is_array( $state ) || !isset( $state["schema"] )
				|| $state["schema"] !== E64LOCAL_ACTION_RATE_SCHEMA
				|| !isset( $state["events"] ) || !is_array( $state["events"] ) )
			{
				// Includes a bucket written by the pre-monotonic release, whose
				// bare array of wall-clock epochs cannot be compared safely.
				$unusable = true;
			}
			elseif ( !is_string( $bootId ) || !isset( $state["bootId"] ) || !is_string( $state["bootId"] ) )
			{
				$unusable = true;
			}
			elseif ( $state["bootId"] === $bootId )
			{
				foreach ( $state["events"] as $event )
				{
					// An event ahead of a monotonic clock is impossible; a clock
					// that stepped backwards must not wipe the window.
					if ( !is_int( $event ) || $event < 0 || $event > $now )
					{
						$unusable = true;
						break;
					}
					if ( $event > $now - E64LOCAL_ACTION_RATE_HOUR_MS )
					{
						$events[] = $event;
					}
				}
			}
			// A bucket from another boot keeps an empty window: its timestamps
			// belong to a clock that no longer exists, so nothing is comparable.
		}

		if ( $unusable )
		{
			// Not pruned and not overwritten: the bucket stays refused until an
			// operator removes it, so a corrupt state can never silently reset.
			flock( $handle, LOCK_UN );
			fclose( $handle );
			$ioError = "rate-limit state is unusable";
			return null;
		}

		$minute = array();
		foreach ( $events as $event )
		{
			if ( $event > $now - E64LOCAL_ACTION_RATE_MINUTE_MS )
			{
				$minute[] = $event;
			}
		}

		if ( $perMinute <= 0 || $perHour <= 0 )
		{
			flock( $handle, LOCK_UN );
			fclose( $handle );
			$retryAfter = 3600;
			return false;
		}
		if ( count( $minute ) >= $perMinute )
		{
			$retryAfter = max( 1, (int)ceil( ( E64LOCAL_ACTION_RATE_MINUTE_MS - ( $now - min( $minute ) ) ) / 1000 ) );
			flock( $handle, LOCK_UN );
			fclose( $handle );
			return false;
		}
		if ( count( $events ) >= $perHour )
		{
			$retryAfter = max( 1, (int)ceil( ( E64LOCAL_ACTION_RATE_HOUR_MS - ( $now - min( $events ) ) ) / 1000 ) );
			flock( $handle, LOCK_UN );
			fclose( $handle );
			return false;
		}

		$events[] = $now;
		$encoded = json_encode( array(
			"schema" => E64LOCAL_ACTION_RATE_SCHEMA,
			"bootId" => $bootId,
			"events" => $events,
		) );
		ftruncate( $handle, 0 );
		rewind( $handle );
		fwrite( $handle, is_string( $encoded ) ? $encoded : "{}" );
		fflush( $handle );
		flock( $handle, LOCK_UN );
		fclose( $handle );
		@chmod( $path, 0600 );
		return true;
	}

	/** Rotate audit.jsonl to .1/.2 and drop the oldest. */
	function _actionAuditRotate()
	{
		$oldest = E64LOCAL_AUDIT_FILE . "." . ( E64LOCAL_ACTION_AUDIT_KEEP - 1 );
		for ( $index = E64LOCAL_ACTION_AUDIT_KEEP - 1; $index >= 2; $index-- )
		{
			$from = E64LOCAL_AUDIT_FILE . "." . ( $index - 1 );
			$to = E64LOCAL_AUDIT_FILE . "." . $index;
			if ( is_file( $from ) )
			{
				@rename( $from, $to );
			}
		}
		if ( is_file( E64LOCAL_AUDIT_FILE ) )
		{
			@rename( E64LOCAL_AUDIT_FILE, E64LOCAL_AUDIT_FILE . ".1" );
		}
		@unlink( $oldest . ".tmp" );
	}

	/**
	 * Append one audit record.  Never throws; returns false when the write
	 * failed so an execute can fail closed before actuation.
	 */
	function _actionAuditWrite( $phase, $route, $actionId, $requestId, $paramsHash, $result, $errorCode, $retryAfter, $durationMs )
	{
		$event = array(
			"ts" => gmdate( "Y-m-d\TH:i:s\Z" ),
			"tsEpoch" => time(),
			"phase" => (string)$phase,
			"route" => (string)$route,
			"actionId" => $actionId === null ? null : (string)$actionId,
			"requestId" => $requestId === null ? null : (string)$requestId,
			"paramsHash" => $paramsHash === null ? null : (string)$paramsHash,
			"result" => is_string( $result ) ? $result : null,
			"errorCode" => (int)$errorCode,
			"retryAfter" => $retryAfter === null ? null : (int)$retryAfter,
			"durationMs" => $durationMs === null ? null : (int)$durationMs,
			"client" => _actionClient(),
		);
		$line = json_encode( $event, JSON_UNESCAPED_SLASHES );
		if ( $line === false )
		{
			return false;
		}
		$line .= "\n";

		if ( !is_dir( dirname( E64LOCAL_AUDIT_FILE ) ) )
		{
			return false;
		}
		$handle = @fopen( E64LOCAL_AUDIT_FILE, "c+" );
		if ( $handle === false )
		{
			return false;
		}
		if ( !flock( $handle, LOCK_EX ) )
		{
			fclose( $handle );
			return false;
		}
		$stat = fstat( $handle );
		$size = is_array( $stat ) && isset( $stat["size"] ) ? (int)$stat["size"] : 0;
		if ( $size > 0 && ( $size + strlen( $line ) ) > E64LOCAL_ACTION_AUDIT_MAX_BYTES )
		{
			flock( $handle, LOCK_UN );
			fclose( $handle );
			_actionAuditRotate();
			$handle = @fopen( E64LOCAL_AUDIT_FILE, "c+" );
			if ( $handle === false )
			{
				return false;
			}
			flock( $handle, LOCK_EX );
		}
		fseek( $handle, 0, SEEK_END );
		$written = fwrite( $handle, $line );
		fflush( $handle );
		flock( $handle, LOCK_UN );
		fclose( $handle );
		@chmod( E64LOCAL_AUDIT_FILE, 0600 );
		return $written === strlen( $line );
	}

	/** Read a page of audit rows, newest first. */
	function _actionAuditRead( $limit, $offset, $sinceEpoch, $untilEpoch )
	{
		$files = array();
		for ( $index = E64LOCAL_ACTION_AUDIT_KEEP - 1; $index >= 0; $index-- )
		{
			$path = $index === 0 ? E64LOCAL_AUDIT_FILE : E64LOCAL_AUDIT_FILE . "." . $index;
			if ( is_file( $path ) )
			{
				$files[] = $path;
			}
		}

		$rows = array();
		foreach ( $files as $path )
		{
			$handle = @fopen( $path, "rb" );
			if ( $handle === false )
			{
				continue;
			}
			while ( ( $line = fgets( $handle ) ) !== false )
			{
				$decoded = json_decode( $line, true );
				if ( !is_array( $decoded ) || !isset( $decoded["tsEpoch"] ) )
				{
					continue;
				}
				$epoch = (int)$decoded["tsEpoch"];
				if ( $sinceEpoch !== null && $epoch < $sinceEpoch )
				{
					continue;
				}
				if ( $untilEpoch !== null && $epoch > $untilEpoch )
				{
					continue;
				}
				$rows[] = $decoded;
			}
			fclose( $handle );
		}

		// Files are chronological; the newest record is the last one read.
		$rows = array_reverse( $rows );
		$total = count( $rows );
		$page = array_slice( $rows, $offset, $limit );
		return array( "rows" => $page, "count" => count( $page ), "total" => $total );
	}

	/** Path of the record for one action id. */
	function _actionRecordPath( $actionId )
	{
		return E64LOCAL_ACTION_DIR . "/" . $actionId . ".json";
	}

	/** Read one action record, or null. */
	function _actionReadRecord( $actionId )
	{
		if ( !is_string( $actionId ) || preg_match( '/^[0-9a-f-]{36}$/', $actionId ) !== 1 )
		{
			return null;
		}
		$path = _actionRecordPath( $actionId );
		if ( !is_file( $path ) || !is_readable( $path ) )
		{
			return null;
		}
		$raw = @file_get_contents( $path );
		$record = is_string( $raw ) ? json_decode( $raw, true ) : null;
		return is_array( $record ) ? $record : null;
	}

	/** Write one action record atomically with mode 0600. */
	function _actionWriteRecord( $record )
	{
		if ( !is_dir( E64LOCAL_ACTION_DIR ) && !@mkdir( E64LOCAL_ACTION_DIR, 0700, true ) )
		{
			return false;
		}
		// JSON_PRESERVE_ZERO_FRACTION keeps 18.0 a float.  Without it
		// json_encode() writes 18, and re-reading the record would yield an int
		// whose canonical form no longer hashes to the prepared paramsHash.
		$encoded = json_encode( $record, JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION );
		if ( $encoded === false )
		{
			return false;
		}
		$path = _actionRecordPath( $record["actionId"] );
		$temporary = $path . ".tmp";
		if ( @file_put_contents( $temporary, $encoded ) === false )
		{
			return false;
		}
		@chmod( $temporary, 0600 );
		if ( !@rename( $temporary, $path ) )
		{
			@unlink( $temporary );
			return false;
		}
		return true;
	}

	function _actionDeleteRecord( $actionId )
	{
		@unlink( _actionRecordPath( $actionId ) );
		@unlink( E64LOCAL_ACTION_DIR . "/" . $actionId . ".lock" );
	}

	/**
	 * Atomically move one prepared record to $state and return it.
	 *
	 * The read-check-write runs under an exclusive per-action flock, so two
	 * concurrent action_execute requests carrying the same confirm token cannot
	 * both pass the "prepared" check and actuate: the token is single-use in
	 * practice, not only by convention.  $expected is the record the caller
	 * already verified; the claim refuses when the record changed underneath
	 * it.  The lock is a flock, so the kernel releases it if the request dies.
	 */
	function _actionClaimRecord( $actionId, $state, $expected = null, &$error = null, &$code = null )
	{
		$error = null;
		$code = 500;

		if ( !is_dir( E64LOCAL_ACTION_DIR ) && !@mkdir( E64LOCAL_ACTION_DIR, 0700, true ) )
		{
			$error = "the action state directory is not writable";
			return null;
		}
		$handle = @fopen( E64LOCAL_ACTION_DIR . "/" . $actionId . ".lock", "c+" );
		if ( $handle === false || !flock( $handle, LOCK_EX ) )
		{
			if ( is_resource( $handle ) )
			{
				fclose( $handle );
			}
			$error = "could not lock the action record";
			return null;
		}

		$current = _actionReadRecord( $actionId );
		if ( $current === null )
		{
			flock( $handle, LOCK_UN );
			fclose( $handle );
			$error = "unknown actionId";
			$code = 404;
			return null;
		}
		if ( !isset( $current["state"] ) || $current["state"] !== "prepared" )
		{
			flock( $handle, LOCK_UN );
			fclose( $handle );
			$error = "action is not in a state that allows execute";
			$code = 409;
			return null;
		}
		if ( time() > (int)$current["expires"] )
		{
			$current["state"] = "expired";
			_actionWriteRecord( $current );
			flock( $handle, LOCK_UN );
			fclose( $handle );
			$error = "the confirm token has expired";
			$code = 409;
			return null;
		}
		if ( !_actionBootMatchesRecord( $current, $bootError, $bootCode ) )
		{
			if ( $bootCode === 409 )
			{
				$current["state"] = "expired";
				_actionWriteRecord( $current );
			}
			flock( $handle, LOCK_UN );
			fclose( $handle );
			$error = $bootError;
			$code = $bootCode;
			return null;
		}
		if ( is_array( $expected ) )
		{
			foreach ( array( "route", "paramsHash", "params", "expires", "requestId" ) as $field )
			{
				if ( !array_key_exists( $field, $current ) || !array_key_exists( $field, $expected )
					|| _actionCanonical( $current[$field] ) !== _actionCanonical( $expected[$field] ) )
				{
					flock( $handle, LOCK_UN );
					fclose( $handle );
					$error = "the prepared action record changed while it was claimed";
					$code = 409;
					return null;
				}
			}
		}

		$current["state"] = (string)$state;
		$current["startedAt"] = gmdate( "Y-m-d\TH:i:s\Z" );
		$current["startedAtEpoch"] = time();
		if ( !_actionWriteRecord( $current ) )
		{
			flock( $handle, LOCK_UN );
			fclose( $handle );
			$error = "could not persist the executing state";
			return null;
		}
		flock( $handle, LOCK_UN );
		fclose( $handle );
		return $current;
	}

	/** List action records, newest first, bounded. */
	function _actionListRecords()
	{
		if ( !is_dir( E64LOCAL_ACTION_DIR ) )
		{
			return array();
		}
		$paths = glob( E64LOCAL_ACTION_DIR . "/*.json" );
		if ( !is_array( $paths ) )
		{
			return array();
		}
		rsort( $paths );
		$records = array();
		foreach ( array_slice( $paths, 0, E64LOCAL_ACTION_MAX_RECORDS ) as $path )
		{
			$raw = @file_get_contents( $path );
			$record = is_string( $raw ) ? json_decode( $raw, true ) : null;
			if ( is_array( $record ) && isset( $record["actionId"] ) )
			{
				$records[] = $record;
			}
		}
		return $records;
	}

	/** Drop records past the retention window; bounded work per request. */
	function _actionPruneRecords()
	{
		$now = time();
		$removed = 0;
		foreach ( _actionListRecords() as $record )
		{
			if ( $removed >= 100 )
			{
				break;
			}
			$preparedAt = isset( $record["preparedAtEpoch"] ) ? (int)$record["preparedAtEpoch"] : 0;
			if ( $preparedAt > 0 && $preparedAt < ( $now - E64LOCAL_ACTION_KEEP_SEC ) )
			{
				_actionDeleteRecord( $record["actionId"] );
				$removed++;
			}
		}
	}

	/** Find a record by caller requestId, or null. */
	function _actionFindByRequestId( $requestId )
	{
		foreach ( _actionListRecords() as $record )
		{
			if ( isset( $record["requestId"] ) && $record["requestId"] === $requestId )
			{
				return $record;
			}
		}
		return null;
	}

	/** Refuse when another action of an incompatible class is executing. */
	function _actionActiveConflict( $route )
	{
		$classes = array(
			"action_grind_start_gbw" => "grind",
			"action_grind_start_gbt" => "grind",
			"action_grind_start_manual" => "grind",
			"action_grind_purge" => "grind",
			"action_agsa_move" => "agsa",
			"action_calibration_loadcell" => "calibration",
			"action_calibration_tare" => "calibration",
			"action_calibration_dd" => "calibration",
		);
		if ( !isset( $classes[$route] ) )
		{
			return null;
		}
		$mine = $classes[$route];
		foreach ( _actionListRecords() as $record )
		{
			if ( !isset( $record["state"] ) || $record["state"] !== "executing" )
			{
				continue;
			}
			if ( !isset( $record["route"] ) || !isset( $classes[$record["route"]] ) )
			{
				continue;
			}
			$theirs = $classes[$record["route"]];
			if ( $theirs === $mine || ( $mine === "calibration" && $theirs === "grind" )
				|| ( $mine === "grind" && $theirs === "calibration" ) )
			{
				return $record["actionId"];
			}
		}
		return null;
	}

	/** Read the firmware update state file; null when absent or unreadable. */
	function _actionFirmwareUpdateState()
	{
		$path = "/tmp/FirmwareUpdateState.json";
		if ( !is_file( $path ) || !is_readable( $path ) )
		{
			return null;
		}
		$raw = @file_get_contents( $path );
		$decoded = is_string( $raw ) ? json_decode( $raw, true ) : null;
		if ( !is_array( $decoded ) )
		{
			return null;
		}
		return isset( $decoded["state"] ) && is_string( $decoded["state"] ) ? $decoded["state"] : null;
	}

	function _actionStateFlagFailed( $value )
	{
		if ( !is_string( $value ) )
		{
			return false;
		}
		$lower = strtolower( $value );
		return strpos( $lower, "fail" ) !== false
			|| strpos( $lower, "error" ) !== false
			|| strpos( $lower, "down" ) !== false
			|| strpos( $lower, "dead" ) !== false;
	}

	/**
	 * Fetch the live driver state through the bounded runner.
	 *
	 * A failed probe reports 503 through $code.  On success $code is left
	 * untouched, so the caller's 409 refusal class survives an unsafe state.
	 */
	function _actionStateProbe( $timeoutMs, &$error, &$code )
	{
		$error = null;
		$probeCode = 503;

		$tokenData = _mintWsToken();
		if ( $tokenData === null )
		{
			$error = "the vendor WSS token surface is unavailable";
			$code = $probeCode;
			return null;
		}

		$jobId = _actionUuid();
		$job = array(
			"verb" => "state",
			"command" => "RequestDriverState",
			"params" => array(),
			"endpoint" => "wss://127.0.0.1:9997/?token=" . $tokenData["token"],
		);
		// _actionRunJob() assigns its own failure code; keep it local so a
		// successful probe cannot rewrite the caller's refusal class.
		$jobCode = $probeCode;
		$result = _actionRunJob( $jobId, $job, $timeoutMs, $error, $jobCode );
		if ( $result === null )
		{
			$code = $jobCode;
			return null;
		}
		if ( !isset( $result["result"]["state"] ) || !is_array( $result["result"]["state"] ) )
		{
			$error = "the driver state reply was not usable";
			$code = $probeCode;
			return null;
		}
		return $result["result"]["state"];
	}

	/**
	 * Unsafe-state and existence preconditions.
	 *
	 * Every check is a refusal, not a warning, unless the comment says the
	 * underlying signal is not available on every firmware generation.
	 */
	function _actionPreconditions( $route, $params, &$warnings, &$error, &$code )
	{
		$catalog = _actionCatalog();
		$entry = isset( $catalog[$route] ) ? $catalog[$route] : null;
		$warnings = array();
		$error = null;
		$code = 409;

		if ( $entry === null || !isset( $entry["preconditions"] ) )
		{
			return true;
		}
		$checks = $entry["preconditions"];

		if ( in_array( "role-limitation", $checks, true ) )
		{
			$warnings[] = "the module cannot verify the vendor session role; calibration is documented as Owner/Technician only and this API cannot enforce it";
		}

		if ( in_array( "update", $checks, true ) )
		{
			$updateState = _actionFirmwareUpdateState();
			if ( $updateState !== null && strcasecmp( $updateState, "Idle" ) !== 0 )
			{
				$error = "firmware update in progress (" . $updateState . ")";
				return false;
			}
		}

		$state = null;
		if ( in_array( "state", $checks, true ) )
		{
			$state = _actionStateProbe( 8000, $error, $code );
			if ( $state === null )
			{
				return false;
			}

			$grindState = isset( $state["grindState"] ) && is_string( $state["grindState"] ) ? $state["grindState"] : "";
			$startsGrind = in_array( $route, array( "action_grind_start_gbw", "action_grind_start_gbt", "action_grind_start_manual", "action_grind_purge" ), true );
			if ( $startsGrind && $grindState !== "Idle" )
			{
				$error = "the grinder is not idle (grindState=" . $grindState . ")";
				return false;
			}
			if ( $startsGrind && !empty( $state["grindFailure"] ) )
			{
				$error = "the last grind reported a failure; clear it before starting a new one";
				return false;
			}
			if ( !empty( $state["overheatNtc1"] ) || !empty( $state["overheatNtc2"] ) )
			{
				$error = "a temperature sensor reports overheat";
				return false;
			}
			if ( array_key_exists( "espAlive", $state ) && $state["espAlive"] === false )
			{
				$error = "the ESP co-processor is not reported alive";
				return false;
			}
			if ( isset( $state["espSdioState"] ) && _actionStateFlagFailed( $state["espSdioState"] ) )
			{
				$error = "the ESP SDIO link reports a failure (" . $state["espSdioState"] . ")";
				return false;
			}
			if ( isset( $state["ddSensorFailed"] ) && $state["ddSensorFailed"] === true )
			{
				$error = "the disc-distance sensor reports a failure";
				return false;
			}

			if ( $route === "action_agsa_move" )
			{
				$current = isset( $state["ddValueDum"] ) && is_numeric( $state["ddValueDum"] ) ? (int)$state["ddValueDum"] : null;
				if ( $current === null )
				{
					$error = "the driver did not report ddValueDum";
					$code = 503;
					return false;
				}
				global $E64LOCAL_ACTION_ABSOLUTE_BOUNDS;
				$maxStep = (int)$E64LOCAL_ACTION_ABSOLUTE_BOUNDS["agsaStepDd"]["max"];
				$delta = abs( (int)$params["targetDdValue"] - $current );
				if ( $delta > $maxStep )
				{
					$error = "AGSA moves are limited to " . $maxStep . " dd units from the current value (current="
						. $current . ", requested=" . (int)$params["targetDdValue"] . ")";
					return false;
				}
				$warnings[] = "no vendor-reported dd minimum/maximum was recovered, so this API allows only incremental moves from the live value";
			}
		}

		if ( in_array( "wizard", $checks, true ) && $state !== null )
		{
			$wizard = isset( $state["setupWizardState"] ) && is_string( $state["setupWizardState"] ) ? $state["setupWizardState"] : "";
			if ( $wizard === "NotRun" )
			{
				$error = "the setup wizard has not run; complete setup before using actions";
				return false;
			}
		}

		if ( in_array( "calibration", $checks, true ) )
		{
			// Refuse only when the firmware records the key and it is empty.  A
			// firmware that does not carry the key cannot be judged here.
			$last = _actionReadSetting( "Gbw.LastGbwCalibrationDate" );
			if ( $last !== null && trim( $last ) === "" )
			{
				$error = "no load-cell calibration date is recorded; calibrate before grinding by weight";
				return false;
			}
			if ( $last === null )
			{
				$warnings[] = "Gbw.LastGbwCalibrationDate is not present on this firmware; the calibration precondition could not be evaluated";
			}
		}

		if ( in_array( "portafilter", $checks, true ) )
		{
			$exists = _tableExists( "portafilters" );
			if ( $exists === true )
			{
				$result = _sqliteQuery( "SELECT COUNT(*) AS count FROM portafilters", 1 );
				if ( $result["returnVal"] !== 0 )
				{
					$error = "database query failed";
					$code = 500;
					return false;
				}
				$count = isset( $result["rows"][0]["count"] ) ? (int)$result["rows"][0]["count"] : 0;
				if ( $count < 1 )
				{
					$error = "no portafilter is configured; add a portafilter record before grinding";
					return false;
				}
			}
			else
			{
				$warnings[] = "the portafilters table is not present on this firmware; the portafilter precondition could not be evaluated";
			}
		}

		if ( $route === "action_recipe_create" || $route === "action_recipe_activate" || $route === "action_recipe_delete" )
		{
			$index = (int)$params["recipeIndex"];
			$result = _sqliteQuery(
				"SELECT recipe_index, recipe_active FROM recipe_entries WHERE recipe_index = " . $index,
				1
			);
			if ( $result["returnVal"] !== 0 )
			{
				$error = "database query failed";
				$code = 500;
				return false;
			}
			$found = $result["count"] === 1;
			if ( $route === "action_recipe_create" && $found )
			{
				$error = "recipe slot " . $index . " is already in use";
				return false;
			}
			if ( $route !== "action_recipe_create" && !$found )
			{
				$error = "recipe slot " . $index . " does not exist";
				$code = 404;
				return false;
			}
			if ( $route === "action_recipe_delete" )
			{
				$active = isset( $result["rows"][0]["recipe_active"] ) ? (int)$result["rows"][0]["recipe_active"] : 0;
				if ( $active === 1 )
				{
					$error = "the active recipe cannot be deleted; activate another slot first";
					return false;
				}
				$total = _sqliteQuery( "SELECT COUNT(*) AS count FROM recipe_entries", 1 );
				if ( $total["returnVal"] !== 0 )
				{
					$error = "database query failed";
					$code = 500;
					return false;
				}
				if ( isset( $total["rows"][0]["count"] ) && (int)$total["rows"][0]["count"] <= 1 )
				{
					$error = "the last recipe cannot be deleted";
					return false;
				}
			}
		}

		if ( $route === "action_recipe_create" || $route === "action_recipe_update" )
		{
			$lookups = array(
				"recipe_modes" => array( "recipe_mode_id", (int)$params["modeId"] ),
				"recipe_types" => array( "recipe_type_id", (int)$params["typeId"] ),
				"recipe_icons" => array( "recipe_icon_id", (int)$params["iconId"] ),
			);
			foreach ( $lookups as $table => $lookup )
			{
				$exists = _tableExists( $table );
				if ( $exists === null )
				{
					$error = "database query failed";
					$code = 500;
					return false;
				}
				if ( $exists === false )
				{
					$warnings[] = "enum table " . $table . " is not present; the write adapter will refuse it";
					continue;
				}
				$result = _sqliteQuery(
					"SELECT " . $lookup[0] . " FROM " . $table . " WHERE " . $lookup[0] . " = " . $lookup[1],
					1
				);
				if ( $result["returnVal"] !== 0 )
				{
					$error = "database query failed";
					$code = 500;
					return false;
				}
				if ( $result["count"] !== 1 )
				{
					$error = "unknown " . $lookup[0] . " " . $lookup[1];
					return false;
				}
			}
		}

		if ( $route === "action_brew_event_add" )
		{
			$exists = _tableExists( "grind_log" );
			if ( $exists === true )
			{
				$uuid = str_replace( "'", "''", (string)$params["grindUuid"] );
				$result = _sqliteQuery(
					"SELECT grind_id FROM grind_log WHERE CAST(grind_uuid AS TEXT) = '" . $uuid . "'",
					1
				);
				if ( $result["returnVal"] !== 0 )
				{
					$error = "database query failed";
					$code = 500;
					return false;
				}
				if ( $result["count"] !== 1 )
				{
					$error = "no grind with that UUID exists";
					$code = 404;
					return false;
				}
			}
			else
			{
				$warnings[] = "the grind_log table is not present on this firmware; the grind-UUID check could not be evaluated";
			}
		}

		$conflict = _actionActiveConflict( $route );
		if ( $conflict !== null )
		{
			$error = "an incompatible action is already executing (" . $conflict . ")";
			return false;
		}

		return true;
	}

	// --- Bounded job execution ------------------------------------------------------

	/** Locate sudo without trusting PATH for the privileged call. */
	function _actionSudoPath()
	{
		foreach ( array( "/usr/bin/sudo", "/bin/sudo" ) as $candidate )
		{
			if ( is_executable( $candidate ) )
			{
				return $candidate;
			}
		}
		// The image's own PATH is the fallback the module already relies on for
		// `sudo -n sqlite3`; the command is fixed and carries no caller data.
		$output = array();
		$returnVal = 0;
		if ( function_exists( "exec" ) )
		{
			@exec( "command -v sudo 2>/dev/null", $output, $returnVal );
			if ( $returnVal === 0 && isset( $output[0] ) && is_executable( trim( $output[0] ) ) )
			{
				return trim( $output[0] );
			}
		}
		return null;
	}

	/**
	 * Run one bounded job through the root-owned helper.
	 *
	 * The helper path and the job path are both server constants; every value
	 * inside the job has already been validated.  proc_open() is given a single
	 * escaped string so no caller data reaches a shell parser.
	 */
	function _actionRunJob( $jobId, $job, $timeoutMs, &$error, &$code )
	{
		$error = null;
		$code = 503;

		$sudo = _actionSudoPath();
		if ( $sudo === null || !is_executable( E64LOCAL_ACTION_RUNNER ) )
		{
			$error = "the action runner is not installed";
			return null;
		}
		if ( !is_dir( E64LOCAL_ACTION_DIR ) && !@mkdir( E64LOCAL_ACTION_DIR, 0700, true ) )
		{
			$error = "the action state directory is not writable";
			$code = 500;
			return null;
		}
		@chmod( E64LOCAL_ACTION_DIR, 0700 );

		$jobPath = E64LOCAL_ACTION_DIR . "/" . $jobId . ".job.json";
		$resultPath = E64LOCAL_ACTION_DIR . "/" . $jobId . ".result.json";
		@unlink( $resultPath );

		$payload = array_merge(
			array(
				"schema" => E64LOCAL_ACTION_JOB_SCHEMA,
				"jobId" => $jobId,
				"timeoutMs" => (int)$timeoutMs,
			),
			$job
		);
		if ( $payload["verb"] === "sqlite" )
		{
			$payload["sqlite3"] = E64LOCAL_SQLITE3;
			$payload["dbPath"] = _dbPath();
			$payload["backupDir"] = E64LOCAL_ACTION_BACKUP_DIR;
		}
		$encoded = json_encode( $payload, JSON_UNESCAPED_SLASHES );
		if ( $encoded === false || @file_put_contents( $jobPath, $encoded ) === false )
		{
			$error = "could not write the action job";
			$code = 500;
			return null;
		}
		@chmod( $jobPath, 0600 );

		$command = escapeshellarg( $sudo ) . " -n " . escapeshellarg( E64LOCAL_ACTION_RUNNER )
			. " " . escapeshellarg( $jobPath );
		$descriptors = array(
			0 => array( "file", "/dev/null", "r" ),
			1 => array( "pipe", "w" ),
			2 => array( "pipe", "w" ),
		);
		$process = @proc_open( $command, $descriptors, $pipes );
		if ( !is_resource( $process ) )
		{
			@unlink( $jobPath );
			$error = "could not start the action runner";
			$code = 500;
			return null;
		}

		stream_set_blocking( $pipes[1], false );
		stream_set_blocking( $pipes[2], false );
		$stdout = "";
		$stderr = "";
		$deadline = microtime( true ) + ( $timeoutMs / 1000.0 ) + 3.0;
		$timedOut = false;
		while ( true )
		{
			$stdout .= (string)stream_get_contents( $pipes[1] );
			$stderr .= (string)stream_get_contents( $pipes[2] );
			$status = proc_get_status( $process );
			if ( !is_array( $status ) || empty( $status["running"] ) )
			{
				break;
			}
			if ( microtime( true ) > $deadline )
			{
				$timedOut = true;
				@proc_terminate( $process, 9 );
				break;
			}
			usleep( 20000 );
		}
		$stdout .= (string)stream_get_contents( $pipes[1] );
		$stderr .= (string)stream_get_contents( $pipes[2] );
		fclose( $pipes[1] );
		fclose( $pipes[2] );
		$exitCode = @proc_close( $process );

		$raw = is_file( $resultPath ) ? @file_get_contents( $resultPath ) : null;
		@unlink( $jobPath );
		@unlink( $resultPath );

		$decoded = is_string( $raw ) ? json_decode( $raw, true ) : null;
		if ( !is_array( $decoded ) || !isset( $decoded["schema"] ) )
		{
			if ( $timedOut )
			{
				$error = "the action exceeded its hard timeout";
				$code = 504;
			}
			else
			{
				$error = "the action runner did not return a result";
				if ( trim( $stderr ) !== "" )
				{
					$error .= ": " . substr( trim( $stderr ), 0, 200 );
				}
				$code = 503;
			}
			return array(
				"ok" => false,
				"state" => $timedOut ? "timed_out" : "failed",
				"errorCode" => $code,
				"error" => $error,
				"result" => array(),
				"durationMs" => null,
				"timedOut" => $timedOut,
				"exitCode" => $exitCode,
			);
		}

		$ok = isset( $decoded["ok"] ) ? (bool)$decoded["ok"] : false;
		$resultCode = isset( $decoded["errorCode"] ) ? (int)$decoded["errorCode"] : ( $ok ? 0 : 500 );
		return array(
			"ok" => $ok,
			"state" => isset( $decoded["state"] ) ? (string)$decoded["state"] : ( $ok ? "completed" : "failed" ),
			"errorCode" => $resultCode,
			"error" => isset( $decoded["error"] ) ? $decoded["error"] : null,
			"result" => isset( $decoded["result"] ) && is_array( $decoded["result"] ) ? $decoded["result"] : array(),
			"durationMs" => isset( $decoded["durationMs"] ) ? (int)$decoded["durationMs"] : null,
			"timedOut" => $timedOut,
			"exitCode" => $exitCode,
		);
	}

	/**
	 * Build the ordered execution steps for a normalized action.
	 *
	 * Each step is one helper invocation.  A fan action that changes both duty
	 * and temperature control needs two vendor commands; everything else is one
	 * step.
	 */
	function _actionSteps( $route, $params )
	{
		$catalog = _actionCatalog();
		$entry = $catalog[$route];
		$steps = array();

		if ( $entry["surface"] === "sqlite" )
		{
			if ( $route === "action_statistics_reset" )
			{
				$steps[] = array( "verb" => "sqlite", "sql" => array( "kind" => "statistics_reset", "params" => array() ) );
			}
			elseif ( $route === "action_recipe_activate" )
			{
				$steps[] = array( "verb" => "sqlite", "sql" => array( "kind" => "recipe_activate", "params" => array( "recipeIndex" => $params["recipeIndex"] ) ) );
			}
			elseif ( $route === "action_recipe_delete" )
			{
				$steps[] = array( "verb" => "sqlite", "sql" => array( "kind" => "recipe_delete", "params" => array( "recipeIndex" => $params["recipeIndex"] ) ) );
			}
			elseif ( $route === "action_recipe_create" || $route === "action_recipe_update" )
			{
				$steps[] = array( "verb" => "sqlite", "sql" => array( "kind" => $entry["sqlKind"], "params" => $params ) );
			}
			else
			{
				$steps[] = array( "verb" => "sqlite", "sql" => array( "kind" => "settings_set_bulk", "params" => array( "entries" => $params["entries"] ) ) );
			}
			return $steps;
		}

		$command = $entry["command"];
		$wssParams = array();
		$followUp = null;

		switch ( $route )
		{
			case "action_grind_start_gbw":
				$wssParams = array( "targetWeightGr" => $params["targetWeightGr"] );
				break;
			case "action_grind_start_gbt":
				$wssParams = array( "grindTimeSec" => $params["grindTimeSec"] );
				break;
			case "action_grind_purge":
				$command = "StartGrindGbt";
				$wssParams = array( "grindTimeSec" => round( $params["durationMs"] / 1000.0, 3 ) );
				break;
			case "action_grind_start_manual":
				$followUp = array( "command" => "Stop", "afterMs" => $params["durationMs"] );
				break;
			case "action_agsa_move":
				$wssParams = array( "targetDdValue" => $params["targetDdValue"] );
				break;
			case "action_fan_set":
				$command = $params["fan"] === 2 ? "SetFan2Duty" : "SetFan1Duty";
				$wssParams = array( "dutyPercent" => $params["dutyPercent"] );
				break;
			case "action_display_backlight":
				// A power-only request must not silently reset the brightness to
				// 100; the brightness step is added below only when asked for.
				$command = "";
				$wssParams = array( "brightness" => isset( $params["brightness"] ) ? $params["brightness"] : 0 );
				break;
			case "action_language_set":
				$wssParams = array( "language" => $params["language"] );
				break;
			case "action_brew_event_add":
				$wssParams = array(
					"grindUuid" => $params["grindUuid"],
					"machineName" => isset( $params["machineName"] ) ? $params["machineName"] : "E64",
					"groupHead" => isset( $params["groupHead"] ) ? $params["groupHead"] : "1",
					"doseIndex" => $params["doseIndex"],
					"validity" => $params["validity"],
					"brewTimeMs" => $params["brewTimeMs"],
					"brewWeightMg" => $params["brewWeightMg"],
				);
				break;
		}

		if ( $route === "action_display_backlight" )
		{
			if ( isset( $params["brightness"] ) )
			{
				$steps[] = array( "verb" => "wss", "command" => "SetBacklightBrightness", "params" => $wssParams, "followUp" => null );
			}
			// Display power is a toggle with no state read-back: accept only the
			// explicit toggle, never an on/off guess.
			if ( isset( $params["power"] ) )
			{
				if ( $params["power"] !== "toggle" )
				{
					return array();
				}
				$steps[] = array( "verb" => "wss", "command" => "ToggleBacklightPower", "params" => array(), "followUp" => null );
			}
			return $steps;
		}

		$steps[] = array( "verb" => "wss", "command" => $command, "params" => $wssParams, "followUp" => $followUp );

		if ( $route === "action_fan_set" && isset( $params["temperatureCtrlEnabled"] ) )
		{
			$steps[] = array(
				"verb" => "wss",
				"command" => "SetFanTemperatureCtrlEnabled",
				"params" => array( "enabled" => $params["temperatureCtrlEnabled"] ),
				"followUp" => null,
			);
		}

		return $steps;
	}

	/** Return true when a route moves a mechanism that has a stop primitive. */
	function _actionHasStopPrimitive( $route )
	{
		return in_array( $route, array(
			"action_grind_start_gbw",
			"action_grind_start_gbt",
			"action_grind_start_manual",
			"action_grind_purge",
		), true );
	}

	/** Best-effort stop after a timeout. */
	function _actionStopAfterTimeout( $route, &$error )
	{
		$error = null;
		if ( _actionHasStopPrimitive( $route ) )
		{
			$command = "Stop";
		}
		elseif ( $route === "action_agsa_move" )
		{
			$command = "StopAgsa";
		}
		else
		{
			return true;
		}
		$tokenData = _mintWsToken();
		if ( $tokenData === null )
		{
			$error = "could not mint a WSS token for the stop";
			return false;
		}
		$result = _actionRunJob(
			_actionUuid(),
			array(
				"verb" => "wss",
				"command" => $command,
				"params" => array(),
				"endpoint" => "wss://127.0.0.1:9997/?token=" . $tokenData["token"],
			),
			5000,
			$error,
			$code
		);
		return $result !== null && $result["ok"];
	}

	/**
	 * Execute one prepared action.  Returns the aggregate result document.
	 *
	 * Each step re-checks nothing user-controlled: the record was written by
	 * prepare and its params hash is verified before this function runs.
	 */
	function _actionExecuteSteps( $route, $params, &$error, &$code )
	{
		$error = null;
		$code = 500;
		$steps = _actionSteps( $route, $params );
		if ( count( $steps ) === 0 )
		{
			$error = "the action has no executable step";
			$code = 422;
			return null;
		}

		$results = array();
		$timedOut = false;
		$failed = false;
		$firstError = null;
		$firstCode = null;

		foreach ( $steps as $step )
		{
			$job = array( "verb" => $step["verb"] );
			if ( $step["verb"] === "sqlite" )
			{
				$job["sql"] = $step["sql"];
			}
			else
			{
				$tokenData = _mintWsToken();
				if ( $tokenData === null )
				{
					$error = "the vendor WSS token surface is unavailable";
					$code = 503;
					return null;
				}
				$job["command"] = $step["command"];
				$job["params"] = $step["params"];
				$job["endpoint"] = "wss://127.0.0.1:9997/?token=" . $tokenData["token"];
				if ( $step["followUp"] !== null )
				{
					$job["followUp"] = $step["followUp"];
				}
			}

			$catalog = _actionCatalog();
			$timeoutMs = (int)$catalog[$route]["timeoutMs"];
			$result = _actionRunJob( _actionUuid(), $job, $timeoutMs, $jobError, $jobCode );
			if ( $result === null )
			{
				$error = $jobError;
				$code = $jobCode;
				$timedOut = $jobCode === 504;
				$failed = true;
				break;
			}
			$results[] = $result["result"];
			if ( $result["timedOut"] )
			{
				$timedOut = true;
			}
			if ( !$result["ok"] )
			{
				$failed = true;
				$firstError = $result["error"];
				$firstCode = $result["errorCode"];
				break;
			}
		}

		if ( $timedOut )
		{
			$stopError = null;
			$stopSent = _actionStopAfterTimeout( $route, $stopError );
			$error = "the action exceeded its hard timeout";
			$code = 504;
			return array(
				"state" => "timed_out",
				"errorCode" => 504,
				"error" => $error,
				"result" => array(
					"steps" => $results,
					"stopAttempted" => _actionHasStopPrimitive( $route ) || $route === "action_agsa_move",
					"stopSent" => $stopSent,
					"stopError" => $stopError,
				),
				"durationMs" => null,
			);
		}

		if ( $failed )
		{
			$error = $firstError !== null ? $firstError : "the action failed";
			$code = is_int( $firstCode ) && $firstCode > 0 ? $firstCode : 500;
			return array(
				"state" => "failed",
				"errorCode" => $code,
				"error" => $error,
				"result" => array( "steps" => $results ),
				"durationMs" => null,
			);
		}

		$merged = array( "steps" => $results );
		if ( count( $results ) === 1 )
		{
			foreach ( $results[0] as $key => $value )
			{
				$merged[$key] = $value;
			}
		}
		return array(
			"state" => "completed",
			"errorCode" => 0,
			"error" => null,
			"result" => $merged,
			"durationMs" => null,
		);
	}

	// --- Action handlers ------------------------------------------------------------

	/** True for an action name that would cross the ESP boundary. */
	function _actionIsBoundaryName( $route )
	{
		return is_string( $route )
			&& preg_match( '/^action_(esp|wifi|firmware|fuse|otp|bootloader|pairing|onboarding|cloud)_/', $route ) === 1;
	}

	/**
	 * True for an action name that would write a credential.
	 *
	 * Credential writes are excluded by owner decision, so the names are absent
	 * from the catalog.  They are refused explicitly instead of being reported
	 * as an unavailable action, and the refusal never echoes the caller's name.
	 */
	function _actionIsCredentialName( $route )
	{
		return is_string( $route )
			&& preg_match( '/^action_(role|password|credential|login)_/', $route ) === 1;
	}

	/** Gate-off refusal shared by every action meta route. */
	function _actionGateRefusal( $reason, &$returnJson, &$success, &$returnVal, $route, $actionId = null )
	{
		_actionAuditWrite( "refuse", $route, $actionId, null, null, "gate_disabled", 403, null, null );
		_failResponse( $returnJson, $success, $returnVal, 403, $reason );
	}

	/** Handle action_prepare. */
	function _handleActionPrepare( $postContent, &$returnJson, &$success, &$returnVal )
	{
		$startedAt = microtime( true );
		$gate = _actionGate( $gateReason );
		if ( !$gate["enabled"] )
		{
			_actionGateRefusal( $gateReason, $returnJson, $success, $returnVal, "action_prepare" );
			return;
		}
		$policy = $gate["policy"];

		$body = _decodeBody( $postContent );
		$route = isset( $body["route"] ) ? $body["route"] : null;
		$params = isset( $body["params"] ) ? $body["params"] : array();
		$requestId = isset( $body["requestId"] ) ? $body["requestId"] : null;

		if ( !_actionValidRequestId( $requestId ) )
		{
			_actionAuditWrite( "refuse", is_string( $route ) ? $route : "action_prepare", null, null, null, "bad_request_id", 400, null, null );
			_failResponse( $returnJson, $success, $returnVal, 400, "requestId is required (8..64 characters: A-Z a-z 0-9 . _ -)" );
			return;
		}
		if ( !is_string( $route ) || $route === "" )
		{
			_actionAuditWrite( "refuse", "action_prepare", null, $requestId, null, "missing_route", 400, null, null );
			_failResponse( $returnJson, $success, $returnVal, 400, "route is required" );
			return;
		}

		$catalog = _actionCatalog();
		if ( !isset( $catalog[$route] ) )
		{
			if ( _actionIsBoundaryName( $route ) )
			{
				_actionAuditWrite( "refuse", $route, null, $requestId, null, "esp_boundary", 403, null, null );
				_failResponse(
					$returnJson,
					$success,
					$returnVal,
					403,
					"ESP, WiFi, firmware, fuse and bootloader operations are outside this API by construction"
				);
				return;
			}
			if ( _actionIsCredentialName( $route ) )
			{
				_actionAuditWrite( "refuse", $route, null, $requestId, null, "credential_excluded", 403, null, null );
				_failResponse(
					$returnJson,
					$success,
					$returnVal,
					403,
					"credential-bearing operations are outside this API by owner decision"
				);
				return;
			}
			_actionAuditWrite( "refuse", $route, null, $requestId, null, "unknown_action", 404, null, null );
			_failResponse( $returnJson, $success, $returnVal, 404, "unknown action" );
			return;
		}

		$entry = $catalog[$route];
		if ( $entry["status"] !== "implemented" )
		{
			$code = isset( $entry["code"] ) ? (int)$entry["code"] : 422;
			_actionAuditWrite( "refuse", $route, null, $requestId, null, "unavailable", $code, null, null );
			_failResponse( $returnJson, $success, $returnVal, $code, "action unavailable: " . $entry["reason"] );
			return;
		}
		if ( !empty( $entry["destructive"] ) && !$gate["destructive"] )
		{
			_actionAuditWrite( "refuse", $route, null, $requestId, null, "destructive_gate_off", 403, null, null );
			_failResponse(
				$returnJson,
				$success,
				$returnVal,
				403,
				"destructive actions are disabled; re-deploy with --enable-destructive-actions"
			);
			return;
		}

		$normalized = _actionNormalizeParams( $route, $params, $policy, $paramError, $paramCode );
		if ( $normalized === null )
		{
			_actionAuditWrite( "refuse", $route, null, $requestId, null, "invalid_params", $paramCode, null, null );
			_failResponse( $returnJson, $success, $returnVal, $paramCode, $paramError );
			return;
		}
		$paramsHash = _actionParamsHash( $normalized );

		// A token is bound to the boot it was prepared in, so expiry across a
		// reboot fails closed.  Without a usable boot id nothing is prepared.
		$bootId = _actionBootId();
		if ( $bootId === null )
		{
			_actionAuditWrite( "refuse", $route, null, $requestId, $paramsHash, "boot_id_unavailable", 503, null, null );
			_failResponse( $returnJson, $success, $returnVal, 503, "the kernel boot id is unavailable; no action can be prepared" );
			return;
		}

		// Idempotency: the same requestId returns the same prepared action; a
		// different payload under the same requestId is a conflict.
		$existing = _actionFindByRequestId( $requestId );
		if ( $existing !== null )
		{
			if ( $existing["route"] !== $route || $existing["paramsHash"] !== $paramsHash )
			{
				_actionAuditWrite( "refuse", $route, $existing["actionId"], $requestId, $paramsHash, "idempotency_conflict", 409, null, null );
				_failResponse( $returnJson, $success, $returnVal, 409, "requestId was already used with different parameters" );
				return;
			}
			// A record from a previous boot can never execute, so a retry must not
			// be answered with its dead token: expire it and prepare anew (which
			// also consumes a rate-limit slot, as a genuinely new action should).
			if ( !isset( $existing["bootId"] ) || !is_string( $existing["bootId"] )
				|| $existing["bootId"] !== $bootId )
			{
				$existing["state"] = "expired";
				_actionWriteRecord( $existing );
			}
			else
			{
				$token = _actionToken( $policy["secret"], $existing["actionId"], $route, $paramsHash, $existing["expires"], $requestId );
				_okResponse( $returnJson, $success, $returnVal, array(
					"schema" => "e64local-api-v" . E64LOCAL_API_VERSION,
					"route" => "action_prepare",
					"actionId" => $existing["actionId"],
					"actionRoute" => $route,
					"confirmToken" => $token,
					"expires" => (int)$existing["expires"],
					"expiresAt" => gmdate( "Y-m-d\TH:i:s\Z", (int)$existing["expires"] ),
					"state" => $existing["state"],
					"warnings" => isset( $existing["warnings"] ) ? $existing["warnings"] : array(),
					"auditId" => isset( $existing["auditId"] ) ? $existing["auditId"] : null,
					"idempotent" => true,
				) );
				return;
			}
		}

		$retryAfter = 0;
		$ioError = null;
		$allowed = _actionRateLimit( $entry["bucket"], $policy, $retryAfter, $ioError );
		if ( $allowed === null )
		{
			// Fail closed: an unusable bucket is corruption or an I/O fault, not
			// a reason to let the request through unthrottled.
			_actionAuditWrite( "refuse", $route, null, $requestId, $paramsHash, "rate_state_unavailable", 503, null, null );
			_failResponse(
				$returnJson,
				$success,
				$returnVal,
				503,
				"rate-limit state is unavailable; refusing rather than exceeding the limit: " . $ioError
			);
			return;
		}
		if ( $allowed === false )
		{
			_actionAuditWrite( "refuse", $route, null, $requestId, $paramsHash, "rate_limited", 429, $retryAfter, null );
			$returnJson["retryAfter"] = $retryAfter;
			_failResponse( $returnJson, $success, $returnVal, 429, "rate limit exceeded; retry after " . $retryAfter . " seconds" );
			return;
		}

		$warnings = array();
		if ( !_actionPreconditions( $route, $normalized, $warnings, $preError, $preCode ) )
		{
			_actionAuditWrite( "refuse", $route, null, $requestId, $paramsHash, "unsafe_state", $preCode, null, null );
			_failResponse( $returnJson, $success, $returnVal, $preCode, $preError );
			return;
		}

		$ttl = !empty( $entry["destructive"] ) || $entry["risk"] === "actuator" ? 60 : 600;
		if ( isset( $policy["tokenTtlSec"] ) && is_array( $policy["tokenTtlSec"] ) )
		{
			$key = !empty( $entry["destructive"] ) ? "destructive" : ( $entry["risk"] === "actuator" ? "actuator" : "stateChanging" );
			if ( isset( $policy["tokenTtlSec"][$key] ) && is_int( $policy["tokenTtlSec"][$key] ) )
			{
				$ttl = min( $ttl, max( 15, $policy["tokenTtlSec"][$key] ) );
			}
		}

		$actionId = _actionUuid();
		$auditId = _actionUuid();
		$expires = time() + $ttl;
		$token = _actionToken( $policy["secret"], $actionId, $route, $paramsHash, $expires, $requestId );

		$record = array(
			"schema" => "e64local-action-record-v1",
			"actionId" => $actionId,
			"auditId" => $auditId,
			"route" => $route,
			"risk" => $entry["risk"],
			"destructive" => !empty( $entry["destructive"] ),
			"paramsHash" => $paramsHash,
			"params" => $normalized,
			"requestId" => $requestId,
			"state" => "prepared",
			"expires" => $expires,
			"bootId" => $bootId,
			"preparedAt" => gmdate( "Y-m-d\TH:i:s\Z" ),
			"preparedAtEpoch" => time(),
			"warnings" => $warnings,
			"client" => _actionClient(),
		);
		if ( !_actionWriteRecord( $record ) )
		{
			_actionAuditWrite( "refuse", $route, $actionId, $requestId, $paramsHash, "record_write_failed", 500, null, null );
			_failResponse( $returnJson, $success, $returnVal, 500, "could not persist the prepared action" );
			return;
		}

		_actionPruneRecords();
		_actionAuditWrite( "prepare", $route, $actionId, $requestId, $paramsHash, "prepared", 0, null, (int)round( ( microtime( true ) - $startedAt ) * 1000 ) );

		_okResponse( $returnJson, $success, $returnVal, array(
			"schema" => "e64local-api-v" . E64LOCAL_API_VERSION,
			"route" => "action_prepare",
			"actionId" => $actionId,
			"actionRoute" => $route,
			"confirmToken" => $token,
			"expires" => $expires,
			"expiresAt" => gmdate( "Y-m-d\TH:i:s\Z", $expires ),
			"state" => "prepared",
			"warnings" => $warnings,
			"auditId" => $auditId,
		) );
	}

	/** Handle action_execute. */
	function _handleActionExecute( $postContent, &$returnJson, &$success, &$returnVal )
	{
		$startedAt = microtime( true );
		$gate = _actionGate( $gateReason );
		if ( !$gate["enabled"] )
		{
			_actionGateRefusal( $gateReason, $returnJson, $success, $returnVal, "action_execute" );
			return;
		}
		$policy = $gate["policy"];

		$body = _decodeBody( $postContent );
		$actionId = isset( $body["actionId"] ) ? $body["actionId"] : null;
		$token = isset( $body["confirmToken"] ) ? $body["confirmToken"] : null;
		$requestId = isset( $body["requestId"] ) ? $body["requestId"] : null;

		if ( !is_string( $actionId ) || preg_match( '/^[0-9a-f-]{36}$/', $actionId ) !== 1 )
		{
			_actionAuditWrite( "refuse", "action_execute", null, null, null, "bad_action_id", 400, null, null );
			_failResponse( $returnJson, $success, $returnVal, 400, "actionId is required" );
			return;
		}
		if ( !is_string( $token ) || preg_match( '/^[0-9a-f]{64}$/', $token ) !== 1 )
		{
			_actionAuditWrite( "refuse", "action_execute", $actionId, null, null, "bad_confirm_token", 400, null, null );
			_failResponse( $returnJson, $success, $returnVal, 400, "confirmToken is required" );
			return;
		}
		if ( $requestId !== null && !_actionValidRequestId( $requestId ) )
		{
			_actionAuditWrite( "refuse", "action_execute", $actionId, null, null, "bad_request_id", 400, null, null );
			_failResponse( $returnJson, $success, $returnVal, 400, "requestId is malformed" );
			return;
		}

		$record = _actionReadRecord( $actionId );
		if ( $record === null )
		{
			_actionAuditWrite( "refuse", "action_execute", $actionId, $requestId, null, "unknown_action_id", 404, null, null );
			_failResponse( $returnJson, $success, $returnVal, 404, "unknown actionId" );
			return;
		}
		$route = $record["route"];
		$paramsHash = $record["paramsHash"];

		if ( $requestId !== null && $requestId !== $record["requestId"] )
		{
			_actionAuditWrite( "refuse", $route, $actionId, $requestId, $paramsHash, "idempotency_conflict", 409, null, null );
			_failResponse( $returnJson, $success, $returnVal, 409, "requestId does not match the prepared action" );
			return;
		}
		if ( $record["state"] !== "prepared" )
		{
			_actionAuditWrite( "refuse", $route, $actionId, $record["requestId"], $paramsHash, "state_" . $record["state"], 409, null, null );
			_failResponse( $returnJson, $success, $returnVal, 409, "action is not in a state that allows execute" );
			return;
		}
		// A token prepared before a reboot must not execute afterwards: the wall
		// clock may have moved either way, so expiry is not a reliable bound
		// across a reboot.
		if ( !_actionBootMatchesRecord( $record, $bootError, $bootCode ) )
		{
			if ( $bootCode === 409 )
			{
				$record["state"] = "expired";
				_actionWriteRecord( $record );
			}
			_actionAuditWrite(
				"refuse",
				$route,
				$actionId,
				$record["requestId"],
				$paramsHash,
				$bootCode === 503 ? "boot_id_unavailable" : "boot_changed",
				$bootCode,
				null,
				null
			);
			_failResponse( $returnJson, $success, $returnVal, $bootCode, $bootError );
			return;
		}
		if ( time() > (int)$record["expires"] )
		{
			$record["state"] = "expired";
			_actionWriteRecord( $record );
			_actionAuditWrite( "refuse", $route, $actionId, $record["requestId"], $paramsHash, "expired", 409, null, null );
			_failResponse( $returnJson, $success, $returnVal, 409, "the confirm token has expired" );
			return;
		}

		$expected = _actionToken( $policy["secret"], $actionId, $route, $paramsHash, (int)$record["expires"], $record["requestId"] );
		if ( !hash_equals( $expected, $token ) )
		{
			_actionAuditWrite( "refuse", $route, $actionId, $record["requestId"], $paramsHash, "token_mismatch", 403, null, null );
			_failResponse( $returnJson, $success, $returnVal, 403, "confirm token does not match this action" );
			return;
		}
		if ( !isset( $record["params"] ) || _actionParamsHash( $record["params"] ) !== $paramsHash )
		{
			_actionAuditWrite( "refuse", $route, $actionId, $record["requestId"], $paramsHash, "record_integrity", 500, null, null );
			_failResponse( $returnJson, $success, $returnVal, 500, "the prepared action record failed its integrity check" );
			return;
		}

		$catalog = _actionCatalog();
		if ( !isset( $catalog[$route] ) || $catalog[$route]["status"] !== "implemented" )
		{
			_actionAuditWrite( "refuse", $route, $actionId, $record["requestId"], $paramsHash, "unavailable", 403, null, null );
			_failResponse( $returnJson, $success, $returnVal, 403, "the action is no longer available" );
			return;
		}
		if ( !empty( $catalog[$route]["destructive"] ) && !$gate["destructive"] )
		{
			_actionAuditWrite( "refuse", $route, $actionId, $record["requestId"], $paramsHash, "destructive_gate_off", 403, null, null );
			_failResponse( $returnJson, $success, $returnVal, 403, "destructive actions are disabled" );
			return;
		}

		$retryAfter = 0;
		$ioError = null;
		$allowed = _actionRateLimit( "execute", $policy, $retryAfter, $ioError );
		if ( $allowed !== true )
		{
			// Fail closed on unusable state, exactly like prepare.
			$code = $allowed === false ? 429 : 503;
			_actionAuditWrite( "refuse", $route, $actionId, $record["requestId"], $paramsHash, $allowed === false ? "rate_limited" : "rate_state_unavailable", $code, $retryAfter, null );
			if ( $allowed === false )
			{
				$returnJson["retryAfter"] = $retryAfter;
			}
			_failResponse(
				$returnJson,
				$success,
				$returnVal,
				$code,
				$allowed === false ? "rate limit exceeded" : "rate-limit state is unavailable; refusing rather than exceeding the limit: " . $ioError
			);
			return;
		}

		$warnings = array();
		if ( !_actionPreconditions( $route, $record["params"], $warnings, $preError, $preCode ) )
		{
			_actionAuditWrite( "refuse", $route, $actionId, $record["requestId"], $paramsHash, "unsafe_state", $preCode, null, null );
			_failResponse( $returnJson, $success, $returnVal, $preCode, $preError );
			return;
		}

		// Claim the record before actuation.  The claim is the atomic
		// prepared -> executing transition, so two concurrent executes with the
		// same confirm token cannot both start the action.
		$claimed = _actionClaimRecord( $actionId, "executing", $record, $claimError, $claimCode );
		if ( $claimed === null )
		{
			_actionAuditWrite( "refuse", $route, $actionId, $record["requestId"], $paramsHash, "claim_failed", $claimCode, null, null );
			_failResponse( $returnJson, $success, $returnVal, $claimCode, $claimError );
			return;
		}
		$record = $claimed;

		// Fail closed when the audit cannot be written: no unaudited actuation.
		if ( !_actionAuditWrite( "execute", $route, $actionId, $record["requestId"], $paramsHash, "executing", 0, null, null ) )
		{
			$record["state"] = "failed";
			$record["errorCode"] = 500;
			_actionWriteRecord( $record );
			_failResponse( $returnJson, $success, $returnVal, 500, "audit log is not writable; the action was not started" );
			return;
		}

		$outcome = _actionExecuteSteps( $route, $record["params"], $executeError, $executeCode );
		$final = $outcome === null
			? array( "state" => "failed", "errorCode" => $executeCode, "error" => $executeError, "result" => array(), "durationMs" => null )
			: $outcome;

		$durationMs = (int)round( ( microtime( true ) - $startedAt ) * 1000 );
		$finalState = $final["state"];
		$record["state"] = $finalState;
		$record["errorCode"] = (int)$final["errorCode"];
		$record["error"] = $final["error"];
		$record["result"] = $final["result"];
		$record["durationMs"] = $durationMs;
		$record["finishedAt"] = gmdate( "Y-m-d\TH:i:s\Z" );
		$record["finishedAtEpoch"] = time();
		$latest = _actionReadRecord( $actionId );
		if ( $latest !== null && !empty( $latest["cancelRequested"] ) && $finalState === "completed" )
		{
			$record["state"] = "cancelled";
		}
		_actionWriteRecord( $record );

		$auditResult = $finalState . ( $final["error"] !== null ? ": " . $final["error"] : "" );
		_actionAuditWrite(
			$finalState === "timed_out" ? "timeout" : "result",
			$route,
			$actionId,
			$record["requestId"],
			$paramsHash,
			$auditResult,
			(int)$final["errorCode"],
			null,
			$durationMs
		);

		if ( $final["errorCode"] !== 0 )
		{
			// The failure envelope still carries the outcome so a client can
			// distinguish "refused before actuation" from "started and failed".
			_failResponse( $returnJson, $success, $returnVal, (int)$final["errorCode"], $final["error"] );
			$returnJson["data"] = array(
				"schema" => "e64local-api-v" . E64LOCAL_API_VERSION,
				"route" => "action_execute",
				"actionId" => $actionId,
				"actionRoute" => $route,
				"state" => $record["state"],
				"auditId" => $record["auditId"],
				"result" => $final["result"],
				"durationMs" => $durationMs,
			);
			return;
		}

		_okResponse( $returnJson, $success, $returnVal, array(
			"schema" => "e64local-api-v" . E64LOCAL_API_VERSION,
			"route" => "action_execute",
			"actionId" => $actionId,
			"actionRoute" => $route,
			"state" => $record["state"],
			"auditId" => $record["auditId"],
			"result" => $final["result"],
			"durationMs" => $durationMs,
		) );
	}

	/** Handle action_status (read-only). */
	function _handleActionStatus( $postContent, &$returnJson, &$success, &$returnVal )
	{
		$gate = _actionGate( $gateReason );
		if ( !$gate["enabled"] )
		{
			_actionGateRefusal( $gateReason, $returnJson, $success, $returnVal, "action_status" );
			return;
		}
		$body = _decodeBody( $postContent );
		$actionId = isset( $body["actionId"] ) ? $body["actionId"] : null;
		if ( !is_string( $actionId ) || preg_match( '/^[0-9a-f-]{36}$/', $actionId ) !== 1 )
		{
			_failResponse( $returnJson, $success, $returnVal, 400, "actionId is required" );
			return;
		}
		$record = _actionReadRecord( $actionId );
		if ( $record === null )
		{
			_failResponse( $returnJson, $success, $returnVal, 404, "unknown actionId" );
			return;
		}
		_okResponse( $returnJson, $success, $returnVal, array(
			"schema" => "e64local-api-v" . E64LOCAL_API_VERSION,
			"route" => "action_status",
			"actionId" => $record["actionId"],
			"actionRoute" => $record["route"],
			"state" => $record["state"],
			"preparedAt" => $record["preparedAt"],
			"expiresAt" => gmdate( "Y-m-d\TH:i:s\Z", (int)$record["expires"] ),
			"startedAt" => isset( $record["startedAt"] ) ? $record["startedAt"] : null,
			"finishedAt" => isset( $record["finishedAt"] ) ? $record["finishedAt"] : null,
			"durationMs" => isset( $record["durationMs"] ) ? (int)$record["durationMs"] : null,
			"errorCode" => isset( $record["errorCode"] ) ? (int)$record["errorCode"] : 0,
			"error" => isset( $record["error"] ) ? $record["error"] : null,
			"result" => isset( $record["result"] ) ? $record["result"] : array(),
			"cancelRequested" => !empty( $record["cancelRequested"] ),
			"auditId" => isset( $record["auditId"] ) ? $record["auditId"] : null,
		) );
	}

	/** Handle action_cancel (idempotent). */
	function _handleActionCancel( $postContent, &$returnJson, &$success, &$returnVal )
	{
		$gate = _actionGate( $gateReason );
		if ( !$gate["enabled"] )
		{
			_actionGateRefusal( $gateReason, $returnJson, $success, $returnVal, "action_cancel" );
			return;
		}
		$body = _decodeBody( $postContent );
		$actionId = isset( $body["actionId"] ) ? $body["actionId"] : null;
		if ( !is_string( $actionId ) || preg_match( '/^[0-9a-f-]{36}$/', $actionId ) !== 1 )
		{
			_failResponse( $returnJson, $success, $returnVal, 400, "actionId is required" );
			return;
		}
		$record = _actionReadRecord( $actionId );
		if ( $record === null )
		{
			_failResponse( $returnJson, $success, $returnVal, 404, "unknown actionId" );
			return;
		}

		$state = $record["state"];
		if ( $state === "prepared" )
		{
			$record["state"] = "cancelled";
			$record["finishedAt"] = gmdate( "Y-m-d\TH:i:s\Z" );
			_actionWriteRecord( $record );
			_actionAuditWrite( "cancel", $record["route"], $actionId, $record["requestId"], $record["paramsHash"], "cancelled_before_execute", 0, null, null );
			_okResponse( $returnJson, $success, $returnVal, array(
				"schema" => "e64local-api-v" . E64LOCAL_API_VERSION,
				"route" => "action_cancel",
				"actionId" => $actionId,
				"actionRoute" => $record["route"],
				"state" => "cancelled",
				"cancelled" => true,
				"stopSent" => false,
			) );
			return;
		}

		if ( $state === "executing" )
		{
			$stopError = null;
			$stopSent = _actionStopAfterTimeout( $record["route"], $stopError );
			$record["cancelRequested"] = true;
			_actionWriteRecord( $record );
			_actionAuditWrite( "cancel", $record["route"], $actionId, $record["requestId"], $record["paramsHash"], "cancel_requested", 0, null, null );
			_okResponse( $returnJson, $success, $returnVal, array(
				"schema" => "e64local-api-v" . E64LOCAL_API_VERSION,
				"route" => "action_cancel",
				"actionId" => $actionId,
				"actionRoute" => $record["route"],
				"state" => "cancelling",
				"cancelled" => false,
				"stopSent" => $stopSent,
				"stopError" => $stopError,
			) );
			return;
		}

		// Idempotent for every terminal state.
		_okResponse( $returnJson, $success, $returnVal, array(
			"schema" => "e64local-api-v" . E64LOCAL_API_VERSION,
			"route" => "action_cancel",
			"actionId" => $actionId,
			"actionRoute" => $record["route"],
			"state" => $state,
			"cancelled" => $state === "cancelled",
			"stopSent" => false,
			"note" => "the action is already in a terminal state",
		) );
	}

	/** Handle action_audit (read-only). */
	function _handleActionAudit( $postContent, &$returnJson, &$success, &$returnVal )
	{
		$gate = _actionGate( $gateReason );
		if ( !$gate["enabled"] )
		{
			_actionGateRefusal( $gateReason, $returnJson, $success, $returnVal, "action_audit" );
			return;
		}
		$body = _decodeBody( $postContent );
		$limit = _limitFromBody( $body, 50, E64LOCAL_ACTION_MAX_AUDIT_PAGE );
		$offset = _offsetFromBody( $body );

		$since = _normalizeTimeValue( isset( $body["since"] ) ? $body["since"] : null, false );
		$until = _normalizeTimeValue( isset( $body["until"] ) ? $body["until"] : null, true );
		if ( $since === false )
		{
			_failResponse( $returnJson, $success, $returnVal, 400, "invalid since (use YYYY-MM-DD, YYYY-MM-DD HH:MM:SS or Unix seconds)" );
			return;
		}
		if ( $until === false )
		{
			_failResponse( $returnJson, $success, $returnVal, 400, "invalid until (use YYYY-MM-DD, YYYY-MM-DD HH:MM:SS or Unix seconds)" );
			return;
		}
		if ( $since !== null && $until !== null && strcmp( $since, $until ) > 0 )
		{
			_failResponse( $returnJson, $success, $returnVal, 400, "since must not be after until" );
			return;
		}

		$page = _actionAuditRead(
			$limit,
			$offset,
			$since === null ? null : (int)strtotime( $since ),
			$until === null ? null : (int)strtotime( $until )
		);
		_okResponse( $returnJson, $success, $returnVal, array(
			"schema" => "e64local-api-v" . E64LOCAL_API_VERSION,
			"route" => "action_audit",
			"rows" => $page["rows"],
			"count" => $page["count"],
			"total" => $page["total"],
			"limit" => $limit,
			"offset" => $offset,
			"since" => $since,
			"until" => $until,
			"hasMore" => ( $offset + $page["count"] ) < $page["total"],
		) );
	}

	/** Dispatch the five action meta routes. */
	function _handleActionRoute( $route, $postContent, &$returnJson, &$success, &$returnVal )
	{
		switch ( $route )
		{
			case "action_prepare":
				_handleActionPrepare( $postContent, $returnJson, $success, $returnVal );
				return true;
			case "action_execute":
				_handleActionExecute( $postContent, $returnJson, $success, $returnVal );
				return true;
			case "action_status":
				_handleActionStatus( $postContent, $returnJson, $success, $returnVal );
				return true;
			case "action_cancel":
				_handleActionCancel( $postContent, $returnJson, $success, $returnVal );
				return true;
			case "action_audit":
				_handleActionAudit( $postContent, $returnJson, $success, $returnVal );
				return true;
		}
		return false;
	}

	/** Action gate facts for the capabilities document. */
	function _actionCapabilities()
	{
		$gate = _actionGate( $gateReason );
		$catalog = _actionCatalog();
		$routes = array();
		$entries = array();
		foreach ( $catalog as $route => $entry )
		{
			$item = array(
				"route" => $route,
				"status" => $entry["status"],
				"risk" => $entry["risk"],
				"destructive" => !empty( $entry["destructive"] ),
				"surface" => isset( $entry["surface"] ) ? $entry["surface"] : null,
				"summary" => isset( $entry["summary"] ) ? $entry["summary"] : null,
				"evidence" => $entry["evidence"],
			);
			// The catalog is always readable for introspection, but a route is
			// only advertised as dispatchable when the gate lets it run: a
			// destructive route is not dispatchable while the second gate is
			// off, and saying otherwise would make capabilities lie about it.
			if ( $entry["status"] === "implemented" && $gate["enabled"] )
			{
				if ( !empty( $entry["destructive"] ) && !$gate["destructive"] )
				{
					$item["blocked"] = "destructive actions are disabled; re-deploy with --enable-destructive-actions";
				}
				else
				{
					$routes[] = $route;
				}
			}
			elseif ( $entry["status"] === "unavailable" )
			{
				$item["reason"] = $entry["reason"];
			}
			$entries[] = $item;
		}

		$document = array(
			"schema" => "e64local-api-v" . E64LOCAL_API_VERSION,
			"enabled" => $gate["enabled"],
			"destructiveEnabled" => $gate["enabled"] && $gate["destructive"],
			"reason" => $gate["reason"],
			"actionRoutes" => $routes,
			"catalog" => $entries,
			"note" => "action identifiers are passed in action_prepare, not posted as paths",
		);
		if ( $gate["enabled"] && is_array( $gate["policy"] ) )
		{
			$policy = $gate["policy"];
			$bounds = array();
			global $E64LOCAL_ACTION_ABSOLUTE_BOUNDS;
			foreach ( $E64LOCAL_ACTION_ABSOLUTE_BOUNDS as $name => $absolute )
			{
				$bounds[$name] = _actionBound( $policy, $name, $absolute["min"], $absolute["max"] );
			}
			$document["policy"] = array(
				"version" => 1,
				"bounds" => $bounds,
				"rateLimits" => isset( $policy["rateLimits"] ) ? $policy["rateLimits"] : array(),
				"tokenTtlSec" => isset( $policy["tokenTtlSec"] ) ? $policy["tokenTtlSec"] : array(
					"actuator" => 60,
					"stateChanging" => 600,
					"destructive" => 60,
				),
				"audit" => array(
					"file" => E64LOCAL_AUDIT_FILE,
					"maxBytes" => E64LOCAL_ACTION_AUDIT_MAX_BYTES,
					"keep" => E64LOCAL_ACTION_AUDIT_KEEP,
				),
			);
		}
		return $document;
	}

	// --- Main dispatcher ------------------------------------------------------------

	/** Local API v1 dispatcher.
	 *
	 * Called by rest_api.php when isDev() is true and the request is not handled
	 * by the vendor's own routes. Runs within an authenticated REST session.
	 *
	 * @param string $requestUri     basename of REQUEST_URI (e.g., "grind_log")
	 * @param string $postContent    raw POST body
	 * @param bool   $mobileAppLogin whether the session is from the mobile app
	 * @param int    &$returnVal     return value (by reference, for error codes)
	 * @param array  &$returnJson    response JSON (by reference)
	 * @param bool   &$success       success flag (by reference)
	 * @return bool  true if the route was handled, false otherwise
	 */
	function restApiDev( $requestUri, $postContent, $mobileAppLogin, &$returnVal, &$returnJson, &$success )
	{
		// Bound the request before touching the token file or the database.
		if ( strlen( (string)$postContent ) > MAX_REQUEST_BYTES )
		{
			_failResponse(
				$returnJson,
				$success,
				$returnVal,
				413,
				"request body too large (max " . MAX_REQUEST_BYTES . " bytes)"
			);
			return true;
		}

		// The vendor dispatcher has already authenticated the session. Mobile-app
		// sessions are excluded here because they are not owner sessions.
		if ( $mobileAppLogin )
		{
			_failResponse( $returnJson, $success, $returnVal, 403, "mobile app sessions cannot use local API" );
			return true;  // handled, but with error
		}

		// The owner token is checked before any route dispatch, so an unknown
		// route name cannot be used to probe the module.
		$tokenError = null;
		if ( !_checkOwnerToken( $postContent, $tokenError ) )
		{
			_failResponse(
				$returnJson,
				$success,
				$returnVal,
				401,
				$tokenError,
				"Local API requires owner token in " . E64LOCAL_TOKEN_FILE
			);
			return true;  // handled, but with error
		}

		// Route to the appropriate handler
		switch ( $requestUri )
		{
			case "capabilities":
				_handleCapabilities( $postContent, $returnJson, $success, $returnVal );
				return true;

			case "machine":
				_handleMachine( $postContent, $returnJson, $success, $returnVal );
				return true;

			case "grind_log":
				_handleGrindLog( $postContent, $returnJson, $success, $returnVal );
				return true;

			case "service_log":
				_handleServiceLog( $postContent, $returnJson, $success, $returnVal );
				return true;

			case "alert_log":
				_handleAlertLog( $postContent, $returnJson, $success, $returnVal );
				return true;

			case "portafilters":
				_handlePortafilters( $postContent, $returnJson, $success, $returnVal );
				return true;

			case "recipes":
				_handleRecipes( $postContent, $returnJson, $success, $returnVal );
				return true;

			case "settings":
				_handleSettings( $postContent, $returnJson, $success, $returnVal );
				return true;

			case "config":
				_handleConfig( $postContent, $returnJson, $success, $returnVal );
				return true;

			case "file":
				_handleFile( $postContent, $returnJson, $success, $returnVal );
				return true;

			case "ws_token":
				_handleWsToken( $postContent, $returnJson, $success, $returnVal );
				return true;

			case "action_prepare":
			case "action_execute":
			case "action_status":
			case "action_cancel":
			case "action_audit":
				_handleActionRoute( $requestUri, $postContent, $returnJson, $success, $returnVal );
				return true;

			default:
				// Action identifiers are not HTTP paths.  Answer a bare POST to
				// one with a pointer instead of letting the vendor dispatcher
				// treat it as an unknown vendor route, and keep the ESP-boundary
				// names indistinguishable from any other excluded name.
				if ( strpos( $requestUri, "action_" ) === 0 )
				{
					if ( _actionIsBoundaryName( $requestUri ) )
					{
						_failResponse( $returnJson, $success, $returnVal, 403, "ESP, WiFi, firmware, fuse and bootloader operations are outside this API by construction" );
					}
					elseif ( _actionIsCredentialName( $requestUri ) )
					{
						_failResponse( $returnJson, $success, $returnVal, 403, "credential-bearing operations are outside this API by owner decision" );
					}
					else
					{
						_failResponse( $returnJson, $success, $returnVal, 404, "action identifiers are not HTTP paths; use action_prepare" );
					}
					return true;
				}
				// Not a local API route
				return false;
		}
	}

	// Module loaded successfully; restApiDev() will be called by the dispatcher
