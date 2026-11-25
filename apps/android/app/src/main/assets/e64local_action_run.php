#!/usr/bin/env php
<?php
	/*
	 * e64local-action-run - bounded execution helper for the Local Owner API
	 *
	 * Installed as /usr/local/bin/e64local-action-run (root:root, mode 0755)
	 * by `e64root api deploy --enable-actions`.  The PHP module invokes it as
	 *
	 *   sudo -n /usr/local/bin/e64local-action-run /db/e64local/actions/<id>.job.json
	 *
	 * with a single server-derived argument.  It is the only process that
	 * touches the WSS command surface or writes the machine database on behalf
	 * of an action, and it re-validates every field of the job file before it
	 * runs anything.  A caller cannot supply a command name, SQL text, a table
	 * name, a column name, a shell fragment or a filesystem path that is not
	 * produced by this file's own allowlist.
	 *
	 * Job file (written 0600 by the module):
	 *
	 *   {
	 *     "schema": "e64local-action-job-v1",
	 *     "jobId": "<uuid>",
	 *     "verb": "wss" | "state" | "sqlite",
	 *     "timeoutMs": 15000,
	 *     "endpoint": "wss://127.0.0.1:9997/?token=...",   (wss/state)
	 *     "command": "StartGrindGbw",                     (wss)
	 *     "params": {"targetWeightGr": 18.0},              (wss)
	 *     "followUp": {"command":"Stop","afterMs":1500},   (wss, optional)
	 *     "sqlite3": "/usr/bin/sqlite3",                  (sqlite)
	 *     "dbPath": "/db/HsgSqlite.db",                   (sqlite)
	 *     "backupDir": "/db/e64local/backup",             (sqlite)
	 *     "sql": {"kind":"settings_set","params":{...}}    (sqlite)
	 *   }
	 *
	 * Result file <job>.result (0600), one JSON object:
	 *
	 *   {"schema":"e64local-action-result-v1","ok":true,"state":"completed",
	 *    "errorCode":0,"error":null,"result":{...},"durationMs":123}
	 *
	 * The helper always writes the result file for a well-formed invocation and
	 * exits 0, so the module can distinguish "the action failed" from "the
	 * helper could not be started".  It exits non-zero only for a malformed
	 * argument or an unreadable job file.
	 *
	 * ESP boundary: this file contains no ESP, WiFi, firmware, eFuse or
	 * bootloader command.  EspFlashApp, EspEraseFlash, EspReset, WifiStaConfig,
	 * RequestOnboarding, UpdateDriverConfig and UpdateCpuConfig are absent from
	 * the command allowlist by construction, so a job file cannot smuggle one.
	 *
	 * Owner-authorized use only.
	 */

	// --- Fixed limits ------------------------------------------------------------

	define( "E64RUN_SCHEMA", "e64local-action-result-v1" );
	define( "E64RUN_JOB_SCHEMA", "e64local-action-job-v1" );
	define( "E64RUN_MIN_TIMEOUT_MS", 1000 );
	define( "E64RUN_MAX_TIMEOUT_MS", 60000 );
	define( "E64RUN_MAX_FRAME_BYTES", 65536 );
	define( "E64RUN_MAX_BACKUPS", 10 );
	define( "E64RUN_BACKUP_BYTES", 33554432 );  // 32 MiB sanity cap on a backup source

	// --- WSS command allowlist ---------------------------------------------------

	/*
	 * Every entry maps an action-engine command to its parameter validator.
	 * A command absent from this array cannot be executed even if a job file
	 * names it.  Evidence for each command is in docs/API_REFERENCE.md
	 * §2.5 "GrinderAction suffixes (39)".
	 */
	$E64RUN_WSS_COMMANDS = array(
		// docs/API_REFERENCE.md §2.5 row 14 (Stop), row 15 (StartGrindManual),
		// row 16 (StartGrindGbw), row 17 (StartGrindGbt).
		"Stop" => "e64run_params_none",
		"StartGrindManual" => "e64run_params_none",
		"StartGrindGbw" => "e64run_params_start_gbw",
		"StartGrindGbt" => "e64run_params_start_gbt",
		// §2.5 row 18, 19, 37.
		"StartCalibration" => "e64run_params_none",
		"StartTara" => "e64run_params_none",
		"CalibrateDdSensor" => "e64run_params_none",
		// §2.5 row 22, 23, 24.
		"SetFanTemperatureCtrlEnabled" => "e64run_params_fan_ctrl",
		"SetFan1Duty" => "e64run_params_fan_duty",
		"SetFan2Duty" => "e64run_params_fan_duty",
		// §2.5 row 27, 28.
		"ToggleBacklightPower" => "e64run_params_none",
		"SetBacklightBrightness" => "e64run_params_brightness",
		// §2.5 row 35, 36.
		"SetAgsaTargetDdValue" => "e64run_params_agsa_dd",
		"StopAgsa" => "e64run_params_none",
		// §2.5 row 40.
		"SetLanguage" => "e64run_params_language",
		// §2.5 row 21, 34.
		"ResetLog" => "e64run_params_none",
		"ResetDriverConfig" => "e64run_params_none",
		// §2.5 row 38.
		"AddBrewEvent" => "e64run_params_brew_event",
		// §2.4 row 2 - read-only state probe used for preconditions/status.
		"RequestDriverState" => "e64run_params_none",
	);

	/*
	 * Deliberately absent, and the reason is recorded here so a future edit
	 * cannot re-add one by accident:
	 *   EspReset / EspFlashApp / EspEraseFlash  - ESP boundary
	 *   WifiStaConfig / RequestOnboarding       - ESP-persisted WiFi/pairing state
	 *   UpdateDriverConfig / UpdateCpuConfig    - unrecovered write schema
	 *   Rc*                                     - press/release pairs cannot be bounded
	 *   StartEnduranceTest / StopEnduranceTest  - unbounded loop, no watchdog
	 *   CalibrateFan1 / CalibrateFan2           - no completion signal or bound
	 *   NozzleLightRunStandby / NozzleLightStop - ESP-side nozzle-light driver
	 *   GbsCreateReport                         - non-standard reply envelope
	 */

	// --- SQLite write allowlist --------------------------------------------------

	/*
	 * The helper builds every statement itself.  The job carries a kind plus
	 * validated scalars, never SQL text, a table name or a column name.
	 */
	$E64RUN_SQL_KINDS = array(
		"settings_set",
		"settings_set_bulk",
		"statistics_reset",
		"recipe_create",
		"recipe_update",
		"recipe_delete",
		"recipe_activate",
	);

	// Settings the helper accepts.  Mirrors the module's allowlist; the module
	// performs the user-facing validation and this table is the second layer.
	// Every key is from the recovered persistent key inventory in
	// docs/SQLITE_SCHEMA.md §"Complete persistent key inventory".
	$E64RUN_SETTINGS = array(
		"System.Language" => array( "type" => "enum", "values" => array( "de", "en", "en_US", "es", "fr", "it", "nl", "pl", "pt", "tr" ) ),
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
		"Agsa.AgsaUponRecipeChange" => array( "type" => "bool" ),
		"Agsa.AgsaStartWithRecipeDd" => array( "type" => "bool" ),
		"Agsa.ShowRecipeDdEnabled" => array( "type" => "bool" ),
		"Agsa.BlockageWarningThreshold" => array( "type" => "int", "min" => 0, "max" => 10000 ),
		"Gbs.Algo.PreventAgsaBrewtimeRange_ms" => array( "type" => "int", "min" => 0, "max" => 600000 ),
		"Standby.ActivationTimeSec" => array( "type" => "int", "min" => 0, "max" => 86400 ),
		"Standby.LedEnabled" => array( "type" => "bool" ),
		"Standby.LedColorRgb" => array( "type" => "color" ),
		"Standby.ShiftTimesEnabled" => array( "type" => "bool" ),
		"Standby.ShiftTimeBegin" => array( "type" => "clock" ),
		"Standby.ShiftTimeEnd" => array( "type" => "clock" ),
		"System.PermanentLedLightingEnabled" => array( "type" => "bool" ),
		"System.PermanentLedColorFadingEnabled" => array( "type" => "bool" ),
		"System.PermanentLedColorRgb" => array( "type" => "color" ),
	);

	// --- Result plumbing ---------------------------------------------------------

	function e64run_result( $resultPath, $ok, $state, $errorCode, $error, $result, $startedAt )
	{
		$payload = array(
			"schema" => E64RUN_SCHEMA,
			"ok" => (bool)$ok,
			"state" => $state,
			"errorCode" => (int)$errorCode,
			"error" => $error,
			"result" => is_array( $result ) ? $result : array(),
			"durationMs" => (int)round( ( microtime( true ) - $startedAt ) * 1000 ),
		);
		$json = json_encode( $payload, JSON_UNESCAPED_SLASHES );
		if ( $json === false )
		{
			$json = '{"schema":"' . E64RUN_SCHEMA . '","ok":false,"state":"failed",'
				. '"errorCode":500,"error":"result encoding failed","result":{},"durationMs":0}';
		}
		$temporary = $resultPath . ".tmp";
		@file_put_contents( $temporary, $json . "\n" );
		@chmod( $temporary, 0600 );
		if ( @rename( $temporary, $resultPath ) === false )
		{
			@file_put_contents( $resultPath, $json . "\n" );
			@chmod( $resultPath, 0600 );
		}
		return 0;
	}

	function e64run_fail( $resultPath, $errorCode, $message, $startedAt )
	{
		return e64run_result( $resultPath, false, "failed", $errorCode, $message, array(), $startedAt );
	}

	// --- Parameter validators ----------------------------------------------------

	function e64run_is_uuid( $value )
	{
		return is_string( $value )
			&& preg_match( '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $value ) === 1;
	}

	function e64run_number( $value, &$error )
	{
		if ( is_bool( $value ) || !( is_int( $value ) || is_float( $value ) ) )
		{
			$error = "number expected";
			return null;
		}
		if ( is_float( $value ) && ( is_nan( $value ) || is_infinite( $value ) ) )
		{
			$error = "finite number expected";
			return null;
		}
		return $value;
	}

	function e64run_integer( $value, $min, $max, &$error )
	{
		if ( is_bool( $value ) || !is_int( $value ) )
		{
			$error = "integer expected";
			return null;
		}
		if ( $value < $min || $value > $max )
		{
			$error = "integer outside " . $min . ".." . $max;
			return null;
		}
		return $value;
	}

	function e64run_no_unknown_keys( $params, $allowed, &$error )
	{
		if ( !is_array( $params ) )
		{
			$error = "params object required";
			return false;
		}
		foreach ( $params as $key => $unused )
		{
			if ( !in_array( (string)$key, $allowed, true ) )
			{
				$error = "unknown parameter " . (string)$key;
				return false;
			}
		}
		return true;
	}

	function e64run_params_none( $params, &$normalized, &$error )
	{
		if ( !e64run_no_unknown_keys( $params, array(), $error ) )
		{
			return false;
		}
		$normalized = array();
		return true;
	}

	function e64run_params_start_gbw( $params, &$normalized, &$error )
	{
		if ( !e64run_no_unknown_keys( $params, array( "targetWeightGr" ), $error ) )
		{
			return false;
		}
		$weight = e64run_number( isset( $params["targetWeightGr"] ) ? $params["targetWeightGr"] : null, $error );
		if ( $weight === null )
		{
			return false;
		}
		if ( $weight < 0.1 || $weight > 50.0 )
		{
			$error = "targetWeightGr outside 0.1..50.0";
			return false;
		}
		$normalized = array( "targetWeightGr" => (float)$weight );
		return true;
	}

	function e64run_params_start_gbt( $params, &$normalized, &$error )
	{
		if ( !e64run_no_unknown_keys( $params, array( "grindTimeSec" ), $error ) )
		{
			return false;
		}
		$seconds = e64run_number( isset( $params["grindTimeSec"] ) ? $params["grindTimeSec"] : null, $error );
		if ( $seconds === null )
		{
			return false;
		}
		if ( $seconds < 0.1 || $seconds > 60.0 )
		{
			$error = "grindTimeSec outside 0.1..60.0";
			return false;
		}
		$normalized = array( "grindTimeSec" => (float)$seconds );
		return true;
	}

	function e64run_params_fan_ctrl( $params, &$normalized, &$error )
	{
		if ( !e64run_no_unknown_keys( $params, array( "enabled" ), $error ) )
		{
			return false;
		}
		if ( !isset( $params["enabled"] ) || !is_bool( $params["enabled"] ) )
		{
			$error = "enabled boolean required";
			return false;
		}
		$normalized = array( "enabled" => (bool)$params["enabled"] );
		return true;
	}

	function e64run_params_fan_duty( $params, &$normalized, &$error )
	{
		if ( !e64run_no_unknown_keys( $params, array( "dutyPercent" ), $error ) )
		{
			return false;
		}
		$duty = e64run_integer( isset( $params["dutyPercent"] ) ? $params["dutyPercent"] : null, 0, 100, $error );
		if ( $duty === null )
		{
			return false;
		}
		$normalized = array( "dutyPercent" => $duty );
		return true;
	}

	function e64run_params_brightness( $params, &$normalized, &$error )
	{
		if ( !e64run_no_unknown_keys( $params, array( "brightness" ), $error ) )
		{
			return false;
		}
		$brightness = e64run_integer( isset( $params["brightness"] ) ? $params["brightness"] : null, 0, 100, $error );
		if ( $brightness === null )
		{
			return false;
		}
		$normalized = array( "brightness" => $brightness );
		return true;
	}

	function e64run_params_agsa_dd( $params, &$normalized, &$error )
	{
		if ( !e64run_no_unknown_keys( $params, array( "targetDdValue" ), $error ) )
		{
			return false;
		}
		$target = e64run_integer( isset( $params["targetDdValue"] ) ? $params["targetDdValue"] : null, 0, 10000, $error );
		if ( $target === null )
		{
			return false;
		}
		$normalized = array( "targetDdValue" => $target );
		return true;
	}

	function e64run_params_language( $params, &$normalized, &$error )
	{
		if ( !e64run_no_unknown_keys( $params, array( "language" ), $error ) )
		{
			return false;
		}
		$language = isset( $params["language"] ) ? $params["language"] : null;
		$allowed = array( "de", "en", "en_US", "es", "fr", "it", "nl", "pl", "pt", "tr" );
		if ( !is_string( $language ) || !in_array( $language, $allowed, true ) )
		{
			$error = "unsupported language";
			return false;
		}
		$normalized = array( "language" => $language );
		return true;
	}

	function e64run_params_brew_event( $params, &$normalized, &$error )
	{
		$allowed = array(
			"grindUuid", "machineName", "groupHead", "doseIndex",
			"validity", "brewTimeMs", "brewWeightMg",
		);
		if ( !e64run_no_unknown_keys( $params, $allowed, $error ) )
		{
			return false;
		}
		if ( !isset( $params["grindUuid"] ) || !e64run_is_uuid( $params["grindUuid"] ) )
		{
			$error = "grindUuid must be a UUID";
			return false;
		}
		$dose = e64run_integer( isset( $params["doseIndex"] ) ? $params["doseIndex"] : null, 0, 1000, $error );
		if ( $dose === null )
		{
			return false;
		}
		if ( !isset( $params["validity"] ) || !is_bool( $params["validity"] ) )
		{
			$error = "validity boolean required";
			return false;
		}
		$brewTime = e64run_integer( isset( $params["brewTimeMs"] ) ? $params["brewTimeMs"] : null, 0, 600000, $error );
		if ( $brewTime === null )
		{
			return false;
		}
		$brewWeight = e64run_integer( isset( $params["brewWeightMg"] ) ? $params["brewWeightMg"] : null, 0, 500000, $error );
		if ( $brewWeight === null )
		{
			return false;
		}

		$machineName = isset( $params["machineName"] ) ? $params["machineName"] : "E64";
		$groupHead = isset( $params["groupHead"] ) ? $params["groupHead"] : "1";
		foreach ( array( "machineName" => $machineName, "groupHead" => $groupHead ) as $name => $value )
		{
			if ( !is_string( $value ) || $value === "" || strlen( $value ) > 64
				|| preg_match( '/^[\p{L}\p{N} ._\-]+$/u', $value ) !== 1 )
			{
				$error = $name . " must be 1..64 safe characters";
				return false;
			}
		}

		$normalized = array(
			"grindUuid" => $params["grindUuid"],
			"machineName" => $machineName,
			"groupHead" => $groupHead,
			"doseIndex" => $dose,
			"validity" => (bool)$params["validity"],
			"brewTimeMs" => $brewTime,
			"brewWeightMg" => $brewWeight,
		);
		return true;
	}

	// --- WebSocket transport -----------------------------------------------------

	function e64run_ws_connect( $endpoint, $timeoutSec, &$error )
	{
		// Only the documented local WSS port is reachable from a job file.
		$parts = parse_url( $endpoint );
		if ( !is_array( $parts ) || !isset( $parts["scheme"] ) || !isset( $parts["host"] ) )
		{
			$error = "invalid endpoint";
			return null;
		}
		$scheme = strtolower( $parts["scheme"] );
		$host = $parts["host"];
		$port = isset( $parts["port"] ) ? (int)$parts["port"] : ( $scheme === "wss" ? 443 : 80 );
		if ( ( $scheme !== "wss" && $scheme !== "ws" ) || $port !== 9997
			|| ( $host !== "127.0.0.1" && $host !== "::1" && $host !== "localhost" ) )
		{
			$error = "endpoint must be the local loopback WSS port 9997";
			return null;
		}
		if ( !isset( $parts["path"] ) || $parts["path"] !== "/" )
		{
			$error = "endpoint path must be /";
			return null;
		}
		// The module writes exactly "/?token=<token>".  Accepting extra query
		// parameters would forward attacker-chosen text (including
		// percent-encoded CRLF) into the vendor server's request line.
		$query = isset( $parts["query"] ) ? (string)$parts["query"] : "";
		if ( preg_match( '/^token=[A-Za-z0-9._-]{1,256}$/', $query ) !== 1 )
		{
			$error = "endpoint must carry exactly one token query parameter";
			return null;
		}

		$contextOptions = array();
		if ( $scheme === "wss" )
		{
			// The image ships a self-signed certificate and this connection is
			// loopback-only, so peer verification is disabled here for the same
			// reason the vendor clients disable it.  It never leaves the host.
			$contextOptions["ssl"] = array(
				"verify_peer" => false,
				"verify_peer_name" => false,
				"allow_self_signed" => true,
				"SNI_enabled" => false,
			);
		}
		$context = stream_context_create( $contextOptions );
		$target = ( $scheme === "wss" ? "ssl://" : "tcp://" ) . $host . ":" . $port;

		$socket = @stream_socket_client(
			$target,
			$errno,
			$errstr,
			max( 1.0, $timeoutSec ),
			STREAM_CLIENT_CONNECT,
			$context
		);
		if ( $socket === false )
		{
			$error = "wss connect failed: " . ( $errstr !== "" ? $errstr : (string)$errno );
			return null;
		}
		stream_set_timeout( $socket, (int)max( 1, floor( $timeoutSec ) ) );
		stream_set_blocking( $socket, true );
		return $socket;
	}

	function e64run_ws_handshake( $socket, $parts, &$error )
	{
		$key = base64_encode( random_bytes( 16 ) );
		$path = isset( $parts["path"] ) && $parts["path"] !== "" ? $parts["path"] : "/";
		$query = isset( $parts["query"] ) ? "?" . $parts["query"] : "";
		$hostHeader = $parts["host"] . ":" . ( isset( $parts["port"] ) ? (int)$parts["port"] : 9997 );

		$request = "GET " . $path . $query . " HTTP/1.1\r\n"
			. "Host: " . $hostHeader . "\r\n"
			. "Upgrade: websocket\r\n"
			. "Connection: Upgrade\r\n"
			. "Sec-WebSocket-Key: " . $key . "\r\n"
			. "Sec-WebSocket-Version: 13\r\n"
			. "\r\n";
		if ( @fwrite( $socket, $request ) === false )
		{
			$error = "wss handshake write failed";
			return false;
		}

		$response = "";
		while ( strpos( $response, "\r\n\r\n" ) === false )
		{
			$chunk = @fread( $socket, 1024 );
			if ( $chunk === false || $chunk === "" )
			{
				$error = "wss handshake read failed";
				return false;
			}
			$response .= $chunk;
			if ( strlen( $response ) > 8192 )
			{
				$error = "wss handshake too large";
				return false;
			}
		}

		$lines = explode( "\r\n", $response );
		if ( count( $lines ) === 0 || strpos( $lines[0], "101" ) === false )
		{
			$error = "wss upgrade rejected";
			return false;
		}
		$accept = "";
		foreach ( $lines as $line )
		{
			$position = strpos( $line, ":" );
			if ( $position === false )
			{
				continue;
			}
			$name = strtolower( trim( substr( $line, 0, $position ) ) );
			if ( $name === "sec-websocket-accept" )
			{
				$accept = trim( substr( $line, $position + 1 ) );
			}
		}
		$expected = base64_encode( sha1( $key . "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", true ) );
		if ( $accept === "" || !hash_equals( $expected, $accept ) )
		{
			$error = "wss accept mismatch";
			return false;
		}
		return true;
	}

	function e64run_ws_frame( $payload, $opcode = 0x1 )
	{
		$length = strlen( $payload );
		$header = chr( 0x80 | $opcode );
		if ( $length < 126 )
		{
			$header .= chr( 0x80 | $length );
		}
		elseif ( $length <= 65535 )
		{
			$header .= chr( 0x80 | 126 ) . pack( "n", $length );
		}
		else
		{
			$header .= chr( 0x80 | 127 ) . pack( "J", $length );
		}
		$mask = random_bytes( 4 );
		$masked = "";
		for ( $i = 0; $i < $length; $i++ )
		{
			$masked .= $payload[$i] ^ $mask[$i % 4];
		}
		return $header . $mask . $masked;
	}

	function e64run_ws_read_exact( $socket, $count, &$error )
	{
		$buffer = "";
		while ( strlen( $buffer ) < $count )
		{
			$chunk = @fread( $socket, $count - strlen( $buffer ) );
			if ( $chunk === false || $chunk === "" )
			{
				$error = "wss frame read failed";
				return null;
			}
			$buffer .= $chunk;
		}
		return $buffer;
	}

	function e64run_ws_read_frame( $socket, &$error )
	{
		$header = e64run_ws_read_exact( $socket, 2, $error );
		if ( $header === null )
		{
			return null;
		}
		$first = ord( $header[0] );
		$second = ord( $header[1] );
		$opcode = $first & 0x0f;
		$masked = ( $second & 0x80 ) !== 0;
		$length = $second & 0x7f;
		if ( $length === 126 )
		{
			$extended = e64run_ws_read_exact( $socket, 2, $error );
			if ( $extended === null )
			{
				return null;
			}
			$length = unpack( "n", $extended )[1];
		}
		elseif ( $length === 127 )
		{
			$extended = e64run_ws_read_exact( $socket, 8, $error );
			if ( $extended === null )
			{
				return null;
			}
			$length = unpack( "J", $extended )[1];
		}
		if ( $length < 0 || $length > E64RUN_MAX_FRAME_BYTES )
		{
			$error = "wss frame too large";
			return null;
		}
		$mask = "";
		if ( $masked )
		{
			$mask = e64run_ws_read_exact( $socket, 4, $error );
			if ( $mask === null )
			{
				return null;
			}
		}
		$payload = $length > 0 ? e64run_ws_read_exact( $socket, $length, $error ) : "";
		if ( $payload === null )
		{
			return null;
		}
		if ( $masked )
		{
			$unmasked = "";
			for ( $i = 0; $i < $length; $i++ )
			{
				$unmasked .= $payload[$i] ^ $mask[$i % 4];
			}
			$payload = $unmasked;
		}
		if ( $opcode === 0x9 )
		{
			@fwrite( $socket, e64run_ws_frame( $payload, 0xA ) );
			return e64run_ws_read_frame( $socket, $error );
		}
		return array( "opcode" => $opcode, "payload" => $payload );
	}

	function e64run_ws_roundtrip( $socket, $message, &$error )
	{
		$encoded = json_encode( $message, JSON_UNESCAPED_SLASHES );
		if ( $encoded === false )
		{
			$error = "command encoding failed";
			return null;
		}
		if ( @fwrite( $socket, e64run_ws_frame( $encoded ) ) === false )
		{
			$error = "wss write failed";
			return null;
		}
		$frame = e64run_ws_read_frame( $socket, $error );
		if ( $frame === null )
		{
			return null;
		}
		if ( $frame["opcode"] === 0x8 )
		{
			$error = "wss closed before reply";
			return null;
		}
		$decoded = json_decode( $frame["payload"], true );
		if ( !is_array( $decoded ) )
		{
			$error = "wss reply is not JSON";
			return null;
		}
		return $decoded;
	}

	// --- SQLite ------------------------------------------------------------------

	function e64run_sqlite( $sqlite3, $dbPath, $arguments, &$output, &$error )
	{
		$command = escapeshellarg( $sqlite3 ) . " " . escapeshellarg( $dbPath );
		foreach ( $arguments as $argument )
		{
			$command .= " " . escapeshellarg( $argument );
		}
		$lines = array();
		$returnVal = 0;
		@exec( $command . " 2>&1", $lines, $returnVal );
		$output = implode( "\n", $lines );
		if ( $returnVal !== 0 )
		{
			$error = "sqlite3 exited " . $returnVal;
			return false;
		}
		return true;
	}

	function e64run_sqlite_value( $sqlite3, $dbPath, $query, &$error )
	{
		$output = "";
		if ( !e64run_sqlite( $sqlite3, $dbPath, array( "-noheader", "-batch", $query ), $output, $error ) )
		{
			return null;
		}
		return trim( $output );
	}

	function e64run_sql_quote( $value )
	{
		if ( $value === null )
		{
			return "NULL";
		}
		if ( is_bool( $value ) )
		{
			return $value ? "1" : "0";
		}
		if ( is_int( $value ) || is_float( $value ) )
		{
			return (string)$value;
		}
		return "'" . str_replace( "'", "''", (string)$value ) . "'";
	}

	function e64run_assert_schema( $sqlite3, $dbPath, $table, $columns, &$error )
	{
		$output = "";
		if ( !e64run_sqlite( $sqlite3, $dbPath, array( "-noheader", "-batch", "PRAGMA table_info(" . $table . ");" ), $output, $error ) )
		{
			return false;
		}
		$present = array();
		foreach ( explode( "\n", trim( $output ) ) as $line )
		{
			$parts = explode( "|", $line );
			if ( count( $parts ) >= 2 )
			{
				$present[] = $parts[1];
			}
		}
		foreach ( $columns as $column )
		{
			if ( !in_array( $column, $present, true ) )
			{
				$error = "schema mismatch: " . $table . "." . $column . " missing";
				return false;
			}
		}
		return true;
	}

	function e64run_setting_value( $key, $value, $spec, &$error )
	{
		switch ( $spec["type"] )
		{
			case "bool":
				if ( !is_bool( $value ) )
				{
					$error = $key . " expects a boolean";
					return null;
				}
				return $value ? "true" : "false";
			case "int":
				$number = e64run_integer( $value, $spec["min"], $spec["max"], $error );
				if ( $number === null )
				{
					return null;
				}
				return (string)$number;
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

	function e64run_backup( $sqlite3, $dbPath, $backupDir, &$error )
	{
		if ( !is_dir( $backupDir ) && !@mkdir( $backupDir, 0700, true ) )
		{
			$error = "backup directory is not writable";
			return null;
		}
		@chmod( $backupDir, 0700 );

		$sourceSize = @filesize( $dbPath );
		if ( $sourceSize === false || $sourceSize <= 0 || $sourceSize > E64RUN_BACKUP_BYTES )
		{
			$error = "database size is not acceptable for a backup";
			return null;
		}

		$base = basename( $dbPath );
		$stamp = gmdate( "Ymd\THis\Z" );
		$target = rtrim( $backupDir, "/" ) . "/" . $base . "." . $stamp . ".bak";
		$output = "";
		if ( !e64run_sqlite( $sqlite3, $dbPath, array( ".backup " . e64run_sql_quote( $target ) ), $output, $error ) )
		{
			return null;
		}
		$targetSize = @filesize( $target );
		if ( $targetSize === false || $targetSize <= 0 )
		{
			$error = "pre-write backup was not created";
			return null;
		}
		@chmod( $target, 0600 );

		// Bounded retention: keep the newest E64RUN_MAX_BACKUPS files.
		$existing = glob( rtrim( $backupDir, "/" ) . "/" . $base . ".*.bak" );
		if ( is_array( $existing ) && count( $existing ) > E64RUN_MAX_BACKUPS )
		{
			sort( $existing );
			$remove = count( $existing ) - E64RUN_MAX_BACKUPS;
			for ( $i = 0; $i < $remove; $i++ )
			{
				@unlink( $existing[$i] );
			}
		}
		return $target;
	}

	function e64run_sql_run( $sqlite3, $dbPath, $backupDir, $script, &$result, &$error )
	{
		$backup = e64run_backup( $sqlite3, $dbPath, $backupDir, $error );
		if ( $backup === null )
		{
			return false;
		}
		$output = "";
		if ( !e64run_sqlite( $sqlite3, $dbPath, array( "-bail", "-batch", $script ), $output, $error ) )
		{
			return false;
		}
		$result = array( "backup" => basename( $backup ) );
		return true;
	}

	// --- Main --------------------------------------------------------------------

	$startedAt = microtime( true );
	$jobPath = isset( $argv[1] ) ? (string)$argv[1] : "";
	if ( !preg_match( '#^/db/e64local/actions/[0-9a-f-]{36}\.job\.json$#', $jobPath ) )
	{
		fwrite( STDERR, "e64local-action-run: invalid job path\n" );
		exit( 2 );
	}
	$resultPath = substr( $jobPath, 0, -strlen( ".job.json" ) ) . ".result.json";

	$raw = @file_get_contents( $jobPath );
	if ( !is_string( $raw ) )
	{
		fwrite( STDERR, "e64local-action-run: cannot read job file\n" );
		exit( 2 );
	}
	// The job carries a short-lived WSS token; remove it before doing work so a
	// killed helper cannot leave it behind.
	@unlink( $jobPath );

	$job = json_decode( $raw, true );
	if ( !is_array( $job ) || !isset( $job["schema"] ) || $job["schema"] !== E64RUN_JOB_SCHEMA )
	{
		fwrite( STDERR, "e64local-action-run: invalid job schema\n" );
		exit( 2 );
	}

	$timeoutMs = isset( $job["timeoutMs"] ) ? (int)$job["timeoutMs"] : 0;
	if ( $timeoutMs < E64RUN_MIN_TIMEOUT_MS || $timeoutMs > E64RUN_MAX_TIMEOUT_MS )
	{
		e64run_fail( $resultPath, 500, "timeoutMs outside the supported range", $startedAt );
		exit( 0 );
	}
	// Leave headroom inside the helper so a follow-up Stop is always attempted
	// before the module's own hard kill.
	$deadline = $startedAt + ( $timeoutMs / 1000.0 );
	$verb = isset( $job["verb"] ) ? (string)$job["verb"] : "";

	if ( $verb === "wss" || $verb === "state" )
	{
		$command = isset( $job["command"] ) ? (string)$job["command"] : "";
		if ( !isset( $E64RUN_WSS_COMMANDS[$command] ) )
		{
			e64run_fail( $resultPath, 403, "command is not in the runner allowlist", $startedAt );
			exit( 0 );
		}
		$params = isset( $job["params"] ) ? $job["params"] : array();
		$normalized = array();
		$error = "";
		$validator = $E64RUN_WSS_COMMANDS[$command];
		if ( !$validator( $params, $normalized, $error ) )
		{
			e64run_fail( $resultPath, 422, $error, $startedAt );
			exit( 0 );
		}
		if ( $verb === "state" && $command !== "RequestDriverState" )
		{
			e64run_fail( $resultPath, 400, "state verb requires RequestDriverState", $startedAt );
			exit( 0 );
		}

		$endpoint = isset( $job["endpoint"] ) ? (string)$job["endpoint"] : "";
		// The endpoint is pasted into the HTTP handshake request line and Host
		// header below; a control character there would smuggle extra headers or
		// a second request into the vendor WSS server.  The module never writes
		// one, so a job file that carries one is refused outright.
		if ( preg_match( '/[\x00-\x20\x7f]/', $endpoint ) === 1 )
		{
			e64run_fail( $resultPath, 422, "endpoint must not contain control characters", $startedAt );
			exit( 0 );
		}

		// The follow-up is part of the safety case (a manual grind is only
		// bounded because a Stop follows it), so it is validated before the
		// command is sent: a rejected follow-up must never leave a started
		// grind running with nothing to stop it.
		$followUp = isset( $job["followUp"] ) && is_array( $job["followUp"] ) ? $job["followUp"] : null;
		if ( $followUp !== null )
		{
			$followCommand = isset( $followUp["command"] ) ? (string)$followUp["command"] : "";
			$afterMs = isset( $followUp["afterMs"] ) ? (int)$followUp["afterMs"] : 0;
			if ( $followCommand !== "Stop" || $afterMs < 0 || $afterMs > 5000 )
			{
				e64run_fail( $resultPath, 422, "followUp is not an allowlisted bounded stop", $startedAt );
				exit( 0 );
			}
		}

		$parts = parse_url( $endpoint );
		$error = "";
		$socket = e64run_ws_connect( $endpoint, max( 1.0, $deadline - microtime( true ) ), $error );
		if ( $socket === null )
		{
			e64run_fail( $resultPath, 503, $error, $startedAt );
			exit( 0 );
		}
		if ( !e64run_ws_handshake( $socket, $parts, $error ) )
		{
			@fclose( $socket );
			e64run_fail( $resultPath, 503, $error, $startedAt );
			exit( 0 );
		}

		if ( $command === "RequestDriverState" )
		{
			$reply = e64run_ws_roundtrip( $socket, array(
				"type" => "RequestDriverState",
				"msgId" => 1,
			), $error );
		}
		else
		{
			$message = array(
				"type" => "GrinderAction",
				"msgId" => 1,
				"data" => array_merge( array( "actionType" => $command ), $normalized ),
			);
			$reply = e64run_ws_roundtrip( $socket, $message, $error );
		}
		if ( $reply === null )
		{
			@fclose( $socket );
			e64run_fail( $resultPath, 503, $error, $startedAt );
			exit( 0 );
		}

		$success = true;
		if ( $command !== "RequestDriverState" )
		{
			$success = isset( $reply["data"]["success"] ) ? (bool)$reply["data"]["success"] : false;
		}

		// Bounded follow-up (manual grind): send Stop after afterMs, always
		// before the helper's own deadline.  The follow-up was validated above,
		// before the command was sent.
		$followUpSent = false;
		if ( $success && $followUp !== null )
		{
			$remainingMs = (int)max( 0, ( $deadline - microtime( true ) ) * 1000 - 1500 );
			$sleepMs = min( $afterMs, $remainingMs );
			usleep( (int)( $sleepMs * 1000 ) );
			$stopReply = e64run_ws_roundtrip( $socket, array(
				"type" => "GrinderAction",
				"msgId" => 2,
				"data" => array( "actionType" => "Stop" ),
			), $error );
			$followUpSent = $stopReply !== null
				&& isset( $stopReply["data"]["success"] )
				&& (bool)$stopReply["data"]["success"];
		}

		@fwrite( $socket, e64run_ws_frame( "", 0x8 ) );
		@fclose( $socket );

		if ( !$success )
		{
			e64run_fail( $resultPath, 503, "the grinder rejected the command", $startedAt );
			exit( 0 );
		}

		$result = array( "command" => $command );
		if ( $command === "RequestDriverState" )
		{
			$result["state"] = isset( $reply["data"] ) && is_array( $reply["data"] ) ? $reply["data"] : array();
		}
		if ( $followUp !== null )
		{
			$result["stopSent"] = $followUpSent;
		}
		e64run_result( $resultPath, true, "completed", 0, null, $result, $startedAt );
		exit( 0 );
	}

	if ( $verb === "sqlite" )
	{
		$sqlite3 = isset( $job["sqlite3"] ) ? (string)$job["sqlite3"] : "/usr/bin/sqlite3";
		$dbPath = isset( $job["dbPath"] ) ? (string)$job["dbPath"] : "";
		$backupDir = isset( $job["backupDir"] ) ? (string)$job["backupDir"] : "";
		if ( !is_executable( $sqlite3 )
			|| !preg_match( '#^/db/[A-Za-z0-9]+Sqlite\.db$#', $dbPath )
			|| !preg_match( '#^/db/e64local/backup$#', $backupDir ) )
		{
			e64run_fail( $resultPath, 500, "sqlite paths are not allowlisted", $startedAt );
			exit( 0 );
		}

		$sql = isset( $job["sql"] ) && is_array( $job["sql"] ) ? $job["sql"] : array();
		$kind = isset( $sql["kind"] ) ? (string)$sql["kind"] : "";
		$params = isset( $sql["params"] ) && is_array( $sql["params"] ) ? $sql["params"] : array();
		if ( !in_array( $kind, $E64RUN_SQL_KINDS, true ) )
		{
			e64run_fail( $resultPath, 403, "sql kind is not in the runner allowlist", $startedAt );
			exit( 0 );
		}

		$error = "";
		$result = array( "kind" => $kind );

		if ( $kind === "settings_set" )
		{
			$key = isset( $params["key"] ) ? (string)$params["key"] : "";
			if ( !isset( $E64RUN_SETTINGS[$key] ) )
			{
				e64run_fail( $resultPath, 403, "setting key is not allowlisted", $startedAt );
				exit( 0 );
			}
			$value = e64run_setting_value( $key, isset( $params["value"] ) ? $params["value"] : null, $E64RUN_SETTINGS[$key], $error );
			if ( $value === null )
			{
				e64run_fail( $resultPath, 422, $error, $startedAt );
				exit( 0 );
			}
			if ( !e64run_assert_schema( $sqlite3, $dbPath, "settings", array( "key", "value" ), $error ) )
			{
				e64run_fail( $resultPath, 500, $error, $startedAt );
				exit( 0 );
			}
			$script = "INSERT OR REPLACE INTO settings (key, value) VALUES ("
				. e64run_sql_quote( $key ) . ", " . e64run_sql_quote( $value ) . ");";
			if ( !e64run_sql_run( $sqlite3, $dbPath, $backupDir, $script, $result, $error ) )
			{
				e64run_fail( $resultPath, 500, $error, $startedAt );
				exit( 0 );
			}
			$result["key"] = $key;
		}
		elseif ( $kind === "settings_set_bulk" )
		{
			$entries = isset( $params["entries"] ) && is_array( $params["entries"] ) ? $params["entries"] : null;
			if ( $entries === null || count( $entries ) < 1 || count( $entries ) > 8 )
			{
				e64run_fail( $resultPath, 422, "entries must contain 1..8 settings", $startedAt );
				exit( 0 );
			}
			if ( !e64run_assert_schema( $sqlite3, $dbPath, "settings", array( "key", "value" ), $error ) )
			{
				e64run_fail( $resultPath, 500, $error, $startedAt );
				exit( 0 );
			}
			$script = "BEGIN IMMEDIATE;";
			$written = array();
			foreach ( $entries as $entry )
			{
				if ( !is_array( $entry ) || !isset( $entry["key"] ) || !is_string( $entry["key"] )
					|| !isset( $E64RUN_SETTINGS[$entry["key"]] ) )
				{
					e64run_fail( $resultPath, 403, "setting key is not allowlisted", $startedAt );
					exit( 0 );
				}
				$key = $entry["key"];
				$value = e64run_setting_value( $key, isset( $entry["value"] ) ? $entry["value"] : null, $E64RUN_SETTINGS[$key], $error );
				if ( $value === null )
				{
					e64run_fail( $resultPath, 422, $error, $startedAt );
					exit( 0 );
				}
				if ( in_array( $key, $written, true ) )
				{
					e64run_fail( $resultPath, 422, "duplicate setting key", $startedAt );
					exit( 0 );
				}
				$written[] = $key;
				$script .= "INSERT OR REPLACE INTO settings (key, value) VALUES ("
					. e64run_sql_quote( $key ) . ", " . e64run_sql_quote( $value ) . ");";
			}
			$script .= "COMMIT;";
			if ( !e64run_sql_run( $sqlite3, $dbPath, $backupDir, $script, $result, $error ) )
			{
				e64run_fail( $resultPath, 500, $error, $startedAt );
				exit( 0 );
			}
			$result["keys"] = $written;
		}
		elseif ( $kind === "statistics_reset" )
		{
			if ( !e64run_assert_schema( $sqlite3, $dbPath, "settings", array( "key", "value" ), $error ) )
			{
				e64run_fail( $resultPath, 500, $error, $startedAt );
				exit( 0 );
			}
			$stamp = gmdate( "Y-m-d H:i:s" );
			$script = "INSERT OR REPLACE INTO settings (key, value) VALUES ('Statistics.Reset.TimeStamp', "
				. e64run_sql_quote( $stamp ) . ");"
				. "INSERT OR REPLACE INTO settings (key, value) VALUES ('Statistics.Reset.Today.TimeStamp', "
				. e64run_sql_quote( $stamp ) . ");";
			if ( !e64run_sql_run( $sqlite3, $dbPath, $backupDir, $script, $result, $error ) )
			{
				e64run_fail( $resultPath, 500, $error, $startedAt );
				exit( 0 );
			}
			$result["timestamp"] = $stamp;
		}
		elseif ( $kind === "recipe_activate" )
		{
			$index = e64run_integer( isset( $params["recipeIndex"] ) ? $params["recipeIndex"] : null, 1, 1000, $error );
			if ( $index === null )
			{
				e64run_fail( $resultPath, 422, $error, $startedAt );
				exit( 0 );
			}
			if ( !e64run_assert_schema( $sqlite3, $dbPath, "recipe_entries", array( "recipe_index", "recipe_active" ), $error ) )
			{
				e64run_fail( $resultPath, 500, $error, $startedAt );
				exit( 0 );
			}
			$exists = e64run_sqlite_value( $sqlite3, $dbPath,
				"SELECT COUNT(*) FROM recipe_entries WHERE recipe_index = " . (int)$index . ";", $error );
			if ( $exists === null || (int)$exists !== 1 )
			{
				e64run_fail( $resultPath, 404, "recipe slot does not exist", $startedAt );
				exit( 0 );
			}
			$script = "UPDATE recipe_entries SET recipe_active = CASE WHEN recipe_index = "
				. (int)$index . " THEN 1 ELSE 0 END;";
			if ( !e64run_sql_run( $sqlite3, $dbPath, $backupDir, $script, $result, $error ) )
			{
				e64run_fail( $resultPath, 500, $error, $startedAt );
				exit( 0 );
			}
			$result["recipeIndex"] = $index;
		}
		elseif ( $kind === "recipe_delete" )
		{
			$index = e64run_integer( isset( $params["recipeIndex"] ) ? $params["recipeIndex"] : null, 1, 1000, $error );
			if ( $index === null )
			{
				e64run_fail( $resultPath, 422, $error, $startedAt );
				exit( 0 );
			}
			if ( !e64run_assert_schema( $sqlite3, $dbPath, "recipe_entries", array( "recipe_index", "recipe_data_id", "recipe_active" ), $error )
				|| !e64run_assert_schema( $sqlite3, $dbPath, "recipe_data", array( "recipe_data_id" ), $error ) )
			{
				e64run_fail( $resultPath, 500, $error, $startedAt );
				exit( 0 );
			}
			$row = e64run_sqlite_value( $sqlite3, $dbPath,
				"SELECT recipe_data_id || '|' || recipe_active FROM recipe_entries WHERE recipe_index = " . (int)$index . ";", $error );
			if ( $row === null || $row === "" )
			{
				e64run_fail( $resultPath, 404, "recipe slot does not exist", $startedAt );
				exit( 0 );
			}
			$parts = explode( "|", $row );
			if ( count( $parts ) !== 2 || (int)$parts[1] === 1 )
			{
				e64run_fail( $resultPath, 409, "the active recipe cannot be deleted", $startedAt );
				exit( 0 );
			}
			$dataId = (int)$parts[0];
			$script = "BEGIN IMMEDIATE;"
				. "DELETE FROM recipe_entries WHERE recipe_index = " . (int)$index . ";"
				. "DELETE FROM recipe_data WHERE recipe_data_id = " . $dataId . ";"
				. "COMMIT;";
			if ( !e64run_sql_run( $sqlite3, $dbPath, $backupDir, $script, $result, $error ) )
			{
				e64run_fail( $resultPath, 500, $error, $startedAt );
				exit( 0 );
			}
			$result["recipeIndex"] = $index;
		}
		elseif ( $kind === "recipe_create" || $kind === "recipe_update" )
		{
			$modeId = e64run_integer( isset( $params["modeId"] ) ? $params["modeId"] : null, 1, 1000, $error );
			$amount = e64run_integer( isset( $params["amountMg"] ) ? $params["amountMg"] : null, 100, 100000, $error );
			$typeId = e64run_integer( isset( $params["typeId"] ) ? $params["typeId"] : null, 1, 1000, $error );
			$iconId = e64run_integer( isset( $params["iconId"] ) ? $params["iconId"] : null, 1, 1000, $error );
			$coarseness = e64run_integer( isset( $params["coarseness"] ) ? $params["coarseness"] : null, 0, 10000, $error );
			$brewTime = e64run_integer( isset( $params["brewTimeMs"] ) ? $params["brewTimeMs"] : null, 0, 120000, $error );
			$brewWeight = e64run_integer( isset( $params["brewWeightMg"] ) ? $params["brewWeightMg"] : null, 0, 200000, $error );
			$index = e64run_integer( isset( $params["recipeIndex"] ) ? $params["recipeIndex"] : null, 1, 1000, $error );
			if ( $error !== "" )
			{
				e64run_fail( $resultPath, 422, $error, $startedAt );
				exit( 0 );
			}
			if ( !e64run_assert_schema( $sqlite3, $dbPath, "recipe_entries", array( "recipe_index", "recipe_data_id", "recipe_active", "recipe_cpr_id" ), $error )
				|| !e64run_assert_schema( $sqlite3, $dbPath, "recipe_data", array( "recipe_data_id", "recipe_uuid", "recipe_mode_id", "recipe_amount", "recipe_type_id", "recipe_icon_id", "recipe_coarseness", "recipe_brew_time", "recipe_brew_weight" ), $error ) )
			{
				e64run_fail( $resultPath, 500, $error, $startedAt );
				exit( 0 );
			}
			// Enum IDs must exist; this keeps a foreign-key-less schema consistent.
			foreach ( array( "recipe_modes" => array( "recipe_mode_id", $modeId ),
				"recipe_types" => array( "recipe_type_id", $typeId ),
				"recipe_icons" => array( "recipe_icon_id", $iconId ) ) as $table => $lookup )
			{
				$found = e64run_sqlite_value( $sqlite3, $dbPath,
					"SELECT COUNT(*) FROM " . $table . " WHERE " . $lookup[0] . " = " . (int)$lookup[1] . ";", $error );
				if ( $found === null || (int)$found !== 1 )
				{
					e64run_fail( $resultPath, 422, "unknown enum id in " . $table, $startedAt );
					exit( 0 );
				}
			}

			if ( $kind === "recipe_create" )
			{
				if ( $index === null )
				{
					e64run_fail( $resultPath, 422, "recipeIndex is required", $startedAt );
					exit( 0 );
				}
				$taken = e64run_sqlite_value( $sqlite3, $dbPath,
					"SELECT COUNT(*) FROM recipe_entries WHERE recipe_index = " . (int)$index . ";", $error );
				if ( $taken === null )
				{
					e64run_fail( $resultPath, 500, $error, $startedAt );
					exit( 0 );
				}
				if ( (int)$taken !== 0 )
				{
					e64run_fail( $resultPath, 409, "recipe slot is already in use", $startedAt );
					exit( 0 );
				}
				$uuid = isset( $params["uuid"] ) ? (string)$params["uuid"] : "";
				if ( !e64run_is_uuid( $uuid ) )
				{
					e64run_fail( $resultPath, 422, "uuid is not a UUID", $startedAt );
					exit( 0 );
				}
				$script = "BEGIN IMMEDIATE;"
					. "INSERT INTO recipe_data (recipe_uuid, recipe_mode_id, recipe_amount, recipe_type_id, recipe_icon_id, recipe_coarseness, recipe_brew_time, recipe_brew_weight) VALUES ("
					. e64run_sql_quote( $uuid ) . ", " . (int)$modeId . ", " . (int)$amount . ", "
					. (int)$typeId . ", " . (int)$iconId . ", " . (int)$coarseness . ", "
					. (int)$brewTime . ", " . (int)$brewWeight . ");"
					. "INSERT INTO recipe_entries (recipe_index, recipe_data_id, recipe_active, recipe_cpr_id) VALUES ("
					. (int)$index . ", last_insert_rowid(), 0, 0);"
					. "COMMIT;";
				if ( !e64run_sql_run( $sqlite3, $dbPath, $backupDir, $script, $result, $error ) )
				{
					e64run_fail( $resultPath, 500, $error, $startedAt );
					exit( 0 );
				}
				$result["recipeIndex"] = $index;
			}
			else
			{
				if ( $index === null )
				{
					e64run_fail( $resultPath, 422, "recipeIndex is required", $startedAt );
					exit( 0 );
				}
				$exists = e64run_sqlite_value( $sqlite3, $dbPath,
					"SELECT COUNT(*) FROM recipe_entries WHERE recipe_index = " . (int)$index . ";", $error );
				if ( $exists === null || (int)$exists !== 1 )
				{
					e64run_fail( $resultPath, 404, "recipe slot does not exist", $startedAt );
					exit( 0 );
				}
				$script = "UPDATE recipe_data SET"
					. " recipe_mode_id = " . (int)$modeId
					. ", recipe_amount = " . (int)$amount
					. ", recipe_type_id = " . (int)$typeId
					. ", recipe_icon_id = " . (int)$iconId
					. ", recipe_coarseness = " . (int)$coarseness
					. ", recipe_brew_time = " . (int)$brewTime
					. ", recipe_brew_weight = " . (int)$brewWeight
					. " WHERE recipe_data_id = (SELECT recipe_data_id FROM recipe_entries WHERE recipe_index = "
					. (int)$index . ");";
				if ( !e64run_sql_run( $sqlite3, $dbPath, $backupDir, $script, $result, $error ) )
				{
					e64run_fail( $resultPath, 500, $error, $startedAt );
					exit( 0 );
				}
				$result["recipeIndex"] = $index;
			}
		}
		else
		{
			e64run_fail( $resultPath, 500, "unhandled sql kind", $startedAt );
			exit( 0 );
		}

		e64run_result( $resultPath, true, "completed", 0, null, $result, $startedAt );
		exit( 0 );
	}

	e64run_fail( $resultPath, 400, "unsupported verb", $startedAt );
	exit( 0 );
