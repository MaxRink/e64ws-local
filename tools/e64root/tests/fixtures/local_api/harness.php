<?php
	/*
	 * Offline PHP harness for ondevice/rest_api_dev.php.
	 *
	 * This file is a test fixture only.  It is never deployed to a device.
	 * The harness stubs the vendor includes, points the module at a temporary
	 * SQLite database and config, then calls restApiDev() once per scenario
	 * case and prints one JSON result per line.
	 *
	 * Scenario features used by the action tests:
	 *   "policy": {...}     write /db/e64local/actions.json before the call
	 *   "policyMissing": 1  remove the policy file
	 *   "policyInvalid": 1  write invalid JSON as the policy
	 *   "capture": "name"   remember this result under a name
	 *   "@name.data.x"      substitute a captured value into a later body
	 *   "__expire"          rewrite an action record's expiry into the past
	 *   "__tamper_params"   change a record's params without updating the hash
	 *   "__fill_audit"      write N bytes into audit.jsonl
	 *   "__block_audit"     replace audit.jsonl with a directory
	 *   "__unblock_audit"   restore audit.jsonl
	 *   "__audit_stats"     report audit file sizes
	 *   "__reset_rate"      delete every rate-limit file
	 *   "__reset_actions"   delete action records and the audit trail
	 *   "__claim"           claim one prepared record (the execute critical section)
	 *   "__runner_job"      hand a raw job file to the bounded runner
	 *   "__clock"           pin/reset the monotonic clock seam
	 *   "__boot_id"         override/reset the boot-id seam
	 *   "__rate_file"       write a raw rate-limit bucket
	 *   "__rate_read"       decode a rate-limit bucket
	 *   "__wss_state"       write /work/state.json for the WSS fixture
	 *   "__wss_log"         report the GrinderAction frames the fixture saw
	 */

	$module = isset( $argv[1] ) ? $argv[1] : "";
	$scenarioFile = isset( $argv[2] ) ? $argv[2] : "";
	if ( $module === "" || $scenarioFile === "" )
	{
		fwrite( STDERR, "usage: harness.php <module> <scenario>\n" );
		exit( 2 );
	}

	$systemVariantCc = "Hsg";
	$machineInfoFile = "/db/HsgConfig.json";

	function isDev()
	{
		return getenv( "E64_DEV" ) !== "0";
	}

	function createToken()
	{
		global $sessionToken;
		$sessionToken = "harness-ws-token";
		@file_put_contents( "/tmp/tok_" . $sessionToken, json_encode( array( "expires" => time() + 300 ) ) );
	}

	function harness_lookup( $path, $captured )
	{
		$parts = explode( ".", ltrim( $path, "@" ) );
		$node = isset( $captured[$parts[0]] ) ? $captured[$parts[0]] : null;
		for ( $index = 1; $index < count( $parts ); $index++ )
		{
			if ( !is_array( $node ) || !array_key_exists( $parts[$index], $node ) )
			{
				return null;
			}
			$node = $node[$parts[$index]];
		}
		return $node;
	}

	function harness_resolve( $value, $captured )
	{
		if ( is_string( $value ) && isset( $value[0] ) && $value[0] === "@" )
		{
			return harness_lookup( $value, $captured );
		}
		if ( is_array( $value ) )
		{
			$resolved = array();
			foreach ( $value as $key => $child )
			{
				$resolved[$key] = harness_resolve( $child, $captured );
			}
			return $resolved;
		}
		return $value;
	}

	function harness_record_path( $actionId )
	{
		return "/db/e64local/actions/" . $actionId . ".json";
	}

	/** Change the first scalar in a params tree; leaves the hash untouched. */
	function harness_tamper( $value )
	{
		if ( is_int( $value ) )
		{
			return $value + 1;
		}
		if ( is_float( $value ) )
		{
			return $value + 1.0;
		}
		if ( is_bool( $value ) )
		{
			return !$value;
		}
		if ( is_string( $value ) )
		{
			return $value . "x";
		}
		if ( is_array( $value ) )
		{
			foreach ( $value as $key => $child )
			{
				$value[$key] = harness_tamper( $child );
			}
		}
		return $value;
	}

	require $module;

	$cases = json_decode( file_get_contents( $scenarioFile ), true );
	if ( !is_array( $cases ) )
	{
		fwrite( STDERR, "scenario is not JSON\n" );
		exit( 2 );
	}

	$captured = array();
	foreach ( $cases as $case )
	{
		$id = isset( $case["id"] ) ? $case["id"] : "?";
		$route = isset( $case["route"] ) ? $case["route"] : "";
		$body = isset( $case["body"] ) ? harness_resolve( $case["body"], $captured ) : array();
		$mobile = !empty( $case["mobile"] );

		// Policy setup.
		if ( array_key_exists( "policy", $case ) )
		{
			@file_put_contents(
				"/db/e64local/actions.json",
				json_encode( $case["policy"], JSON_UNESCAPED_SLASHES )
			);
		}
		if ( !empty( $case["policyMissing"] ) )
		{
			@unlink( "/db/e64local/actions.json" );
		}
		if ( !empty( $case["policyInvalid"] ) )
		{
			@file_put_contents( "/db/e64local/actions.json", "{not json" );
		}

		// Harness-only control routes.
		if ( strpos( $route, "__" ) === 0 )
		{
			$result = array( "ok" => true );
			if ( $route === "__expire" )
			{
				$path = harness_record_path( $body["actionId"] );
				$record = json_decode( @file_get_contents( $path ), true );
				$record["expires"] = time() - 5;
				@file_put_contents( $path, json_encode( $record, JSON_UNESCAPED_SLASHES ) );
				$result["expires"] = $record["expires"];
			}
			elseif ( $route === "__tamper_params" )
			{
				// Flip the first scalar found at any depth.  Nested params such
				// as settings entries must be reachable for this to bite.
				$path = harness_record_path( $body["actionId"] );
				$record = json_decode( @file_get_contents( $path ), true );
				$record["params"] = harness_tamper( $record["params"] );
				@file_put_contents(
					$path,
					json_encode( $record, JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION )
				);
				$result["tampered"] = true;
			}
			elseif ( $route === "__fill_audit" )
			{
				$bytes = isset( $body["bytes"] ) ? (int)$body["bytes"] : 1100000;
				@file_put_contents( "/db/e64local/audit.jsonl", str_repeat( "x", $bytes ) . "\n" );
				$result["bytes"] = $bytes;
			}
			elseif ( $route === "__block_audit" )
			{
				@rename( "/db/e64local/audit.jsonl", "/db/e64local/audit.jsonl.bak" );
				@unlink( "/db/e64local/audit.jsonl" );
				@mkdir( "/db/e64local/audit.jsonl" );
				$result["blocked"] = true;
			}
			elseif ( $route === "__unblock_audit" )
			{
				@rmdir( "/db/e64local/audit.jsonl" );
				@rename( "/db/e64local/audit.jsonl.bak", "/db/e64local/audit.jsonl" );
				$result["unblocked"] = true;
			}
			elseif ( $route === "__reset_rate" )
			{
				foreach ( glob( "/db/e64local/rate/*.json" ) ?: array() as $path )
				{
					@unlink( $path );
				}
				$result["rateReset"] = true;
			}
			elseif ( $route === "__wss_state" )
			{
				@file_put_contents( "/work/state.json", json_encode( $body, JSON_UNESCAPED_SLASHES ) );
				$result["state"] = $body;
			}
			elseif ( $route === "__wss_log" )
			{
				$rows = array();
				$path = "/work/wss.log";
				if ( is_file( $path ) )
				{
					foreach ( explode( "\n", trim( (string)file_get_contents( $path ) ) ) as $line )
					{
						if ( $line === "" )
						{
							continue;
						}
						$decoded = json_decode( $line, true );
						if ( is_array( $decoded ) )
						{
							$rows[] = $decoded;
						}
					}
				}
				$result["frames"] = $rows;
				$result["count"] = count( $rows );
			}
			elseif ( $route === "__reset_actions" )
			{
				foreach ( glob( "/db/e64local/actions/*" ) ?: array() as $path )
				{
					@unlink( $path );
				}
				@unlink( "/db/e64local/audit.jsonl" );
				$result["reset"] = true;
			}
			elseif ( $route === "__clock" )
			{
				// Pin the monotonic seam to an absolute millisecond value, or
				// remove the override so the real hrtime() is used again.
				if ( !empty( $body["reset"] ) )
				{
					unset( $E64LOCAL_ACTION_HOOKS["monotonicNow"] );
					$result["monotonicNow"] = _actionMonotonicNow();
				}
				else
				{
					$ms = isset( $body["ms"] ) ? (int)$body["ms"] : 0;
					$E64LOCAL_ACTION_HOOKS["monotonicNow"] = function () use ( $ms ) {
						return $ms;
					};
					$result["monotonicNow"] = _actionMonotonicNow();
				}
			}
			elseif ( $route === "__boot_id" )
			{
				if ( !empty( $body["reset"] ) )
				{
					unset( $E64LOCAL_ACTION_HOOKS["bootId"] );
				}
				elseif ( !empty( $body["unreadable"] ) )
				{
					$E64LOCAL_ACTION_HOOKS["bootId"] = function () {
						return null;
					};
				}
				else
				{
					$id = isset( $body["id"] ) ? (string)$body["id"] : "";
					$E64LOCAL_ACTION_HOOKS["bootId"] = function () use ( $id ) {
						return $id;
					};
				}
				$result["bootId"] = _actionBootId();
			}
			elseif ( $route === "__rate_file" )
			{
				// Write a bucket exactly where the module keeps it.  "json"
				// encodes a structure; "raw" writes bytes verbatim so a legacy
				// file can be modelled.
				$bucket = preg_replace( '/[^a-z_]/', '', strtolower( (string)$body["bucket"] ) );
				$path = "/db/e64local/rate/" . $bucket . ".json";
				@mkdir( "/db/e64local/rate", 0700, true );
				$content = array_key_exists( "raw", $body )
					? (string)$body["raw"]
					: json_encode( $body["json"] );
				@file_put_contents( $path, $content );
				$result["path"] = $path;
				$result["bytes"] = strlen( $content );
			}
			elseif ( $route === "__rate_read" )
			{
				$bucket = preg_replace( '/[^a-z_]/', '', strtolower( (string)$body["bucket"] ) );
				$path = "/db/e64local/rate/" . $bucket . ".json";
				$result["raw"] = is_file( $path ) ? (string)file_get_contents( $path ) : null;
				$result["state"] = json_decode( $result["raw"], true );
				$result["bootId"] = _actionBootId();
			}
			elseif ( $route === "__claim" )
			{
				// The same critical section execute uses: exactly one caller may
				// move a record out of "prepared".
				$claim = _actionClaimRecord( $body["actionId"], "executing", null, $claimError, $claimCode );
				$result["claim"] = $claim === null ? null : array( "state" => $claim["state"] );
				$result["code"] = $claim === null ? $claimCode : 0;
				$result["error"] = $claimError;
			}
			elseif ( $route === "__runner_job" )
			{
				// Write a job file exactly where the module would, then invoke the
				// helper through sudo the way _actionRunJob() does, so the runner's
				// own validation is exercised on attacker-shaped input.
				$jobId = _actionUuid();
				$job = is_array( $body["job"] ) ? $body["job"] : array();
				$job["jobId"] = $jobId;
				$path = "/db/e64local/actions/" . $jobId . ".job.json";
				@file_put_contents( $path, json_encode( $job, JSON_UNESCAPED_SLASHES ) );
				$command = "/usr/bin/sudo -n " . escapeshellarg( "/usr/local/bin/e64local-action-run" )
					. " " . escapeshellarg( $path );
				$output = array();
				$status = 0;
				@exec( $command . " 2>&1", $output, $status );
				$result["exit"] = $status;
				$result["output"] = implode( "\n", $output );
				$resultPath = substr( $path, 0, -strlen( ".job.json" ) ) . ".result.json";
				$result["result"] = json_decode( @file_get_contents( $resultPath ), true );
				@unlink( $resultPath );
			}
			elseif ( $route === "__update_state" )
			{
				@file_put_contents(
					"/tmp/FirmwareUpdateState.json",
					json_encode( array( "state" => isset( $body["state"] ) ? $body["state"] : "Idle" ) )
				);
				$result["state"] = isset( $body["state"] ) ? $body["state"] : "Idle";
			}
			elseif ( $route === "__exec" )
			{
				try
				{
					$pdo = new PDO( "sqlite:/db/HsgSqlite.db" );
					$pdo->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
					$pdo->exec( $body["sql"] );
					$result["executed"] = true;
				}
				catch ( Throwable $error )
				{
					$result["executed"] = false;
					$result["error"] = $error->getMessage();
				}
			}
			elseif ( $route === "__audit_stats" )
			{
				$stats = array();
				foreach ( array( "", ".1", ".2" ) as $suffix )
				{
					$path = "/db/e64local/audit.jsonl" . $suffix;
					$stats[$suffix === "" ? "current" : ltrim( $suffix, "." )] =
						is_file( $path ) ? filesize( $path ) : null;
				}
				$result["sizes"] = $stats;
			}
			else
			{
				$result["error"] = "unknown harness route";
			}
			echo json_encode( array(
				"id" => $id,
				"handled" => true,
				"returnVal" => 0,
				"success" => true,
				"json" => array( "success" => true, "errorCode" => 0, "data" => $result ),
			), JSON_UNESCAPED_SLASHES ) . "\n";
			continue;
		}

		// Failure-case setup.  Each mutation is restored after the call.
		if ( !empty( $case["hide_db"] ) )
		{
			@rename( "/db/HsgSqlite.db", "/db/HsgSqlite.db.bak" );
		}
		if ( !empty( $case["hide_config"] ) )
		{
			@rename( "/db/HsgConfig.json", "/db/HsgConfig.json.bak" );
		}
		if ( !empty( $case["hide_token"] ) )
		{
			@rename( "/db/e64local/token", "/db/e64local/token.bak" );
		}
		if ( !empty( $case["empty_token"] ) )
		{
			@file_put_contents( "/db/e64local/token", "\n" );
		}
		if ( !empty( $case["drop_alert_log"] ) )
		{
			try
			{
				$pdo = new PDO( "sqlite:/db/HsgSqlite.db" );
				$pdo->exec( "DROP TABLE alert_log" );
			}
			catch ( Throwable $error )
			{
				// The case will fail visibly if the table was not dropped.
			}
		}

		unset( $_SERVER["HTTP_X_E64_LOCAL_TOKEN"] );
		if ( isset( $case["headerToken"] ) && $case["headerToken"] !== null )
		{
			$_SERVER["HTTP_X_E64_LOCAL_TOKEN"] = (string)$case["headerToken"];
		}

		$returnJson = array();
		$success = null;
		$returnVal = null;
		$postContent = json_encode( $body );
		if ( isset( $case["rawBody"] ) )
		{
			$postContent = (string)$case["rawBody"];
		}

		$handled = restApiDev( $route, $postContent, $mobile, $returnVal, $returnJson, $success );

		if ( !empty( $case["hide_db"] ) )
		{
			@rename( "/db/HsgSqlite.db.bak", "/db/HsgSqlite.db" );
		}
		if ( !empty( $case["hide_config"] ) )
		{
			@rename( "/db/HsgConfig.json.bak", "/db/HsgConfig.json" );
		}
		if ( !empty( $case["hide_token"] ) )
		{
			@rename( "/db/e64local/token.bak", "/db/e64local/token" );
		}
		if ( !empty( $case["empty_token"] ) )
		{
			@file_put_contents( "/db/e64local/token", "harness-owner-token\n" );
		}

		if ( isset( $case["capture"] ) )
		{
			$captured[$case["capture"]] = $returnJson;
		}

		echo json_encode( array(
			"id" => $id,
			"handled" => $handled,
			"returnVal" => $returnVal,
			"success" => $success,
			"json" => $returnJson,
		), JSON_UNESCAPED_SLASHES ) . "\n";
	}
