#!/usr/bin/env php
<?php
	/*
	 * Minimal loopback WebSocket fixture for the action runner test.
	 *
	 * Test fixture only; never deployed.  It speaks just enough RFC 6455 for
	 * ondevice/e64local_action_run.php:
	 *
	 *   php wss_fixture.php <port> <state.json> <log.jsonl> [--tls <cert.pem>|--self-signed]
	 *
	 * With ``--tls`` the listener is an ``ssl://`` stream using the supplied
	 * certificate; ``--self-signed`` generates a throwaway one in memory, which
	 * is what the module's ``wss://`` endpoint requires.  Without either the
	 * listener is plain TCP.
	 *
	 * GrinderAction frames are appended to the log and answered with
	 * {"type":"GrinderActionResult","data":{"success":true}}; RequestDriverState
	 * re-reads the state file and is answered with that document.  One
	 * connection at a time is enough for the sequential runner.
	 */

	$port = isset( $argv[1] ) ? (int)$argv[1] : 9997;
	$stateFile = isset( $argv[2] ) ? $argv[2] : "";
	$logFile = isset( $argv[3] ) ? $argv[3] : "";
	$certFile = "";
	$tls = false;
	for ( $i = 1; $i < count( $argv ); $i++ )
	{
		if ( $argv[$i] === "--tls" && isset( $argv[$i + 1] ) )
		{
			$certFile = (string)$argv[$i + 1];
			$tls = true;
		}
		elseif ( $argv[$i] === "--self-signed" )
		{
			$tls = true;
		}
	}
	if ( $tls && $certFile === "" )
	{
		// Throwaway key/cert for this process only; never written to a device.
		$key = openssl_pkey_new( array( "private_key_bits" => 2048, "private_key_type" => OPENSSL_KEYTYPE_RSA ) );
		$csr = $key === false ? false : openssl_csr_new( array( "commonName" => "127.0.0.1" ), $key, array( "digest_alg" => "sha256" ) );
		$cert = $csr === false ? false : openssl_csr_sign( $csr, null, $key, 1, array( "digest_alg" => "sha256" ) );
		if ( $cert === false || !openssl_x509_export( $cert, $certPem ) || !openssl_pkey_export( $key, $keyPem ) )
		{
			fwrite( STDERR, "wss fixture: cannot generate a self-signed certificate\n" );
			exit( 1 );
		}
		$certFile = tempnam( sys_get_temp_dir(), "wsscert" );
		if ( $certFile === false || file_put_contents( $certFile, $certPem . $keyPem ) === false )
		{
			fwrite( STDERR, "wss fixture: cannot write the certificate\n" );
			exit( 1 );
		}
		@chmod( $certFile, 0600 );
		$tlsGenerated = true;
	}

	$state = array( "grindState" => "Idle", "ddValueDum" => 5000 );
	if ( $stateFile !== "" && is_file( $stateFile ) )
	{
		$decoded = json_decode( file_get_contents( $stateFile ), true );
		if ( is_array( $decoded ) )
		{
			$state = $decoded;
		}
	}

	function ws_read_exact( $socket, $count )
	{
		$buffer = "";
		while ( strlen( $buffer ) < $count )
		{
			$chunk = @fread( $socket, $count - strlen( $buffer ) );
			if ( $chunk === false || $chunk === "" )
			{
				return null;
			}
			$buffer .= $chunk;
		}
		return $buffer;
	}

	function ws_read_frame( $socket )
	{
		$header = ws_read_exact( $socket, 2 );
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
			$extended = ws_read_exact( $socket, 2 );
			if ( $extended === null )
			{
				return null;
			}
			$length = unpack( "n", $extended )[1];
		}
		elseif ( $length === 127 )
		{
			$extended = ws_read_exact( $socket, 8 );
			if ( $extended === null )
			{
				return null;
			}
			$length = unpack( "J", $extended )[1];
		}
		$mask = "";
		if ( $masked )
		{
			$mask = ws_read_exact( $socket, 4 );
			if ( $mask === null )
			{
				return null;
			}
		}
		$payload = $length > 0 ? ws_read_exact( $socket, $length ) : "";
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
		return array( "opcode" => $opcode, "payload" => $payload );
	}

	function ws_frame( $payload, $opcode = 0x1 )
	{
		$length = strlen( $payload );
		$header = chr( 0x80 | $opcode );
		if ( $length < 126 )
		{
			$header .= chr( $length );
		}
		elseif ( $length <= 65535 )
		{
			$header .= chr( 126 ) . pack( "n", $length );
		}
		else
		{
			$header .= chr( 127 ) . pack( "J", $length );
		}
		return $header . $payload;
	}

	if ( $tls )
	{
		$context = stream_context_create( array(
			"ssl" => array(
				"local_cert" => $certFile,
				"allow_self_signed" => true,
				"verify_peer" => false,
				"verify_peer_name" => false,
			),
		) );
		$server = @stream_socket_server(
			"ssl://127.0.0.1:" . $port,
			$errno,
			$errstr,
			STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
			$context
		);
	}
	else
	{
		$server = @stream_socket_server( "tcp://127.0.0.1:" . $port, $errno, $errstr );
	}
	if ( $server === false )
	{
		fwrite( STDERR, "wss fixture: " . $errstr . "\n" );
		exit( 1 );
	}
	if ( !empty( $tlsGenerated ) )
	{
		// PHP reads the certificate lazily on each accept, so the file must stay
		// until the process exits.
		register_shutdown_function( function () use ( $certFile ) {
			@unlink( $certFile );
		} );
	}
	stream_set_timeout( $server, 20 );

	while ( true )
	{
		$client = @stream_socket_accept( $server, 20 );
		if ( $client === false )
		{
			continue;
		}
		stream_set_timeout( $client, 5 );

		$request = "";
		while ( strpos( $request, "\r\n\r\n" ) === false )
		{
			$chunk = @fread( $client, 1024 );
			if ( $chunk === false || $chunk === "" )
			{
				break;
			}
			$request .= $chunk;
			if ( strlen( $request ) > 8192 )
			{
				break;
			}
		}
		$key = "";
		foreach ( explode( "\r\n", $request ) as $line )
		{
			$position = strpos( $line, ":" );
			if ( $position !== false && strtolower( trim( substr( $line, 0, $position ) ) ) === "sec-websocket-key" )
			{
				$key = trim( substr( $line, $position + 1 ) );
			}
		}
		if ( $key === "" )
		{
			@fclose( $client );
			continue;
		}
		$accept = base64_encode( sha1( $key . "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", true ) );
		$response = "HTTP/1.1 101 Switching Protocols\r\n"
			. "Upgrade: websocket\r\n"
			. "Connection: Upgrade\r\n"
			. "Sec-WebSocket-Accept: " . $accept . "\r\n\r\n";
		@fwrite( $client, $response );

		while ( true )
		{
			$frame = ws_read_frame( $client );
			if ( $frame === null || $frame["opcode"] === 0x8 )
			{
				break;
			}
			if ( $frame["opcode"] === 0x9 )
			{
				@fwrite( $client, ws_frame( $frame["payload"], 0xA ) );
				continue;
			}
			$message = json_decode( $frame["payload"], true );
			if ( !is_array( $message ) )
			{
				continue;
			}
			if ( $logFile !== "" )
			{
				file_put_contents( $logFile, $frame["payload"] . "\n", FILE_APPEND );
			}
			$type = isset( $message["type"] ) ? $message["type"] : "";
			$msgId = isset( $message["msgId"] ) ? $message["msgId"] : 1;
			if ( $type === "RequestDriverState" )
			{
				// Re-read the state file so a harness case can change the
				// reported state between two runner invocations.
				if ( $stateFile !== "" && is_file( $stateFile ) )
				{
					$fresh = json_decode( file_get_contents( $stateFile ), true );
					if ( is_array( $fresh ) )
					{
						$state = $fresh;
					}
				}
				$reply = array(
					"type" => "RequestDriverStateResult",
					"refId" => $msgId,
					"data" => $state,
				);
			}
			elseif ( $type === "GrinderAction" )
			{
				$reply = array(
					"type" => "GrinderActionResult",
					"refId" => $msgId,
					"data" => array( "success" => true ),
				);
			}
			else
			{
				$reply = array( "type" => "UnknownType", "refId" => $msgId, "data" => array( "success" => false ) );
			}
			@fwrite( $client, ws_frame( json_encode( $reply, JSON_UNESCAPED_SLASHES ) ) );
		}
		@fclose( $client );
	}
