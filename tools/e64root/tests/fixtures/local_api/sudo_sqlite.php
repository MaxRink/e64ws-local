#!/usr/bin/env php
<?php
	/*
	 * Offline stand-in for ``sudo -n /usr/bin/sqlite3 -readonly -header -csv``.
	 *
	 * The real module invokes that exact command.  This fixture implements the
	 * tiny subset it needs with PDO SQLite so the module can be exercised in a
	 * container without a sqlite3 CLI or a real device.  It refuses anything
	 * that is not a SELECT, mirroring the module's read-only contract.
	 */

	$args = array_slice( $argv, 1 );
	if ( isset( $args[0] ) && $args[0] === "-n" )
	{
		array_shift( $args );
	}
	array_shift( $args );  // /usr/bin/sqlite3

	$positional = array();
	foreach ( $args as $arg )
	{
		if ( $arg !== "" && $arg[0] === "-" )
		{
			continue;
		}
		$positional[] = $arg;
	}

	$db = isset( $positional[0] ) ? $positional[0] : "";
	$sql = isset( $positional[1] ) ? $positional[1] : "";
	if ( $db === "" || $sql === "" )
	{
		fwrite( STDERR, "fake sqlite3: missing database or SQL\n" );
		exit( 1 );
	}
	if ( !preg_match( '/^\s*SELECT\b/i', $sql ) )
	{
		fwrite( STDERR, "fake sqlite3: only SELECT is allowed\n" );
		exit( 1 );
	}

	try
	{
		$pdo = new PDO( "sqlite:" . $db );
		$pdo->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
		$stmt = $pdo->query( $sql );
		$out = fopen( "php://stdout", "w" );

		$headers = array();
		for ( $i = 0; $i < $stmt->columnCount(); $i++ )
		{
			$meta = $stmt->getColumnMeta( $i );
			$headers[] = $meta["name"];
		}
		fputcsv( $out, $headers );

		while ( ( $row = $stmt->fetch( PDO::FETCH_NUM ) ) !== false )
		{
			fputcsv( $out, array_map( function ( $value ) {
				return $value === null ? "" : $value;
			}, $row ) );
		}
		fclose( $out );
	}
	catch ( Throwable $error )
	{
		fwrite( STDERR, $error->getMessage() . "\n" );
		exit( 1 );
	}
