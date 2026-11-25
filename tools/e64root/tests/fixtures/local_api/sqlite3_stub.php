#!/usr/bin/env php
<?php
	/*
	 * Offline stand-in for /usr/bin/sqlite3.
	 *
	 * Test fixture only; never deployed.  It implements the argument shapes the
	 * module and the action runner actually use:
	 *
	 *   sqlite3 -readonly -header -csv <db> <SQL>     (read routes)
	 *   sqlite3 -noheader -batch <db> <SQL>           (runner reads)
	 *   sqlite3 -bail -batch <db> <SQL>               (runner writes)
	 *   sqlite3 <db> ".backup '<path>'"               (pre-write backup)
	 *
	 * SELECT/PRAGMA are printed; INSERT/UPDATE/DELETE/BEGIN/COMMIT are executed.
	 * ATTACH/DETACH and VACUUM INTO are refused so a fixture bug cannot reach
	 * outside the temporary database.
	 */

	$args = array_slice( $argv, 1 );
	$flags = array();
	$positional = array();
	foreach ( $args as $arg )
	{
		if ( $arg !== "" && $arg[0] === "-" )
		{
			$flags[$arg] = true;
			continue;
		}
		$positional[] = $arg;
	}

	$db = isset( $positional[0] ) ? $positional[0] : "";
	$command = isset( $positional[1] ) ? $positional[1] : "";
	if ( $db === "" || $command === "" )
	{
		fwrite( STDERR, "fake sqlite3: missing database or command\n" );
		exit( 1 );
	}
	if ( !is_file( $db ) )
	{
		fwrite( STDERR, "fake sqlite3: no such database: " . $db . "\n" );
		exit( 1 );
	}

	// .backup '<path>' - a consistent-enough copy for the fixture.
	if ( strpos( ltrim( $command ), ".backup" ) === 0 )
	{
		$rest = trim( substr( ltrim( $command ), strlen( ".backup" ) ) );
		$rest = trim( $rest, "'\"" );
		if ( $rest === "" || !copy( $db, $rest ) )
		{
			fwrite( STDERR, "fake sqlite3: backup failed\n" );
			exit( 1 );
		}
		exit( 0 );
	}
	if ( strpos( ltrim( $command ), ".timeout" ) === 0 )
	{
		exit( 0 );
	}

	if ( preg_match( '/\b(ATTACH|DETACH)\b/i', $command )
		|| preg_match( '/VACUUM\s+INTO/i', $command ) )
	{
		fwrite( STDERR, "fake sqlite3: refusing an out-of-scope statement\n" );
		exit( 1 );
	}

	try
	{
		$pdo = new PDO( "sqlite:" . $db );
		$pdo->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
		$pdo->setAttribute( PDO::ATTR_TIMEOUT, 5 );

		$isRead = preg_match( '/^\s*(SELECT|PRAGMA|WITH|EXPLAIN)\b/i', $command ) === 1;
		if ( $isRead )
		{
			$stmt = $pdo->query( $command );
			if ( $stmt === false )
			{
				exit( 1 );
			}
			$headers = array();
			for ( $i = 0; $i < $stmt->columnCount(); $i++ )
			{
				$meta = $stmt->getColumnMeta( $i );
				$headers[] = isset( $meta["name"] ) ? $meta["name"] : "column" . $i;
			}

			$csv = isset( $flags["-csv"] );
			$header = isset( $flags["-header"] );
			$out = fopen( "php://stdout", "w" );

			if ( $csv )
			{
				if ( $header )
				{
					fputcsv( $out, $headers );
				}
				while ( ( $row = $stmt->fetch( PDO::FETCH_NUM ) ) !== false )
				{
					fputcsv( $out, array_map( function ( $value ) {
						return $value === null ? "" : $value;
					}, $row ) );
				}
			}
			else
			{
				if ( $header )
				{
					fwrite( $out, implode( "|", $headers ) . "\n" );
				}
				while ( ( $row = $stmt->fetch( PDO::FETCH_NUM ) ) !== false )
				{
					fwrite( $out, implode( "|", array_map( function ( $value ) {
						return $value === null ? "" : $value;
					}, $row ) ) . "\n" );
				}
			}
			fclose( $out );
			exit( 0 );
		}

		// Write path: split on statement terminators.  Every statement the
		// runner builds is free of quoted semicolons.
		$statements = array_filter(
			array_map( "trim", explode( ";", $command ) ),
			function ( $statement ) {
				return $statement !== "";
			}
		);
		foreach ( $statements as $statement )
		{
			if ( preg_match( '/^\s*(INSERT|UPDATE|DELETE|BEGIN|COMMIT|ROLLBACK|REPLACE|CREATE)\b/i', $statement ) !== 1 )
			{
				fwrite( STDERR, "fake sqlite3: refusing statement: " . substr( $statement, 0, 60 ) . "\n" );
				exit( 1 );
			}
			$pdo->exec( $statement );
		}
		exit( 0 );
	}
	catch ( Throwable $error )
	{
		fwrite( STDERR, $error->getMessage() . "\n" );
		exit( 1 );
	}
