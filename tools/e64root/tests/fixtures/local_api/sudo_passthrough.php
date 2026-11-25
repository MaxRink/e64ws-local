#!/usr/bin/env php
<?php
	/*
	 * Offline stand-in for ``sudo -n <command>``.
	 *
	 * Test fixture only; never deployed.  It drops the ``-n`` flag and runs the
	 * remaining argv without changing privileges, so the module's real command
	 * construction (escapeshellarg, fixed binaries) is exercised end to end.
	 */

	$args = array_slice( $argv, 1 );
	if ( isset( $args[0] ) && $args[0] === "-n" )
	{
		array_shift( $args );
	}
	if ( count( $args ) === 0 )
	{
		fwrite( STDERR, "fake sudo: no command\n" );
		exit( 1 );
	}

	$descriptors = array(
		0 => STDIN,
		1 => STDOUT,
		2 => STDERR,
	);
	$process = @proc_open( $args, $descriptors, $pipes );
	if ( !is_resource( $process ) )
	{
		fwrite( STDERR, "fake sudo: cannot start " . $args[0] . "\n" );
		exit( 127 );
	}
	exit( proc_close( $process ) );
