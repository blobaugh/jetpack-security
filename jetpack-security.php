<?php

/*
 * Plugin Name: Jetpack Security
 * Plugin URI: https://github.com/blobaugh/jetpack-security
 * Description: Provides some extra security features for Jetpack such as only allowing access to the xmlrpc to Jetpack Servers
 * Author: Ben Lobaugh
 * Version: 0.6
 * Author URI: http://ben.lobaugh.net
 */


class Jetpack_Security {

	/**
	 * Contains the ranges of IPs used by Automattic for
	 * the Jetpack servers.
	 *
	 * @link http://whois.arin.net/rest/org/AUTOM-93/nets
	 * @var array
	 **/
	private $ip_ranges = array(
		array( '216.151.209.64',	'216.151.209.127'	),
		array( '66.135.48.128',		'66.135.48.255'		),
		array( '69.174.248.128',	'69.174.248.255'	),
		array( '76.74.255.0',		'76.74.255.127'		),
		array( '216.151.210.0', 	'216.151.210.127'	),
		array( '76.74.248.128', 	'76.74.248.255'		),
		array( '76.74.254.0',		'76.74.254.127'		),
		array( '207.198.112.0',		'207.198.113.255'	),
		array( '207.198.101.0',		'207.198.101.127'	),
		array( '198.181.116.0',		'198.181.119.255'	),
		array( '192.0.64.0',		'192.0.127.25'		),
		array( '66.155.8.0',		'66.155.11.255'		),
		array( '66.155.38.0',		'66.155.38.0'		),
		array( '72.233.119.192',	'72.233.119.255'	),
		array( '209.15.21.0',		'209.15.21.255'		),
	);
	
	public function __construct() {
	
		// Ensure this has a high priority. We want to intercept 
		// xmlrpc calls before Jetpack gets to it
		add_action( 'init', array( $this, 'setup_if_xmlrpc_request' ), 1 );
	}

	/**
	 * The security features contained in here should only be run 
	 * if the request is coming into WordPress via the xmlrpc. 
	 * This method tests for that and if it is via xmlrpc the
	 * appropriate actions will occur to secure the xmlrpc call
	 *
	 **/
	public function setup_if_xmlrpc_request() {
		
		// Make sure the request is to xmlrpc
		if( !defined('XMLRPC_REQUEST') || ! XMLRPC_REQUEST ) {
			return;
		}

		// Make sure request is for Jetpack
		if( !isset( $_GET['for'] ) || 'jetpack' != $_GET['for'] ) {
			return;
		}

	
		/*
		 * Now we need to loop through the provided IP ranges of the Jetpack
		 * servers and ensure that the incoming request is from a valid Jetpack
		 * server before we let it though
		 */
		if( !$this->is_valid_ip_range( $_SERVER["REMOTE_ADDR"] ) ) {
			die( 'Pretending to be a Jetpack Server eh?' );
		}
	}


	/**
	 * Checks to make sure that the incoming IP is in a valid range for the
	 * Jetpack Servers
	 *
	 * @param string $ip - The IP to check
	 * @return bool
	 **/
	public function is_valid_ip_range( $ip ) {
		$valid_ip = false; // Make the incoming request earn your trust

		// Convert the ip to a value we can compare against
		$ip = ip2long( $ip );

		foreach( $this->ip_ranges AS $key => $range ) {
			if( $ip >= ip2long ($range[0] ) && $ip <= ip2long( $range[1] ) ) {
				$valid_ip = true;
				break;
			}
		}

		return $valid_ip;
	}
} // end class Jetpack_Security

new Jetpack_Security();
