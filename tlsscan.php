#!/usr/bin/php
<?php
/*****
 * Version 0.2 - 2016-02-10 - Chris Kitzmiller
 *     Added support for starttls
 * Version 0.1 - 2016-02-04 - Chris Kitzmiller
 *****/

// Get options
$shortopts = "H:p:hv";
$longopts = array(
	"browser:",
	"ciphers:",
	"help",
	"include-failures",
	"pretty",
	"progress",
	"starttls:",
	"version"
);
$o = getopt($shortopts, $longopts);

// Resolve dependencies 
$OPENSSL = exec("which openssl", $output, $retval);
if($retval) { die("Unable to find openssl\n"); }

if(is_readable("/etc/ssl/certs/ca-certificates.crt")) {
	$CAFILE = "-CAfile /etc/ssl/certs/ca-certificates.crt";
} else {
	$CAFILE = "";
}

// Help
if(isset($o["h"]) || isset($o["help"])) { usage(); exit(0); }

// Version
if(isset($o["v"]) || isset($o["version"])) { version(); exit(0); }

// Check syntax
if(!isset($o["H"])) { usage(); exit(1); }
if(isset($o["pretty"]) && (version_compare("5.4.0", phpversion()) > 0)) { echo("Error: --pretty not supported on PHP version " . phpversion() . "\n"); exit(1); }

// Build internal variables
$final = array();
$protocols = array("tls1.2", "tls1.1", "tls1", "ssl3", "ssl2");
$cipherstring = isset($o["ciphers"]) ? $o["ciphers"] : "ALL:eNULL:aNULL";
if(isset($o["browser"])) {
	switch($o["browser"]) {
		case "chrome47":
		case "chrome":
			$cipherstring = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:AES128-GCM-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA";
			$protocols = array("tls1.2", "tls1.1", "tls1");
			break;
		case "firefox":
		case "firefox38":
		case "firefox44":
			$cipherstring = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA:DES-CBC3-SHA";
			$protocols = array("tls1.2", "tls1.1", "tls1");
			break;
		case "ie8":
			$cipherstring = "RC4-MD5:RC4-SHA:DES-CBC3-SHA:DES-CBC-SHA:EXP1024-RC4-SHA:EXP1024-DES-CBC-SHA:EXP-RC4-MD5:EXP-RC2-CBC-MD5:EDH-DSS-DES-CBC3-SHA:EDH-DSS-DES-CBC-SHA:EXP1024-DHE-DSS-DES-CBC-SHA";
			$protocols = array("tls1", "ssl3");
			break;
		case "ie":
		case "ie11":
			$cipherstring = "ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:DHE-DSS-AES256-SHA256:DHE-DSS-AES128-SHA256:DHE-DSS-AES256-SHA:DHE-DSS-AES128-SHA:DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:RC4-SHA:RC4-MD5";
			$protocols = array("tls1.2", "tls1.1", "tls1", "ssl3", "ssl2");
			break;
		case "ios8":
			$cipherstring = "ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDH-ECDSA-AES256-SHA384:ECDH-ECDSA-AES128-SHA256:ECDH-ECDSA-AES256-SHA:ECDH-ECDSA-AES128-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-RSA-AES256-SHA384:ECDH-RSA-AES128-SHA256:ECDH-RSA-AES256-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-DES-CBC3-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:EDH-RSA-DES-CBC3-SHA:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:RC4-SHA:RC4-MD5";
			$protocols = array("tls1.2", "tls1.1", "tls1", "ssl3");
			break;
		case "ios":
		case "ios9":
			$cipherstring = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-RSA-RC4-SHA:RC4-SHA:RC4-MD5";
			$protocols = array("tls1.2", "tls1.1", "tls1");
			break;
		case "edge":
		case "edge12":
			$cipherstring = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-DSS-AES256-SHA:DHE-DSS-AES128-SHA:DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA";
			$protocols = array("tls1.2", "tls1.1", "tls1", "ssl3", "ssl2");
			break;
		case "safari":
		case "safari8":
			$cipherstring = "ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDH-ECDSA-AES256-SHA384:ECDH-ECDSA-AES128-SHA256:ECDH-ECDSA-AES256-SHA:ECDH-ECDSA-AES128-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-RSA-AES256-SHA384:ECDH-RSA-AES128-SHA256:ECDH-RSA-AES256-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-DES-CBC3-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:EDH-RSA-DES-CBC3-SHA:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:RC4-SHA:RC4-MD5";
			$protocols = array("tls1.2", "tls1.1", "tls1", "ssl3");
			break;
		default:
			echo("Error: Unknown browser \"" . $o["browser"] . "\".\n"); exit(1);
	}
}
$progress = isset($o["progress"]) ? true : false;
$pretty = isset($o["pretty"]) ? true : false;
$includefailures = isset($o["include-failures"]) ? true : false;
$connect = $o["H"];
if(isset($o["p"])) {
	$connect .= ":" . $o["p"];
} else {
	$connect .= ":443";
}
if(isset($o["starttls"])) {
	$connect .= " -starttls " . $o["starttls"];
} else {
	if(isset($o["p"])) {
		switch($o["p"]) {
			case 21: $connect .= " -starttls ftp"; break;
			case 25: $connect .= " -starttls smtp"; break;
			case 110: $connect .= " -starttls pop3"; break;
			case 143: $connect .= " -starttls imap"; break;
			case 587: $connect .= " -starttls smtp"; break;
		}
	}
}

// check for -V support
$voffset = 0;
$ciphers = array();
unset($output);
$lastline = exec("openssl ciphers -V '$cipherstring' | sed -e 's/^ *//;s/ \+/ /g'", $output, $retval);
if(sizeof($output) == 1) {
	// -V not supported. Do -v instead.
	unset($output);
	$lastline = exec("openssl ciphers -v '$cipherstring' | sed -e 's/^ *//;s/ \+/ /g'", $output, $retval);
	$voffset = 2;
}

// Build cipher list
foreach($output as $line) {
	$splode = explode(" ", $line);
	$keyexchange = substr($splode[4 - $voffset], 3);
	switch($keyexchange) {
		case "DH":
		case "DH(512)":
		case "ECDH":
			$pfs = true; break;
		// this is right, right?
		case "ECDH/ECDSA":
		case "ECDH/RSA":
		default:
			$pfs = false;
	}
	$authentication = substr($splode[5 - $voffset], 3);
	if($authentication == "None") { $authentication = false; }
	$cipher = substr($splode[6 - $voffset], 4, strpos($splode[6 - $voffset], "(", 5) - 4);
	if($cipher == "") {
		$cipher = false;
		$bitlength = null;
	} else {
		$bitlength = (int) substr(substr($splode[6 - $voffset], strpos($splode[6 - $voffset], "(") + 1), 0, -1);
	}
	$mac = substr($splode[7 - $voffset], 4);
	if(strpos($splode[2 - $voffset], "EXP") === 0) {
		$export = true;
	} else {
		$export = false;
	}
	$ciphers[$splode[2 - $voffset]] = array(
		"ciphersuite" => $splode[2 - $voffset],
		"keyexchange" => $keyexchange,
		"authentication" => $authentication,
		"cipher" => $cipher,
		"bitlength" => $bitlength,
		"mac" => $mac,
		"export" => $export,
		"forwardsecrecy" => $pfs
	);
	if(!$voffset) { $ciphers[$splode[2 - $voffset]]["hexcode"] = $splode[0]; }
}

// Test connect to target
switch($protocols[0]) {
	case "tls1.2": $testproto = ""; break;
	case "tls1.1": $testproto = "-no_tls1_2"; break;
	case "tls1":   $testproto = "-no_tls1_2 -no_tls1_1"; break;
	case "ssl3":   $testproto = "-no_tls1_2 -no_tls1_1 -no_tls1"; break;
	case "ssl2":   $testproto = "-no_tls1_2 -no_tls1_1 -no_tls1 -no_ssl3"; break;
	default: echo("Unexpected protocol \"" . $protocols[0] . "\"\n"); exit(1);
}
unset($output);
$execstring = "echo|$OPENSSL s_client $CAFILE $testproto -cipher '$cipherstring' -connect $connect 2>&1";
$lastline = exec($execstring, $output, $retval);
if($retval || sizeof($output) < 30) {
	echo($output[0] . "\n");
	if($retval) { exit($retval); } else { exit(1); }
}

$parsed = parse_output($output);
$final["preferred"][$parsed["ciphersuite"]] = $parsed;
$maxproto = $parsed["protocol"];

// Try all the protocols with all of the ciphers
// TODO: fix this so that if not using --browser it returns the server's ordering
$protoskip = true;
for($i = 0; $i < sizeof($protocols); $i++) {
	if($protocols[$i] == $maxproto) { $protoskip = false; }
	if(!$protoskip) {
		if($progress) { echo(str_pad($protocols[$i], 6) . ": "); }
		switch($protocols[$i]) {
			case "tls1.2": $sclientproto = "-tls1_2"; break;
			case "tls1.1": $sclientproto = "-tls1_1"; break;
			case "tls1": $sclientproto = "-tls1"; break;
			case "ssl3": $sclientproto = "-ssl3"; break;
			case "ssl2": $sclientproto = "-ssl2"; break;
			default: echo("unexpected protocol \"" . $protocols[$i] . "\"\n"); exit(1);
		}
		foreach($ciphers as $ciphersuite => $cipher) {
			unset($output);
			unset($error);
			$lastline = exec("echo|$OPENSSL s_client $sclientproto $CAFILE -cipher '$ciphersuite' -connect $connect 2>&1", $output, $retval);
			$result = true;
			for($j = 0; $result && $j < sizeof($output); $j++) {
				if(strpos($output[$j], ":error:")) {
					$splode = explode(":", $output[$j]);
					$error = $splode[5];
					$result = false;
					//echo(".:" . $protocols[$i] . ":" . $ciphersuite . ": " . $output[$j] . "\n");
				}
			}
			if($retval || !$result || $j < 30) {
				if($progress) { echo("."); }
				if($includefailures) {
					$final[$protocols[$i]][$ciphersuite]["result"] = false;
					if(isset($error)) {
						$final[$protocols[$i]][$ciphersuite]["error"] = $error;
					}
				}
			} else {
				//echo("Y:" . $protocols[$i] . ":" . $ciphersuite . ": " . $lastline . "\n");
				if($progress) { echo("Y"); }
				$parsed = parse_output($output);
				$parsed["result"] = true;
				$final[$protocols[$i]][$ciphersuite] = $parsed;
			}
		}
		if($progress) { echo("\n"); }
	}
}
if($pretty) {
	echo(json_encode($final, JSON_PRETTY_PRINT) . "\n");
} else {
	echo(json_encode($final) . "\n");
}

function parse_output($output) {
	global $ciphers;
	$blocks = array();
	$newblock = array();
	$parsed = array();
	foreach($output as $line) {
		if($line == "---") {
			$blocks[] = $newblock;
			$newblock = array();
		} else {
			$newblock[] = $line;
		}
	}
	foreach($blocks as $block) {
		if(strpos($block[0], "New, ") === 0) {
			foreach($block as $line) {
				if(strpos($line, "    Protocol  : ") === 0) {
					$splode = explode(":", $line);
					switch(trim($splode[1])) {
						case "TLSv1.2": $parsed["protocol"] = "tls1.2"; break;
						case "TLSv1.1": $parsed["protocol"] = "tls1.1"; break;
						case "TLSv1": $parsed["protocol"] = "tls1"; break;
						case "SSLv3": $parsed["protocol"] = "ssl3"; break;
						case "SSLv2": $parsed["protocol"] = "ssl2"; break;
						default: $parsed["protocol"] = trim($splode[1]);
					}
				}
				if(strpos($line, "    Cipher    : ") === 0) {
					$splode = explode(":", $line);
					foreach($ciphers[trim($splode[1])] as $key => $val) {
						$parsed[$key] = $val;
					}
				}
				if(strpos($line, "Server public key is ") === 0) {
					$splode = explode(" ", $line);
					$parsed["bitlength"] = $splode[4];
				}
				/* don't care about this right now
				if(strpos($line, "Secure Renegotiation IS ") === 0) {
					$splode = explode(" ", $line);
					if($splode[3] == "supported") {
						$parsed["renegotiation"] = true;
					} else {
						$parsed["renegotiation"] = false;
					}
				} */
			}
		}
	}
	return $parsed;
}

function version() {
	global $argv, $OPENSSL;
	echo($argv[0] . " v0.1 - " . exec($OPENSSL . " version") . "\n");
}

function usage() {
	global $argv, $OPENSSL;
	    //12345678901234567890123456789012345678901234567890123456789012345678901234567890
	echo($argv[0] . " [ OPTIONS ] -H host\n");
	echo("\n");
	echo("  A program to scan for SSL/TLS protocols and cipher suites\n");
	echo("\n");
	echo("OPTIONS:\n");
	echo("  --browser BROWSER  Imitate as best as possible a given browser where BROWSER\n");
	echo("                     is one of chrome, chrome47, edge, edge12, firefox,\n");
	echo("                     firefox38, firefox44, ie, ie8, ie11, ios, ios8, ios9,\n");
	echo("                     safari, safari8. No version means latest version.\n");
	echo("                     Overrides --ciphers.\n");
	echo("  --ciphers STRING   Use an OpenSSL cipher string when connecting.\n");
	echo("  -h, --help         This message\n");
	echo("  -p                 Port, defaults to 443. If 21, 25, 110, 143, 587 then\n");
	echo("                     starttls with the appropriate protocol is assumed. can\n");
	echo("                     be overridden with --starttls though.\n");
	echo("  --progress         Show progress while scanning\n");
	echo("  --pretty           Use JSON_PRETTY_PRINT\n");
	echo("  --starttls PROTO   PROTO must be supported by OpenSSL. Typically just ftp,\n");
	echo("                     smtp, pop3, or imap\n");
	echo("  --include-failures Include failed connections in output\n");
	echo("  -v, --version      Show version information\n");
	echo("\n");
	echo("  Note: Because this program is dependent on OpenSSL its results will vary\n");
	echo("        with the version and capabilities of OpenSSL.\n");
}
