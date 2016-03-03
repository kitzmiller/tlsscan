#!/usr/bin/php
<?php
/*****
 * Version 0.4 - 2016-03-03 - Chris Kitzmiller
 *     Added detection of enabled protocols with no ciphers
 *     Skip scanning of unsupported protocols
 * Version 0.3 - 2016-02-11 - Chris Kitzmiller
 *     Added detection of DH parameter size and ECDH curve types
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
	"protocols:",
	"starttls:",
	"version"
);
$o = getopt($shortopts, $longopts);

// Resolve dependencies 
$OPENSSL = exec("which openssl", $output, $retval);
if($retval) { echo("Unable to find openssl\n"); exit(1); }

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
$STDERR = fopen('php://stderr', 'w+');
$final = array();

//determine OpenSSL's protocol support
$opensslprotocols = array();
$protocols = array();
$lastline = exec("$OPENSSL ciphers 'TLSv1.2' 2>&1 >/dev/null", $output, $retval);
if(!$retval) { $opensslprotocols[] = "tls1.2"; $opensslprotocols[] = "tls1.1"; }

$lastline = exec("$OPENSSL ciphers 'TLSv1' 2>&1 >/dev/null", $output, $retval);
if(!$retval) { $opensslprotocols[] = "tls1"; }

$lastline = exec("$OPENSSL ciphers 'SSLv3' 2>&1 >/dev/null", $output, $retval);
if(!$retval) { $opensslprotocols[] = "ssl3"; }

$lastline = exec("$OPENSSL ciphers 'SSLv2' 2>&1 >/dev/null", $output, $retval);
if(!$retval) { $opensslprotocols[] = "ssl2"; }

// Set a default protocol list
$protocols = $opensslprotocols;

$curves = array(
	1 => "sect163k1",
	2 => "sect163r1",
	3 => "sect163r2",
	4 => "sect193r1",
	5 => "sect193r2",
	6 => "sect233k1",
	7 => "sect233r1",
	8 => "sect239k1",
	9 => "sect283k1",
	10 => "sect283r1",
	11 => "sect409k1",
	12 => "sect409r1",
	13 => "sect571k1",
	14 => "sect571r1",
	15 => "secp160k1",
	16 => "secp160r1",
	17 => "secp160r2",
	18 => "secp192k1",
	19 => "secp192r1",
	20 => "secp224k1",
	21 => "secp224r1",
	22 => "secp256k1",
	23 => "secp256r1",
	24 => "secp384r1",
	25 => "secp521r1",
	65281 => "arbitrary_explicit_prime_curves",
	65282 => "arbitrary_explicit_char2_curves"
);

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
if(isset($o["ciphers"])) { $cipherstring = $o["ciphers"]; }
if(empty($cipherstring)) { $cipherstring = "ALL:aNULL:eNULL"; }
if(isset($o["protocols"])) { $protocols = explode(",", $o["protocols"]); }
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
$testprotocols = array_intersect($protocols, $opensslprotocols);
foreach($protocols as $key => $proto) {
	if(!in_array($proto, $testprotocols)) {
		fwrite($STDERR, "Warning: unable to test " . $proto . "\n");
		unset($protocols[$key]);
	}
}

$skipprotos = array();
foreach($opensslprotocols as $oproto) {
	if(!in_array($oproto, $testprotocols)) {
		switch($oproto) {
			case "tls1.2": $skipprotos[] = "-no_tls1_2"; break;
			case "tls1.1": $skipprotos[] = "-no_tls1_1"; break;
			case "tls1":   $skipprotos[] = "-no_tls1";   break;
			case "ssl3":   $skipprotos[] = "-no_ssl3";   break;
			case "ssl2":   $skipprotos[] = "-no_ssl2";   break;
		}
	}
}
$skipprotostring = implode(" ", $skipprotos);

unset($output);
$execstring = "echo|$OPENSSL s_client $CAFILE $skipprotostring -cipher '$cipherstring' -connect $connect -msg 2>&1";
$lastline = exec($execstring, $output, $retval);
if($retval || sizeof($output) < 30) {
	echo($execstring . "\n");
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
			$lastline = exec("echo|$OPENSSL s_client $sclientproto $CAFILE -cipher '$ciphersuite' -connect $connect -msg 2>&1", $output, $retval);
			$result = true;
			foreach($output as $line) {
				$splode = explode(":", $line);
				if(isset($splode[1]) && ($splode[1] == "error")) {
					$result = false;
					$error = $splode[5];
					switch($error) {
						case "no cipher match": break;
						case "no cipher list": if(!isset($final[$protocols[$i]])) { $final[$protocols[$i]] = new stdClass(); } break; // protocol enabled but no ciphers, important for DROWN
						case "ssl handshake failure": break;
						case "sslv3 alert handshake failure": break;
						default:
					}
				}
			}
			// if s_client errored, or exited 0 but had a line with "xyz:error:...", or simply didn't output enough then mark this connection as a failure
			if($retval || !$result || sizeof($output) < 30) {
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
	global $curves;
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
	$dhparamsize = false;
	$curve = false;
	$curvehex = false;
	$curvetype = false;
	$curvetypehex = false;
	for($i = 0; $i < sizeof($blocks[0]); $i++) {
		if(strpos($blocks[0][$i], "ServerKeyExchange")) {
			$line = $blocks[0][$i + 1];

			// For DH
			$sizehexbytes = "0x" . substr($line, 16, 2) . substr($line, 19, 2);
			$dhparamsize = hexdec($sizehexbytes) * 8;

			// For ECDH
			$curvetypehex = substr($line, 16, 2);
			switch($curvetypehex) {
				case "01": $curvetype = "explicit_prime"; break;
				case "02": $curvetype = "explicit_char2"; break;
				case "03": $curvetype = "named_curve"; break;
				default: $curvetype = "unknown ($curvetypehex)";
			}
			if($curvetype == "named_curve") {
				$curvehex = "0x" . substr($line, 19, 2) . substr($line, 22, 2);
			}
		}
	}
	foreach($blocks as $key => $block) {
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
					if($dhparamsize && ($ciphers[trim($splode[1])]["keyexchange"] == "DH")) {
						$parsed["dhbitlength"] = $dhparamsize;
					}
					if($curvetypehex && ($ciphers[trim($splode[1])]["keyexchange"] == "ECDH")) {
						$parsed["curvetype"] = $curvetype;
						if($curvetype == "named_curve") {
							$parsed["curvehex"] = $curvehex;
							if(isset($curves[hexdec($curvehex)])) {
								$parsed["curvename"] = $curves[hexdec($curvehex)];
							}
						}
					}
				}
				if(strpos($line, "Server public key is ") === 0) {
					$splode = explode(" ", $line);
					$parsed["bitlength"] = $splode[4];
				}
			}
		}
	}
	return $parsed;
}

function version() {
	global $argv, $OPENSSL;
	echo($argv[0] . " v0.3 - " . exec($OPENSSL . " version") . "\n");
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
	echo("  --ciphers STRING   Use an OpenSSL cipher string when connecting. Overrides\n");
	echo("                     --browser.\n");
	echo("  -h, --help         This message\n");
	echo("  -p                 Port, defaults to 443. If 21, 25, 110, 143, 587 then\n");
	echo("                     starttls with the appropriate protocol is assumed. Can\n");
	echo("                     be overridden with --starttls though.\n");
	echo("  --pretty           Use JSON_PRETTY_PRINT\n");
	echo("  --progress         Show progress while scanning\n");
	echo("  --protocols LIST   A comma separated list. Overrides --browser\n");
	echo("                     (e.g. tls1.2,tls1.1,tls1,ssl3,ssl2)\n");
	echo("  --starttls PROTO   PROTO must be supported by OpenSSL. Typically just ftp,\n");
	echo("                     smtp, pop3, or imap\n");
	echo("  --include-failures Include failed connections in output\n");
	echo("  -v, --version      Show version information\n");
	echo("\n");
	echo("  Note: Because this program is dependent on OpenSSL its results will vary\n");
	echo("        with the version and capabilities of OpenSSL.\n");
}
