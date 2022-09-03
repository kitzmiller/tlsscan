# A script to scan for TLS protocol and cipher support

This is a PHP script which uses OpenSSL to scan a remote host's SSL/TLS protocol and cipher support

* Output in JSON
* Shows preferred connection parameters
* Shows information about export level cipher suites
* Shows information about forward secrecy
* Shows Diffie-Hellman bit length 
* Shows elliptic curve type/name

## Compatibility
* Tested with OpenSSL 0.9.8 through 1.0.1
* Scans for SSLv2 through TLSv1.2

## Usage
    ./tlsscan.php [ OPTIONS ] -H host
    A program to scan for SSL/TLS protocols and cipher suites

    OPTIONS:
    Options:"
      --ciphers LIST    An openssl cipher string for use with TLSv1.2 and lower.
                        Default: "ALL:COMPLEMENTOFALL"
      --suites LIST     An openssl ciphersuite string for use with TLSv1.3.
                        Default: all available TLSv1.3 suites
      -h, --help        This message.
      -p, --port PORT   Which port to use. Defaults to 443. If 21, 25, 110, 143,
                        389, or 589 then --starttls is assumed.
      --pretty          Pretty print output.
      --progress        Display progress while scanning.
      --protocols LIST  A space seperated list of protocols. Defaults to detected
                        openssl s_client capability.
                        Example: --protocols "tls1 tls1_1"
      --starttls PROTO  Use starttls for given PROTO, assumed with standard ports.
      -v, --version     Show version information.

## Note
Because this program is dependent on OpenSSL its results will vary with the version and capabilities of OpenSSL.
