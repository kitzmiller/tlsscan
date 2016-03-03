# A script to scan for TLS protocol and cipher support

This is a PHP script which uses OpenSSL to scan a remote host's SSL/TLS protocol and cipher support

* Output in JSON
* Shows preferred connection parameters
* Shows information about export level cipher suites
* Shows information about forward secrecy
* Shows Diffie-Hellman bit length 
* Shows elliptic curve type/name
* Can emulate cipher suite and protocol ordering of various browsers

##Compatibility
* Tested with OpenSSL 0.9.8 through 1.0.1
* Scans for SSLv2 through TLSv1.2

##Requirements
* php
* OpenSSL

##Usage
    ./tlsscan.php [ OPTIONS ] -H host

    A program to scan for SSL/TLS protocols and cipher suites

    OPTIONS:
    --browser BROWSER  Imitate as best as possible a given browser where BROWSER
                       is one of chrome, chrome47, edge, edge12, firefox,
                       firefox38, firefox44, ie, ie8, ie11, ios, ios8, ios9,
                       safari, safari8. No version means latest version.
    --ciphers STRING   Use an OpenSSL cipher string when connecting. Overrides
                       --browser.
    -h, --help         This message
    -p                 Port, defaults to 443. If 21, 25, 110, 143, 587 then
                       starttls with the appropriate protocol is assumed. Can
                       be overridden with --starttls though.
    --pretty           Use JSON_PRETTY_PRINT
    --progress         Show progress while scanning
    --protocols LIST   A comma separated list. Overrides --browser
                       (e.g. tls1.2,tls1.1,tls1,ssl3,ssl2)
    --starttls PROTO   PROTO must be supported by OpenSSL. Typically just ftp,
                       smtp, pop3, or imap
    --include-failures Include failed connections in output
    -v, --version      Show version information

    Note: Because this program is dependent on OpenSSL its results will vary
          with the version and capabilities of OpenSSL.

##Note
Because this program is dependent on OpenSSL its results will vary with the version and capabilities of OpenSSL.
