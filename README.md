# A script to scan for TLS protocol and cipher support

This is a PHP script which uses OpenSSL to scan a remote host's SSL/TLS protocol and cipher support

* Output in JSON
* Shows preferred connection parameters
* Shows information about export level cipher suites
* Shows information about forward secrecy
* Can emulate cipher suite and protocol ordering of various browsers

##Compatibility
* Works with OpenSSL 0.9.8
* Scans for SSLv2 through TLSv1.2

##Requirements
* php
* OpenSSL

##Usage
./tlsscan.php [ OPTIONS ] -H host

OPTIONS:
  --browser BROWSER  Imitate as best as possible a given browser where BROWSER
                     is one of chrome, chrome47, edge, edge12, firefox,
                     firefox38, firefox44, ie, ie8, ie11, safari,
                     safari8. Overrides --ciphers.
  --ciphers STRING   Use an OpenSSL cipher string when connecting.
  -h, --help         This message
  -p                 Port, defaults to 443
  --progress         Show progress while scanning
  --pretty           Use JSON_PRETTY_PRINT
  --include-failures Include failed connections in output
  -v, --version      Show version information

##Note
Because this program is dependent on OpenSSL its results will vary with the version and capabilities of OpenSSL.
