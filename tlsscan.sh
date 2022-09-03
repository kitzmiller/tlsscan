#!/bin/bash
# Chris Kitzmiller - 8/31/2022

# TODO: Quick fail on connection refused / timeout
# TODO: Curve enumeration

# Check requsites
# ensure openssl is in our path
if [ -x /usr/local/ssl/bin/openssl ] ; then
        # Prefer localcally compiled openssl if avail
        # If compiling locally you can use this ./config line to enable SSLv3 / 3DES, RC4, IDEA, etc.:
        #       apt-get install linux-libc-dev libc6-dev
        #       ./config enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers --prefix=/usr/local/ssl --openssldir=/usr/local/ssl -Wl,--enable-new-dtags,-rpath,'$(LIBRPATH)'
        #
        # Test sites:
        #       SSLv3:  www.ssllabs.com:10300
        #       TLS1:   www.ssllabs.com:10301
        #       TLS1.1: www.ssllabs.com:10302
        #       TLS1.2: www.ssllabs.com:10303
        #       DHE 1024: dh1024.badssl.com:443

        OPENSSL="/usr/local/ssl/bin/openssl"
else
        OPENSSL=`which openssl`
        if [ "$?" -ne 0 ] ; then
                echo "Error, openssl not found"
                exit 1
        fi
fi

# ensure jq is in our path
JQ=`which jq`
if [ "$?" -ne 0 ] ; then
        echo "Error, jq not found"
        exit 1
fi

# Set CAfile arg
if [ -r "/etc/ssl/certs/ca-certificates.crt" ] ; then
        CAFILE="-CAfile /etc/ssl/certs/ca-certificates.crt"
else
        CAFILE=""
fi

usage() {
             #12345678901234567890123456789012345678901234567890123456789012345678901234567890
        echo "Usage: $0 options host"
        echo "  A program to scan for SSL/TLS protocols and cipher suites"
        echo ""
        echo "Options:"
        echo "  --ciphers LIST    An openssl cipher string for use with TLSv1.2 and lower."
        echo "                    Default: \"ALL:COMPLEMENTOFALL\""
        echo "  --suites LIST     An openssl ciphersuite string for use with TLSv1.3."
        echo "                    Default: all available TLSv1.3 suites"
        echo "  -h, --help        This message."
        echo "  -p, --port PORT   Which port to use. Defaults to 443. If 21, 25, 110, 143,"
        echo "                    389, or 589 then --starttls is assumed."
        echo "  --pretty          Pretty print output."
        echo "  --progress        Display progress while scanning."
        echo "  --protocols LIST  A space seperated list of protocols. Defaults to detected"
        echo "                    openssl s_client capability."
        echo "                    Example: --protocols \"tls1 tls1_1\""
        echo "  --starttls PROTO  Use starttls for given PROTO, assumed with standard ports."
        echo "  -v, --version     Show version information."
        exit 1
}

version() {
        echo "tlsscan.sh version 0.5 - Chris Kitzmiller 6/29/2020"
        exit 0
}

# Get options
if ! options=$(/usr/bin/getopt -o p:hv -l ciphers:,help,port,pretty,progress,protocols:,starttls:,version -- "$@")
then
        exit 1
fi
eval set -- "$options"

# Set defaults
startciphers="ALL:COMPLEMENTOFALL"
port=443
pretty=0
progress=0
protocols=`$OPENSSL s_client -help 2>&1 | sed -n 's/^ \-\(ssl[23]\|tls1\(_[123]\)\?\).*/\1/p' | tr '\n' ' '`
starttls=""
startsuites=`$OPENSSL ciphers -V -s -tls1_3 | awk '{ print $3 }' | tr '\n' ':' | sed -e 's/:$//'`

# Parse options
while [ $# -gt 0 ]
do
        case $1 in
                -h|--help)
                        usage
                        ;;
                -v|--version)
                        version
                        ;;
                -p|--port)
                        port="$2"
                        shift
                        ;;
                --ciphers)
                        startciphers="$2"
                        shift
                        ;;
                --pretty)
                        pretty=1
                        ;;
                --progress)
                        progress=1
                        ;;
                --protocols)
                        protocols="$2"
                        shift
                        ;;
                --starttls)
                        starttls="$2"
                        shift
                        ;;
                (--)
                        shift
                        break
                        ;;
                (-*)
                        echo "$0: error - unrecognized option $1" 1>&2
                        exit 1
                        ;;
                (*)
                        break
                        ;;
        esac
        shift
done

# Check options
if [ -z "$1" ] ; then
        usage
fi

# Parse host argument and possibly break out port
host="$1"
# if host has a colon in it then use that port number
echo $host | grep -q : && port=`echo $host | cut -d: -f2`
echo $host | grep -q : && host=`echo $host | cut -d: -f1`
target="${host}:${port}"

# assume starttls if port is a default port for tls services
case $port in
        21) starttls="ftp" ;;
        25) starttls="smtp" ;;
        110) starttls="pop3" ;;
        143) starttls="imap" ;;
        389) starttls="ldap" ;;
        587) starttls="smtp" ;;
esac

if [ "$starttls" != "" ] ; then
        starttlsarg="-starttls $starttls"
fi

# Declare internal variables
declare -A curvetypes
curvetypes[1]="explicit_prime"
curvetypes[2]="explicit_char2"
curvetypes[3]="named_curve"

# from rfc 4492 section 5.1.1 and rfc 8422 section 5.1.1
declare -A curvelist
curvelist[1]="sect163k1"                           # deprecated
curvelist[2]="sect163r1"                           # deprecated
curvelist[3]="sect163r2"                           # deprecated
curvelist[4]="sect193r1"                           # deprecated
curvelist[5]="sect193r2"                           # deprecated
curvelist[6]="sect233k1"                           # deprecated
curvelist[7]="sect233r1"                           # deprecated
curvelist[8]="sect239k1"                           # deprecated
curvelist[9]="sect283k1"                           # deprecated
curvelist[10]="sect283r1"                         # deprecated
curvelist[11]="sect409k1"                         # deprecated
curvelist[12]="sect409r1"                         # deprecated
curvelist[13]="sect571k1"                         # deprecated
curvelist[14]="sect571r1"                         # deprecated
curvelist[15]="secp160k1"                         # deprecated
curvelist[16]="secp160r1"                         # deprecated
curvelist[17]="secp160r2"                         # deprecated
curvelist[18]="secp192k1"                         # deprecated
curvelist[19]="secp192r1"                         # deprecated
curvelist[20]="secp224k1"                         # deprecated
curvelist[21]="secp224r1"                         # deprecated
curvelist[22]="secp256k1"                         # deprecated
curvelist[23]="secp256r1"
curvelist[24]="secp384r1"
curvelist[25]="secp521r1"
# from rfc 7027
curvelist[26]="brainpoolP256r1"
curvelist[27]="brainpoolP384r1"
curvelist[28]="brainpoolP512r1"
# from rfc 8422
curvelist[29]="x25519"
curvelist[30]="x448"
                                                   # 65024 - 65279 reserved
curvelist[65281]="arbitrary_explicit_prime_curves" # deprecated
curvelist[65282]="arbitrary_explicit_char2_curves" # deprecated

data="{}"
protojson="{}"
startdate=`date +%s.%N`
cert="{}"


ipregex='^[0-9.]{7,15}$'
if [[ "$host" =~ $ipregex ]] ; then
        hostfound="true"
else
        host $host >/dev/null 2>&1
        if [ $? -ne 0 ] ; then
                hostfound="false"
                protocols="" # skip main loop by voiding protocol list
                enddate=`date +%s.%N`
        else
                hostfound="true"
        fi
fi

# Begin main loop for each protocol
for protocol in $protocols ; do
        ret=0
        protojson="{}"

        # with sslv2 - tls1.2 we can just remove a cipher from the -ciphers parama by concatenating ":-CIPHER_TO_REMOVE" to the end of the list
        # but TLSv1.3 uses the -ciphersuites option, not the -ciphers option.
        # additionally the ":-CIPHERSUITE_TO_REMOVE" syntax does not seem to work at all but giving a goodlist of ciphersuites does

        ciphers="$startciphers"
        suites="$startsuites"
        if [ $progress -gt 0 ] ; then
                echo -n "$protocol: "
        fi
        while [ "$ret" -eq 0 ] ; do
                outfile=`mktemp -p /tmp tlsscan-XXXXXXXX.tmp`

                if [ "$protocol" == "tls1_3" ] ; then
                        cipherarg="-ciphersuites $suites"
                else
                        cipherarg="-cipher $ciphers"
                fi

                # attempt to connect with given params
                echo|$OPENSSL s_client -msg -$protocol $CAFILE $cipherarg -connect $target $starttlsarg > "$outfile" 2>&1
                ret=$?
                enddate=`date +%s.%N`

                # if the protocol is enabled but there are no ciphers available then
                # some configurations result in a successful connection though practically
                # this is a failure.
                grep -q 'no peer certificate available' "$outfile" && ret=1

                if [ "$ret" -eq 0 ] ; then
                        if [ $progress -gt 0 ] ; then
                                echo -n "."
                        fi

                        # connection success, parse results
                        cipher=`sed -ne 's/^New, \(SSL\|TLS\)[^,]*, Cipher is \(.*\)$/\2/p' "$outfile"`

                        # get info about the cipher
                        if [ "$protocol" == "tls1_3" ] ; then
                                read cipherhex kx au enc mac <<< $($OPENSSL ciphers -V -ciphersuites "$cipher" | awk -v cipher=$cipher '$3 == cipher { printf("%s %s %s %s %s\n", substr($1, 1, 4) substr($1, 8, 2), substr($5, 4), substr($6, 4), substr($7, 5), substr($8, 5)) }')
                        else
                                read cipherhex kx au enc mac <<< $($OPENSSL ciphers -V "$cipher" | awk -v cipher=$cipher '$3 == cipher { printf("%s %s %s %s %s\n", substr($1, 1, 4) substr($1, 8, 2), substr($5, 4), substr($6, 4), substr($7, 5), substr($8, 5)) }')
                        fi

                        keysize=`sed -ne 's/^Server public key is \([0-9]*\) bit/\1/p' "$outfile"`
                        keyexmsg=`grep -C 1 "TLS .* ServerKeyExchange" "$outfile"| tail -n 1`
                        case $kx in
                                *EC*)
                                        curvetype=`echo "$keyexmsg" | awk '{ print $5 }'`
                                        curvehex=`echo "$keyexmsg" | awk '{ print $6 $7 }'`
                                        curvedec=`echo $((16#$curvehex))`
                                        curvename="${curvelist[$curvedec]}"
                                        ;;
                                DH)
                                        dhparamsizehex=`echo "$keyexmsg" | awk '{ print $5$6 }'`
                                        dhparamsize=`echo $((16#$dhparamsizehex))`
                                        # this isnt exaclty true but it is close enough in practice
                                        dhparamsizebits=`echo $((dhparamsize * 8))`
                                        ;;
                        esac

                        # build info on this cipher
                        cipherjson=`echo '{}' | $JQ -cM \
                                --arg protocol "$protocol" \
                                --arg cipher "$cipher" \
                                --arg cipherhex "$cipherhex" \
                                --arg keyexmsg "$keyexmsg" \
                                --arg keyexchange "$kx" \
                                --arg keysize "$keysize" \
                                --arg curvetype "$curvetype" \
                                --arg curvetypename "${curvetypes[$((16#$curvetype))]}" \
                                --arg curvehex "$curvehex" \
                                --arg curvedec "$curvedec" \
                                --arg curvename "$curvename" \
                                --arg dhparamsizebits "$dhparamsizebits" \
                                --arg authentication "$au" \
                                --arg encryption "$enc" \
                                --arg mac "$mac" \
                                '. + {
                                        ($cipher): ({
                                                "cipher": $cipher,
                                                "cipherhex": $cipherhex,
                                                "keyexchange": $keyexchange,
                                                "keysizebits": $keysize | tonumber,
                                                "authentication": $authentication,
                                                "encryption": $encryption,
                                                "mac": $mac
                                        } + (if $keyexchange == "ECDH" then {
                                                "curvetypehex": ("0x" + $curvetype),
                                                "curvetype": $curvetypename,
                                                "curvehex": ("0x" + $curvehex),
                                                "curvedec": $curvedec | tonumber,
                                                "curvename": $curvename,
                                                "pfs": true
                                        } elif $keyexchange == "DH" then {
                                                "dhparamsizebits": $dhparamsizebits | tonumber,
                                                "pfs": true
                                        } else (if $protocol == "tls1_3" then {"pfs": true} else {"pfs": false} end) end))
                                }'`

                        # add this cipher object to the protocol object
                        protojson=`echo "$protojson" | $JQ --arg cipher "$cipher" --argjson cipherjson "$cipherjson" -cM '. + $cipherjson'`

                        # update cipherarg for next iteration
                        if [ "$protocol" == "tls1_3" ] ; then
                                suites=`echo "$suites" | sed -e "s/$cipher//;s/::/:/g;s/^://;s/:$//"`
                        else
                                ciphers="$ciphers:-$cipher"
                        fi

                        if [ "$cert" == "{}" ] ; then
                                # just parse the certificate the first time
                                certfile=`mktemp -p /tmp tlsscan-cert-XXXXXXXX.tmp`
                                certparsedfile=`mktemp -p /tmp tlsscan-cert-parsed-XXXXXXXX.tmp`
                                sed -e '0,/^Server certificate$/d;/^subject/,$d' "$outfile" > "$certfile"
                                $OPENSSL x509 -in "$certfile" -noout -text > "$certparsedfile"

                                subject=`grep -i Subject: "$certparsedfile"  | tr ',' '\n' | grep -i 'cn *=' | sed -e 's/.*= *//'`
                                datestart=`date -d "$(grep 'Not Before' "$certparsedfile" | sed -e 's/.*Not Before: *//')" +%s`
                                dateend=`date -d "$(grep 'Not After' "$certparsedfile" | sed -e 's/.*Not After *: *//')" +%s`
                                sans=`openssl x509 -in "$certfile" -noout -ext subjectAltName | grep -v '^X509v3' | sed -e 's/^ *DNS://;s/, DNS:/ /g;s/^/["/;s/ /", "/g;s/$/"]/'`
                                publickeyalgorithm=`grep 'Public Key Algorithm:' "$certparsedfile" | sed -e 's/[[:space:]]*Public Key Algorithm:[[:space:]]*//'`
                                publickeysize=`grep 'Public-Key:' "$certparsedfile" | sed -e 's/.*(//;s/ .*//'`

                                cert=`echo '{}' | $JQ -cM \
                                        --arg subject "$subject" \
                                        --arg datestart "$datestart" \
                                        --arg dateend "$dateend" \
                                        --argjson sans "$sans" \
                                        --arg pubkeyalgo "$publickeyalgorithm" \
                                        --arg publickeysize "$publickeysize" \
                                        '. + {
                                                "dateend": $dateend,
                                                "datestart": $datestart,
                                                "publickeyalgorithm": $pubkeyalgo,
                                                "publickeysize": $publickeysize,
                                                "subject": $subject,
                                                "x509v3sans": $sans
                                        }'`

                                rm "$certparsedfile"
                                rm "$certfile"
                        fi
                fi
                rm "$outfile"
        done

        if [ $progress -gt 0 ] ; then
                echo
        fi

        # add protocol object to the return data
        data=`echo "$data" | $JQ -cM --arg protocol "$protocol" --argjson protojson "$protojson" '. + {($protocol): $protojson}'`
done

# Construct metadata
duration=`echo $startdate $enddate | awk '{ printf("%.6f\n", $2 - $1) }'`
data=`echo "$data" | $JQ -cM --arg duration "$duration" --argjson hostfound "$hostfound" --argjson cert "$cert" '{ "certificate": $cert, "protocols": ., "metadata": { "duration": $duration | tonumber, "hostfound": $hostfound, "success": ($hostfound and ([.[] | length] | max > 0))}}'`

# Print output
if [ "$pretty" -gt 0 ] ; then
        echo "$data" | $JQ -C .
else
        echo "$data"
fi

# Exit success or failure
if [ "$(echo "$data" | $JQ -r '.metadata.success')" == "true" ] ; then
        exit 0
else
        exit 1
fi
