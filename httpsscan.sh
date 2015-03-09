#!/usr/bin/env bash
#Credits: Based on TLSSLed by  Raul Siles (www.taddong.com).

# Script to test the most security flaws on a target SSL/TLS.
# Author:  Alexandro Silva (alexos at alexos dot org)
# Date:    03-05-2015
# Version: 1.0
#
# References:
# OWASP Testing for Weak SSL/TLS Ciphers, Insufficient Transport Layer Protection 
# https://www.owasp.org/index.php/Testing_for_Weak_SSL/TLS_Ciphers,_Insufficient_Transport_Layer_Protection_%28OTG-CRYPST-001%29
# CVE-2014-3566
# https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-3566
# CVE-2015-0204
# https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-0204
# Forward Secrecy
# http://blog.ivanristic.com/2013/06/ssl-labs-deploying-forward-secrecy.html

VERSION=1.2

clear
echo ":::    ::::::::::::::::::::::::::::::::::  ::::::::  ::::::::  ::::::::     :::    ::::    ::: "
echo ":+:    :+:    :+:        :+:    :+:    :+::+:    :+::+:    :+::+:    :+:  :+: :+:  :+:+:   :+: "
echo "+:+    +:+    +:+        +:+    +:+    +:++:+       +:+       +:+        +:+   +:+ :+:+:+  +:+ "
echo "+#++:++#++    +#+        +#+    +#++:++#+ +#++:++#+++#++:++#+++#+       +#++:++#++:+#+ +:+ +#+ "
echo "+#+    +#+    +#+        +#+    +#+              +#+       +#++#+       +#+     +#++#+  +#+#+# "
echo "#+#    #+#    #+#        #+#    #+#        #+#    #+##+#    #+##+#    #+##+#     #+##+#   #+#+ "
echo "###    ###    ###        ###    ###        ########  ########  ######## ###     ######    #### "
echo "V. $VERSION by Alexos Core Labs                                                        "

if [ $# -ne 2 ]; then
   echo Usage: $0 IP PORT
   exit
fi

HOST=$1
PORT=$2
TARGET=$HOST:$PORT
LOGFILE=sslscan\_$TARGET.log

echo
echo [*] Analyzing SSL/TLS Vulnerabilities on $HOST:$PORT ...
echo
echo Generating Report...Please wait
sslscan $HOST:$PORT > $LOGFILE
echo
echo [*] Testing for SSLv2
cat $LOGFILE | grep "Accepted  SSLv2"
echo
echo [*] Testing for Poodle CVE-2014-3566
cat $LOGFILE | grep "Accepted  SSLv3"
echo
echo [*] Testing for FREAK CVE-2015-0204
cat $LOGFILE | grep "EXP-" | grep Accepted
echo
echo [*] Testing for NULL cipher
cat $LOGFILE | grep "NULL" | grep Accepted
echo
echo [*] Testing for weak ciphers
cat $LOGFILE | grep " 40 bits" | grep Accepted

cat $LOGFILE | grep " 56 bits" | grep Accepted
echo
echo [*] Checking for Forward Secrecy
cat $LOGFILE | grep "ECDHE" | grep  Accepted

cat $LOGFILE | grep "DHE" | grep  Accepted
echo
echo [*] Checking preferred server ciphers
cat $LOGFILE| sed '/Prefered Server Cipher(s):/,/^$/!d' | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g"
rm $LOGFILE
echo [*] done
