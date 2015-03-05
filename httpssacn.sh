echo " HTTPSScan - ($VERSION)"
echo " by Alexandro Silva - Alexos (http://alexos.org)"
echo " REQUIRE: sslscan and OpenSSL"
echo ------------------------------------------------------
if [ $# -ne 2 ]; then
   echo Usage: $0 IP PORT
   exit
fi

HOST=$1
PORT=$2
echo
echo [*] Analyzing SSL/TLS Vulnerabilities on $HOST:$PORT ...
echo
echo -n '                           (0%)\r'
sleep 10
echo -n '###                       (10%)\r'
sleep 20
echo -n '#######                   (30%)\r'
sleep 30
echo -n '#############             (60%)\r'
sleep 20
echo -n '###################       (80%)\r'
sleep 60
echo -n '#######################   (100%)\r'
echo -n '\n'
echo
echo Generating Report...Please wait
echo
# Run sslcan once, store the results to a log file and
# analyze that file for all the different tests:
DATE=$(date +%F_%R:%S)
TARGET=$HOST:$PORT
LOGFILE=sslscan\_$TARGET\_$DATE.log
ERRFILE=sslscan\_$TARGET\_$DATE.err

#echo [*] Running sslscan on $HOST:$PORT...
sslscan $HOST:$PORT | grep Accepted > $LOGFILE

echo [*] Testing for SSLv2
cat $LOGFILE | grep "Accepted  SSLv2"
echo
echo [*] Testing for Poodle CVE-2014-3566
cat $LOGFILE |  grep -q "Accepted  SSLv3"
echo
echo [*] Testing for FREAK CVE-2015-0204
cat $LOGFILE | grep "EXP-"
echo
echo [*] Testing for NULL cipher
cat $LOGFILE | grep "NULL"
echo
echo [*] Testing for weak ciphers
cat $LOGFILE | grep " 40 bits"

cat $LOGFILE | grep " 56 bits"
echo
echo [*] Checking preferred server ciphers
cat $LOGFILE | sed '/Prefered Server Cipher(s):/,/^$/!d' | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g"
echo

#Remove log files
rm *.log
echo [*] done
echo
