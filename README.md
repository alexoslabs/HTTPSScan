# HTTPSScan
Shell script for testing the SSL/TLS Protocols

Check for SSL/TLS Vulnerabilities:

* SSLv2 (CVE-2011-1473)
* TLS CRIME (CVE-2012-4929)
* RC4 (CVE-2013-2566)
* Heartbleed (CVE-2014-0160) 
* Poodle (CVE-2014-3566)
* FREAK (CVE-2015-0204)
* Logjam (CVE-2015-4000)
* Weak Ciphers

Usage:

bash httpsscan.sh [target] [port] [option]

Options:

all, --all, a

ssl2, --ssl2

crime, --crime

rc4, --rc4

heartbleed, --heartbleed

poodle, --poodle

freak, --freak

null, --null

weak40, --weak40

weak56, --weak56

forward, --forward

![ScreenShot](http://alexos.org/wp-content/uploads/2015/04/httpsscan5.png)
