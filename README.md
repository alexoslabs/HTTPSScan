# HTTPSSscan
Shell script for testing the SSL/TLS Protocols

Detect the SSL/TLS Vulnerabilities:

* Poodle CVE-2014-3566
* FREAK CVE-2015-0204
* Weak Ciphers

Usage:

sh httpsscan.sh [target] [port]

Example:

sh httpsscan.sh example.com 443

-------------------------------------------------

HTTPSScan - (1.0)

by Alexandro Silva - Alexos (http://alexos.org)

REQUIRE: sslscan and OpenSSL

-------------------------------------------------

[*] Analyzing SSL/TLS Vulnerabilities on example.com:443 ...

####################### (100%)

Generating Report...Please wait

[*] Testing for SSLv2

[*] Testing for Poodle CVE-2014-3566

[*] Testing for FREAK CVE-2015-0204

    Accepted  TLSv1  40 bits   EXP-DES-CBC-SHA
    
    Accepted  TLSv1  40 bits   EXP-RC2-CBC-MD5
    
    Accepted  TLSv1  40 bits   EXP-RC4-MD5
    

[*] Testing for NULL cipher


[*] Testing for weak ciphers

    Accepted  TLSv1  40 bits   EXP-DES-CBC-SHA
    
    Accepted  TLSv1  40 bits   EXP-RC2-CBC-MD5
    
    Accepted  TLSv1  40 bits   EXP-RC4-MD5
    
    Accepted  TLSv1  56 bits   DES-CBC-SHA

[*] Checking preferred server ciphers


[*] done
