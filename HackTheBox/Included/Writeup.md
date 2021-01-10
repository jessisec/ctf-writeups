# Hack The Box | Included
###### Writeup by. Jessi

## Enumeration
### Nmap Scan
Begin with an nmap scan against the target.  
**Target:** 10.10.10.55  
~~~Bash
┌──(jessi㉿teatimesec)-[~/HTB/Included]
└─$ nmap -sC -sV 10.10.10.55
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-10 15:53 EST
Nmap scan report for 10.10.10.55
Host is up (0.027s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was http://10.10.10.55/?file=index.php

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.86 seconds
~~~
The only port open in the TCP scan is 80. So I'll run a UDP scan as well.  
~~~Bash
