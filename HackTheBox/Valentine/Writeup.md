# Hack The Box | [Valentine](https://app.hackthebox.eu/machines/127)
###### Writeup by. Jessi

## Enumeration
### Nmap Scan
Begin with an nmap scan against the target.  
**Target:** 10.129.1.110  
~~~Bash
┌──(jessi㉿teatimesec)-[~/HTB/Valentine]
└─$ nmap -sC -sV 10.129.1.190
 Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-10 10:31 EST
Nmap scan report for 10.129.1.190
Host is up (0.026s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2.04 seconds
~~~
The scan only picked up port 22 in the scan. So I tried doing an intense scan on all TCP ports.  
~~~Bash
┌──(jessi㉿teatimesec)-[~/HTB/Valentine]
└─$ nmap -p 1-65535 -T4 -A 10.129.1.190
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-10 11:00 EST
Nmap scan report for 10.129.1.190
Host is up (0.025s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE    VERSION
22/tcp  open  tcpwrapped
| ssh-hostkey: 
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
80/tcp  open  http       Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http   Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
|_ssl-date: 2021-01-10T16:05:06+00:00; +4m07s from scanner time.
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=1/10%OT=80%CT=1%CU=36172%PV=Y%DS=2%DC=T%G=Y%TM=5FFB24B
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=109%TI=Z%CI=Z%TS=8)SEQ(SP=1
OS:07%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=8)OPS(O1=M54DST11NW4%O2=M54DST11NW4%O
OS:3=M54DNNT11NW4%O4=M54DST11NW4%O5=M54DST11NW4%O6=M54DST11)WIN(W1=3890%W2=
OS:3890%W3=3890%W4=3890%W5=3890%W6=3890)ECN(R=Y%DF=Y%T=40%W=3908%O=M54DNNSN
OS:W4%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T=4
OS:0%W=3890%S=O%A=S+%F=AS%O=M54DST11NW4%RD=0%Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=
OS:Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF
OS:=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=
OS:%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G
OS:)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops

Host script results:
|_clock-skew: 4m06s

TRACEROUTE (using port 8080/tcp)
HOP RTT      ADDRESS
1   24.45 ms 10.10.14.1
2   24.66 ms 10.129.1.190

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 47.69 seconds
~~~
### Open Ports/Services
22/tcp - SSH  
80/tcp - HTTP  
443/tcp - SSL  
### HTTP
I decided to use gobuster to brute-force directories on the web server.  
~~~Bash
┌──(jessi㉿teatimesec)-[~/HTB/Valentine]
└─$ gobuster dir -u http://10.129.1.190/ -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.129.1.190/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/01/10 11:17:27 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htpasswd (Status: 403)
/.htaccess (Status: 403)
/cgi-bin/ (Status: 403)
/decode (Status: 200)
/dev (Status: 301)
/encode (Status: 200)
/index (Status: 200)
/index.php (Status: 200)
/server-status (Status: 403)
===============================================================
2021/01/10 11:17:39 Finished
===============================================================
~~~
Upon browsing to /dev, I was greeted with some files in the directory.  
