# Hack The Box | Vaccine
###### Writeup by. Jessi

## Enumeration
### Nmap Scan
Begin with an nmap scan against the target.  
**Target:** 10.10.10.46  
~~~Bash
┌──(jessi㉿teatimesec)-[~/HTB/Vaccine]
└─$ nmap -sC -sV 10.10.10.46
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-07 09:29 EST
Nmap scan report for 10.10.10.46
Host is up (0.028s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.0p1 Ubuntu 6build1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c0:ee:58:07:75:34:b0:0b:91:65:b2:59:56:95:27:a4 (RSA)
|   256 ac:6e:81:18:89:22:d7:a7:41:7d:81:4f:1b:b8:b2:51 (ECDSA)
|_  256 42:5b:c3:21:df:ef:a2:0b:c9:5e:03:42:1d:69:d0:28 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: MegaCorp Login
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.18 seconds
~~~
#### Description of parameters used
**-sC:** Scan with default NSE scripts. Considered useful for discovery and safe.  
**-sV:** Attempts to determine the version of the service running on port.  
### Open Ports/Services
21/tcp - FTP  
22/tcp - SSH  
80/tcp - HTTP  
### FTP
I was able to access FPT using credentials received from the previous pwned box. ftpuser / mc@F1l3ZilL4.  
~~~Bash
┌──(jessi㉿teatimesec)-[~/HTB/Vaccine]
└─$ ftp 10.10.10.46
Connected to 10.10.10.46.
220 (vsFTPd 3.0.3)
Name (10.10.10.46:jessi): ftpuser
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
~~~
And from here I browsed around the directory and found a file called **backup.zip**. I downloaded the file for further inspection.  
~~~Bash
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0            2533 Feb 03  2020 backup.zip
226 Directory send OK.
ftp> get backup.zip
local: backup.zip remote: backup.zip
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for backup.zip (2533 bytes).
226 Transfer complete.
2533 bytes received in 0.00 secs (24.1566 MB/s)
ftp> 
~~~
### Password Cracking: backup.zip
Using John, I am able to crack the password to the zip file. First I need to prepare the hash using **zip2john**.  Then I can crack it by referencing rockyou.txt wordlist.  
~~~Bash
┌──(jessi㉿teatimesec)-[~/HTB/Vaccine]
└─$ zip2john backup.zip > hash
Created directory: /home/jessi/.john
ver 2.0 efh 5455 efh 7875 backup.zip/index.php PKZIP Encr: 2b chk, TS_chk, cmplen=1201, decmplen=2594, crc=3A41AE06
ver 2.0 efh 5455 efh 7875 backup.zip/style.css PKZIP Encr: 2b chk, TS_chk, cmplen=986, decmplen=3274, crc=1B1CCD6A
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
┌──(jessi㉿teatimesec)-[~/HTB/Vaccine]
└─$ john hash --fork=4 -w=/usr/share/wordlists/rockyou.txt
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Node numbers 1-4 of 4 (fork)
Press 'q' or Ctrl-C to abort, almost any other key for status
741852963        (backup.zip)
1 1g 0:00:00:00 DONE (2021-01-07 09:41) 2.000g/s 512.0p/s 512.0c/s 512.0C/s football1..simpleplan
Waiting for 3 children to terminate
2 0g 0:00:00:00 DONE (2021-01-07 09:42) 0g/s 3814Kp/s 3814Kc/s 3814KC/s  derrickak47.abygurl69
3 0g 0:00:00:01 DONE (2021-01-07 09:42) 0g/s 3230Kp/s 3230Kc/s 3230KC/s  brian89.a6_123
4 0g 0:00:00:01 DONE (2021-01-07 09:42) 0g/s 3012Kp/s 3012Kc/s 3012KC/s  mar ..*7¡Vamos!
Use the "--show" option to display all of the cracked passwords reliably
Session completed
~~~
Success!  
#### Cracked Password
Password: 741852963  
Using the password, I was able to unzip the file. Inside there were two files - **index.php** and **style.css**.  Mainly interested in the index.php file.  
