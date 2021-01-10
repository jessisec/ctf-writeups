# Hack The Box | Pathfinder
###### Writeup by. Jessi

## Enumeration
### Nmap Scan
Begin with an nmap scan on the target.  
**Target:** 10.10.10.30  
~~~Bash
┌──(jessi㉿teatimesec)-[~/HTB/Pathfinder]
└─$ nmap -sC -sV 10.10.10.30           
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-10 14:27 EST
Nmap scan report for 10.10.10.30
Host is up (0.026s latency).
Not shown: 989 closed ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-01-11 03:36:11Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: PATHFINDER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 8h08m30s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-01-11T03:36:16
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.27 seconds
~~~
### Open Ports/Services
88/tcp - Kerberos  
389/tcp - LDAP  
5985/tcp - WinRM  
Target looks like a domain controller.  
### Active Directory
Using the credentials I obtained from a previously compromised box (sandra / Password1234!), I can attempt to enumerate Active Directory. I can achieve this with **BloodHound** - using the Python ingester first to get data.    
~~~Bash
┌──(jessi㉿teatimesec)-[~/HTB/Pathfinder]
└─$ bloodhound-python -d megacorp.local -u sandra -p Password1234! -gc pathfinder.megacorp.local -c all -ns 10.10.10.30
INFO: Found AD domain: megacorp.local
INFO: Connecting to LDAP server: Pathfinder.MEGACORP.LOCAL
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: Pathfinder.MEGACORP.LOCAL
INFO: Found 5 users
INFO: Connecting to GC LDAP server: pathfinder.megacorp.local
INFO: Found 51 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: Pathfinder.MEGACORP.LOCAL
INFO: Done in 00M 06S
~~~
### BloodHound
Now with the data I gathered with the python ingester, I can now start the Neo4j DB and login to bloodhound to access the data.  
