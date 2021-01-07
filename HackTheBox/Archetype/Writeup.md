# Hack The Box | Archetype
###### Writeup by. Jessi

## Enumeration
### Nmap Scan
I started with an nmap scan against the target.  
**Target:** 10.10.10.27
~~~Bash
┌──(jessi㉿teatimesec)-[~/HTB/Archetype]
└─$ nmap -sC -sV -T4 10.10.10.27
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-06 19:40 EST
Nmap scan report for 10.10.10.27
Host is up (0.025s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE      VERSION
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds
1433/tcp open  ms-sql-s     Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: ARCHETYPE
|   NetBIOS_Domain_Name: ARCHETYPE
|   NetBIOS_Computer_Name: ARCHETYPE
|   DNS_Domain_Name: Archetype
|   DNS_Computer_Name: Archetype
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2021-01-07T00:08:48
|_Not valid after:  2051-01-07T00:08:48
|_ssl-date: 2021-01-07T01:01:15+00:00; +20m03s from scanner time.
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h56m03s, deviation: 3h34m40s, median: 20m02s
| ms-sql-info: 
|   10.10.10.27:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb-os-discovery: 
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: Archetype
|   NetBIOS computer name: ARCHETYPE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-01-06T17:01:07-08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-01-07T01:01:08
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.14 seconds
~~~

### Open Ports/Services Found
445/tcp - SMB  
1433/tcp - SQL

### SMB
I attempted to access SMB with anonymous user access.
~~~Bash
┌──(jessi㉿teatimesec)-[~/HTB/Archetype]
└─$ smbclient -N -L \\\\10.10.10.27\\

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backups         Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
SMB1 disabled -- no workgroup available
~~~

The **backups** share looked interesting, so I decided to take a look inside. Inside of the share, I found a file called **prod.dtsConfig**, so I decided to download it for further inspection.
~~~Bash
┌──(jessi㉿teatimesec)-[~/HTB/Archetype]
└─$ smbclient -N \\\\10.10.10.27\\backups
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Jan 20 07:20:57 2020
  ..                                  D        0  Mon Jan 20 07:20:57 2020
  prod.dtsConfig                     AR      609  Mon Jan 20 07:23:02 2020

                10328063 blocks of size 4096. 8259126 blocks available
smb: \> get prod.dtsConfig
getting file \prod.dtsConfig of size 609 as prod.dtsConfig (6.1 KiloBytes/sec) (average 6.1 KiloBytes/sec)
~~~
