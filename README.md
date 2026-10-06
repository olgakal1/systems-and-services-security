# systems-and-services-security
Security engineering projects developed as part of the Systems and Services Security course at the Technical University of Crete

## Projects

### 01 — Secure Client-Server Communication with Mutual TLS

Implementation of secure client-server communication using TLS 1.2 and
OpenSSL, featuring X.509 certificate-based mutual authentication and
rogue-client detection.

**Technologies:** C · OpenSSL · TLS 1.2 · X.509 · mTLS · TCP/IP · Linux

[View Project →](./01-secure-client-server-mtls/)


### 02 — Cryptographic Algorithms: ECDH & RSA

Implementation of cryptographic algorithms including Curve25519-based Elliptic Curve Diffie–Hellman (ECDH) key exchange with key derivation, and RSA for key generation, encryption/decryption, digital signatures, and performance benchmarking across multiple key sizes.

**Technologies:** C · Libsodium · GMP · Curve25519 · ECDH · RSA · SHA-256 · KDF

[View Project →](./02-cryptographic-algorithms/)


### 03 — Access Control Logging

Implementation of a Linux file-access auditing system that intercepts file
operations, records security events with SHA-256 integrity hashes, and analyzes
audit logs to detect suspicious users and track file modifications.

**Technologies:** C · Linux · SHA-256 · OpenSSL · Dynamic Linking · LD_PRELOAD · File Auditing

[View Project →](./03-access-control-logging/)


### 04 — Supply-Chain Malware Detection

Simulation of a software supply-chain attack by modifying the Paramiko SSH
library used by Fabric, followed by detection of dependency tampering through
real-time file monitoring and custom YARA signatures.

**Technologies:** Python · Paramiko · Fabric · SSH · YARA · Linux · inotify · Malware Detection

[View Project →](./04-supply-chain-malware-detection/)


### 05 — Web-based Vulnerabilities & Attacks

Security assessment of an intentionally vulnerable Flask web application,
covering the identification and exploitation of common web vulnerabilities
including SQL injection, reflected and DOM-based XSS, local file inclusion,
and open redirects.

**Technologies:** Python · Flask · SQLite · SQL Injection · XSS · LFI · Web Security

[View Project →](./05-web-based-vulnerabilities-and-attacks/)


### 06 — Linux Firewall & Ad Blocking

Implementation of a Linux firewall and network-level ad-blocking tool using
iptables and ip6tables, supporting domain resolution, IPv4/IPv6 filtering,
rule persistence, restoration, and firewall management.

**Technologies:** Bash · Linux · iptables · ip6tables · IPv4 · IPv6 · DNS · Network Security

[View Project →](./06-linux-firewall-and-adblocking/)


### 07 — Network Traffic Monitoring with Snort

Implementation and evaluation of a network intrusion detection workflow using
Snort, including custom packet generation, PCAP traffic analysis, custom IDS
rules, malicious traffic detection, and Slammer Worm analysis.

**Technologies:** Python · Snort · Wireshark · PCAP · TCP/IP · IDS · Network Security · Packet Analysis

[View Project →](./07-network-traffic-monitoring-with-snort/)


### 08 — Ransomware Implementation

Implementation of a ransomware simulation in an isolated Docker environment,
combining AES-256-CBC file encryption with access-control auditing and
behavioral detection of high-volume file activity and encryption patterns.

**Technologies:** Bash · C · Docker · OpenSSL · AES-256-CBC · PBKDF2 · SHA-256 · LD_PRELOAD · Linux · Malware Detection

[View Project →](./08-ransomware-implementation/)


### 09 — Buffer Overflow Exploitation

Analysis and exploitation of stack-based buffer overflow vulnerabilities,
covering arbitrary code execution, shellcode injection, return-to-libc
techniques for DEP bypass, and information leaks for ASLR bypass.

**Technologies:** C · Python · GDB · Pwntools · x86/x86-64 · Linux · Buffer Overflow · Return-to-libc · DEP · ASLR

[View Project →](./09-buffer-overflow-exploitation/)

