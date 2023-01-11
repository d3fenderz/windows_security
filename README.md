# Is Windows a joke [security analysis]?

Is Windows a joke or are you? 🧢

## Disclaimers

If you find something wrong or inaccurate, please share your point of view (e.g., in an issue).

It's important you don't get confused by this guide. I'm deliberately ignoring essential parts of the critics, like **privacy**.

In this case, yes, Windows is a bad joke, and I mean it. You may want to disable all telemetries, but the system starts multiple processes silently (e.g., with Edge) without asking for your permission.
Despite some notable efforts in the latest releases, a quick analysis reveals **surprising** behaviors...

In another perpsective, I'm not saying Windows is "unhackable." THAT would be a terrible joke! Besides, I know it's relatively easy to full Windows built-in security, for example, using obfuscation, but we'll see it's not necessarily a good indicator.

## General

I'm probably not the only one to make jokes about Windows and its vulnerabilities. Indeed, Microsoft sells products to the vast majority of individuals, but organizations as well.
A large range of businesses rely on Active Directories and other Microsoft technologies for their daily activities.

Millions of users use these products every day. That's why it's a primary target for cybercriminals.

While Windows' bad reputation was probably justified at a time, news versions seem particularly secure. It's just that Microsoft does not enable everything by default to appeal to the largest market share.

### Constructive Critics

This year, I've seen multiple cases where Microsoft teams did not answer appropriately to major security alerts, ignoring security researchers and almost marking critical vulnerabilities as _won't fix_ or not answering at all.

Specialists regularly complain about that. It's problematic as some flaws remain unpatched for weeks or months without remediation, sometimes without any mitigation.

### Windows vs. Linux vs. macOS

If you compare with other OSes, Windows is secure. I'm definitely a Linux fan boy, but I can't recommend it to everyone, especially for security purposes.

It shifts the responsibility to the end-users, exposing beginners and non-technical users to various risks, especially if you install alternative distros. A huge part of the global security is handled by browsers, not the system itself.
You need to be a power user to leverage the benefits of Linux. While the latest versions are usually patched and way more usable, it's easy to completely mess up your configuration.

At least, Windows simplifies the process and helps all users secure their machine (e.g., security patches, automatic updates, BIOS flashing, firmware updates).

IMHO, the only operating system that does a much better job than Windows to protect its users is macOS, with robust configurations, isolation, and other magics.

### What you will find here

I'm writing this guide to help you understand Windows and its security mechanisms. You'll also get helpful links to dig further. We'll see how to harden your configuration and activate interesting options.

We'll see practical examples that help defending your system against common exploits.

### But security tools and policies can be disabled!

Yes, and it's undeniably a good point. Many attacks attempt to modify registry entries to disable security tools and mechanims, allowing malware to spread and infect the entire system.

Attackers can also leverage [LOTL attacks](https://encyclopedia.kaspersky.com/glossary/lotl-living-off-the-land/), using legitimate software to bypass detection.

### Static analysis is not enough

Attacks can be identified by static analysis and signature-based detection. It's necessary but no longer sufficient.

During forensic investigations and malware analysis, you may upload binaries or `.dll` to VirusTotal, but such static analysis on suspicious files won't help you with malicious instructions in memory.
In many cases, defenders need dynamic analysis too, like behavioral detection, as built-in commands and mechanisms can be used to download poison from external IPs to install malware.

Windows cannot prevent users from installing third-party applications, which is often how cybercriminal compromise their victims.

### So, Windows is perfect?

Nope. Don't get me wrong with this guide. My point is that it's probably less shitty than you and I think. Besides, your family and friends won't switch to Tails (even macOS) tomorrow.

## Basics of security on Windows

### 7 recommentations for the individuals

My shortlist, no bullshit:

* Enable Windows built-in security (Defender, Firewall, etc).
* Keep the system up-to-date: download and install **all** patches available.
* Keep the BIOS and the firmware up-to-date.
* Encrypt the hard drive with [BitLocker](https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-overview).
* Connecting with Microsoft accounts is only useful to enable [Windows Hello](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello). Otherwise, use local accounts only.
* Apply the least privilege principle: not all users need admin privileges.
* As admin, define local security policies (e.g., strong password policy), apply mitigations, and sync files to make regular backups (e.g., have a clear recovery strategy).

It does not mean you get a digital fortress after that, but it's not trivial to hack and usually requires social engineering and more sophisticated scenarios to make people install crap.

### About Windows 11

Windows has better default policies and settings.

If your machine meets the following requirements (you can use [health check](https://support.microsoft.com/en-us/windows/how-to-check-if-your-device-meets-windows-11-system-requirements-after-changing-device-hardware-f3bc0aeb-6884-41a1-ab57-88258df6812b) to verify it):

* TPM 2.0
* Security boot Enabled
* DEP (Data Execution Prevention)
* UEFI MAT

It's recommended to switch to Windows 11. The latest version of the OS (at the time of writing) enables interesting features by default, such as Memory integrity, which protects the core from various hijacks and memory corruptions.

The requirements also provide [zero trust protection](https://www.ibm.com/topics/zero-trust) out of the box. More pragmatically, such configuration eliminates _de facto_ entire classes of threats.

A big caveat is that many people will attempt to bypass system requirements, trying to upgrade old machines to Windows 11, which is a very bad move, as it's not meant for that by definition, and you may lose both the security benefits and the usability (e.g., hardware performances). Many advanced security features, like [VBS](https://learn.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity) are available on Windows 10 too.

**Windows 10 will be maintained until Oct. 14, 2025**

### 7 Recommendations for the admins (businesses, organizations)

It's hard to provide a generic list, as there are many configurations and products (e.g., Windows Server), but let's keep it simple:

* Keep the system up-to-date, including the BIOS and the firmware, but also applications
* Encrypt hard drives with [BitLocker](https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-overview).
* Consider suites like Windows 365 that provides recommendations for admins and advanced endpoint protection (there are many credible alternatives, but cloud-based security can be rewarding)
* Apply the least privilege principle
* Don't trust the default settings: define security policies (e.g., strong password policy), apply mitigations, and have a recovery strategy
* Disable sensitive [Powershell](https://learn.microsoft.com/en-us/powershell/) commands
* Monitor endpoints, network traffic, and unusual activities

### Most bypasses involve initial access and malicious TCP connections

Most demos that bypass Windows security need initial access before, but that's not the most complicated part. Phishing attacks are more and more sophisticated these days, so it's not uncommon employees get tricked into deploying RATs and other "connect-back" tools, especially when the company has no security culture.

However, what bypasses Windows Defender is usually obfuscated powershell commands that start reverse shells and other malicious TCP connections. While it definitely works, any system would be fooled unless you monitor/filter packets and outgoing connections correctly, even on a fully-patched Windows (not a valid demonstration to me).

Besides, cybercriminals often use legitimate platforms as "C&C" servers to bypass detection tools that focus on blacklisted domains and IP ranges.

### The System32

You can read [this blog post](https://jmau111.github.io/2022/11/25/windows-system32-forensics/) for a quick introduction to essential concepts. 

`C:\Windows\System32` is the heart of the system. It contains all system configurations, settings, and binaries. If you or something else (e.g., a virus) damages this folder, you can say good bye to your environmment (regular backups are strongly recommended).

That's why Windows does not let you destroy this folder and locks most files within, even for admins.

Cybercriminals use it all the time, for example, to hijack `.dll` and or replace system binaries with evil executables.

### Active directory vs. LDAP

Also known as AD, it's a Windows service that stores data objects, which can be users, devices, applications, or groups. Enterprises often use it to allow users to authenticate and manage various resources. It requires Windows Professional or Windows Enterprise, at least, but you usually test it with Windows Server editions.

Attackers have multiple angles to attack, but they will likely target the domain controller, which is like a central computer (a server) that manages all other computers, devices and users (credentials) in the AD.

It's essential to monitor events and attribute the right permissions (admins must fine tune access rights and controls) to keep the AD secure. For example, pen-testers like to perform password spraying and other malicious attacks on such service.

Admins can enable features like Security auditing to monitor success and failures. They can also track operations like synchronizations, backups, or migrations.

LDAP means "Lightweight Directory Access Protocol" and is designed for enterprises. It provides a pretty convenient set of commands to query information. Active Directory can implement this protocol to allow interactions with LDAP-based applications.

There are various enumerations and attacks that pen-testers can perform to extract sensitive information from crafted LDAP requests, so admin must ensure it's correctly configured.

## The Windows Registry

### In short

> Registry files are located C:\Windows\System32\Config and contain keys and associated values that control critical functions. For example, UAC (User Account Control) can be deactivated by modifying the value of a specific key in the Windows Registry.

[Source: A quick Journey In The System32](https://jmau111.github.io/2022/11/25/windows-system32-forensics/#basic-forensics)

**It's essential to backup registry entries before any modification**, as the system continually references them during its operations.

The Registry is one of the most critical areas to protect and monitor, as `reg query` commands allows reading and modifying pretty much everything on the system, including security settings. Using a group policy (gpedit.msc > user configuration > system: "prevent access to the registry editing tools") or the Registry itself, you can restrict its access.

It's not the ultimate protection, but it's still an additional layer.

You can use software like [regshot](https://sourceforge.net/projects/regshot/) to take snapshots of the Registry. It's useful to restore the system when it gets unstable, and also valuable for forensic analysis.

### What are the hives?

> A registry hive is a group of keys, subkeys, and values in the registry that has a set of supporting files that contain backups of its data

Most hives[^1] begin with "HKEY" and are on the top of the tree (~ hierarchy). You may find the term "root keys" instead, but it's the same thing. If you open the Registry editor, you'll see the following virtual folders:

* `HKEY_CLASSES_ROOT`: data for applications
* `HKEY_CURRENT_USER`: personal settings of the current logged-in user
* `HKEY_LOCAL_MACHINE`: system settings
* `HKEY_USERS`: settings of all users
* `HKEY_CURRENT_CONFIG`: hardware, drivers

The system does not let you modify their names or locations, as it considers there's no valid reason for that. Inside, you'll find various keys that control different functionalities, system settings, or users' preferences.

The values associated to the keys can be `1` or `O` to enable/disable features but also strings like paths for system binaries.

_N.B.: The editor represents the Registry as a **hierarchical tree**, but it does not reflect their actual locations on the disk._

### Typical Windows commands

Classic attacks often involve `reg query` commands to enumerate specific software (e.g., remote access tools), extract sensitive information, and even modify entries (e.g., abusing ImagePath to point to malicious executables).

[Source: reg query - Microsoft](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-query)

Of course, you can also open the Registry editor by typing "regedit" in the search bar, but it usually requires admin privileges.

More sophisticated attacks can store instructions for malware in registry entries, which allows evading signature-based detection. This can happen after a phishing attack or on a malicious website that leverages JavaScript to trick users into modifying their system.

The ultimate goal is usually to gain persistence, as some hives and keys control the startup (e.g., HKEY_LOCAL_MACHINE).

### How to protect the Registry

There are several ways:

* backup entries regularly
* monitor registry editing
* whitelist allowed software
* restrict access to the editor
* define local group policies to lock keys
* program `reg query` commands to reset keys on startup
* stop using software like ccleaner that can mess up everything (it allows the user to delete keys)

### Practical example: reverse shell

```
reg add "HKLM\SYSTEM\CurrentControlSet\services\regsvc" /t REG_EXPAND_SZ /v ImagePath /d "C:Temp\reverse_shell.exe" /f
```

The above command is a typical attack that attempts to abuse the ImagePath of a system binary to replace it with a malicious one and execute the reverse shell with higher privileges.

The attacker only has to restart the service to make changes effective.

It relies on weak permissions for Registry hives that allows users to modify keys for system components, which can ultimately lead to privilege escalation.

## Windows Mitigations

### Intro

Windows 10 allows configuring additional security measures to mitigate common threats.

For example, Pass-the-Hash or Pass-the-Ticket attacks can be mitigated by virtualization-based security (VBS) and Credential Guard in Enterprise and Server editions. Such attacks are massively used by attackers.

Many CTFs emulate that, but it's not possible, or, at least, extremely hard with such mitigations.

[Source: Windows documentation - mitigate threats](https://learn.microsoft.com/en-us/windows/security/threat-protection/overview-of-threat-mitigations-in-windows-10)

### Mitigation vs. remediation

Both terms are part of risk assessment, but it's not the same concept. Remediation closes security holes and is the best option, but it's not always possible. While mitigations won't address the vulnerabilities, it can buy some time, reducing the likelihood of security flaws being exploited.

### Misknown security features

[Specific functionalities](https://learn.microsoft.com/en-us/windows/security/threat-protection/overview-of-threat-mitigations-in-windows-10#table-3-windows-10-mitigations-to-protect-against-memory-exploits--no-configuration-needed) help mitigate common threats such as memory heap or pool memory exploits.

You can also protect processes from tampering attacks. These mitigations remain quite misknown by most users, admins and developers. If correctly set, it can reduce the attack surface dramatically and contain infections.

Other features include defenses against bootkits, rootkits, fake drivers, viruses and various malware. While this will certainly not stop everything, it can slow down adversaries, at the very least.

### Exploit guard and other mitigation controls

[Exploit Guard](https://learn.microsoft.com/en-us/mem/configmgr/protect/deploy-use/create-deploy-exploit-guard-policy) is the successor to EMET (The Enhanced Mitigation Experience Toolkit) and provides core isolation and advanced kernel protection. Defenders can leverage it to enforce Windows 10 security significantly.

Again, it's not available on all editions, but in a corporate context, it's highly recommended. Some overflows, race conditions, and logic bugs can be mitigated when your turn on core isolation.

As you may already know, the kernel is the head of the system. Everything that runs at that level will have full permissions. That's why it's so important to isolate processes and prevent nasty leaks.

## Security policies

### Introduction

Windows allows you to set [security policies](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/how-to-configure-security-policy-settings) on the local device, on a domain-joined device, and on a domain controller.

Many pre-defined policies are set to "no configuration" by default, but you can change the value and significantly harden your configuration. Just type `secpol.msc` on the start screen. You can also use `gpedit.msc` to modify local group policies. For example, you can use it to force strong passwords for all users.

On Windows 11, you can also type "Local Security Policy" in the search bar. Indeed, there are multiple ways to open the editor.

### Pros and cons

In my experience, Local Security Policy provides an interesting granularity, but it can be overwhelming at the beginning, as there are tons of rules, and labels are not always easy to understand.

Besides, as it's a policy, it can be modified, for example, using Powershell commands to retrieve policies as objects. However, it's not a valid reason to skip such configuration, as you can restrict what users can do significantly.

The good news is you can export/import policies as Windows allows you to save them as `.inf` files.

### A Misknown feature

The vast majority of Windows users, including admins, rely on default policies. However, Windows does not enable many security mechanisms by default ( Windows 11 has a better default strategy, though), which extends the attack suface.

It can prevent some risky behaviors and force good security hygiene.

### Practical examples

Here are a few examples of security rules you can set:

* Disable guest accounts: such accounts are not password-protected, so if you don't need them, set the corresponding policy
* Set password expiration age: force users to renew their passwords regularly
* Set minimum passwords length: secure passwords use various chars, lowercases, uppercases, and numbers, but length is even more critical
* Disable Anonymous SID Enumeration: if you don't need that, just drop the functionality, as hackers will likely try to exploit it 
* Prohibit User Install: you can prevent users from installing third-party software

### Monitor changes

I do not recommend building custom Powershell scripts to monitor GPO changes unless you master your art. Instead, many editions and cloud-based configurations allow you to be alerted of such changes automatically.

It's strongly recommended for AD (Active Directory).

## Mitigate privilege escalations

### A short definition 

Privilege escalation consists of gaining unauthorized privileged access into a system, for example, by hacking an account with high privileges or by elevating the privileges of a classic account.

You may also read the terms "horizontal" and "vertical." The first one refers to classic attacks when attackers impersonate users with similar access level or steal sessions (e.g.: XSS, CSRF). The term "vertical" is used to describe an **elevation**, a.k.a. when you get higher privileges (e.g., root).

### Obvious recommendations

It might look obvious, but the following _reco_ are helpful:

* don't give admin privileges to non-admin roles (least privilege principle)
* don't rely on out-of-the-box roles and default permissions
* update and patch all the things
* disallow unused protocols and remove remote access tools when it's not needed
* disable services with unquoted service paths
* use password manager or PAM (Privileged Access Management) solutions
* force MFA for **all** accounts

### Don't focus on the tools

Many evasion techniques can be used to fool signature-based detection. It's better to put your attention on the results and the behaviors rather than the attacking tools.

Enabling Credential Guard can mitigate credentials thefts seriously. Even if attackers manage to hide evil binaries such as Mimikatz, which is documented, enabling that _fabulous_ `SeDebugPrivilege` capability becomes challenging.

### Remove orphaned and guest accounts

It's not uncommon for attackers to exploit orphaned accounts, especially in Active Directory. Such "ghosts" can be used as a point of entry, as the likelihood of weak password, disabled 2FA/MFA, or default settings tend to increase, and you won't see it coming.

Unless you're a public platform, there's no reason to keep old accounts you may have created "temporarily" for a short period. It's the same with guest accounts that do no require passwords. The scope for such features seems pretty limited.

### Restrict Powershell, don't kill it

Of course, you could disable it completely, but such radical measure usually creates more problems than it solves. Besides, Powershell commands can actually help forensics and incident response. Administrators also use it to automate security tasks.

You can start with a group policy, so non-admin users cannot start the Powershell interpreter. There are documented ways to bypass such restrictions (e.g., [PowerShdll](https://github.com/p3nt4/PowerShdll)), but it's still a good layer to add.

Another approach can consist of whitelisting specific PowerShell scripts only to mitigate the risks. You can reject unsigned scripts and restricting script execution.

Admins must disable and uninstall any deprecated version of Powershell to mitigate abuses like that:

```
PowerShell -Version 2
```

Or classic downgrade attacks and injections powered by [unicorn](https://github.com/trustedsec/unicorn).

Don't forget PowerShell has advanced logging capabilities to record and monitor sensitive commands, like `Invoke`.

### Even more mitigations 🔒

Some situations are more tricky for attackers:

* if app developers use fully qualified path when loading DLLs
* if admins change the ACLs of the folder when system privileges are required
* if admins remove the path entry from the SYSTEM path variable when it's not needed
* if only authorized admins can interact with service changes and target path locations
* if file execution is disabled in user directories (e.g., downloads, tmp)
* if `AlwaysInstallElevated` policy is set to disabled [^2] (as you woud expect by default)
* if standard users do no have write permissions in the Registry

[Source: Microsoft - Dynamic-Link Security](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-security?redirectedfrom=MSDN)


## Best resources

* [Attacking AD](https://zer1t0.gitlab.io/posts/attacking_ad/)
* [PayloadsAllTheThings - Windows](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
* [Windows Privesc resources](https://www.willchatham.com/security/windows-privilege-escalation-privesc-resources/)
* [PowerShell loves the Blue Team](https://devblogs.microsoft.com/powershell/powershell-the-blue-team/)
* [Fuzzy Security - Windows Privesc](https://fuzzysecurity.com/tutorials/16.html)
* [Windows local privilege escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
* [Windows Defender review 2022](https://www.comparitech.com/antivirus/reviews/windows-defender-review/)

[^1]: the term "hive" is supposedly a dev's joke (easter egg), as one of the developers hated bees 

[^2]: it's no uncommon to find the value set to `1` in [vulnerable] machines configured for CTFs, but if your machine has the same configuration, it's a massive risk. Check values in HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer and HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer.
