---
layout: post
title:  "Digging for secrets on corporate shares"
date:   2023-01-23 09:00:00
excerpt: "Sometimes during red team engagements there is no obvious path to escalate and the only way to move forward is to perform an evaluation of the filesystem and network shares. This article discusses how to perform such evaluation efficiently to find the needles in the haystack."
categories: powershell windows
permalink: /blog/digging-for-secrets
---

*[COM]: Component Object Model
*[WMI]: Windows Management Instrumentation

You will probably recognize the situation that during a red team you run into the event where it _was_ possible to get an initial foothold, however there are no obvious paths to escalate/move from there.

In those situations, the only feasible way forward is to plow through the machine's filesystems and any reachable shares like the domain controller's SYSVOL share or company shared drives. These locations often contain scripts, logs, documents and files in which frequently also sensitive information like credentials and tokens are stored. Manually browsing through the directories however takes a lot of time and it is easy to overlook something.

In this blogpost I will expand on several methods that exist to efficiently work through directory listings and search for interesting files. Additionally, I am releasing a .NET tool called **Dir2json** to expand on these methods in an OPSEC friendly way.

# Searching the directory structure
Besides manually going through the directory structure there are various ways to more easily search for potentially interesting files which can subsequentially manually be collected. In the examples below the C-drive is recursively searched for files with the `.kdb` and `.kdbx` (KeePass password database) file extension and files that contain the `password` string in the filename. This search string can be expanded to include many patterns to identify potentially interesting files. Moreover, in the examples only the full path is outputted, but other attributes like the file size and last modified date can also be shown.

## Command Prompt (cmd.exe)
Use the dir command to search for one or more patterns to identify files on disk. The output can also be redirected to a file by appending `> file.txt`. More examples of searching using dir can be found in the `localrecon.cmd` script on the BITSADMIN GitHub, a script I created back when I was working on the OSCP lab[^1].
```bash
dir /S /B /A C:\*.kdb* C:\*password*
```

| Parameter | Meaning  |
| --------- | -------- |
| `/S`      | Search recursively |
| `/B`      | Show in bare format |
| `/A`      | Include hidden and system folders |

## PowerShell
Use the `Get-ChildItem` cmdlet to search for files where the `-Force` parameter makes sure that also hidden and system files are included. Unauthorized access exceptions can be hidden by appending `-ErrorAction SilentlyContinue` (shorthand: `-ea 0`) to the `Get-ChildItem` cmdlet parameters. The output can be redirected to a file by piping to `Out-File file.txt`.
```powershell
Get-ChildItem -Path C:\ -Recurse -Force -Include *.kdbx,*password* | Select-Object -ExpandProperty FullName
```

## Windows Management Instrumentation (WMI)
In this example PowerShell is used to perform the WMI queries, but any language that is able to interface with WMI is able to perform such query. The advantage of WMI is that using the `-ComputerName` or `-CimSession` parameters such queries can also be performed against remote machines of which only port 135/TCP (RPC) is accessible (or 5985/TCP / 5986/TCP when used over WinRM), meaning port 445/TCP (Microsoft-DS) is not required for enumeration. Administrative privileges on the remote machine are required though. More information on remotely interacting with WMI can be found in this blog post[^2]. To search in a specific folder the `Path Like 'C:\\Users\\%'` condition can be added to the query. Moreover, besides the `CIM_LogicalFile` class also the `CIM_DataFile` class can be used.
```powershell
Get-CimInstance -Query "Select * from CIM_LogicalFile Where Drive='C:' And ((Extension Like 'kdb%') Or (FileName Like '%password%'))" | Select-Object -ExpandProperty FullName
```

## Component Object Model (COM)
This option is not directly feasible for quick filesystem enumeration, however when turned into code which recurses the directory structure, it could also be used. A PowerShell snippet to search the filesystem using COM is added here for completeness, but like with WMI, any language that is able to interface with COM could be used to enumerate the filesystem.
```powershell
$o = New-Object -ComObject Scripting.FileSystemObject
$c = $o.GetDrive('C').RootFolder
Function Search-Folder
{
    Param($folder)
    $folder.Files | Where-Object Name -Match $filter
    $folder.SubFolders | ForEach-Object { Search-Folder $_ }
}
$filter = '.*(password|\.kdb).*'
Search-Folder $c | Select-Object -ExpandProperty Path
```

## Summary and limitations
Besides using the various interfaces Windows offers to query the filesystem, another option is to directly access the NTFS Master File Table (MFT). In this blog this option is not considered as the assumption is that one is in a low-privileged context.

Although all aforementioned approaches work to identify files on the filesystem, they have various limitations:
* Whenever you want to perform another search query, the full filesystem needs to be iterated again;
* If based on the results you want to list the other files in the directory of the respective file, interaction with the target (file)system is required again.
 
The next section discusses an alternative approach to searching the directory structure.

# Build directory tree using PowerShell
Instead of searching through the directory structure for a specific pattern, another option is to create a (one-time) file listing which, in addition to the file name and path, also contains information like the file size, modification date and mode flags. This tree can subsequentially be pulled to the attacker's system and queried offline in various ways. No further interaction with the target system will be required anymore until the moment a file has been identified which you as the attacker want to analyze further. This specific file can then be downloaded and further evaluated offline. Because Windows can have issues with long paths, some tweaks have been added to different ways of collection that deal with long paths correctly.

Windows PowerShell is preinstalled on all Windows versions starting from Windows 7 SP1/2008 R2 SP1 and runs up to version number 5.1. Besides Windows PowerShell there is also PowerShell Core which is built on the .NET Core framework and therefore in addition to Windows, also runs Linux and Mac operating systems and can be obtained from [https://aka.ms/pscore6](https://aka.ms/pscore6). The first PowerShell Core version is version 6.0 and can be installed separately. The two editions of PowerShell are mostly similar but have some minor differences resulting in slightly different commandlines for enumeration.

## Windows PowerShell
The following commandline creates a file listing of the `C:\` drive and stores it in the `Drive_C.csv` file. The DOS path syntax (`\\?\`) is used to avoid running into issues with long file paths. In case a file listing of a network share needs to be created, use the `\\?\UNC\MYSERVER\MyShare` value for the `-LiteralPath` parameter. Additionally, update the `\\?\` value to `\?\UNC` in the `$_.FullName.Replace('\\?\','')` code. Unless when logic is built into a script, Windows PowerShell does not support avoiding symlinked directories. Such directories can be dangerous because they can be self-referencing and therefore lead to infinite recursion. In the oneliner below the maximum depth is set to 25 which should be sufficient in most cases to collect all relevant files and folders, however if needed this number can be increased, or replaced with the `-Recurse` parameter to allow for infinite recursions.

```powershell
Get-ChildItem -LiteralPath '\\?\C:\' -Depth 25 -Force | ForEach-Object { [PSCustomObject]@{Name=$_.Name; Mode=$_.Mode; Length=$_.Length; LastWriteTime=$_.LastWriteTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'); FullName=$_.FullName.Replace('\\?\','') } } | Export-Csv -Encoding UTF8 -NoTypeInformation Drive_C.csv
```

## PowerShell Core
Even though the Windows PowerShell oneliner can also be used in PowerShell Core, the PowerShell Core onlineliner is slightly shorter and looks a bit cleaner. In contrast to Windows PowerShell, PowerShell Core does not enter into directory symlinks by default. This behavior can be changed by adding the `-FollowSymlink` flag to the `Get-ChildItem` cmdlet. Moreover, PowerShell Core also natively deals well with long paths, so no DOS path syntax needs to be used. Like with Windows PowerShell, the `-Depth X` parameter can be used instead of `-Recurse` to limit the depth of enumeration.

```powershell
Get-ChildItem -Path 'C:\' -Recurse -Force | ForEach-Object { [PSCustomObject]@{Name=$_.Name; Mode=$_.Mode+'-'; Length=$_.Length; LastWriteTime=$_.LastWriteTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'); FullName=$_.FullName } } | Export-Csv -NoTypeInformation Drive_C.csv
```

In many occasions the PowerShell oneliners will be sufficient for collecting the filesystem trees. In some cases however, a stealthy approach is required and the execution of PowerShell (or load of `System.Management.dll`) might trigger alarms. In the next section the newly developed **Dir2json** tool is discussed which allows for stealthy collection.

# Dir2json
Dir2json is a tool I wrote when I noticed the need for a stealthy tool which from the memory of a Cobalt Strike infection is able to create a directory listing, and without touching the disk send the results back to the Cobalt Strike Team Server. Initially I developed a C++ version of the tool to practice the knowledge obtained in Pavel Yosifovich' (@zodiacon) Windows System Programming course. This tool works well, but then I realized it was not possible to easily turn this into a Beacon Object File (BOF). For that reason instead of fixing the C++ tool to make it work as a BOF I rewrote the Dir2json tool in C# which allows for in-memory execution and file download thanks to Ceri Coburn's (@_EthicalChaos_) BOF.NET project[^3]. Additionally, the project can also be compiled and executed as a regular .NET executable. The C# version of Dir2json is available at [https://github.com/bitsadmin/dir2json/](https://github.com/bitsadmin/dir2json/). The video below shows how to execute the tool from Cobalt Strike.

<video width="740" height="430" controls>
  <source src="/assets/img/20230323_efficient-directory-enumeration/cobaltstrike.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

## In-memory execution
Because the tool runs in-memory and does not (like the PowerShell oneliners) directly flush the identified files and folders to disk, it initially needs to store the full directory listing in memory before sending it back to the Cobalt Strike Team Server. For that reason, instead of storing the full paths of the identified items, it builds up a tree structure where subfolders and -files are linked to its parent folder. When the download of the tree is triggered, the tree is serialized to JSON, gzip compressed, and then sent back to the Cobalt Strike Team Server. Because the Dir2json tool might be executed on machines that are tight on memory, or against drives or shares which contain millions of files, it also provides an option (`/EntriesPerFile=X`) to flush the memory every `X` thousand items collected and download the partial results to the Team Server. Finally, Dir2json can be instructed to follow symbolic links using the `/FollowSymlinks` parameter which can be used in combination with the `/MaxDepth=Y` parameter to restrict recursion to a maximum of `Y` directories, with that avoiding possible infinite recursions.

## JSON to CSV
As it is not very easy to search through JSON, the Dir2json repository contains the `Json2csv.ps1` PowerShell script which takes the `.json`(`.gz`) file(s) as input, if needed decompresses it, and then stores the output into a `.csv` output file. In case the first file of a split Dir2json file is provided as input, the tool also immediately merges them back to a single `.csv` output file. Because the script can also be executed with PowerShell Core, it is also compatible with non-Windows operating systems.

## Statistics
To get a better feeling of usage of the different tools, some statistics of execution. The tests have been executed against my laptop with an SSD which contains a combined 1.2 million files and folders entries.

| Tool               | Duration | Output file | Size   |
| ------------------ | -------: | ----------- | -----: |
| Windows PowerShell |   02:30m | `.csv`      | 255 MB |
| PowerShell Core    |   03:20m | `.csv`      | 245 MB |
| Dir2json           |      20s | `.json.gz`  |  13 MB |

In both PowerShell versions, enumeration takes between 2.5 and 3.5 minutes while for Dir2json enumeration takes just 20 seconds. Regarding Windows PowerShell and PowerShell Core one would expect they yield exactly the same results, however because the Windows PowerShell oneliner does not avoid symbolic links, in Windows PowerShell folders inside of symlinked directories are listed while in PowerShell Core these directories are avoided. This for example happens for the `C:\Users\All Users` directory which is a symlink to `C:\ProgramData` where in case of Windows PowerShell these files are listed twice in the resulting `.csv`.

As mentioned before, to convert the `.json.gz` file to a `.csv` using the `Json2csv.ps1` script, either Windows PowerShell or PowerShell Core can be used. The table below shows that, although it uses 1.5 times more memory, PowerShell Core converts the file 5x faster compared to Windows Powershell. Once the `.json.gz` file has been converted, the `.csv` contains exactly the same data as the one created by the PowerShell Core oneliner.

| Tool               | Duration | Max. memory usage |
| ------------------ | -------: | ----------------- |
| Windows PowerShell |   10:00m | 2.7 GB            |
| PowerShell Core    |   02:00m | 4.2 GB            |

The next sections will take the `.csv` file created by either PowerShell or Dir2json + Json2csv tool as an input and discuss the different ways PowerShell can import the data and query it to find interesting files.

# Importing csv into PowerShell
There are various ways to query data in a `.csv` file, from using `grep` and `awk` in Linux to parsing the data using Python. In this section PowerShell's powerful functionality for dealing with structured data will be discussed. Even though in this article going through the `.csv` using Linux commands is not discussed, examples on how to perform equivalent queries are available in the Dir2json repository in the `CheatSheet.sh` file. 
 
PowerShell has native support for importing `.csv` files using the `Import-Csv` cmdlet. During importing it is also possible to enrich the imported data in various ways which, at the expense of an increased loading time and memory usage, improves querying the dataset significantly once it has loaded. The following paragraphs discuss the advantages of the different import methods, where each of the methods builds upon the previous one adding additional attributes.
 
**D0: Plain CSV**

The plain import is by far the quickest and allows for wildcard searches in the `FullPath` attribute. It however lacks to possibility to perform smart queries.

**D1: Length attribute as integer**

When using the `Import-Csv` cmdlet, PowerShell simply considers all column values as strings. This means that when for example sorting and filtering based on file sizes, the digits will be sorted in an alphabetical way instead of the expected order (e.g. `1`,`10`,`2`,`3` instead of `1`,`2`,`3`,`10`). Forcing conversion of the string to a 64-bit integer will increase import time and memory usage, however result in a better usable data set.

**D2: Extension attribute**

As based on the file extension it is easy to quickly identify interesting files, another useful attribute to have that attribute prepared. The .NET framework which can be accessed from PowerShell has built-in functionality to obtain the extension based on a filename using the static `GetExtension` method in the `System.IO.Path` namespace. Because the function does not have any other input than the name string and a directory which contains a period can also be confused to be a file with an extension, the **D2** oneliner contains a check to make sure the item is not a directory.

**D3: Depth attribute**

Because in the `.csv` the hierarchical structure has been flattened, it is more challenging to list the files in a specific directory which in turn also has subdirectories. To be able to list the files and folders in a specific folder without also listing the subfolders, the `Depth` attribute can be used. In the **D3** import oneliner the `FullName` attribute which contains the full path and filename of the file or directory is split by the directory separator character (backslash - `\`) and the number of directories is counted to determine the depth.

**D4: Mode attributes**

A final option is to also translate the Mode string attribute into multiple boolean values to be able to filter on those attributes as well. In practice when searching for interesting files to identify credentials, the Mode attribute is less relevant, and both the import time is 1.7 times significantly longer compared to **D3** and memory usage also increases by 60% so generally importing using **D3** provides sufficient attributes. Moreover, the mode attribute can still be filtered despite it being a string.
 
The statistics in the table below have been generated making use of PowerShell Core while importing the 1.2 million-record `.csv` file created earlier.

| #  | Features                                                   | Command                                                        | Import time | Memory usage |
| -- | ---------------------------------------------------------- | -------------------------------------------------------------- | ----------: | -----------: |
| D0 | Plain CSV                                                  | `$csv = Import-Csv Drive_C.csv`                                | 10s         | 1.9 GB       |
| D1 | D0 + CSV with Length converted to integer                  | `$csv = Import-Csv Drive_C.csv | Select-Object Name,@{n='Length';e={[int64]$_.Length}},Mode,LastWriteTime,FullName` | 01:56m      | 2.9 GB       |
| D2 | D1 + Extension attribute                                   | `$csv = Import-Csv Drive_C.csv | Select-Object Name,@{n='Length';e={[int64]$_.Length}},Mode,LastWriteTime,FullName,@{n='Extension';e={if($_.Mode[0] -ne 'd'){[System.IO.Path]::GetExtension($_.Name)}else{''}}}` | 02:23m      | 3.5 GB       |
| D3 | D2 + Depth attribute                                       | `$csv = Import-Csv Drive_C.csv | Select-Object Name,@{n='Length';e={[int64]$_.Length}},Mode,LastWriteTime,FullName,@{n='Extension';e={if($_.Mode[0] -ne 'd'){[System.IO.Path]::GetExtension($_.Name)}else{''}}},@{n='Depth';e={$_.FullName.Split('\').Count - 1}}` | 02:49m      | 3.8 GB       |
| D4 | D3 + Mode attribute all converted to individual attributes | `$csv = Import-Csv Drive_C.csv | Select-Object  Name,@{n='Length';e={[int64]$_.Length}},Mode,LastWriteTime,FullName,@{n='Extension';e={if($_.Mode[0] -ne 'd'){[System.IO.Path]::GetExtension($_.Name)}else{''}}},@{n='Depth';e={$_.FullName.Split('\').Count - 1}},@{n='Directory';e={$_.Mode[0] -eq 'd'}},@{n='Archive';e={$_.Mode[1] -eq 'a'}},@{n='ReadOnly';e={$_.Mode[2] -eq 'r'}},@{n='Hidden';e={$_.Mode[3] -eq 'h'}},@{n='System';e={$_.Mode[4] -eq 's'}},@{n='ReparsePoint';e={$_.Mode[5] -eq 'l' -or $_.Mode[0] -eq 'l'}}` | 04:47m      | 6.1 GB       |

# Querying using PowerShell
After the directory listing has been imported, it is available in the `$csv` variable. PowerShell supports a lot of filtering, sorting, grouping and data manipulation features, which we can use to quickly get a good insight into the file system or share that has been enumerated. In this section for most queries the requirement is that the data has been imported using the **D3** (or even more extensive **D4**) oneliner.

To be able to systematically evaluate the output, the command can also be piped to the `Out-Host -Paging` command (shorthand: `oh -p`) or stored in a `.csv` file by piping it to the `Export-Csv` cmdlet). For some more information on the usage the `Export-Csv` cmdlet, check out the Cypher query tools section of the Dealing with large BloodHound datasets blog post[^4].

<video width="740" height="430" controls>
  <source src="/assets/img/20230323_efficient-directory-enumeration/powershell.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

## Statistics
Some numbers to give an idea of how large the dataset is.

| Query                   | Long                                                         | Short                                                   | Notes                                                        |
| ----------------------- | ------------------------------------------------------------ | ------------------------------------------------------- | ------------------------------------------------------------ |
| Total number of entries | `$csv | Measure-Object | Select-Object -ExpandProperty Count` | `$csv | Measure | % Count`                              | `%` is an alias for `ForEach-Object`. In this case it iterates over the  output of `Measure-Object` (which is only a single entry) and displays the `Count` attribute. |
| Number of files         | `$csv | Where-Object Mode -NotMatch 'd.....' | Measure-Object | Select-Object -ExpandProperty Count` | `$csv | ? Mode -NotMatch 'd.....' | Measure | % Count` | `?` is an alias for `Where-Object`. In case import method **D4** has been used, the `Where-Object` can also simply look as follows: `? -not Directory`. |
| Number of directories   | `$csv | Where-Object Mode -Match 'd.....' | Measure-Object | Select-Object  -ExpandProperty Count` | `$csv | ? Mode -Match 'd.....' | Measure | % Count`    | In case import method **D4** has been used, the `Where-Object` can also simply  look as follows: `? Directory`. |

## Extensions
As mentioned before, file extensions can be very useful to identify potentially interesting files. 

| Query                          | Long                                                         | Short                                                        |
| ------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| Compile list of top extensions | `$exts = $csv | Group-Object Extension -NoElement | Sort-Object -Descending Count,Name` | `$exts = $csv | group Extension -NoElement | sort -Desc Count,Name` |
| Show list of top 25 extensions | `$exts | Select-Object -First 25 | Format-Table Name,Count` | `$exts | select -First 25 | ft Name,Count`                   |

Example output
```powershell
PS C:\> $exts = $csv | Group-Object Extension -NoElement | Sort-Object -Descending Count,Name
PS C:\> $exts | Format-Table Name,Count | Out-Host -Paging
 
Name        Count
----        -----
           189583
.dll        94405
.manifest   82083
.mui        50736
.cat        46573
.mum        43343
.js         22687
.png        16834
.pyc        15442
.xml        12666
.exe        12101
.py         10394
.rtf         9705
.go          8900
<SPACE> next page; <CR> next line; Q quit
```

**Admin file extensions**

Some extensions are specifically interesting to investigate if the objective is to locate sensitive information for use of escalation or lateral movement. To get an overview of which extensions related to administrators are present on the system, the following two lines can be used.

```powershell
PS C:\> $admin = $csv | Where-Object Extension -Match '^\.(kdbx?|pfx|p12|pem|p7b|key|ppk|crt|pub|config|cfg|ini|sln|\w{2}proj|sql|cmd|bat|ps1|vbs|log|rdp|rdg|ica|wim|vhdx?|vmdk)$'
PS C:\> $admin | Group-Object Extension -NoElement | Sort-Object -Descending Count,Name | Format-Table Name,Count | Out-Host -Paging
 
Name    Count
----    -----
.ps1     1037
.config   476
.ini      302
.sql      130
.log      158
.pem      123
.cmd      111
.bat       96
.vbs       84
.p7b       53
.cfg       47
.wim       22
.crt       20
.sln       15
.kdbx       1
<SPACE> next page; <CR> next line; Q quit
```

In case of common admin extensions, the paths need to be evaluated and filtered further in order to get to the files that seems relevant. Examples of such queries are.

| Query                                                        | Command                                                      |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| List admin files from most recent to oldest                 | `$admin | Sort-Object -Descending LastWriteTime | Format-Table  LastWriteTime,Length,FullName` |
| Files with the .cmd extension, not located in the `Program Files` folders nor in the `Windows` directory | `$admin | Where-Object Extension -EQ '.cmd' | Where-Object FullName -NotMatch 'C:\\(Program Files|Windows).*' | Format-Table  FullName,Length,LastWriteTime,Mode` |

**Office file extensions**

Like with the admin extensions, office extensions can also be interesting if you are looking for specific information stored in documents and text files.

| Query                                         | Command                                                      |
| --------------------------------------------- | ------------------------------------------------------------ |
| Collect office documents and related files    | `$office = $csv | Where-Object Extension -Match '^\.((doc|xls|ppt|pps|vsd)[xm]?|txt|csv|one|pst|url|lnk)$'` |
| Store all details of the found files to a csv | `$office | Sort-Object FullName | Select-Object FullName,Length,LastWriteTime,Mode | Export-Csv -NoTypeInformation C:\Tmp\office_files.csv` |

Additional interesting admin and office file extensions can be found at [https://filesec.io/](https://filesec.io/). Once the list of file paths and details are saved, one can systematically work through the list and the download potentially interesting files for further analysis.

## Browse folders
Because we have the full directory listing at our disposal and during the import the `Depth` attribute has been calculated, it is also possible to list directories to better understand the directory structure and sizes of folders.

```powershell
PS C:\> $csv | Where-Object Depth -EQ 1 | Where-Object FullName -Like 'C:\*' | Format-Table -AutoSize Mode,LastWriteTime,Length,Name
 
Mode   LastWriteTime                   Length Name
----   -------------                   ------ ----
d--hs- 2022-11-08T21:57:12.893547Z          1 $Recycle.Bin
d----- 2023-02-02T22:13:33.703302Z          1 Install
-a-hs- 2023-01-27T14:11:55.974858Z 5905580032 pagefile.sys
d----- 2019-12-07T09:14:52.147417Z          1 PerfLogs
d-r--- 2022-12-02T17:02:34.260006Z          1 Program Files
d-r--- 2022-11-04T21:14:26.375868Z          1 Program Files (x86)
d--h-- 2022-12-02T12:33:08.733117Z          1 ProgramData
d--hs- 2022-11-08T21:57:19.553494Z          1 Recovery
-a-hs- 2023-01-27T14:11:56.639391Z   16777216 swapfile.sys
d--hs- 2022-11-03T18:43:34.085655Z          1 System Volume Information
d-r--- 2022-11-03T18:30:48.610580Z          1 Users
d----- 2023-01-26T22:03:45.756666Z          1 Windows
 
PS C:\> $csv | Where-Object Depth -EQ 2 | Where-Object FullName -Like 'C:\Users\*' | Format-Table -AutoSize Mode,LastWriteTime,Length,Name
 
Mode   LastWriteTime               Length Name
----   -------------               ------ ----
d-rh-- 2022-12-01T22:42:21.545340Z      1 Default
-a-hs- 2019-12-07T09:12:42.731564Z    174 desktop.ini
d-r--- 2022-11-02T21:58:06.552554Z      1 Public
d----- 2022-11-04T21:37:32.159099Z      1 bitsadmin
 
PS C:\> ($csv | Where-Object FullName -Like 'C:\Install\*' | Measure-Object -Sum Length).Sum / 1MB
513.31
 
PS C:\>
```

# Future work
Because the `.csv` data structure is not optimized for browsing the filesystem like this I started working on a PowerShell provider[^5] that would allow to load the `.json` collected using Dir2json and expose a drive (e.g. `d2j:\C\Users\`) to browse, recurse (`Get-ChildItem -Recurse`) and filter the filesystem using the native PowerShell functions through the hierarchical structure. Building such provider however took more time than I anticipated so hereby I am dropping the idea with you in case you want to practice writing C# code and learning about PowerShell internals 😊.

Another nice programming challenge would be to implement enumeration of SharePoint environments. This would be relevant because besides filesystem drives and network shares nowadays an increasing amount of information is stored on SharePoint environments. Classes and functions from the `Microsoft.SharePoint.Client` namespace appears to be a good start to implement this functionality in C#.


# Conclusion
Instead of searching for specific files, a much more efficient method is to perform a one-time collection of the directory listing and then query the file offline through PowerShell for interesting files. Either a PowerShell oneliner can be used to perform the collection, or the Dir2json tool which allows through in-memory execution through BOF.NET in Cobalt Strike.

Analysis of the resulting csv containing the directory structure can be performed effectively using PowerShell's filtering, grouping and sorting functions, and any interesting files identified can be downloaded and investigated. The PowerShell queries discussed above and various other queries can be found in the `CheatSheet.ps1` file in the Dir2json GitHub repository.

# References
[^1]: [BITSADMIN GitHub: Miscellaneous](https://github.com/bitsadmin/miscellaneous)
[^2]: [BITSADMIN Blog: Extracting credentials from a remote Windows system](https://blog.bitsadmin.com/blog/extracting-credentials-from-remote-windows-system)
[^3]: [CCob GitHub: BOF.NET](https://github.com/CCob/BOF.NET)
[^4]: [BITSADMIN Blog: Dealing with large BloodHound datasets](https://blog.bitsadmin.com/blog/dealing-with-large-bloodhound-datasets#cypher-query-tools)
[^5]: [Microsoft Learn: PowerShell Providers](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_providers)
