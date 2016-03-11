<#
.SYNOPSIS
    PowerShell script to setup a complete web server on Windows Server 2012 R2. 
.DESCRIPTION
    PowerShell script to setup a complete web server on Windows Server 2012 R2. This includes installing
    and configuring IIS, FTP, PHP, MySQL and creating a website and FTP site.
.NOTES
    Author   : Ingvald Belmans
    Website  : http://www.supersysadmin.com
    Version  : 1.0 
    Changelog:
        - 1.0 (2016-03-11) Initial version.
.LINK
    http://www.supersysadmin.com
#>

####################################################################################################
### 01: Create Base Directory Structure ############################################################
####################################################################################################

# Variables.
$BaseDirectory = "C:\BASE"
$AppDirectory = "$BaseDirectory\APP"
$SrcDirectory = "$BaseDirectory\SRC"

# Create BASE directory.
New-Item -ItemType Directory -Path $BaseDirectory

# Remove NTFS inheritance from the BASE directory.
$ACL = Get-Acl -Path $BaseDirectory
$ACL.SetAccessRuleProtection($True,$True)
Set-Acl -Path $BaseDirectory -AclObject $ACL

# Remove all NTFS permissions from the BASE directory, except Administrators.
$ACL = Get-Acl -Path $BaseDirectory
$ACL.Access | Where-Object -FilterScript {$_.IdentityReference -notlike "*Administrators*"} | ForEach-Object -Process {$ACL.RemoveAccessRule($_)}
Set-Acl -Path $BaseDirectory -AclObject $ACL

# Add SYSTEM with Full Control NTFS permissions to the BASE directory.
$ACL = Get-Acl -Path $BaseDirectory
$NTAccount = New-Object System.Security.Principal.NTAccount("SYSTEM") 
$FileSystemRights = [System.Security.AccessControl.FileSystemRights]"FullControl"
$InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
$PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None 
$AccessControlType =[System.Security.AccessControl.AccessControlType]::Allow
$UserPermissions = $NTAccount,$FileSystemRights,$InheritanceFlags,$PropagationFlags,$AccessControlType
$AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $UserPermissions
$ACL.SetAccessRule($AccessRule)
$ACL | Set-Acl -Path $BaseDirectory

# Create the APP and SRC directories.
New-Item -ItemType Directory -Path $AppDirectory
New-Item -ItemType Directory -Path $SrcDirectory

####################################################################################################
### 02: Install IIS/FTP ############################################################################
####################################################################################################

# Variables.
$IISDirectory = "$AppDirectory\IIS"
$URLRewriteDownloadLocation = "http://go.microsoft.com/?linkid=9722532"
$URLRewritePackage = "rewrite_2.0_rtw_x64.msi"

# Install IIS.
Install-WindowsFeature -Name Web-Default-Doc, Web-Dir-Browsing, Web-Http-Errors, Web-Static-Content, Web-Http-Redirect, Web-Http-Logging,`
    Web-Stat-Compression, Web-Dyn-Compression, Web-Filtering, Web-Basic-Auth, Web-Net-Ext, Web-Net-Ext45, Web-Asp-Net, Web-Asp-Net45,`
    Web-CGI, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Mgmt-Console

# Install FTP Server.
Install-WindowsFeature -Name Web-Ftp-Server, Web-Ftp-Service

# Create IIS directory.
New-Item -ItemType Directory -Path $IISDirectory

# Download URL Rewrite.
Invoke-WebRequest -Uri $URLRewriteDownloadLocation -OutFile $SrcDirectory\$URLRewritePackage

# Install URL Rewrite.
Start-Process -FilePath "$SrcDirectory\rewrite_2.0_rtw_x64.msi" -ArgumentList "/qn" -Wait

# Remove Default Web Site.
Remove-Website -Name "Default Web Site"

# Remove default Application Pools.
Remove-WebAppPool -Name ".NET v2.0"
Remove-WebAppPool -Name ".NET v2.0 Classic"
Remove-WebAppPool -Name ".NET v4.5"
Remove-WebAppPool -Name ".NET v4.5 Classic"
Remove-WebAppPool -Name "Classic .NET AppPool"
Remove-WebAppPool -Name "DefaultAppPool"

####################################################################################################
### 03: Install PHP ################################################################################
####################################################################################################

# Variables.
$VisualStudioRedistributableDownloadLocation = "https://download.microsoft.com/download/9/3/F/93FCF1E7-E6A4-478B-96E7-D4B285925B00/vc_redist.x64.exe"
$VisualStudioRedistributablePackage = "vc_redist.x64.exe"
$PHPDirectory = "$AppDirectory\PHP"
$PHPSessionDirectory = "$PHPDirectory\session"
$PHPUploadDirectory = "$PHPDirectory\upload"
$PHPLogDirectory = "$PHPDirectory\log"
$PHPUserGroup = "PHP Users"
$PHPDownloadLocation = "http://windows.php.net/downloads/releases/php-7.0.4-nts-Win32-VC14-x86.zip"
$PHPPackage = "php-7.0.4-nts-Win32-VC14-x86.zip"
$PHPDefaultDocument = "index.php"
$PHPErrorLogFile = "error.log"

# Download Visual C++ Redistributable for Visual Studio 2015 x64.
Invoke-WebRequest -Uri $VisualStudioRedistributableDownloadLocation -OutFile $SrcDirectory\$VisualStudioRedistributablePackage

# Install Visual C++ Redistributable for Visual Studio 2015 x64.
Start-Process -FilePath $SrcDirectory\$VisualStudioRedistributablePackage -ArgumentList "/q /norestart" -Wait

# Create the PHP directory structure.
New-Item -ItemType Directory -Path $PHPDirectory
New-Item -ItemType Directory -Path $PHPSessionDirectory
New-Item -ItemType Directory -Path $PHPUploadDirectory
New-Item -ItemType Directory -Path $PHPLogDirectory

# Create the PHP Users local Windows group.
$LocalAccountDB = [ADSI]"WinNT://$env:ComputerName"
$CreateGroupPHPUsers = $LocalAccountDB.Create("Group","$PHPUserGroup")
$CreateGroupPHPUsers.SetInfo()
$CreateGroupPHPUsers.Description = "Members of this group can use PHP on their website"
$CreateGroupPHPUsers.SetInfo()

# Set Read/Execute NTFS permissions for the group PHP Users on the PHP directory.
$ACL = Get-Acl -Path $PHPDirectory
$NTAccount = New-Object System.Security.Principal.NTAccount("$PHPUserGroup") 
$FileSystemRights = [System.Security.AccessControl.FileSystemRights]"ReadAndExecute"
$InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
$PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None 
$AccessControlType =[System.Security.AccessControl.AccessControlType]::Allow
$UserPermissions = $NTAccount,$FileSystemRights,$InheritanceFlags,$PropagationFlags,$AccessControlType
$AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $UserPermissions
$ACL.SetAccessRule($AccessRule)
$ACL | Set-Acl -Path $PHPDirectory

# Set Modify NTFS permissions for PHP Users on the session directory.
$ACL = Get-Acl -Path $PHPSessionDirectory
$NTAccount = New-Object System.Security.Principal.NTAccount("$PHPUserGroup") 
$FileSystemRights = [System.Security.AccessControl.FileSystemRights]"Modify"
$InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
$PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None 
$AccessControlType =[System.Security.AccessControl.AccessControlType]::Allow
$UserPermissions = $NTAccount,$FileSystemRights,$InheritanceFlags,$PropagationFlags,$AccessControlType
$AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $UserPermissions
$ACL.SetAccessRule($AccessRule)
$ACL | Set-Acl -Path $PHPSessionDirectory

# Set Modify NTFS permissions for PHP Users on the upload directory.
$ACL = Get-Acl -Path $PHPUploadDirectory
$NTAccount = New-Object System.Security.Principal.NTAccount("$PHPUserGroup") 
$FileSystemRights = [System.Security.AccessControl.FileSystemRights]"Modify"
$InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
$PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None 
$AccessControlType =[System.Security.AccessControl.AccessControlType]::Allow
$UserPermissions = $NTAccount,$FileSystemRights,$InheritanceFlags,$PropagationFlags,$AccessControlType
$AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $UserPermissions
$ACL.SetAccessRule($AccessRule)
$ACL | Set-Acl -Path $PHPUploadDirectory

# Set Modify NTFS permissions for PHP Users on the log directory.
$ACL = Get-Acl -Path $PHPLogDirectory
$NTAccount = New-Object System.Security.Principal.NTAccount("$PHPUserGroup") 
$FileSystemRights = [System.Security.AccessControl.FileSystemRights]"Modify"
$InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
$PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None 
$AccessControlType =[System.Security.AccessControl.AccessControlType]::Allow
$UserPermissions = $NTAccount,$FileSystemRights,$InheritanceFlags,$PropagationFlags,$AccessControlType
$AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $UserPermissions
$ACL.SetAccessRule($AccessRule)
$ACL | Set-Acl -Path $PHPLogDirectory

# Create the PHP log file.
New-Item -ItemType File -Path "$PHPLogDirectory\$PHPErrorLogFile"

# Download the PHP Non Thread Safe .zip package (x64).
Invoke-WebRequest -Uri $PHPDownloadLocation -OutFile "$SrcDirectory\$PHPPackage"

# Extract the .zip file to the PHP directory. In PowerShell 5 (Windows 10, Windows Server 2016) we have the Expand-Archive cmdlet for this,
# but since there is no production version yet of PowerShell 5 for previous operating systems, we use .NET for this.
Add-Type -AssemblyName "system.io.compression.filesystem"
[io.compression.zipfile]::ExtractToDirectory("$SrcDirectory\$PHPPackage", $PHPDirectory)

# Add the PHP installation directory to the Path environment variable.
$CurrentPath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).PATH
$NewPath = $CurrentPath + ";$PHPDirectory\"
Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $NewPath

# Create a Handler Mapping for PHP.
New-WebHandler -Name "PHPFastCGI" -Path "*.php" -Modules FastCgiModule -ScriptProcessor "$PHPDirectory\php-cgi.exe" -Verb 'GET,HEAD,POST' -ResourceType Either

# Configure FastCGI Settings for PHP.
Add-WebConfiguration -Filter /system.webServer/fastCgi -PSPath IIS:\ -Value @{fullpath="$PHPDirectory\php-cgi.exe"}

# Add index.php to the Default Documents.
Add-WebConfiguration -Filter /system.webServer/defaultDocument/files -PSPath IIS:\ -Value @{value="$PHPDefaultDocument"} 

# Create php.ini and configure values.
$PHPIniBaseFile = Get-Content -Path "$PHPDirectory\php.ini-production"
$PHPIniValues = @{'max_execution_time = 30' = 'max_execution_time = 600';
'max_input_time = 60' = 'max_input_time = 600';
'; max_input_vars = 1000' = "max_input_vars = 2000";
'memory_limit = 128M' = "memory_limit = 256M";
';error_log = php_errors.log' = 'error_log = "C:\DATA\APP\PHP\log\error.log"';
'post_max_size = 8M' = 'post_max_size = 128M';
'; extension_dir = "ext"' = 'extension_dir = "C:\DATA\APP\PHP\ext"';
';cgi.force_redirect = 1' = 'cgi.force_redirect = 0';
';cgi.fix_pathinfo=1' = 'cgi.fix_pathinfo = 1';
';fastcgi.impersonate = 1' = 'fastcgi.impersonate = 1';
';upload_tmp_dir =' = 'upload_tmp_dir = "C:\DATA\APP\PHP\upload"';
'upload_max_filesize = 2M' = 'upload_max_filesize = 128M';
';extension=php_bz2.dll' = 'extension=php_bz2.dll';
';extension=php_curl.dll' = 'extension=php_curl.dll';
';extension=php_gd2.dll' = 'extension=php_gd2.dll';
';extension=php_mbstring.dll' = 'extension=php_mbstring.dll';
';extension=php_mysqli.dll' = 'extension=php_mysqli.dll';
';date.timezone =' = 'date.timezone = Europe/Brussels';
';session.save_path = "/tmp"' = 'session.save_path = "C:\DATA\APP\PHP\session"'   
}
foreach ($Entry in $PHPIniValues.Keys)
{
    $PHPIniBaseFile = $PHPIniBaseFile -replace $Entry, $PHPIniValues[$Entry]
}
Set-Content -Path "$PHPDirectory\php.ini" -Value $PHPIniBaseFile 

####################################################################################################
### 04: Install MySQL ##############################################################################
####################################################################################################

# Variables.
$MysqlDirectory = "$AppDirectory\MYSQL"
$MysqlDownloadLocation = "http://dev.mysql.com/get/Downloads/MySQL-5.7/mysql-5.7.11-winx64.zip"
$MysqlPackage = "mysql-5.7.11-winx64.zip"

# Download the Windows (x86, 64-bit) ZIP Archive.
Invoke-WebRequest -Uri $MysqlDownloadLocation -OutFile "$SrcDirectory\$MysqlPackage"

# Extract the .zip file to the BASE directory.
Add-Type -AssemblyName "system.io.compression.filesystem"
[io.compression.zipfile]::ExtractToDirectory("$SrcDirectory\$MysqlPackage", $AppDirectory)

# Rename the extracted directory to MYSQL.
Get-ChildItem -Path $AppDirectory | Where-Object -FilterScript {$_.Name -like "*mysql*"} | Rename-Item -NewName "MYSQL"

# Create my.ini and configure values.
$MyIniBaseFile = Get-Content -Path "$MysqlDirectory\my-default.ini"
$MyIniValues = @{'# basedir = .....' = 'basedir = C:/BASE/APP/MYSQL';
'# datadir = .....' = 'datadir = C:/BASE/APP/MYSQL/data'
}
foreach ($Entry in $MyIniValues.Keys)
{
    $MyIniBaseFile = $MyIniBaseFile -replace $Entry, $MyIniValues[$Entry]
}
Set-Content -Path "$MysqlDirectory\my.ini" -Value $MyIniBaseFile 

# As from MySQL 5.7.7, the noninstall .zip package does no longer include the data directory. So we need to initialize it.
# A new PowerShell window will popup, but no output will be returned. After initialization, a temporary root password will be created.
# You can find it in $MysqlDirectory\data\<servername>.err.
Start-Process -FilePath $PSHOME\powershell.exe -ArgumentList "-noexit Set-Location -Path $MysqlDirectory\bin ; .\mysqld --initialize"

# Perform a test run. A new PowerShell window will popup. Ensure you see "ready for connections" near the end of the output and no errors are returned.
# Once you have confirmed everything is OK, use Control-C to shutdown the MySQL server again.
Start-Process -FilePath $PSHOME\powershell.exe -ArgumentList "-noexit Set-Location -Path $MysqlDirectory\bin ; .\mysqld --console"

# Verify that the mysqld.exe process has been correctly shutdown from the previous step to avoid problems with starting the service later on.
$CheckMysqldProcess = Get-Process -Name "mysqld"
if ($CheckMysqldProcess)
{
    Stop-Process -Name "mysqld" -Force
}

# Add the MySQL installation directory to the Path Environment variable.
$CurrentPath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).PATH
$NewPath = $CurrentPath + ";$MysqlDirectory\bin"
Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $NewPath

# Install MySQL as a service.
Start-Process -FilePath $PSHOME\powershell.exe -ArgumentList "-noexit Set-Location -Path $MysqlDirectory\bin ; .\mysqld --install MySQL --defaults-file=$MysqlDirectory\my.ini"

# Start the MySQL service. In case the service fails to start, verify there is no more active mysqld.exe process from the test run.
# If yes, kill the process and attempt to start the service again.
Start-Service -Name "MySQL" -PassThru

####################################################################################################
### 05: Configure firewall #########################################################################
####################################################################################################

# Variables.
$FWDirectory = "$AppDirectory\FW"
$FWLogDirectory = "$FWDirectory\Log"
$FWLogFileDomain = "FWLogDomain.log"
$FWLogFilePrivate = "FWLogPrivate.log"
$FWLogFilePublic = "FWLogPublic.log"
$FWLogFileSize = 32767

# Create the FW Directory.
New-Item -ItemType Directory -Path $FWDirectory

# Create the FW log Directory.
New-Item -ItemType Directory -Path $FWLogDirectory

# Configure the log file for the Domain profile.
New-Item -ItemType File -Path $FWLogDirectory -Name $FWLogFileDomain
Set-NetFirewallProfile -Profile Domain -LogFileName $FWLogDirectory\$FWLogFileDomain -LogMaxSizeKilobytes $FWLogFileSize -LogBlocked True

# Configure the log file for the Private profile.
New-Item -ItemType File -Path $FWLogDirectory -Name $FWLogFilePrivate
Set-NetFirewallProfile -Profile Private -LogFileName $FWLogDirectory\$FWLogFilePrivate -LogMaxSizeKilobytes $FWLogFileSize -LogBlocked True

# Configure the log file for the Public profile.
New-Item -ItemType File -Path $FWLogDirectory -Name $FWLogFilePublic
Set-NetFirewallProfile -Profile Public -LogFileName $FWLogDirectory\$FWLogFilePublic -LogMaxSizeKilobytes $FWLogFileSize -LogBlocked True

# Configure the Domain profile to block outbound connections by default.
Set-NetFirewallProfile -Profile Domain -DefaultOutboundAction Block

# Configure the Private profile to block outbound connections by default.
Set-NetFirewallProfile -Profile Private -DefaultOutboundAction Block

# Configure the Public profile to block outbound connections by default.
Set-NetFirewallProfile -Profile Public -DefaultOutboundAction Block

# Disable the inbound rules that are enabled by default and are not required.
[array]$FWRulesInboundDefault = `
"Core Networking - Dynamic Host Configuration Protocol (DHCP-In)",`
"Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPV6-In)",`
"File and Printer Sharing (LLMNR-UDP-In)",`
"File and Printer Sharing (NB-Datagram-In)",`
"File and Printer Sharing (NB-Name-In)",`
"File and Printer Sharing (NB-Session-In)",`
"File and Printer Sharing (SMB-In)",`
"File and Printer Sharing (Spooler Service - RPC)",`
"File and Printer Sharing (Spooler Service - RPC-EPMAP)",`
"Remote Desktop - Shadow (TCP-In)",`
"Windows Remote Management (HTTP-In)",`
"Windows Remote Management (HTTP-In)"
foreach ($Rule in $FWRulesInboundDefault)
{    
    Set-NetFirewallRule -DisplayName $Rule -Enabled False
}

# Disable the outbound rules that are enabled by default and are not required.
[array]$FWRulesOutboundDefault = `
"Core Networking - Dynamic Host Configuration Protocol (DHCP-Out)",`
"Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPV6-Out)",`
"Core Networking - Group Policy (LSASS-Out)",`
"Core Networking - Group Policy (NP-Out)",`
"Core Networking - Group Policy (TCP-Out)",`
"File and Printer Sharing (LLMNR-UDP-Out)",`
"File and Printer Sharing (NB-Datagram-Out)",`
"File and Printer Sharing (NB-Name-Out)",`
"File and Printer Sharing (NB-Session-Out)",`
"File and Printer Sharing (SMB-Out)"
foreach ($Rule in $FWRulesOutboundDefault)
{
    Set-NetFirewallRule -DisplayName $Rule -Enabled False
}

# Enable the outbound rules that are disabled by default and that are useful to have enabled.
[array]$FWRulesOutboundDefaultDisabled = `
"File and Printer Sharing (Echo Request - ICMPv4-Out)",`
"File and Printer Sharing (Echo Request - ICMPv6-Out)"
foreach ($Rule in $FWRulesOutboundDefaultDisabled)
{
    Set-NetFirewallRule -DisplayName $Rule -Enabled True
}

# Modify the port range for FTP Server passive incoming traffic to a more limited range.
Get-NetFirewallRule -Name "IIS-WebServerRole-FTP-Passive-In-TCP" | Set-NetFirewallRule -LocalPort "10000-10500"

# Custom rule to enable outbound web traffic from the server on port 80 (HTTP).
New-NetFirewallRule -Profile Public -Direction Outbound -Protocol TCP -RemotePort 80 -Name "WebAccess-HTTP-TCP-Out" -DisplayName "WebAccess (HTTP-TCP-Out)" -Group "Custom - WebAccess" -Action Allow

# Custom rule to enable outbound web traffic from the server on port 443 (HTTPS).
New-NetFirewallRule -Profile Public -Direction Outbound -Protocol TCP -RemotePort 443 -Name "WebAccess-HTTPS-TCP-Out" -DisplayName "WebAccess (HTTPS-TCP-Out)" -Group "Custom - WebAccess" -Action Allow

####################################################################################################
### 06: Configure website ##########################################################################
####################################################################################################

# Variables.
$Domain = "supersysadmin.com"
$DomainDirectory = "$IISDirectory\$Domain"
$DomainWebDirectory = "$DomainDirectory\wwwroot"
$DomainLogDirectory = "$DomainDirectory\logs"
$DomainIPAddress = "10.10.20.100"

# Create website directories.
New-Item -ItemType Directory -Path $DomainDirectory
New-Item -ItemType Directory -Path $DomainLogDirectory
New-Item -ItemType Directory -Path $DomainWebDirectory

# Create application pool for the website.
New-WebAppPool -Name $Domain

# Set Read/Execute NTFS permissions for the application pool user on the wwwroot directory.
# For each application pool you create, IIS will create a Windows user with the same name. However you will not find it in Local Users and Computers.
# If you want to add it manually to the NTFS permissions of a directory, you have to type it ass "IIS AppPool\user" (where user is the name of your application pool.
$ACL = Get-Acl -Path $DomainWebDirectory
$NTAccount = New-Object System.Security.Principal.NTAccount("IIS AppPool\$Domain") 
$FileSystemRights = [System.Security.AccessControl.FileSystemRights]"ReadAndExecute"
$InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
$PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None 
$AccessControlType =[System.Security.AccessControl.AccessControlType]::Allow
$UserPermissions = $NTAccount,$FileSystemRights,$InheritanceFlags,$PropagationFlags,$AccessControlType
$AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $UserPermissions
$ACL.SetAccessRule($AccessRule)
$ACL | Set-Acl -Path $DomainWebDirectory

# Create the website.
New-Website -Name $Domain -ApplicationPool $Domain -HostHeader $Domain -IPAddress $DomainIPAddress -PhysicalPath $DomainWebDirectory

# Add host header for www.
$WWWHostHeader = "www." + $Domain
New-WebBinding -Name $Domain -IPAddress $DomainIPAddress -HostHeader $WWWHostHeader

# Configure logging settings for the website.
Set-ItemProperty -Path IIS:\Sites\$Domain -Name logFile.logExtFileFlags -Value "Date,Time,ClientIP,UserName,SiteName,ComputerName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,UserAgent,Cookie,Referer,ProtocolVersion,Host,HttpSubStatus"
Set-ItemProperty -Path IIS:\Sites\$Domain -Name logFile.directory -Value $DomainLogDirectory
Set-ItemProperty -Path IIS:\Sites\$Domain -Name logFile.localTimeRollover -Value $True

# Configure the website to use the application pool identity for anonymous authentication.
Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/anonymousAuthentication -Name userName -Value "" -PSPath IIS:\ -Location $Domain

# Add the application pool user to the group PHP Users.
$NTAccount = New-Object System.Security.Principal.NTAccount("IIS AppPool\$Domain")
$NTAccountSID = $NTAccount.Translate([System.Security.Principal.SecurityIdentifier])
$GroupPHPUsers = [ADSI]"WinNT://$env:ComputerName/$PHPUserGroup,Group"
$AppPoolUser = [ADSI]"WinNT://$NTACcountSID"
$GroupPHPUsers.Add($AppPoolUser.Path)

# Create a basic index.html page.
$IndexFileContent = @"
<html>
<head>
<title>$($Domain)</title>
</head>
<body>
<h1>$($Domain)</h1>
</body>
</html>
"@
New-Item -ItemType File -Path $DomainWebDirectory -Name index.html -Value $IndexFileContent

# Create a page to test PHP.
$PhpTestFileContent = @"
<html>
<head>
<title>$($Domain) - phpinfo</title>
</head>
<body>
<?php phpinfo(); ?>
</body>
</html>
"@
New-Item -ItemType File -Path $DomainWebDirectory -Name test.php -Value $PhpTestFileContent

# Test our website by calling the two files we created via our browser.
Start-Process -FilePath "http://$Domain/index.html"
Start-Process -FilePath "http://$Domain/test.php"

####################################################################################################
### 07: Configure ftp site #########################################################################
####################################################################################################

#Variables.
$DomainFTP = "ftp.supersysadmin.com"
$DomainFTPDirectory = "$IISDirectory\$DomainFTP"
$DomainFTPRootDirectory = "$DomainFTPDirectory\ftproot"
$DomainFTPLocalUserDirectory = "$DomainFTPRootDirectory\LocalUser"
$DomainFTPLogDirectory = "$DomainFTPDirectory\logs"
$DomainFTPIPAddress = "10.10.20.100"
$FTPPort = "21"
$FTPLowDataChannelPort = 10000
$FTPHighDataChannelPort = 10500
$FTPUserGroup = "FTP Users"
$FTPUser = "ftp_supersysadmin"
$FTPPassword = "P@ssword"

# Configure FTP Firewall Support (server level).
Set-WebConfigurationProperty -Filter system.ftpServer/firewallSupport -Name lowDataChannelPort -Value $FTPLowDataChannelPort
Set-WebConfigurationProperty -Filter system.ftpServer/firewallSupport -Name highDataChannelPort -Value $FTPHighDataChannelPort

# Create directories.
New-Item -ItemType Directory -Path $DomainFTPDirectory
New-Item -ItemType Directory -Path $DomainFTPRootDirectory
New-Item -ItemType Directory -Path $DomainFTPLocalUserDirectory
New-Item -ItemType Directory -Path $DomainFTPLogDirectory

# Create FTP Users local Windows group.
$LocalAccountDB = [ADSI]"WinNT://$env:ComputerName"
$CreateGroupFTPUsers = $LocalAccountDB.Create("Group","$FTPUserGroup")
$CreateGroupFTPUsers.SetInfo()
$CreateGroupFTPUsers.Description = "Members of this group can use connect via FTP"
$CreateGroupFTPUsers.SetInfo()

# Create FTP user.
$LocalAccountDB = [ADSI]"WinNT://$env:ComputerName"
$CreateUserFTPUser = $LocalAccountDB.Create("User","$FTPUser")
$CreateUserFTPUser.SetInfo()
$CreateUserFTPUser.SetPassword("$FTPPassword")
$CreateUserFTPUser.SetInfo()

# Add FTP user to the group FTP Users.
$NTAccount = New-Object System.Security.Principal.NTAccount("$FTPUser")
$NTAccountSID = $NTAccount.Translate([System.Security.Principal.SecurityIdentifier])
$GroupFTPUsers = [ADSI]"WinNT://$env:ComputerName/$FTPUserGroup,Group"
$UserFTPUser = [ADSI]"WinNT://$NTACcountSID"
$GroupFTPUsers.Add($UserFTPUser.Path)

# Set Read NTFS permissions for the group FTP Users to the ftproot directory.
$ACL = Get-Acl -Path $DomainFTPRootDirectory
$NTAccount = New-Object System.Security.Principal.NTAccount("$FTPUserGroup") 
$FileSystemRights = [System.Security.AccessControl.FileSystemRights]"ReadAndExecute"
$InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
$PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None 
$AccessControlType =[System.Security.AccessControl.AccessControlType]::Allow
$UserPermissions = $NTAccount,$FileSystemRights,$InheritanceFlags,$PropagationFlags,$AccessControlType
$AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $UserPermissions
$ACL.SetAccessRule($AccessRule)
$ACL | Set-Acl -Path $DomainFTPRootDirectory

# Create the FTP site.
New-WebFtpSite -Name $DomainFTP -IPAddress $DomainFTPIPAddress -Port $FTPPort -PhysicalPath $DomainFTPRootDirectory

# Enable basic authentication on the FTP site.
Set-ItemProperty -Path IIS:\Sites\$DomainFTP -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $True

# Change the SSL policy from Require SSL connections to Allow SSL connections.
Set-ItemProperty -Path IIS:\Sites\$DomainFTP -Name ftpServer.security.ssl.controlChannelPolicy -Value 0 
Set-ItemProperty -Path IIS:\Sites\$DomainFTP  -Name ftpServer.security.ssl.dataChannelPolicy -Value 0 

# Add an Authorization read rule for FTP Users.
Add-WebConfiguration -Filter "/system.ftpServer/security/authorization" -Value @{accessType="Allow";roles="$FTPUserGroup";permissions=1} -PSPath IIS:\ -Location $DomainFTP

# Enable virtual directories in FTP Directory Browsing.
Set-ItemProperty -Path IIS:\Sites\$DomainFTP -Name ftpServer.directoryBrowse.showFlags -Value "DisplayVirtualDirectories"

# Configure FTP Firewall Support (site level).
Set-ItemProperty -Path IIS:\Sites\$DomainFTP -Name ftpServer.firewallSupport.externalIp4Address -Value $DomainFTPIPAddress

# Configure logging settings for the FTP site.
Set-ItemProperty -Path IIS:\Sites\$DomainFTP -Name ftpServer.logFile.logExtFileFlags -Value "Date,Time,ClientIP,UserName,SiteName,ComputerName,ServerIP,Method,UriStem,FtpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,Host,FtpSubStatus,Session,FullPath,Info,ClientPort"
Set-ItemProperty -Path IIS:\Sites\$DomainFTP -Name ftpServer.logFile.directory -Value $DomainFTPLogDirectory
Set-ItemProperty -Path IIS:\Sites\$DomainFTP -Name ftpServer.logFile.localTimeRollover -Value $True

# Enable user isolation.
Set-ItemProperty -Path IIs:\Sites\$DomainFTP -Name ftpServer.userIsolation.mode -Value "IsolateAllDirectories"

# Create the username directory.
New-Item -ItemType Directory -Path $DomainFTPLocalUserDirectory\$FTPUser

# Set Modify NTFS permissions for the FTP user on the username directory.
$ACL = Get-Acl -Path $DomainFTPLocalUserDirectory\$FTPUser
$NTAccount = New-Object System.Security.Principal.NTAccount("$FTPUser") 
$FileSystemRights = [System.Security.AccessControl.FileSystemRights]"Modify"
$InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
$PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None 
$AccessControlType =[System.Security.AccessControl.AccessControlType]::Allow
$UserPermissions = $NTAccount,$FileSystemRights,$InheritanceFlags,$PropagationFlags,$AccessControlType
$AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $UserPermissions
$ACL.SetAccessRule($AccessRule)
$ACL | Set-Acl -Path $DomainFTPLocalUserDirectory\$FTPUser

# Create a virtual directory for the website domain root directory under the FTP site.
New-WebVirtualDirectory -Site "$DomainFTP\LocalUser\$FTPUser" -Name "$Domain" -PhysicalPath $DomainDirectory

# Set Modify NTFS permissions for the FTP user on the website domain root.
$ACL = Get-Acl -Path $DomainDirectory
$NTAccount = New-Object System.Security.Principal.NTAccount("$FTPUser") 
$FileSystemRights = [System.Security.AccessControl.FileSystemRights]"Modify"
$InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
$PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None 
$AccessControlType =[System.Security.AccessControl.AccessControlType]::Allow
$UserPermissions = $NTAccount,$FileSystemRights,$InheritanceFlags,$PropagationFlags,$AccessControlType
$AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $UserPermissions
$ACL.SetAccessRule($AccessRule)
$ACL | Set-Acl -Path $DomainDirectory

# Add an Authorization rule for FTP user on virtual directory.
Add-WebConfiguration "/system.ftpServer/security/authorization" -Value @{accessType="Allow";roles="$FTPUser";permissions=3} -PSPath IIS:\ -Location $DomainFTP/LocalUser/$FTPUser/$Domain
