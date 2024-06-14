# Run as Admin
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell.exe -Verb RunAs "-NoLogo -NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    exit;
}

# Create a global HashSet to store unique strings
$Global:ListDomains = [System.Collections.Generic.HashSet[string]]::new()
$Global:ListIps = [System.Collections.Generic.HashSet[string]]::new()

$Global:DateAndTime = (Get-Date).ToString('dd-MM-yyyy_HH-mm-ss')

$Global:WhiteListDomains = @(
    # https://github.com/W4RH4WK/Debloat-Windows-10/blob/master/scripts/block-telemetry.ps1
    "cs1.wpc.v0cdn.net" # WingetUi is using this Url, to get the latest Microsoft Redistributable
    "b.ads2.msads.net" # WingetUi is using this Url, to get the latest Windows Desktop Runtime
    "a.ads2.msads.net" # WingetUi is using this Url, to get the latest Windows Desktop Runtime
    "a248.e.akamai.net" # makes iTunes download button disappear
    "ipv6.msftncsi.com" # Issues may arise where Windows 10 thinks it doesn't have internet
    "ipv6.msftncsi.com.edgesuite.net" # Issues may arise where Windows 10 thinks it doesn't have internet
    "settings-win.data.microsoft.com" # may cause issues with Windows Updates
    "sls.update.microsoft.com.nsatc.net" # may cause issues with Windows Updates
    "www.msftncsi.com" # Issues may arise where Windows 10 thinks it doesn't have internet
    "wdcp.microsoft.com" # may cause issues with Windows Defender Cloud-based protection
    "dns.msftncsi.com" # may cause issues with Windows Defender Cloud-based protection
    "storeedgefd.dsx.mp.microsoft.com" # breaks Windows Store
    "sls.update.microsoft.com" # may cause issues with Windows Updates
    "static.ads-twitter.com" # may cause issues with Twitter login
    "p.static.ads-twitter.com" # may cause issues with Twitter login
    "login.live.com" # prevents login to outlook and other live apps
    "g.live.com" # Used to save BitLocker recovery keys to a Microsoft account
)

$Global:WhiteListIps = @(
    # https://github.com/W4RH4WK/Debloat-Windows-10/blob/master/scripts/block-telemetry.ps1
    "65.52.108.33" # Causes problems with Microsoft Store
)

function CheckInternetConnection {
    # Check the internet connection for max 60 seconds
    $number = 60
    $i = 1

    do{
        try {
            $pingresult = ping -4 -n 2 -w 700 8.8.8.8 | Select-String -Pattern 'TTL='
        }
        catch
        {
            Write-Host "Internet error" -ForegroundColor Red
        }

        Write-Output "Internet Connection Check Attempt Nr: $i"
        sleep 1

        if($pingresult -Match 'TTL=') {
            break
        }
        else {
            if($i -eq $number) {
		        Write-Host "You are not connected to the internet, we will try it again after a system restart." -ForegroundColor Red
                $ScriptName = [io.path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
                $ScriptPath = $MyInvocation.MyCommand.Path
                # C:\WINDOWS\system32
                $env:SystemDirectory = [Environment]::SystemDirectory
                New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Force -Name "$ScriptName" -PropertyType "String" -Value "`"$env:SystemDirectory\WindowsPowerShell\v1.0\powershell.exe`" -NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
                pause
                exit
            }
        }
        $i++ 
    } while ($i -le $number)
}

# Function to validate IP addresses
function IsValidIpAddress {
    param (
        [string]$address
    )
    try {
        [System.Net.IPAddress]::Parse($address) | Out-Null
        return $true
    } catch {
        return $false
    }
}

function IsValidIPv6 {
    param (
        [string]$IPAddress
    )

    # Try to parse the IP address
    $result = [System.Net.IPAddress]::TryParse($IPAddress, [ref]$null)

    # Check if it's a valid IPv6 address
    if ($result -and [System.Net.IPAddress]::Parse($IPAddress).AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        return $true
    } else {
        return $false
    }
}

function GetIp {
    # Writes a new line
    foreach ($domain in $Global:ListDomains -split "`n") {
        $url = $domain.trim()
        # if line doesnt have a hashtag
        if ($domain -inotmatch "#") {
            # if line not empty
            if ((-Not [String]::IsNullOrWhiteSpace($url))) {
                # Split domains by whitespace, because format of list is 0.0.0.0 domain.com
                $SplitDomain = $url.ToLower() -Split '\s+'
                # Write-Output $SplitDomain[1]
                if ($Global:WhiteListDomains -notcontains $SplitDomain[1]) {
                    # Domain to ip
                    $Resolve = $null
                    # Get only "A" = IPv4 Records. AAAA is = IPv6
                    $Resolve = Resolve-DnsName -Name $SplitDomain[1] -Type A -ErrorAction SilentlyContinue

                    $ObjectOutput = [PSCustomObject]@{
                        IP = $Resolve.IPAddress
                        Name = $Resolve.Name
                        Type = $Resolve.Type
                        TTL = $Resolve.TTL
                        Section = $Resolve.Section
                        NameHost = $Resolve.NameHost
                    }

                    # Hosts can have multiple Ip Addresses, we just select the first one
                    #$OutputIp = $ObjectOutput.IP | select -First 1
                    $OutputIp = $ObjectOutput.IP
                    foreach ($ip in $OutputIp -split "`n") {
                        if ((-Not [String]::IsNullOrWhiteSpace($ip))) {
                            if ($Global:WhiteListIps -notcontains $ip.ToLower()) {
                                # checks for empty ipv4 adress
                                if (!($ip.ToLower().Contains("0.0.0.0"))) {
                                    if (IsValidIpAddress $ip) {
                                        #Write-Output "Ip:" $ip "Domain:" $SplitDomain[1]
                                        # Add Ips to List
                                        $Global:ListIps.Add($ip) | Out-Null
                                    }
                                }
                            }
                        }
                    }

                    $ResolveIpV6 = Resolve-DnsName -Name $SplitDomain[1] -Type AAAA -ErrorAction SilentlyContinue

                    $ObjectOutputIPV6 = [PSCustomObject]@{
                        IP = $ResolveIpV6.IPAddress
                        Name = $ResolveIpV6.Name
                        Type = $ResolveIpV6.Type
                        TTL = $ResolveIpV6.TTL
                        Section = $ResolveIpV6.Section
                        NameHost = $ResolveIpV6.NameHost
                    }

                    $OutputIPV6 = $ObjectOutputIPV6.IP
                    foreach ($ipv6 in $OutputIPV6 -split "`n") {
                        if ((-Not [String]::IsNullOrWhiteSpace($ipv6))) {
                            if ($Global:WhiteListIps -notcontains $ipv6.ToLower()) {
                                # checks for empty ipv6 adress | if not only ::
                                if (!($ipv6.ToLower() -match '^[::]*$')) {
                                    if (IsValidIpAddress $ipv6) { 
                                        #Write-Output "Ip:" $ipv6 "Domain:" $SplitDomain[1]
                                        # Add Ips to List
                                        $Global:ListIps.Add($ipv6) | Out-Null
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

function DoBackupAndRemoveCurrentHostsFile {
    Write-Host "Creating backup of current hosts file" -ForegroundColor Yellow
    # Backup hosts file
    if (Test-Path "$env:systemroot\System32\drivers\etc\hosts" -PathType Leaf) {
        If(!(test-path -PathType container "$PSScriptRoot\Hosts-File-Backup")) {
            New-Item -ItemType Directory -Path "$PSScriptRoot\Hosts-File-Backup"
        }
        Copy-Item "$env:systemroot\System32\drivers\etc\hosts" "$PSScriptRoot\Hosts-File-Backup\hosts-$Global:DateAndTime.BACKUP" -Force
        if (Test-Path "$PSScriptRoot\Hosts-File-Backup\hosts-$Global:DateAndTime.BACKUP" -PathType Leaf) {
            Remove-Item -Path "$env:systemroot\System32\drivers\etc\hosts" -Force
        }
    }
}

function DoBackupAndRemoveCurrentFirewallIps {
    Write-Host "Creating backup of current firewall" -ForegroundColor Yellow
    # Backup firewall
    if(!(test-path -PathType container "$PSScriptRoot\Firewall-Backup")) {
        New-Item -ItemType Directory -Path "$PSScriptRoot\Firewall-Backup"
    }
    reg export "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" "$PSScriptRoot\Firewall-Backup\Firewall-$Global:DateAndTime.reg.BACKUP" /y

    Write-Host "Remove any existing rule with the same name to avoid duplicates" -ForegroundColor Green
    # https://stackoverflow.com/a/77599067
    # Get the firewall rules with the name "Block Telemetry IPs"
    $rulesToRemove = Get-NetFirewallRule | Where-Object { $_.DisplayName -eq "Block Telemetry IPs" }

    # Extract the names of the rules
    $ruleNames = $rulesToRemove.Name

    # Define the batch size to avoid quota limits
    $batchSize = 250  # Adjust this value based on your system's quota limits

    # Remove the rules in batches
    if ($ruleNames) {
        $ruleNames | ForEach-Object -Begin { $batch = @() } -Process {
            $batch += $_
            if ($batch.Count -ge $batchSize) {
                Remove-NetFirewallRule -Name $batch -ErrorAction SilentlyContinue | Out-Null
                $batch = @()
            }
        } -End {
            if ($batch.Count -gt 0) {
                Remove-NetFirewallRule -Name $batch -ErrorAction SilentlyContinue | Out-Null
            }
        }
    }
}

function DoBackupAndRemoveCurrentPersistentRoutes {
    Write-Host "Creating backup of current persistent routes" -ForegroundColor Yellow
    # Backup routes
    if(!(test-path -PathType container "$PSScriptRoot\Persistent-Routes-Backup")) {
        New-Item -ItemType Directory -Path "$PSScriptRoot\Persistent-Routes-Backup"
    }
    reg export "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes" "$PSScriptRoot\Persistent-Routes-Backup\Persistent-Routes-$Global:DateAndTime.reg.BACKUP" /y
    
    Write-Host "Deleting current persistent routes" -ForegroundColor Green
    if (Test-Path "$PSScriptRoot\Persistent-Routes-Backup\Persistent-Routes-$Global:DateAndTime.reg.BACKUP" -PathType Leaf) {
        # reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes" /va /f
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes" -Name *
    }
}

function HostsFile {
    Write-Host "Blocking telemetry via hosts file.." -ForegroundColor Magenta

    # Create a hosts file, if not already exists
    if (Test-Path "$env:systemroot\System32\drivers\etc\hosts" -PathType Leaf) {
        $hosts_file = "$env:systemroot\System32\drivers\etc\hosts"
    } else {
        $hosts_file = "$env:systemroot\System32\drivers\etc\hosts"
        Write-Host "Sorry you dont have a hosts file, we will create one" -ForegroundColor Yellow
        New-Item "$hosts_file" -Force
    }

    Write-Host "Adding telemetry endpoints from self research" -ForegroundColor Green
    # https://learn.microsoft.com/de-de/mem/configmgr/desktop-analytics/enable-data-sharing#server-connectivity-endpoints
    # https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization#endpoints
    # https://learn.microsoft.com/en-us/windows/privacy/manage-windows-11-endpoints
    # https://github.com/undergroundwires/privacy.sexy/blob/master/src/application/collections/windows.yaml#L9433
    $domains = @(
        # Windows Error Reporting
        "watson.telemetry.microsoft.com"
        "umwatsonc.events.data.microsoft.com"
        "ceuswatcab01.blob.core.windows.net"
        "ceuswatcab02.blob.core.windows.net"
        "eaus2watcab01.blob.core.windows.net"
        "eaus2watcab02.blob.core.windows.net"
        "weus2watcab01.blob.core.windows.net"
        "weus2watcab02.blob.core.windows.net"
        "www.telecommandsvc.microsoft.com"

        # Online Crash Analysis
        "oca.telemetry.microsoft.com"
        "oca.microsoft.com"
        "kmwatsonc.events.data.microsoft.com"

        # Connected User Experiences and Telemetry component
        "self.events.data.microsoft.com"

        # https://github.com/undergroundwires/privacy.sexy/blob/master/src/application/collections/windows.yaml#L9433
        "co4.telecommand.telemetry.microsoft.com"
        "cs11.wpc.v0cdn.net"
        "cs1137.wpc.gammacdn.net"
        "modern.watson.data.microsoft.com"
        "eu-watsonc.events.data.microsoft.com"
        "telemetry.dropbox.com"
        "telemetry.v.dropbox.com"
    )

    foreach ($domain in $domains) {
        $url = $domain.trim()
        if ($Global:WhiteListDomains -notcontains $url.ToLower()) {
            # ipv4 hosts file format
            $Global:ListDomains.Add("0.0.0.0 $url") | Out-Null
            # ipv6 hosts file format
            $Global:ListDomains.Add(":: $url") | Out-Null
        }
    }

    Write-Host "Adding telemetry endpoints from RPiList" -ForegroundColor Green
    # https://github.com/RPiList/specials/blob/master/Blocklisten/Win10Telemetry
    $request = $(Invoke-WebRequest -Uri "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Win10Telemetry").Content | out-string
    foreach ($domain in $request -split "`n") {
        $url = $domain.trim()
        if ($Global:WhiteListDomains -notcontains $url.ToLower()) {
            # if line doesnt have a hashtag
            if ($url -inotmatch "#") {
                # if line not empty
                if ((-Not [String]::IsNullOrWhiteSpace($url))) {
                    # 0.0.0.0 = IPV4, :: = IPV6
                    $Global:ListDomains.Add("0.0.0.0 $url") | Out-Null
                    $Global:ListDomains.Add(":: $url") | Out-Null
                }
            }
        }
    }

    Write-Host "Adding telemetry endpoints from WindowsSpyBlocker" -ForegroundColor Green
    $arrUrls = @('https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt','https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy_v6.txt')
    foreach ($myUrl in $arrUrls) {
        $request = $(Invoke-WebRequest -Uri $myUrl).Content | out-string
        foreach ($domain in $request -split "`n") {
            $url = $domain.trim()
            $SplitDomain = $url.ToLower() -Split '\s+'
            if ($Global:WhiteListDomains -notcontains $SplitDomain[1]) {
                # if line doesnt have a hashtag
                if ($url -inotmatch "#") {
                    # if line not empty
                    if ((-Not [String]::IsNullOrWhiteSpace($url))) {
                        $Global:ListDomains.Add("$url") | Out-Null
                    }
                }
            }
        }
    }

    Write-Host "Get the ips from the parsed domains" -ForegroundColor Green
    GetIp

    Write-Host "Writing hosts file" -ForegroundColor Green
    foreach ($domain in $Global:ListDomains -split "`n") {
        $url = $domain.trim()
        if ($Global:WhiteListDomains -notcontains $url.ToLower()) {
            # if line doesnt have a hashtag
            if ($url -inotmatch "#") {
                # if line not empty
                if ((-Not [String]::IsNullOrWhiteSpace($url))) {
                    # Append domains to hosts file
                    Write-Output "$url" | Out-File -Encoding ASCII -Append $hosts_file
                }
            }
        }
    }
}

function Firewall {
    Write-Host "Blocking telemetry via firewall.." -ForegroundColor Magenta

    Write-Host "Adding telemetry endpoints from WindowsSpyBlocker" -ForegroundColor Green
    # https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/firewall/spy.txt
    $request = $(Invoke-WebRequest -Uri "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/firewall/spy.txt").Content | out-string
    foreach ($IpAddress in $request -split "`n") {
        $Ip = $IpAddress.trim()
        if ($Global:WhiteListIps -notcontains $Ip.ToLower()) {
            # if line doesnt have a hashtag
            if ($Ip -inotmatch "#") {
                # if line not empty
                if ((-Not [String]::IsNullOrWhiteSpace($Ip))) {
                    if (IsValidIpAddress $Ip) {
                        if (!($Ip.ToLower().Contains("0.0.0.0"))) {
                            # checks for empty ipv6 adress | if not only ::
                            if (!($ip.ToLower() -match '^[::]*$')) {
                                if (!($Ip.ToLower().Contains("127.0.0.1"))) {
                                    $Global:ListIps.Add("$Ip") | Out-Null
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Write-Host "Adding telemetry ips to firewall" -ForegroundColor Green
    foreach ($IpAddress in $Global:ListIps -split "`n") {
        $Ip = $IpAddress.trim()
        if ($Global:WhiteListIps -notcontains $Ip.ToLower()) {
            # if line not empty
            if ((-Not [String]::IsNullOrWhiteSpace($Ip))) {
                if (IsValidIpAddress $Ip) {
                    if (!($Ip.ToLower().Contains("0.0.0.0"))) {
                        # checks for empty ipv6 adress | if not only ::
                        if (!($ip.ToLower() -match '^[::]*$')) {
                            if (!($Ip.ToLower().Contains("127.0.0.1"))) {
                                New-NetFirewallRule -DisplayName "Block Telemetry IPs" -Direction Outbound `
                                    -Action Block -RemoteAddress $Ip | Out-Null
                                New-NetFirewallRule -DisplayName "Block Telemetry IPs" -Direction Inbound `
                                    -Action Block -RemoteAddress $Ip | Out-Null
                            }
                        }
                    }
                }
            }
        }
    }
}

function PersistentRoutes {
    Write-Host "Blocking telemetry via persistent routes.." -ForegroundColor Magenta

    Write-Host "Remove any existing ipv6 persistent route to avoid duplicates" -ForegroundColor Green
    foreach ($IpAddress in $Global:ListIps -split "`n") {
        $Ip = $IpAddress.trim()
        if (IsValidIPv6 $Ip) {
            route -p delete $Ip/32 | Out-Null
        }
    }

    Write-Host "Adding telemetry ips to persistent routes" -ForegroundColor Green
    foreach ($IpAddress in $Global:ListIps -split "`n") {
        $Ip = $IpAddress.trim()
        if ($Global:WhiteListIps -notcontains $Ip.ToLower()) {
            # if line not empty
            if ((-Not [String]::IsNullOrWhiteSpace($Ip))) {
                if (IsValidIpAddress $Ip) {
                    if (!($Ip.ToLower().Contains("0.0.0.0"))) {
                        # checks for empty ipv6 adress | if not only ::
                        if (!($ip.ToLower() -match '^[::]*$')) {
                            if (!($Ip.ToLower().Contains("127.0.0.1"))) {
                                if (IsValidIPv6 $Ip) {
                                    route -p add $Ip/32 ::1 | Out-Null
                                } else {
                                    route -p add $Ip/32 0.0.0.0 | Out-Null
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

DoBackupAndRemoveCurrentHostsFile
DoBackupAndRemoveCurrentFirewallIps
DoBackupAndRemoveCurrentPersistentRoutes

Start-Process -FilePath "$env:SystemRoot\System32\netsh.exe" -ArgumentList "interface ip delete arpcache" -Verb "RunAs" -WindowStyle Hidden -Wait
Start-Process -FilePath "$env:SystemRoot\System32\netsh.exe" -ArgumentList "interface ip delete destinationcache" -Verb "RunAs" -WindowStyle Hidden -Wait
Clear-DnsClientCache

CheckInternetConnection
HostsFile
Firewall
PersistentRoutes

Start-Process -FilePath "$env:SystemRoot\System32\netsh.exe" -ArgumentList "interface ip delete arpcache" -Verb "RunAs" -WindowStyle Hidden -Wait
Start-Process -FilePath "$env:SystemRoot\System32\netsh.exe" -ArgumentList "interface ip delete destinationcache" -Verb "RunAs" -WindowStyle Hidden -Wait
Clear-DnsClientCache

exit
