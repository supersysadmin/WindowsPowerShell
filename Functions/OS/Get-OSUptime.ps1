<#
.SYNOPSIS
    Function to get the uptime of one or more computers.
.DESCRIPTION
    Function to get the uptime of one or more computers.
.PARAMETER ComputerName
    In the parameter ComputerName you can specify which computer(s) you want to target. 
.EXAMPLE
    PS C:\>Get-OSUptime -ComputerName computer1

    This command retrieves the uptime of computer1.
.EXAMPLE
    PS C:\>Get-Content -Path C:\computers.txt | Get-OSUptime | Export-Csv -Path C:\uptime.csv

    This command reads a list of computernames from a .txt file, then retrieves their uptime and finally exports the result to a .csv file.
.NOTES
    Author   : Ingvald Belmans
    Website  : http://www.supersysadmin.com
    Version  : 1.0 
    Changelog:
        - 1.0 (2015-08-23) Initial version.
.LINK
    http://www.supersysadmin.com  
#>
function Get-OSUptime
{
    [CmdletBinding()]
    Param
    (
        [Parameter(
            Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true
            )
        ]
        [String[]]
        $ComputerName
    )

    Begin
    {
        $CurrentTime = Get-Date
    }
    Process
    {
        $UptimeResult = @()
        foreach ($Computer in $ComputerName)
        {
            $WMIOS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer
            $BootTime = [Management.ManagementDateTimeConverter]::ToDateTime($WMIOS.LastBootUpTime)
            $Uptime = $CurrentTime - $BootTime
            $UptimeResultObject = New-Object -TypeName System.Object 
            $UptimeResultObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $WMIOS.PSComputerName
            $UptimeResultObject | Add-Member -MemberType NoteProperty -Name "BootTime" -Value $BootTime.DateTime
            $UptimeResultObject | Add-Member -MemberType NoteProperty -Name "UptimeDays" -Value $Uptime.Days
            $UptimeResultObject | Add-Member -MemberType NoteProperty -Name "UptimeHours" -Value $Uptime.Hours
            $UptimeResultObject | Add-Member -MemberType NoteProperty -Name "UptimeMinutes" -Value $Uptime.Minutes
            $UptimeResultObject | Add-Member -MemberType NoteProperty -Name "UptimeSeconds" -Value $Uptime.Seconds
            $UptimeResult += $UptimeResultObject            
        }
        Write-Output $UptimeResult
    }
    End
    {
    }
}
