<#
.SYNOPSIS
    Function to determine if the paging file usage of one or more computers is high.
.DESCRIPTION
    Function to determine if the paging file usage of one or more computers is high. The pool nonpaged bytes usage is considered high if the counter \Paging File(*)\% Usage is higher than 80%.
.PARAMETER ComputerName
    In the parameter ComputerName you can specify which computer(s) you want to target.
.PARAMETER Samples
    In the parameter Samples you can specify how many counter samples you want to retrieve. By default this is 5.
.PARAMETER SampleInterval
    In the parameter SampleInterval you can specify the interval in seconds between each counter sample that is retrieved.
.PARAMETER CounterPagingFileUsageTreshold
    In the parameter CounterPagingFileUsageTreshold you can specify the treshold for the counter \Paging File(*)\% Usage. By default this is 80 and this should normally not be changed.
.EXAMPLE
    PS C:\>Get-OSPerformanceMemoryPagingFileHigh -ComputerName localhost

    This command analyzes the paging file usage usage of the local computer.
.EXAMPLE
    PS C:\>Get-OSPerformanceMemoryPagingFileHigh -ComputerName computer1,computer2 -Samples 10 -SampleInterval 5

    This command analyzes the paging file usage of computer1 and computer2. It will retrieve 10 samples from each computer with an interval of 5 seconds between each sample.
.NOTES
    Author   : Ingvald Belmans
    Website  : http://www.supersysadmin.com
    Version  : 1.0 
    Changelog:
        - 1.0 (2016-01-08) Initial version.
.LINK
    http://www.supersysadmin.com  
#>
function Get-OSPerformanceMemoryPagingFileHigh
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
        $ComputerName,
        [int]
        $Samples = 5,
        [int]
        $SampleInterval = 1,
        [int]
        $CounterPagingFileUsageTreshold = 80
    )
    Begin
    {
    }
    Process
    {
        Write-Verbose -Message "MemoryPageFileAboveThreshold is TRUE if '\Paging File(*)\% Usage' > 80%"
        Write-Verbose -Message "Getting $Samples sample(s) from $($ComputerName.Count) computer(s) with an interval of $SampleInterval seconds. Please wait..."
        $CounterResult = @()
        $ComputerCounter = 0
        foreach ($Computer in $ComputerName)
        {
            Write-Verbose -Message "Currently processing computer '$Computer'."
            $ComputerCounter++
            Write-Progress -Activity "Getting counter samples of $($ComputerName.Count) computer(s)" -Status "Currently processing computer $ComputerCounter of $($ComputerName.Count)" -PercentComplete (($ComputerCounter/$ComputerName.Count)*100) -Id 1
            Write-Verbose -Message "Currently retrieving RAM size from computer '$Computer'." 
            $WMIComputerSystem = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $Computer
            $WMIComputerSystemTotalRAM = $WMIComputerSystem.TotalPhysicalMemory
            $MemoryPoolNonPagedBytesThreshold = 0.80 * (0.75 * $WMIComputerSystemTotalRAM)
            $SampleCounter = 0 
            While ($SampleCounter -lt $Samples)
            {
                $SampleCounter++
                Write-Progress -Activity "Getting counter samples from computer $Computer" -Status "Currently retrieving sample $SampleCounter of $Samples" -PercentComplete (($SampleCounter/$Samples)*100) -ParentId 1
                Write-Verbose -Message "Currently retrieving counter '\Paging File(*)\% Usage' from computer '$Computer'."               
                $CounterPagingFileUsage = Get-Counter -Counter "\\$Computer\Paging File(*)\% Usage" -MaxSamples 1 -SampleInterval 1
                $CounterPagingFileUsageSample = $CounterPagingFileUsage.CounterSamples | Where-Object -FilterScript {$_.InstanceName -eq "_total"}
                $CounterPagingFileUsageSampleTimestamp = $CounterPagingFileUsageSample.Timestamp
                $CounterPagingFileUsageSampleCookedValue = "{0:N2}" -f ($CounterPagingFileUsageSample.CookedValue)           
                if ($CounterPagingFileUsageSampleCookedValue -gt $CounterPagingFileUsageTreshold)
                {
                    $MemoryPageFileAboveThreshold = $true
                }
                else
                {
                    $MemoryPageFileAboveThreshold = $false
                }
                $CounterResultObject = New-Object -TypeName System.Object 
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $Computer
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "Timestamp" -Value $CounterPagingFileUsageSampleTimestamp
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "PageFileUsage(%)" -Value $CounterPagingFileUsageSampleCookedValue
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "MemoryPageFileAboveThreshold" -Value $MemoryPageFileAboveThreshold
                $CounterResult += $CounterResultObject
                Start-Sleep -Seconds ($SampleInterval - 1)
            }
        }
        Write-Output -InputObject $CounterResult
    }
    End
    {
    }
}
