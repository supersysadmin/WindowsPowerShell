<#
.SYNOPSIS
    Function to determine if the committed bytes usage of one or more computers is high.
.DESCRIPTION
    Function to determine if the committed bytes usage of one or more computers is high.This is done by analyzing 2 specific performance counters and querying the amount of RAM the computer has installed. The committed bytes usage is considered high if the counter \Memory\Committed Bytes is higher than 80% of the counter \Memory\Commit Limit (if the amount of installed RAM is less than or equal to 8GB) or if the counter \Memory\Committed Bytes is higher than the counter \Memory\Commit Limit -2GB (if the amount of installed RAM is more then 8GB).
.PARAMETER ComputerName
    In the parameter ComputerName you can specify which computer(s) you want to target.
.PARAMETER Samples
    In the parameter Samples you can specify how many counter samples you want to retrieve. By default this is 5.
.PARAMETER SampleInterval
    In the parameter SampleInterval you can specify the interval in seconds between each counter sample that is retrieved.
.EXAMPLE
    PS C:\>Get-OSPerformanceMemoryCommittedBytesHigh -ComputerName localhost

    This command analyzes committed bytes usage of the local computer.
.EXAMPLE
    PS C:\>Get-OSPerformanceMemoryCommittedBytesHigh -ComputerName computer1,computer2 -Samples 10 -SampleInterval 5

    This command analyzes the committed bytes usage of the computer1 and computer2. It will retrieve 10 samples from each computer with an interval of 5 seconds between each sample.
.NOTES
    Author   : Ingvald Belmans
    Website  : http://www.supersysadmin.com
    Version  : 1.0 
    Changelog:
        - 1.0 (2016-01-06) Initial version.
.LINK
    http://www.supersysadmin.com  
#>
function Get-OSPerformanceMemoryCommittedBytesHigh
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
        $SampleInterval = 1
    )
    Begin
    {
    }
    Process
    {
        Write-Verbose -Message "MemoryCommittedBytesAboveThreshold (RAM <= 8GB) is TRUE if '\Memory\Committed Bytes' > (80% x '\Memory\Commit Limit')"
        Write-Verbose -Message "MemoryCommittedBytesAboveThreshold (RAM  > 8GB) is TRUE if '\Memory\Committed Bytes' > ('\Memory\Commit Limit' - 2GB)"
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
            $WMIComputerSystemTotalRAMGB = "{0:N2}" -f ($WMIComputerSystemTotalRAM / 1GB)            
            $SampleCounter = 0 
            While ($SampleCounter -lt $Samples)
            {
                $SampleCounter++
                Write-Progress -Activity "Getting counter samples from computer $Computer" -Status "Currently retrieving sample $SampleCounter of $Samples" -PercentComplete (($SampleCounter/$Samples)*100) -ParentId 1
                Write-Verbose -Message "Currently retrieving counter '\Memory\Committed Bytes' from computer '$Computer'."               
                $CounterMemoryCommittedBytes = Get-Counter -Counter "\\$Computer\Memory\Committed Bytes" -MaxSamples 1 -SampleInterval 1
                $CounterMemoryCommittedBytesSample = $CounterMemoryCommittedBytes.CounterSamples
                $CounterMemoryCommittedBytesSampleTimestamp = $CounterMemoryCommittedBytesSample.Timestamp
                $CounterMemoryCommittedBytesSampleCookedValue = $CounterMemoryCommittedBytesSample.CookedValue
                Write-Verbose -Message "Currently retrieving counter '\Memory\Commit Limit' from computer '$Computer'."                  
                $CounterMemoryCommitLimit = Get-Counter -Counter "\\$Computer\Memory\Commit Limit" -MaxSamples 1 -SampleInterval 1
                $CounterMemoryCommitLimitSample = $CounterMemoryCommitLimit.CounterSamples
                $CounterMemoryCommitLimitSampleTimestamp = $CounterMemoryCommitLimitSample.Timestamp
                $CounterMemoryCommitLimitSampleCookedValue = $CounterMemoryCommitLimitSample.CookedValue
                if ($WMIComputerSystemTotalRAM -le 8589934592)
                {
                    $CounterMemoryCommitLimitThreshold = $CounterMemoryCommitLimitSampleCookedValue * 0.8
                }
                else
                {
                    $CounterMemoryCommitLimitThreshold = $CounterMemoryCommitLimitSampleCookedValue - 2147483648
                }
                if ($CounterMemoryCommittedBytesSampleCookedValue -gt $CounterMemoryCommitLimitThreshold)
                {
                    $MemoryCommittedBytesAboveThreshold = $true
                }
                else 
                {
                    $MemoryCommittedBytesAboveThreshold = $false
                }
                $CounterResultObject = New-Object -TypeName System.Object 
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $Computer
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "TotalRAM(Bytes)" -Value $WMIComputerSystemTotalRAM
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "TotalRAM(GigaBytes)" -Value $WMIComputerSystemTotalRAMGB
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "Timestamp(CommittedBytes)" -Value $CounterMemoryCommittedBytesSampleTimestamp
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "CommittedBytes" -Value $CounterMemoryCommittedBytesSampleCookedValue
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "Timestamp(CommitLimit)" -Value $CounterMemoryCommitLimitSampleTimestamp
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "CommitLimit" -Value $CounterMemoryCommitLimitSampleCookedValue
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "CommitLimitThreshold" -Value $CounterMemoryCommitLimitThreshold
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "MemoryCommittedBytesAboveThreshold" -Value $MemoryCommittedBytesAboveThreshold
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
