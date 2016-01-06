<#
.SYNOPSIS
    Function to determine if the pool nonpaged bytes usage of one or more computers is high.
.DESCRIPTION
    Function to determine if the pool nonpaged bytes usage of one or more computers is high. The pool nonpaged bytes usage is considered high if the counter \Memory\Pool Nonpaged Bytes is higher than 80% of 75% of the RAM size.
.PARAMETER ComputerName
    In the parameter ComputerName you can specify which computer(s) you want to target.
.PARAMETER Samples
    In the parameter Samples you can specify how many counter samples you want to retrieve. By default this is 5.
.PARAMETER SampleInterval
    In the parameter SampleInterval you can specify the interval in seconds between each counter sample that is retrieved.
.EXAMPLE
    PS C:\>Get-OSPerformanceMemoryPoolNonPagedBytesHigh -ComputerName localhost

    This command analyzes pool nonpaged bytes usage of the local computer.
.EXAMPLE
    PS C:\>Get-OSPerformanceMemoryPoolNonPagedBytesHigh -ComputerName computer1,computer2 -Samples 10 -SampleInterval 5

    This command analyzes pool nonpaged bytes usage of the computer1 and computer2. It will retrieve 10 samples from each computer with an interval of 5 seconds between each sample.
.NOTES
    Author   : Ingvald Belmans
    Website  : http://www.supersysadmin.com
    Version  : 1.0 
    Changelog:
        - 1.0 (2016-01-06) Initial version.
.LINK
    http://www.supersysadmin.com  
#>
function Get-OSPerformanceMemoryPoolNonPagedBytesHigh
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
        Write-Verbose -Message "MemoryPoolNonPagedBytesAboveThreshold is TRUE if '\Memory\Pool Nonpaged Bytes' > (80% x (75% x RAM Size))"
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
                Write-Verbose -Message "Currently retrieving counter 'Memory\Pool Nonpaged Bytes' from computer '$Computer'."               
                $CounterMemoryPoolNonPagedBytes = Get-Counter -Counter "\\$Computer\Memory\Pool Nonpaged Bytes" -MaxSamples 1 -SampleInterval 1
                $CounterMemoryPoolNonPagedBytesSample = $CounterMemoryPoolNonPagedBytes.CounterSamples
                $CounterMemoryPoolNonPagedBytesSampleTimestamp = $CounterMemoryPoolNonPagedBytesSample.Timestamp
                $CounterMemoryPoolNonPagedBytesSampleCookedValue = $CounterMemoryPoolNonPagedBytesSample.CookedValue
                if ($CounterMemoryPoolNonPagedBytesSampleCookedValue -gt $MemoryPoolNonPagedBytesThreshold)
                {
                    $MemoryPoolNonPagedBytesAboveThreshold = $true
                }
                else 
                {
                    $MemoryPoolNonPagedBytesAboveThreshold = $false
                } 

                $CounterResultObject = New-Object -TypeName System.Object 
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $Computer
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "Timestamp(PoolNonPagedBytes)" -Value $CounterMemoryPoolNonPagedBytesSampleTimestamp
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "MemoryPoolNonPagedBytes" -Value $CounterMemoryPoolNonPagedBytesSampleCookedValue
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "TotalRAM(Bytes)" -Value $WMIComputerSystemTotalRAM
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "MemoryPoolNonPagedBytesThreshold" -Value $MemoryPoolNonPagedBytesThreshold
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "MemoryPoolNonPagedBytesAboveThreshold" -Value $MemoryPoolNonPagedBytesAboveThreshold
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
