<#
.SYNOPSIS
    Function to determine if the processor usage of one or more computers is high.
.DESCRIPTION
    Function to determine if the processor usage of one or more computers is high. This is done by analyzing 3 specific performance counters. The processor usage is considered high if the counter \Processor(_Total)\% Processor Time is higher than 90 AND the counter \System\Context Switches/sec is higher than 20000 AND the counter \System\Processor Queue Length is higher than 2.
.PARAMETER ComputerName
    In the parameter ComputerName you can specify which computer(s) you want to target.
.PARAMETER Samples
    In the parameter Samples you can specify how many counter samples you want to retrieve. By default this is 5.
.PARAMETER SampleInterval
    In the parameter SampleInterval you can specify the interval in seconds between each counter sample that is retrieved.
.PARAMETER CounterProcessorPercentageProcessorTimeThreshold
    In the parameter CounterProcessorPercentageProcessorTimeThreshold you can specify the treshold for the counter \Processor(_Total)\% Processor Time. By default this is 90 and this should normally not be changed.
.PARAMETER CounterSystemContextSwitchesTreshold
    In the parameter CounterSystemContextSwitchesTreshold you can specify the treshold for the counter \System\Context Switches/sec. By default this is 20000 and this should normally not be changed.
.PARAMETER CounterSystemProcessorQueueLengthTreshold
    In the parameter CounterSystemProcessorQueueLengthTreshold you can specify the treshold for the counter \System\Processor Queue Length. By default this is 2 and this should normally not be changed.
.EXAMPLE
    PS C:\>Get-OSPerformanceProcessorUsageHigh -ComputerName localhost

    This command analyzes the processor usage of the local computer.
.EXAMPLE
    PS C:\>Get-OSPerformanceProcessorUsageHigh -ComputerName computer1,computer2 -Samples 10 -SampleInterval 5

    This command analyzes the processor usage of the computer1 and computer2. It will retrieve 10 samples from each computer with an interval of 5 seconds between each sample.
.NOTES
    Author   : Ingvald Belmans
    Website  : http://www.supersysadmin.com
    Version  : 1.0 
    Changelog:
        - 1.0 (2016-01-05) Initial version.
.LINK
    http://www.supersysadmin.com  
#>
function Get-OSPerformanceProcessorUsageHigh
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
        $CounterProcessorPercentageProcessorTimeThreshold = 90,
        [int]
        $CounterSystemContextSwitchesTreshold = 20000,
        [int]
        $CounterSystemProcessorQueueLengthTreshold = 2
    )
    Begin
    {
    }
    Process
    {
        Write-Verbose -Message "ProcessorUsageHighAboveThreshold is TRUE if '\Processor(_Total)\% Processor Time' > 90 AND '\System\Context Switches/sec' > 20000 AND '\System\Processor Queue Length' > 2."
        Write-Verbose -Message "Getting $Samples sample(s) from $($ComputerName.Count) computer(s) with an interval of $SampleInterval seconds. Please wait..."
        $CounterResult = @()
        $ComputerCounter = 0
        foreach ($Computer in $ComputerName)
        {
            Write-Verbose -Message "Currently processing computer '$Computer'."
            $ComputerCounter++
            Write-Progress -Activity "Getting counter samples of $($ComputerName.Count) computer(s)" -Status "Currently processing computer $ComputerCounter of $($ComputerName.Count)" -PercentComplete (($ComputerCounter/$ComputerName.Count)*100) -Id 1
            $SampleCounter = 0 
            While ($SampleCounter -lt $Samples)
            {                
                $SampleCounter++
                Write-Progress -Activity "Getting counter samples from computer $Computer" -Status "Currently retrieving sample $SampleCounter of $Samples" -PercentComplete (($SampleCounter/$Samples)*100) -ParentId 1
                Write-Verbose -Message "Currently retrieving counter '\Processor(_Total)\% Processor Time' from computer '$Computer'."
                $CounterProcessorPercentageProcessorTime = Get-Counter -Counter "\\$Computer\Processor(_Total)\% Processor Time" -MaxSamples 1 -SampleInterval 1
                $CounterProcessorPercentageProcessorTimeSample = $CounterProcessorPercentageProcessorTime.CounterSamples
                $CounterProcessorPercentageProcessorTimeSampleTimeStamp = $CounterProcessorPercentageProcessorTimeSample.TimeStamp
                $CounterProcessorPercentageProcessorTimeSampleCookedValue = $CounterProcessorPercentageProcessorTimeSample.CookedValue
                Write-Verbose -Message "Currently retrieving counter '\System\Context Switches/sec' from computer '$Computer'."
                $CounterSystemContextSwitches = Get-Counter -Counter "\\$Computer\System\Context Switches/sec" -MaxSamples 1 -SampleInterval 1
                $CounterSystemContextSwitchesSample = $CounterSystemContextSwitches.CounterSamples
                $CounterSystemContextSwitchesSampleTimeStamp = $CounterSystemContextSwitchesSample.TimeStamp
                $CounterSystemContextSwitchesSampleCookedValue = $CounterSystemContextSwitchesSample.CookedValue
                Write-Verbose -Message "Currently retrieving counter '\System\Processor Queue Length' from computer '$Computer'."
                $CounterSystemProcessorQueueLength = Get-Counter -Counter "\\$Computer\System\Processor Queue Length" -MaxSamples 1 -SampleInterval 1
                $CounterSystemProcessorQueueLengthSample = $CounterSystemProcessorQueueLength.CounterSamples
                $CounterSystemProcessorQueueLengthSampleTimeStamp = $CounterSystemProcessorQueueLengthSample.TimeStamp
                $CounterSystemProcessorQueueLengthSampleCookedValue = $CounterSystemProcessorQueueLengthSample.CookedValue
                Write-Verbose -Message "Currently calculating ProcessorUsageHighAboveThreshold for computer '$Computer'."
                if (($CounterProcessorPercentageProcessorTimeSampleCookedValue -gt $CounterProcessorPercentageProcessorTimeThreshold) -and ($CounterSystemContextSwitchesSampleCookedValue -gt $CounterSystemContextSwitchesTreshold) -and ($CounterSystemProcessorQueueLengthSampleCookedValue -gt $CounterSystemProcessorQueueLengthTreshold))
                {
                    $ProcessorUsageHighAboveThreshold = $true
                }
                else
                {
                    $ProcessorUsageHighAboveThreshold = $false
                }
                $CounterResultObject = New-Object -TypeName System.Object 
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $Computer
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "Timestamp(%ProcessorTime)" -Value $CounterProcessorPercentageProcessorTimeSampleTimeStamp
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "%ProcessorTime" -Value $CounterProcessorPercentageProcessorTimeSampleCookedValue
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "Timestamp(ContextSwitches/sec)" -Value $CounterSystemContextSwitchesSampleTimeStamp
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "ContextSwitches/sec" -Value $CounterSystemContextSwitchesSampleCookedValue
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "Timestamp(ProcessorQueueLength)" -Value $CounterSystemProcessorQueueLengthSampleTimeStamp
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "ProcessorQueueLength" -Value $CounterSystemProcessorQueueLengthSampleCookedValue
                $CounterResultObject | Add-Member -MemberType NoteProperty -Name "ProcessorUsageHighAboveThreshold" -Value $ProcessorUsageHighAboveThreshold
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
