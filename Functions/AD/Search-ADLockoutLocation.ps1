<#
.SYNOPSIS
    Function to find the location (computer) where an Active Directory user was locked out.
.DESCRIPTION
    In case an Active Directory user gets frequently locked out, you can use this function to check on which computer the lockout occurs. It does so by querying the Security Event Logs of the Domain Controllers. Once you have determined on which computer the lockout occurs, you still need to determine what exactly is causing the account lockout. This can be manual drive mapping, a service running under the user account, an ODBC connection, etc.
.PARAMETER UserName
    In the parameter UserName you can specify the Active Directory user for which you want to find on which computer it was locked out. You need to specify the SamAccountName of the user.
.EXAMPLE
    PS C:\>Search-ADLockoutLocation -UserName user1

    This command will search for the location where user1 was locked out.
.NOTES
    Author   : Ingvald Belmans
    Website  : http://www.supersysadmin.com
    Version  : 1.0 
    Changelog:
        - 1.0 (2015-12-30) Initial version.
.LINK
    http://www.supersysadmin.com
#>
function Search-ADLockoutLocation
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
        [String]
        $UserName
    )
    Begin
    {
        Write-Verbose -Message "Checking if module 'ActiveDirectory' is loaded."
        if ((Get-Module -name 'ActiveDirectory') -eq $null) 
        { 
            Write-Verbose -Message "Module 'ActiveDirectory' is currently not loaded."	
	        if(Get-Module -ListAvailable | Where-Object { $_.name -eq 'ActiveDirectory' }) 
            { 
		        Write-Verbose -Message "Module 'ActiveDirectory' is available, importing it."
                Import-Module -Name 'ActiveDirectory'
    		    if ((Get-Module -name 'ActiveDirectory') -ne $null)
		        {
			        Write-Verbose -Message "Module 'ActiveDirectory' has been loaded now."
		        }
		        else
		        {
		            Write-Warning -Message "Module 'ActiveDirectory' could not be loaded. Script will exit."
		            break
		        }
            } 
            else
	        {
	            Write-Warning -Message "Module 'ActiveDirectory' is not available on this system. Script will exit."
		        break
	        }
        }
        else
        {
            Write-Verbose -Message "Module 'ActiveDirectory' is already loaded."
	    }
    }
    Process
    {
        Write-Verbose -Message "Searching in Active Directory for user '$UserName'."
        $QueryLockedUser = Get-ADUser -Filter "(SamAccountName -eq '$UserName')"
        if ($QueryLockedUser -eq $null)
        {
            Write-Warning -Message "Did not find any Active Directory user with username '$UserName'. Please ensure you are searching on the correct username (SamAccountName). Script will now exit."
            break
        }
        else
        {
            $LockoutEvents = @()
            Write-Verbose -Message "Retrieving list of all Domain Controllers."
            $DomainControllers = Get-ADDomainController -Filter *
            foreach ($DomainController in $DomainControllers)
            {
                Write-Verbose -Message "Querying Domain Controller '$DomainController'."
                Write-Verbose -Message "Checking if Domain Controller '$DomainController' is the PDC Emulator."
                if ($DomainController.OperationMasterRoles -contains "PDCEmulator")
                {
                    Write-Verbose -Message "Domain Controller '$DomainController' is the PDC Emulator."
                    $DomainControllerPDCEmulator = "Yes"
                }
                else
                {
                    Write-Verbose -Message "Domain Controller '$DomainController' is not the PDC Emulator."
                    $DomainControllerPDCEmulator = "No"
                }
                Write-Verbose -Message "Retrieving user information for user '$UserName' from Domain Controller '$DomainController'."                
                $QueryADUser = Get-ADUser -Filter "(SamAccountName -eq '$UserName')" -Properties * -Server $DomainController
                Write-Verbose -Message "Querying the Security Event Log of Domain Controller'$DomainController' for events with ID 4740."               
                
                try
                {
                    $QueryDomainControllerEventLog = Get-WinEvent -ComputerName $DomainController -FilterHashtable @{LogName='Security';Id=4740} -ErrorAction Stop
                }
                catch [exception]
                {
                    if ($_.Exception -match "No events were found that match the specified selection criteria")
                    {
                        Write-Verbose -Message "Did not find any event with ID 4740 in the Security Event Log of Domain Controller '$DomainController'."
                    }                    
                }
                foreach ($LockoutEvent in $QueryDomainControllerEventLog)
                {
                    Write-Verbose -Message "Found event with ID 4740 on Domain Controller '$DomainController'."
                    $LockoutEventXML = [xml]$LockoutEvent.ToXml()
                    $LockoutEventXMLEventLogTime = $LockoutEventXML.Event.System.TimeCreated.SystemTime
                    $LockoutEventXMLLockoutLocation = $LockoutEventXML.Event.EventData.Data[1].'#text'
                    $LockoutEventXMLSID = $LockoutEventXML.Event.EventData.Data[2].'#text'
                    if ($QueryADUser.SID.Value -match $LockoutEventXMLSID)
                    {
                        Write-Verbose -Message "Found event with ID 4740 in the Security Event Log of Domain Controller '$DomainController' which refers to user '$UserName'."
                        $LockoutEventsObject = New-Object -TypeName System.Object
                        $LockoutEventsObject | Add-Member -MemberType NoteProperty -Name "DomainController" -Value $DomainController.HostName
                        $LockoutEventsObject | Add-Member -MemberType NoteProperty -Name "PDCEmulator" -Value $DomainControllerPDCEmulator
                        $LockoutEventsObject | Add-Member -MemberType NoteProperty -Name "SamAccountName" -Value $QueryADUser.SamAccountName
                        $LockoutEventsObject | Add-Member -MemberType NoteProperty -Name "LockedOut" -Value $QueryADUser.LockedOut
                        $LockoutEventsObject | Add-Member -MemberType NoteProperty -Name "EventLogTime" -Value $LockoutEventXMLEventLogTime
                        $LockoutEventsObject | Add-Member -MemberType NoteProperty -Name "LockoutLocation" -Value $LockoutEventXMLLockoutLocation
                        $LockoutEvents += $LockoutEventsObject
                    }
                    else
                    {
                        Write-Verbose -Message "Found event with ID 4740 in the Security Event Log of Domain Controller '$DomainController', but it does not refer to user '$UserName'."
                    }                   
                }
            }
            if ($LockoutEvents.Count -eq '0')
            {
                Write-Verbose -Message "Did not find any event with ID 4740 in the Security Event Log of any Domain Controller that refer to user '$UserName'."
            }
            else
            {
                Write-Output -InputObject $LockoutEvents | Sort-Object EventLogTime -Descending
            }
        }
    }
    End
    {
    }
}
