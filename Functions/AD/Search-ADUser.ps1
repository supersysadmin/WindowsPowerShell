<#
.SYNOPSIS
    Function to search users in Active Directory.
.DESCRIPTION
    Function to search users in Active Directory.
.PARAMETER SearchQuery
    In the parameter SearchQuery you can specify on what you want to search. You can search on multiple search strings in 1 query.
.PARAMETER SearchType
    In the parameter SearchType you can specify on which property of the user you want to perform your search query. Possbile types are UserName (searches in SamAccountName), Name (searches in GivenName, SurName and DisplayName) and EmailAddress. The default is UserName.
.PARAMETER Domain
    In the parameter Domain you can specify in which domain you want to search. If not specified, it uses a Get-ADDomain query to get the current domain name.
.EXAMPLE
    PS C:\>Search-ADUser -SearchQuery user1

    This command will search for users which have user1 in their UserName in the current domain.
.EXAMPLE
    PS C:\>Search-ADUser -SearchQuery John -SearchType EmailAddress -Domain example.com

    This command will search for users which have John in their EmailAddress in the domain example.com.
.NOTES
    Author   : Ingvald Belmans
    Website  : http://www.supersysadmin.com
    Version  : 1.0 
    Changelog:
        - 1.0 (2015-12-25) Initial version.
.LINK
    http://www.supersysadmin.com
#>
function Search-ADUser
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
        $SearchQuery,
        [validateset('UserName','Name','EmailAddress')]
        [string]
        $SearchType = "UserName",
	    [string]
        $Domain = (Get-ADDomain).Forest
    )
    Begin
    {
        Write-Verbose -Message "Checking module 'ActiveDirectory'."
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
        $SearchResult = @()
        foreach ($SearchQueryItem in $SearchQuery)
        {
            if ($SearchType -eq 'UserName')
            {
                $ADQuery = Get-ADUser -Filter "SamAccountName -like '*$SearchQueryItem*'" -Server $Domain -Properties *
                Write-Verbose -Message "Searching for users in the domain '$Domain' which have '$SearchQueryItem' in their 'UserName'. Please wait..."
            
            }
            elseif ($SearchType -eq 'Name')
            {
                $ADQuery = Get-ADUser -Filter "(GivenName -like '*$SearchQueryItem*') -or (SurName -like '*$SearchQueryItem*') -or (DisplayName -like '*$SearchQueryItem*')" -Server $Domain -Properties *
                Write-Verbose -Message "Searching for users in the domain '$Domain' which have '$SearchQueryItem' in their 'GivenName, SurName or DisplayName'. Please wait..."
            }
            elseif ($SearchType -eq 'EmailAddress')
            {
                $ADQuery = Get-ADUser -Filter "EmailAddress -like '*$SearchQueryItem*'" -Server $Domain -Properties *
                Write-Verbose -Message "Searching for users in the domain '$Domain' which have '$SearchQueryItem' in their 'EmailAddress'. Please wait..."
            } 
            foreach ($Result in $ADQuery)
            {
                $SearchResultObject = New-Object -TypeName System.Object 
                $SearchResultObject | Add-Member -MemberType NoteProperty -Name "SamAccountName" -Value $Result.SamAccountName
                $SearchResultObject | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $Result.DisplayName
                $SearchResultObject | Add-Member -MemberType NoteProperty -Name "GivenName" -Value $Result.GivenName
                $SearchResultObject | Add-Member -MemberType NoteProperty -Name "SurName" -Value $Result.SurName
                $SearchResultObject | Add-Member -MemberType NoteProperty -Name "EmailAddress" -Value $Result.EmailAddress
                $SearchResultObject | Add-Member -MemberType NoteProperty -Name "HomeDirectory" -Value $Result.HomeDirectory
                $SearchResultObject | Add-Member -MemberType NoteProperty -Name "DistinguishedName" -Value $Result.DistinguishedName
                $SearchResultObject | Add-Member -MemberType NoteProperty -Name "Enabled" -Value $Result.Enabled
                $SearchResultObject | Add-Member -MemberType NoteProperty -Name "LockedOut" -Value $Result.LockedOut
                $SearchResult += $SearchResultObject            
            }
        }
        Write-Output $SearchResult        
    }    
    End
    {
    }
}
