<#
.SYNOPSIS
    Function to find files which match a certain name.
.DESCRIPTION
    Function to find files which match a certain name.
.PARAMETER Path
    In the parameter Path you can specify the directory you want to query. This can be both a local or remote (UNC) path.
.PARAMETER SearchString
    In the parameter SearchString you can specify the (partial) filename you want to find.
.PARAMETER Recurse
    When using the switch Recurse the function will also search in subdirectories.
.EXAMPLE
    PS C:\>Find-FSFile -Path C:\Windows -SearchString "exe" -Recurse

    This command will retrieve a list of files in C:\Windows (and subdirectories) which have "exe" in their name.
.NOTES
    Author   : Ingvald Belmans
    Website  : http://www.supersysadmin.com
    Version  : 1.0 
    Changelog:
        - 1.0 (2015-12-24) Initial version.
.LINK
    http://www.supersysadmin.com
#>
function Find-FSFile
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
        $Path,
        [Parameter(
            Mandatory=$true,
            ValueFromPipeline=$true, 
            ValueFromPipelineByPropertyName=$true
            )
        ]
        [String]
        $SearchString,
        [switch]
        $Recurse
    )
    Begin
    {
    }
    Process
    {
        Write-Verbose -Message "Searching for files in '$Path' which match '$SearchString'. Please wait..."
        $SearchResult = @()
        if($Recurse)
        {
            $SearchQuery = Get-ChildItem -Path $Path -File -Recurse | Where-Object -FilterScript { $_.Name -match $SearchString}
        }
        else
        {
            $SearchQuery = Get-ChildItem -Path $Path -File | Where-Object -FilterScript { $_.Name -match $SearchString}
        }
        foreach ($SearchQueryItem in $SearchQuery)
        {
            $SearchResultObject = New-Object -TypeName System.Object 
            $SearchResultObject | Add-Member -MemberType NoteProperty -Name "FileName" -Value $SearchQueryItem.Name
            $SearchResultObject | Add-Member -MemberType NoteProperty -Name "Directory" -Value $SearchQueryItem.Directory
            $SearchResultObject | Add-Member -MemberType NoteProperty -Name "Extension" -Value $SearchQueryItem.Extension
            $SearchResultObject | Add-Member -MemberType NoteProperty -Name "Size(MB)" -Value ($SearchQueryItem.Length/1MB)
            $SearchResultObject | Add-Member -MemberType NoteProperty -Name "LastWriteTime" -Value $SearchQueryItem.LastWriteTime
            $SearchResultObject | Add-Member -MemberType NoteProperty -Name "LastAccessTime" -Value $SearchQueryItem.LastAccessTime  
            $SearchResult += $SearchResultObject
        }
        Write-Output -InputObject $SearchResult
    }    
    End
    {
    }
}
