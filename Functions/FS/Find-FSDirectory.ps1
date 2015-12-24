<#
.SYNOPSIS
    Function to find directories which match a certain name.
.DESCRIPTION
    Function to find directories which match a certain name.
.PARAMETER Path
    In the parameter Path you can specify the directory you want to query. This can be both a local or remote (UNC) path.
.PARAMETER SearchString
    In the parameter SearchString you can specify the (partial) directory you want to find.
.PARAMETER Recurse
    When using the switch Recurse the function will also search in subdirectories.
.EXAMPLE
    PS C:\>Find-FSDirectory -Path C:\Windows -SearchString "System" -Recurse

    This command will retrieve a list of directories in C:\Windows (and subdirectories) which have "System" in their name.
.NOTES
    Author   : Ingvald Belmans
    Website  : http://www.supersysadmin.com
    Version  : 1.0 
    Changelog:
        - 1.0 (2015-12-24) Initial version.
.LINK
    http://www.supersysadmin.com
#>
function Find-FSDirectory
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
        Write-Verbose -Message "Searching for directories in '$Path' which match '$SearchString'. Please wait..."
        $SearchResult = @()
        if($Recurse)
        {
            $SearchQuery = Get-ChildItem -Path $Path -Directory -Recurse | Where-Object -FilterScript { $_.Name -match $SearchString}
        }
        else
        {
            $SearchQuery = Get-ChildItem -Path $Path -Directory | Where-Object -FilterScript { $_.Name -match $SearchString}
        }
        foreach ($SearchQueryItem in $SearchQuery)
        {
            $SearchResultObject = New-Object -TypeName System.Object 
            $SearchResultObject | Add-Member -MemberType NoteProperty -Name "DirectoryName" -Value $SearchQueryItem.Name
            $SearchResultObject | Add-Member -MemberType NoteProperty -Name "FullPath" -Value $SearchQueryItem.FullName
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
