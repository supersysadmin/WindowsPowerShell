<#
.SYNOPSIS
    Function to retrieve a list of files in a directory which are bigger than a given size.
.DESCRIPTION
    Function to retrieve a list of files in a directory which are bigger than a given size.
.PARAMETER Path
    In the parameter Path you can specify the directory you want to query. This can be both a local or remote (UNC) path.
.PARAMETER MinimumSize
    In the parameter MinimumSize you can specify the minimum size of the files you want to search for.
.PARAMETER Recurse
    When using the switch Recurse the function will also search in subdirectories.
.EXAMPLE
    PS C:\>Search-FSBiggestFiles -Path C:\Temp -MinimumSize 1MB -Recurse

    This command retrieves a list of files from C:\Temp and its subdirectories with a size of 1MB or more.
.NOTES
    Author   : Ingvald Belmans
    Website  : http://www.supersysadmin.com
    Version  : 1.0 
    Changelog:
        - 1.0 (2015-12-23) Initial version.
.LINK
    http://www.supersysadmin.com
#>
function Search-FSBiggestFiles
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
            Mandatory=$true
            )
        ]
        [string]
        $MinimumSize,
        [switch]
        $Recurse
    )
    Begin
    {        
    }
    Process
    {
        Write-Verbose -Message "Querying '$Path'. Please wait..."
        $SearchResult = @()
        if($Recurse)
        {
            $SearchQuery = Get-ChildItem -Path $Path -File -Recurse | Where-Object -FilterScript {($_.Length) -ge $MinimumSize}
        }
        else
        {
            $SearchQuery = Get-ChildItem -Path $Path -File | Where-Object -FilterScript {($_.Length) -ge $MinimumSize}
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
        Write-Output $SearchResult
    }    
    End
    {
    }
}
