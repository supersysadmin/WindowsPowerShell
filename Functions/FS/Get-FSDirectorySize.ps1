<#
.SYNOPSIS
    Function to retrieve the size of a directory and the number of files and directories inside of it.
.DESCRIPTION
    Function to retrieve the size of a directory and the number of files and directories inside of it.
.PARAMETER Path
    In the parameter Path you can specify the directory you want to query. This can be both a local or remote (UNC) path.
.PARAMETER OutputFormat
    In the parameter OutputFormat you can specify the format in which the directory size should be outputted. Possible formats are KB, MB and GB. The default is GB.
.PARAMETER NoRecurse
    When using the switch NoRecurse the function will only query the directory specified in the Path parameter and will not query child directories and files.
.EXAMPLE
    PS C:\>Get-FSDirectorySize -Path C:\Windows

    This command will retrieve the size (in GB) of the directory C:\Windows and the number of files and directories insides of it.
.NOTES
    Author   : Ingvald Belmans
    Website  : http://www.supersysadmin.com
    Version  : 1.0 
    Changelog:
        - 1.0 (2015-12-31) Initial version.
.LINK
    http://www.supersysadmin.com
#>
function Get-FSDirectorySize
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
        [validateset('KB','MB','GB')]
        [string]
        $OutputFormat = "GB",
        [switch]
        $NoRecurse
    )
    Begin
    {
    }
    Process
    {
        Write-Verbose -Message "Testing if path '$Path' exists."
        if (Test-Path -Path $Path)
        {
            Write-Verbose -Message "Path '$Path' exists."       
            $DirectorySize = @()
            $DirectorySizeObject = New-Object -TypeName System.Object
            if ($NoRecurse)
            {
                Write-Verbose -Message "Performing a non-recursive search on path '$Path'."
                $QueryDirectory = Get-ChildItem -Path $Path -ErrorVariable QueryDirectoryErrors -ErrorAction SilentlyContinue
            }
            else
            {
                Write-Verbose -Message "Performing a recursive search on path '$Path'."
                $QueryDirectory = Get-ChildItem -Path $Path -Recurse -ErrorVariable QueryDirectoryErrors -ErrorAction SilentlyContinue
            }
            foreach ($QueryDirectoryError in $QueryDirectoryErrors)
            {
                Write-Warning -Message $QueryDirectoryError
            }
            $DirectorySizeObject | Add-Member -MemberType NoteProperty -Name "Directory" -Value $Path
            Write-Verbose -Message "Calculating size of path '$Path'."
            $QueryDirectorySize = $QueryDirectory | Measure-Object -Property Length -Sum
            if ($OutputFormat -eq "KB")
            {
                Write-Verbose -Message "Setting OutputFormat to KB."
                $QueryDirectorySizeFormattedHeader = "Size(KB)"
                $QueryDirectorySizeFormatted = "{0:N2}" -f ($QueryDirectorySize.Sum / 1KB)
            }
            elseif ($OutputFormat -eq "MB")
            {
                Write-Verbose -Message "Setting OutputFormat to MB."
                $QueryDirectorySizeFormattedHeader = "Size(MB)"
                $QueryDirectorySizeFormatted = "{0:N2}" -f ($QueryDirectorySize.Sum / 1MB)
            }
            elseif ($OutputFormat -eq "GB")
            {
                Write-Verbose -Message "Setting OutputFormat to GB."
                $QueryDirectorySizeFormattedHeader = "Size(GB)"
                $QueryDirectorySizeFormatted = "{0:N2}" -f ($QueryDirectorySize.Sum / 1GB)
            }
            $DirectorySizeObject | Add-Member -MemberType NoteProperty -Name $QueryDirectorySizeFormattedHeader -Value $QueryDirectorySizeFormatted
            Write-Verbose -Message "Calculating amount of directories in path '$Path'."
            $QueryDirectoryDirectories = $QueryDirectory | Where-Object -FilterScript {$_.PSIsContainer -eq $true}
            $DirectorySizeObject | Add-Member -MemberType NoteProperty -Name "Directories" -Value $QueryDirectoryDirectories.Count
            Write-Verbose -Message "Calculating amount of files in path '$Path'."
            $QueryDirectoryFiles = $QueryDirectory | Where-Object -FilterScript {$_.PSIsContainer -eq $false}
            $DirectorySizeObject | Add-Member -MemberType NoteProperty -Name "Files" -Value $QueryDirectoryFiles.Count
            $DirectorySize += $DirectorySizeObject
            Write-Output -InputObject $DirectorySize
        }
        else
        {
            Write-Warning -Message "Path '$path' does not exist."
            break
        }
    }    
    End
    {
    }
}
