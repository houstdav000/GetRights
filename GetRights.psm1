# GetRights.psm1
#
# Public Functions

Function Get-RightsOwner {
    Param([string] $Path = '.')

    return (Get-Acl -Path $Path).Owner
}

Function Get-RightsTable {
    Param(
        [string] $Path = '.',
        [string[]] $User
        )

    $rights = Get-RightsUser -Path $Path -User $User

    $rightsTable = New-Object System.Collections.ArrayList
    foreach ($UserObj in $User) {
        $rightsObj = New-Object PSObject
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'User' -Value $right.User
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'FullControl' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'TakeOwnerShip' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'ChangePermissions' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'ReadPermissions' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'Delete' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'WriteAttributes' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'ReadAttributes' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'DeleteSubDirectoriesAndFiles' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'ExecuteFile' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'WriteExtendedAttributes' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'ReadExtendedAttribtes' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'AppendData' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'WriteData' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'ReadData' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'Synchronize' -Value $false
        $rightsTable.Add($rightObj) > $null
    }

    # Parse statements
    foreach ($right in $rights) {
        $user = $right.User
        foreach ($ace in $right.ACL) {
            if ($ace.AccessControlType -eq 'Allow') {
                $fileRights = $ace.FileSystemRights.toString().Split() -replace '[,]',''

                foreach ($fileRight in $fileRights) {
                    switch ($fileRight) {
                        "FullControl" {

                        }
                    }
                }
            }
        }
    }
}

Function Get-RightsUser {
    Param(
        [string] $Path = '.',
        [string[]] $User
        )

    # Create array of Rights objects
    $rights = New-Object System.Collections.ArrayList

    $acl = Get-Acl -Path $Path

    # Check each acl for users
    foreach ($ace in $acl.Access) {
        $newRight = $null
        $created = $false

        # Check for existing User in rights array
        foreach ($right in $rights) {
            if ($right.User -eq $ace.IdentityReference.toString()) {
                $newRight = $right
            }
        }
        
        # Create new rights object if user is to be captured, and there isn't one already
        if (($User -contains $ace.IdentityReference.toString()) -and ($newRight -eq $null)) {
            $created = $true
            $newRight = New-Object PSObject
            $AllowList = New-Object System.Collections.ArrayList
            $DenyList = New-Object System.Collections.ArrayList
            
            $fileRights = $ace.FileSystemRights.toString().Split() -replace '[,]',''

            foreach ($fileRight in $fileRights) {
                if (($ace.AccessControlType.toString() -eq 'Allow') -and (-not ($AllowList -contains $fileRight))) {
                    $AllowList.Add($fileRight) > $null
                } elseif (-not ($DenyList -contains $fileRight)) {
                    $DenyList.Add($fileRight) > $null
                }
            }

            Add-Member -InputObject $newRight -MemberType NoteProperty -Name 'User' -Value $ace.IdentityReference.toString()
            Add-Member -InputObject $newRight -MemberType NoteProperty -Name 'Allow' -Value $AllowList
            Add-Member -InputObject $newRight -MemberType NoteProperty -Name 'Deny' -Value $DenyList
        } elseif ($newRight -ne $null) {
            $fileRights = $ace.FileSystemRights.toString().Split() -replace '[,]',''

            foreach ($fileRight in $fileRights) {
                if (($ace.AccessControlType.toString() -eq 'Allow') -and (-not ($newRight.Allow -contains $fileRight))) {
                    $newRight.Allow.Add($fileRight) > $null
                } elseif (-not ($newRight.Deny -contains $fileRight)) {
                    $newRight.Deny.Add($fileRight) > $null
                }
            }
        }
            
        # If the right existed, or we created one, add it to the list
        if ($created) {
            $rights.Add($newRight) > $null
        }
    }

    return $rights
}

Export-ModuleMember -Function 'Get-*'
