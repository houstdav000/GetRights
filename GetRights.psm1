# GetRights.psm1
#
# Public Functions

Function Get-RightsOwner {
    Param([string] $Path = '.')

    return (Get-Acl -Path $Path).Owner
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

Function Get-RightsTable {
    Param(
        [string] $Path = '.',
        [string[]] $User
        )

    $rights = Get-RightsUser -Path $Path -User $User

    $rightsTable = New-Object System.Collections.ArrayList

    # Parse statements
    foreach ($right in $rights) {
        # Create an object to store the rights as a table
        $rightsObj = New-Object PSObject
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'User' -Value $right.User
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'FullControl' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'TakeOwnership' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'ChangePermissions' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'ReadPermissions' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'Delete' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'WriteAttributes' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'ReadAttributes' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'DeleteSubdirectoriesAndFiles' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'ExecuteFile' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'WriteExtendedAttributes' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'ReadExtendedAttributes' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'AppendData' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'CreateFiles' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'ReadData' -Value $false
        Add-Member -InputObject $rightsObj -Membertype NoteProperty -Name 'Synchronize' -Value $false
        
        # Switch to turn on all Allow rights
        foreach ($fileRight in $right.Allow) {
            switch ($fileRight) {
                'Write' {
                    $rightsObj.WriteAttributes = $true
                    $rightsObj.WriteExtendedAttributes = $true
                    $rightsObj.AppendData = $true
                    $rightsObj.CreateFiles = $true
                }
                'Read' {
                    $rightsObj.ReadPermissions = $true
                    $rightsObj.ReadAttributes = $true
                    $rightsObj.ReadExtendedAttributes = $true
                    $rightsObj.ReadData = $true
                }
                'ReadAndExecute' {
                    $rightsObj.ReadPermissions = $true
                    $rightsObj.ReadAttributes = $true
                    $rightsObj.ExecuteFile = $true
                    $rightsObj.ReadExtendedAttributes = $true
                    $rightsObj.ReadData = $true
                }
                'Modify' {
                    $rightsObj.ReadPermissions = $true
                    $rightsObj.Delete = $true
                    $rightsObj.WriteAttributes = $true
                    $rightsObj.ReadAttributes = $true
                    $rightsObj.ExecuteFile = $true
                    $rightsObj.WriteExtendedAttributes = $true
                    $rightsObj.ReadExtendedAttributes = $true
                    $rightsObj.AppendData = $true
                    $rightsObj.CreateFiles = $true
                    $rightsObj.ReadData = $true
                }
                'FullControl' {
                    $rightsObj.FullControl = $true
                    $rightsObj.TakeOwnership = $true
                    $rightsObj.ChangePermissions = $true
                    $rightsObj.ReadPermissions = $true
                    $rightsObj.Delete = $true
                    $rightsObj.WriteAttributes = $true
                    $rightsObj.ReadAttributes = $true
                    $rightsObj.DeleteSubdirectoriesAndFiles = $true
                    $rightsObj.ExecuteFile = $true
                    $rightsObj.WriteExtendedAttributes = $true
                    $rightsObj.ReadExtendedAttributes = $true
                    $rightsObj.AppendData = $true
                    $rightsObj.CreateFiles = $true
                    $rightsObj.ReadData = $true
                    $rightsObj.Synchronize = $true
                }
                'TakeOwnership' {
                    $rightsObj.TakeOwnership = $true
                }
                'ChangePermissions' {
                    $rightsObj.ChangePermissions = $true
                }
                'ReadPermissions' {
                    $rightsObj.ReadPermissions = $true
                }
                'Delete' {
                    $rightsObj.Delete = $true
                }
                'WriteAttributes' {
                    $rightsObj.WriteAttributes = $true
                }
                'ReadAttributes' {
                    $rightsObj.ReadAttributes = $true
                }
                'DeleteSubdirectoriesAndFiles' {
                    $rightsObj.DeleteSubdirectoriesAndFiles = $true
                }
                'ExecuteFile' {
                    $rightsObj.ExecuteFile = $true
                }
                'WriteExtendedAttributes' {
                    $rightsObj.WriteExtendedAttributes = $true
                }
                'ReadExtendedAttributes' {
                    $rightsObj.ReadExtendedAttributes = $true
                }
                'AppendData' {
                    $rightsObj.AppendDate = $true
                }
                'CreateFiles' {
                    $rightsObj.CreateFiles = $true
                }
                'ReadData' {
                    $rightsObj.ReadData = $true
                }
                'Synchronize' {
                    $rightsObj.Synchronize = $true
                }
            }
        }

        # Switch to turn off all Deny rights
        foreach ($fileRight in $right.Deny) {
            switch ($fileRight) {
                'Write' {
                    $rightsObj.WriteAttributes = $false
                    $rightsObj.WriteExtendedAttributes = $false
                    $rightsObj.AppendData = $false
                    $rightsObj.CreateFiles = $false
                }
                'Read' {
                    $rightsObj.ReadPermissions = $false
                    $rightsObj.ReadAttributes = $false
                    $rightsObj.ReadExtendedAttributes = $false
                    $rightsObj.ReadData = $false
                }
                'ReadAndExecute' {
                    $rightsObj.ReadPermissions = $false
                    $rightsObj.ReadAttributes = $false
                    $rightsObj.ExecuteFile = $false
                    $rightsObj.ReadExtendedAttributes = $false
                    $rightsObj.ReadData = $false
                }
                'Modify' {
                    $rightsObj.ReadPermissions = $false
                    $rightsObj.Delete = $false
                    $rightsObj.WriteAttributes = $false
                    $rightsObj.ReadAttributes = $false
                    $rightsObj.ExecuteFile = $false
                    $rightsObj.WriteExtendedAttributes = $false
                    $rightsObj.ReadExtendedAttributes = $false
                    $rightsObj.AppendData = $false
                    $rightsObj.CreateFiles = $false
                    $rightsObj.ReadData = $false
                }
                'FullControl' {
                    $rightsObj.FullControl = $false
                    $rightsObj.TakeOwnership = $false
                    $rightsObj.ChangePermissions = $false
                    $rightsObj.ReadPermissions = $false
                    $rightsObj.Delete = $false
                    $rightsObj.WriteAttributes = $false
                    $rightsObj.ReadAttributes = $false
                    $rightsObj.DeleteSubdirectoriesAndFiles = $false
                    $rightsObj.ExecuteFile = $false
                    $rightsObj.WriteExtendedAttributes = $false
                    $rightsObj.ReadExtendedAttributes = $false
                    $rightsObj.AppendData = $false
                    $rightsObj.CreateFiles = $false
                    $rightsObj.ReadData = $false
                    $rightsObj.Synchronize = $false
                }
                'TakeOwnership' {
                    $rightsObj.TakeOwnership = $false
                }
                'ChangePermissions' {
                    $rightsObj.ChangePermissions = $false
                }
                'ReadPermissions' {
                    $rightsObj.ReadPermissions = $false
                }
                'Delete' {
                    $rightsObj.Delete = $false
                }
                'WriteAttributes' {
                    $rightsObj.WriteAttributes = $false
                }
                'ReadAttributes' {
                    $rightsObj.ReadAttributes = $false
                }
                'DeleteSubdirectoriesAndFiles' {
                    $rightsObj.DeleteSubdirectoriesAndFiles = $false
                }
                'ExecuteFile' {
                    $rightsObj.ExecuteFile = $false
                }
                'WriteExtendedAttributes' {
                    $rightsObj.WriteExtendedAttributes = $false
                }
                'ReadExtendedAttributes' {
                    $rightsObj.ReadExtendedAttributes = $false
                }
                'AppendData' {
                    $rightsObj.AppendDate = $false
                }
                'CreateFiles' {
                    $rightsObj.CreateFiles = $false
                }
                'ReadData' {
                    $rightsObj.ReadData = $false
                }
                'Synchronize' {
                    $rightsObj.Synchronize = $false
                }
            }
        }

        $rightsTable.Add($rightsObj) > $null
    }
    
    return $rightsTable
}

Export-ModuleMember -Function 'Get-*'
