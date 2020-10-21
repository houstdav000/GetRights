# GetRights.psm1
#
# Public Functions

Function Get-RightsOwner {
    Param([string] $Path = '.')

    return (Get-Acl -Path $Path).Owner
}

<#
Function Get-RightsTable {
    Param(
        [string] $Path = '.',
        [string[]] $User
        )

    $rights = Get-RightsUser -Path $Path -User $User

    $rightsTable = System.Collections.ArrayList
    foreach ($UserObj in $User) {
        $rightsObj = New-Object PSObject
        Add-Member -InputObject $rightsObj -Membertype Property -Name User -Value $right.User
        Add-Member -InputObject $rightsObj -Membertype Property -Name "FullControl" -Value $false
        Add-Member -InputObject $rightsObj -Membertype Property -Name "TakeOwnerShip" -Value $false
        Add-Member -InputObject $rightsObj -Membertype Property -Name "ChangePermissions" -Value $false
        Add-Member -InputObject $rightsObj -Membertype Property -Name "ReadPermissions" -Value $false
        Add-Member -InputObject $rightsObj -Membertype Property -Name "Delete" -Value $false
        Add-Member -InputObject $rightsObj -Membertype Property -Name "WriteAttributes" -Value $false
        Add-Member -InputObject $rightsObj -Membertype Property -Name "ReadAttributes" -Value $false
        Add-Member -InputObject $rightsObj -Membertype Property -Name "DeleteSubDirectoriesAndFiles" -Value $false
        Add-Member -InputObject $rightsObj -Membertype Property -Name "ExecuteFile/Traverse" -Value $false
        Add-Member -InputObject $rightsObj -Membertype Property -Name "WriteExtendedAttributes" -Value $false
        Add-Member -InputObject $rightsObj -Membertype Property -Name "ReadExtendedAttribtes" -Value $false
        Add-Member -InputObject $rightsObj -Membertype Property -Name "CreateDirectories/AppendData" -Value $false
        Add-Member -InputObject $rightsObj -Membertype Property -Name "WriteData/CreateFiles" -Value $false
        Add-Member -InputObject $rightsObj -Membertype Property -Name "ReadDataListDirectory/ReadData" -Value $false
        $rightTable.Add($rightObj)
    }

    # Parse Allow statements
    foreach ($right in $rights) {
        if ($right.AccessControlType -eq "Allow"){
            switch ($right.FileSystemRights) {
                "FullControl" {
                    $rightsObj.FullControl = $true
                    $rightsObj.TakeOwnership = $true
                }
            }
        }
    }
}
#>

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

        # Check for existing User in rights array
        foreach ($right in $rights) {
            if ($right.User -eq $ace.IdentityReference) {
                $newRight = $right
            }
        }
        
        # Create new rights object if user is to be captured, and there isn't one already
        if (($User -contains $ace.IdentityReference) -and ($newRight -eq $null)) {
            $newRight = New-Object PSObject
            $ArrayList = New-Object System.Collections.ArrayList
            $returnCode = $ArrayList.Add($ace)
            if ($returnCode -ne 0) {
                Write-Host "Error in adding to array"
            }
            Add-Member -InputObject $newRight -Membertype NoteProperty -Name User -Value $ace.IdentityReference
            Add-Member -InputObject $newRight -Membertype NoteProperty -Name ACL -Value $ArrayList
        } elseif ($newRight -ne $null) {
            $returnCode = $newRight.ACL.Add($ace)
            if ($returnCode -ne 0) {
                Write-Host "Error in adding to array"
            }
        }
            
        # If the right existed, or we created one, add it to the list
        if ($newRight -ne $null) {
            $returnCode = $rights.Add($newRight)
            if ($returnCode -ne 0) {
                Write-Host "Error in adding to array"
            }
        }
    }

    return $rights
}

Export-ModuleMember -Function 'Get-*'
