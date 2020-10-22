# PowerShell_Get-Rights

A PowerShell project to expand on Get-Acl.

This PowerShell Script Module exposes three functions:

- Get-RightsOwner
- Get-RightsUser
- Get-RightsTable

## `Get-RightsOwner`

It's nothing too special, just getting the Owner of a particular file

```PowerShell
Get-RightsOwner -Path ./README.md
```

Output:

```txt
DH-LAPTOP2\david
```

## `Get-RightsUser`

A bit more special, we get the ACL of the file, and play around with the ACEs to get an object consisting of a given User, and a list of `Allow` permissions and a list of `Deny` permissions:

```PowerShell
Get-RightsUser -Path ./README.md -User 'DH-LAPTOP2\david','BUILTIN\Administrators'
```

Output:

```txt
User                   Allow                                               Deny
----                   -----                                               ----
BUILTIN\Administrators {FullControl}                                       {}
DH-LAPTOP2\david       {WriteAttributes, Read, TakeOwnership, Synchronize} {}
```

## `Get-RightsTable`

Here we have some fun: Taking that output from `Get-RightsUser` and looking up what effectively those permissions result in, getting a table.

```PowerShell
Get-RightsTable -Path ./README.md -User 'DH-LAPTOP2\david','BUILTIN\Administrators'
```

Output:

```
User                         : BUILTIN\Administrators
FullControl                  : True
TakeOwnership                : True
ChangePermissions            : True
ReadPermissions              : True
Delete                       : True
WriteAttributes              : True
ReadAttributes               : True
DeleteSubdirectoriesAndFiles : True
ExecuteFile                  : True
WriteExtendedAttributes      : True
ReadExtendedAttributes       : True
AppendData                   : True
CreateFiles                  : True
ReadData                     : True
Synchronize                  : True

User                         : DH-LAPTOP2\david
FullControl                  : False
TakeOwnership                : True
ChangePermissions            : False
ReadPermissions              : True
Delete                       : False
WriteAttributes              : True
ReadAttributes               : True
DeleteSubdirectoriesAndFiles : False
ExecuteFile                  : False
WriteExtendedAttributes      : False
ReadExtendedAttributes       : True
AppendData                   : False
CreateFiles                  : False
ReadData                     : True
Synchronize                  : True
```

I originally meant for this to output to a table, but might have to create a formatter script to do that.

## References

For their amazing graphic chart on NTFS permissions, Ryan S White with Code Project:
[https://www.codeproject.com/Reference/871338/AccessControl-FileSystemRights-Permissions-Table](https://www.codeproject.com/Reference/871338/AccessControl-FileSystemRights-Permissions-Table)

To help with understanding the basics of writing a PowerShell Script Module, Get-ChildItemColor:
[https://github.com/joonro/Get-ChildItemColor](https://github.com/joonro/Get-ChildItemColor)
