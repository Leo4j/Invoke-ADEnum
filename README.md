# Invoke-ADEnum
Active Directory Enumerator - Automate Active Directory Enumeration using PowerView

.PARAMETER `Domain` (not mandatory)
The Domain to enumerate for (it will attempt to retrieve the Master DC for the specified domain - if it fails, it will prompt the user to specify a domain controller)
If not specified, the tool will enumerate for all the domains it can find

.PARAMETER `Server` (not mandatory)
The DC to bind to (requires you specify a Domain)

.PARAMETER `Output` (not mandatory)
Specify where to save the output from the tool (default is pwd)

.SWITCH `NoServers`
Do not enumerate for Servers

.SWITCH `NoWorkstations`
Do not enumerate for Workstations

.SWITCH `NoUnsupportedOS`
Do not enumerate for machines running unsupported OS

.SWITCH `NoUsers`
Do not enumerate for Users

.SWITCH `NoShares`
Do not enumerate for Shares

.SWITCH `NoLocalAdminAccess`
Do not enumerate for LocalAdminAccess

.SWITCH `NoACLs`
Do not enumerate for ACLs

.SWITCH `NoGPOs`
Do not enumerate for GPOs

.SWITCH `NoFindDomainUserLocation`
Do not enumerate for FindDomainUserLocation

Run as follows:
```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Invoke-ADEnum/main/Invoke-ADEnum.ps1')
```

.EXAMPLE - Run for each domain the tool can find
```
Invoke-ADEnum
```

.EXAMPLE - Run for a specific Domain/DC
```
Invoke-ADEnum -Domain <domain FQDN> -Server <DC FQDN or IP>
```

.EXAMPLE - Run for each domain the tool can find and save output to C:\Windows\Temp\Invoke-ADEnum.txt
```
Invoke-ADEnum -Output C:\Windows\Temp\Invoke-ADEnum.txt
```

.EXAMPLE - Run for each domain the tool can find but do not enumerate for Workstations and Servers
```
Invoke-ADEnum -NoWorkstations -NoServers
```
