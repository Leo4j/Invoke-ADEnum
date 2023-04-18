# Invoke-ADEnum
Active Directory Enumerator - Automate Active Directory Enumeration using PowerView

.PARAMETER `Domain`
The Domain to enumerate for (requires you specify a Server)

.PARAMETER `Server`
The DC to bind to (requires you specify a Domain)

.PARAMETER `Output`
Specify where to save the output from the tool (default is pwd)

.SWITCH NoServers
Do not enumerate for Servers

.SWITCH NoWorkstations
Do not enumerate for Workstations

.SWITCH NoShares
Do not enumerate for Shares

.SWITCH NoLocalAdminAccess
Do not enumerate for LocalAdminAccess

.SWITCH NoACLs
Do not enumerate for ACLs

.SWITCH NoGPOs
Do not enumerate for GPOs

.SWITCH NoFindDomainUserLocation
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
