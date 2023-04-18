# Invoke-ADEnum
Active Directory Enumerator
Automate Active Directory Enumeration using PowerView

.PARAMETER `Domain`
The Domain to enumerate for (requires you specify a Server)

.PARAMETER `Server`
The DC to bind to (requires you specify a Domain)

.EXAMPLE - Run for each domain the tool will find
```
Invoke-ADEnum
```

.EXAMPLE - Run for a specific Domain/DC
```
Invoke-ADEnum -Domain <domain FQDN> -Server <DC FQDN or IP>
```
