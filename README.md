# Invoke-ADEnum
Active Directory Enumerator - Automate Active Directory Enumeration using PowerView

.PARAMETER `Domain`
The Domain to enumerate for (requires you specify a Server)

.PARAMETER `Server`
The DC to bind to (requires you specify a Domain)

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
