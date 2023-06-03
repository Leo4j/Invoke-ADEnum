# Invoke-ADEnum
Active Directory Enumeration

Invoke-ADEnum is an Active Directory enumeration tool designed to automate the process of gathering information from an Active Directory environment, leveraging the capabilities of PowerView.

With Invoke-ADEnum, you can quickly and efficiently enumerate various aspects of Active Directory, including forests, domains, trusts, domain controllers, users, groups, computers, shares, ACLs, OUs, GPOs, and more.

One of the features of Invoke-ADEnum is its ability to generate an Active Directory Audit Report in HTML format. Whether performing security assessments, compliance audits, or general Active Directory enumeration tasks, the report will provide a detailed overview of the Active Directory infrastructure, in an easy-to-navigate layout.

Invoke-ADEnum is a tool for any IT professional working with Active Directory.

PARAMETERS:

`-Domain <domain FQDN>`           The Domain to enumerate for. If not specified, the tool will enumerate for all the domains it can find

`-Server <DC FQDN or IP>`         The DC to bind to (requires you specify a Domain)

`-Output <path-on-disk>`          Specify where to save the output from the tool (default is pwd)         `-Output C:\Windows\Temp\Invoke-ADEnum.txt`

`-Exclude <domain FQDN>`          Exclude one or more domains from enumeration                            `-Exclude contoso.local,ad.example.org`

`-CustomURL <URL>`                Specify the Server URL where you're hosting PowerView.ps1               `-CustomURL http://yourserver.com/Tools/PowerView.ps1`

`-Local <path-on-disk>`           Specify the local path to PowerView.ps1                                 `-Local c:\Windows\Temp\PowerView.ps1`


+++> NOTE: If you use -CustomURL or -Local parameters you'll have to bypass AMSI manually <+++


SWITCHES:

`-TargetsOnly`                    Show only Target Domains

`-NoServers`                      Do not enumerate for Servers

`-Workstations`                   Enumerate for Workstations

`-NoUnsupportedOS`                Do not enumerate for machines running unsupported OS

`-DomainUsers`                    Enumerate for Users

`-Shares`                         Enumerate for Shares

`-FindLocalAdminAccess`           Enumerate for Machines where the Current User is Local Admin

`-DomainACLs`                     Enumerate for Domain ACLs

`-NoGPOs`                         Do not enumerate for GPOs and Who can Modify/Link them

`-MoreGPOs`                       More enumeration leveraging GPOs

`-NoLAPS`                         Do not enumerate for LAPS GPO

`-NoAppLocker`                    Do not enumerate for AppLocker GPO

`-NoVulnCertTemplates`            Do not enumerate for Misconfigured Certificate Templates

`-DomainOUs`                      Enumerate for Organizational Units

`-MoreOUs`                        More enumeration leveraging Organizational Units

`-FindDomainUserLocation`         Enumerate for Machines where Domain Admins are Logged into

`-AllGroups`                      Enumerate for All Domain Groups

`-Help`                           Show the Help page


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


![2023-06-03_15-27](https://github.com/Leo4j/Invoke-ADEnum/assets/61951374/b1f72991-2177-4ff3-ae38-07b4ae43dd90)
![2023-06-03_15-28](https://github.com/Leo4j/Invoke-ADEnum/assets/61951374/ab4d4280-bffe-4d23-a327-65a616d8c967)
![2023-06-03_15-25](https://github.com/Leo4j/Invoke-ADEnum/assets/61951374/062e0c9c-aa06-4170-b4b5-1b0148bb6c0d)
![2023-06-03_15-26_1](https://github.com/Leo4j/Invoke-ADEnum/assets/61951374/a0e78a2b-8b75-4bab-ad6a-3ae9a20fc98c)
