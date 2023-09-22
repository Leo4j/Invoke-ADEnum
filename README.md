# Invoke-ADEnum
Active Directory Enumeration

Invoke-ADEnum is an Active Directory enumeration tool designed to automate the process of gathering information from an Active Directory environment, leveraging the capabilities of PowerView.

With Invoke-ADEnum, you can quickly and efficiently enumerate various aspects of Active Directory, including forests, domains, trusts, domain controllers, users, groups, computers, shares, subnets, ACLs, OUs, GPOs, and more.

One of the features of Invoke-ADEnum is its ability to generate an Active Directory Audit Report in HTML format. Whether performing security assessments, compliance audits, or general Active Directory enumeration tasks, the report will provide a detailed overview of the Active Directory infrastructure, in an easy-to-navigate layout.

Invoke-ADEnum will generate a client-oriented report as well, which will include only relevant findings and list remediations/recommendations.

NOTE: By clicking on the tables' titles, you can generate and download a CSV version of the results. Additionally, you have the option to export the entire HTML report in XLSX format by clicking on "Active Directory Audit" at the top of the page. The XLSX export will include a separate sheet for each table of findings.

![image](https://github.com/Leo4j/Invoke-ADEnum/assets/61951374/32736c18-7ee2-4031-a670-584af3a87065)


An offline version of the tool is also available, which won't load PowerView from the internet (useful against web filtering or lab scenarios).

Invoke-ADEnum is a tool for any IT professional working with Active Directory.

Run as follows:
  
```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Invoke-ADEnum/main/Invoke-ADEnum.ps1')
```

For usage, please refer to the Help page:

```
Invoke-ADEnum -Help
```

Check your targets first, and make sure you stay in scope

```
Invoke-ADEnum -TargetsOnly
```

Recommended Coverage

```
Invoke-ADEnum -SecurityGroups -GPOsRights -LAPSReadRights -LAPSExtended -RBCD -AllGroups -SprayEmptyPasswords -UserCreatedObjects
```

+++> NOTE: If you use `-CustomURL` or `-Local` parameters you'll have to bypass AMSI manually <+++

<a href='https://ko-fi.com/leo4j' target='_blank'><img height='35' style='border:0px;height:46px;' src='https://az743702.vo.msecnd.net/cdn/kofi3.png?v=0' border='0' alt='Buy Me a Coffee at ko-fi.com' />

![2023-06-03_15-27](https://github.com/Leo4j/Invoke-ADEnum/assets/61951374/b1f72991-2177-4ff3-ae38-07b4ae43dd90)
![2023-06-03_15-28](https://github.com/Leo4j/Invoke-ADEnum/assets/61951374/ab4d4280-bffe-4d23-a327-65a616d8c967)
![2023-06-03_15-25](https://github.com/Leo4j/Invoke-ADEnum/assets/61951374/062e0c9c-aa06-4170-b4b5-1b0148bb6c0d)
![2023-06-03_15-26_1](https://github.com/Leo4j/Invoke-ADEnum/assets/61951374/a0e78a2b-8b75-4bab-ad6a-3ae9a20fc98c)
