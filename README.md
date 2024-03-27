# Invoke-ADEnum
![ADEnum](https://github.com/Leo4j/Invoke-ADEnum/assets/61951374/93fe1fed-6056-4ba0-ae5b-6f3ac4c62ddc)

### Active Directory Enumeration
Invoke-ADEnum is an Active Directory enumeration tool designed to automate the process of gathering information from an Active Directory environment, leveraging the capabilities of PowerView.

With Invoke-ADEnum, you can quickly and efficiently enumerate various aspects of Active Directory, including forests, domains, trusts, domain controllers, users, groups, computers, shares, subnets, ACLs, OUs, GPOs, and more.

One of the features of Invoke-ADEnum is its ability to generate an Active Directory Audit Report in HTML format. Whether performing security assessments, compliance audits, or general Active Directory enumeration tasks, the report will provide a detailed overview of the Active Directory infrastructure in an easy-to-navigate layout, as well as recommendations to remediate findings.

NOTE: By clicking on the tables' titles, you can generate and download a CSV version of the results. Additionally, you have the option to export the entire HTML report in XLSX format by clicking on "Active Directory Audit" at the top of the page. The XLSX export will include a separate sheet for each table of findings.

![image](https://github.com/Leo4j/Invoke-ADEnum/assets/61951374/32736c18-7ee2-4031-a670-584af3a87065)

Invoke-ADEnum is a tool for any IT professional working with Active Directory.

**If you find Invoke-ADEnum valuable and use it in your work, please consider giving us a star on GitHub. Your support motivates the developer to continue improving and maintaining this project**

### Usage

Load the script in memory:
  
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
Invoke-ADEnum -SecurityGroups -GPOsRights -LAPSReadRights -RBCD -AllGroups -SprayEmptyPasswords -UserCreatedObjects
```

+++> NOTE: If you use `-CustomURL` or `-Local` parameters you'll have to bypass AMSI manually <+++

![image](https://github.com/Leo4j/Invoke-ADEnum/assets/61951374/6f2ae901-818f-490e-abe4-a13314628f2f)

![image](https://github.com/Leo4j/Invoke-ADEnum/assets/61951374/5a1f8f67-7445-48b5-a294-dc9e725a5d40)

# Disclaimer

Invoke-ADEnum is intended exclusively for research, education, and authorized testing. Its purpose is to assist professionals and researchers in identifying vulnerabilities and enhancing system security. 

Users must secure explicit, mutual consent from all parties involved before utilizing this tool on any system, network, or digital environment, as unauthorized activities can lead to serious legal consequences. Users are responsible for adhering to all applicable laws and regulations related to cybersecurity and digital access.

The creator of Invoke-ADEnum disclaims liability for any misuse or illicit use of the tool and is not responsible for any resulting damages or losses.
