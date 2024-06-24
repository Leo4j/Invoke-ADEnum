# Invoke-ADEnum
![ADEnum](https://github.com/Leo4j/Invoke-ADEnum/assets/61951374/93fe1fed-6056-4ba0-ae5b-6f3ac4c62ddc)

### Active Directory Enumeration
Invoke-ADEnum is an enumeration tool designed to automate the process of gathering information from an Active Directory environment.

With Invoke-ADEnum, you can enumerate various aspects of Active Directory, including forests, domains, trusts, domain controllers, users, groups, computers, shares, subnets, ACLs, OUs, GPOs, and more.

One of the features of Invoke-ADEnum is its ability to generate an Active Directory Audit Report in HTML format. Whether performing security assessments, compliance audits, or general Active Directory enumeration tasks, the report will provide a detailed overview of the Active Directory infrastructure in an easy-to-navigate layout, as well as recommendations to remediate findings.

NOTE: By clicking on the tables' titles, you can generate and download a CSV version of the results. Additionally, you have the option to export the entire HTML report in XLSX format by clicking on "Active Directory Audit" at the top of the page. The XLSX export will include a separate sheet for each table of findings.

**If you find Invoke-ADEnum valuable and use it in your work, please consider giving it a star. Your support motivates me to continue improving and maintaining this project**

![ADEnum](https://github.com/Leo4j/Invoke-ADEnum/assets/61951374/67527c9b-330b-4437-8d4d-7b7d5742607e)

### Usage

Load the script in memory:
  
```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Invoke-ADEnum/main/Invoke-ADEnum.ps1')
```

Help page:

```
Invoke-ADEnum -Help
```

Check your targets first, and make sure you stay in scope

```
Invoke-ADEnum -TargetsOnly
```

Recommended Coverage

```
Invoke-ADEnum -Recommended -SprayEmptyPasswords
```
```
Invoke-ADEnum -Recommended -SprayEmptyPasswords -RBCD -UserCreatedObjects
```

Specify a single domain to enumerate and a DC to bind to

```
Invoke-ADEnum -Domain contoso.local -Server DC01.contoso.local
```

Exclude out-of-scope domains

```
Invoke-ADEnum -Exclude "contoso.local,domain.local"
```

Full Coverage (may take a long time depending on domain size)

```
Invoke-ADEnum -AllEnum -Force
```
# Disclaimer

Invoke-ADEnum is intended exclusively for research, education, and authorized testing. Its purpose is to assist professionals and researchers in identifying vulnerabilities and enhancing system security. 

Users must secure explicit, mutual consent from all parties involved before utilizing this tool on any system, network, or digital environment, as unauthorized activities can lead to serious legal consequences. Users are responsible for adhering to all applicable laws and regulations related to cybersecurity and digital access.

The creator of Invoke-ADEnum disclaims liability for any misuse or illicit use of the tool and is not responsible for any resulting damages or losses.
