iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1')

iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/PowerView.ps1')

Set-Variable MaximumHistoryCount 32767

function Invoke-ADEnum
{
<#

.SYNOPSIS
Active Directory PowerView Enumerator

.PARAMETER Domain (not mandatory)
The Domain to enumerate for (it will attempt to retrieve the Master DC for the specified domain - if it fails, it will prompt the user to specify a domain controller)
If not specified, the tool will enumerate for all the domains it can find

.PARAMETER Server (not mandatory)
The DC to bind to (requires you specify a Domain)

.PARAMETER Output
Specify where to save the output from the tool (default is pwd)

.SWITCH NoServers
Do not enumerate for Servers

.SWITCH NoWorkstations
Do not enumerate for Workstations

.SWITCH NoUnsupportedOS
Do not enumerate for machines running unsupported OS

.SWITCH NoUsers
Do not enumerate for Users

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

.EXAMPLE - Run for each domain you can find
Invoke-ADEnum

.EXAMPLE - Run for a specific Domain/DC
Invoke-ADEnum -Domain <domain FQDN> -Server <DC FQDN or IP>

.EXAMPLE - Run for each domain the tool can find and save output to C:\Windows\Temp\Invoke-ADEnum.txt
Invoke-ADEnum -Output C:\Windows\Temp\Invoke-ADEnum.txt

#>

    [CmdletBinding()] Param(

        [Parameter (Mandatory=$False, Position = 0, ValueFromPipeline=$true)]
        [String]
        $Domain,

        [Parameter (Mandatory=$False, Position = 1, ValueFromPipeline=$true)]
        [String]
        $Server,
        
        [Parameter (Mandatory=$False, Position = 2, ValueFromPipeline=$true)]
        [String]
        $Output,
        
        [Parameter (Mandatory=$False, Position = 3, ValueFromPipeline=$true)]
        [Switch]
        $NoServers,
        
        [Parameter (Mandatory=$False, Position = 4, ValueFromPipeline=$true)]
        [Switch]
        $NoWorkstations,
        
        [Parameter (Mandatory=$False, Position = 5, ValueFromPipeline=$true)]
        [Switch]
        $NoUnsupportedOS,
        
        [Parameter (Mandatory=$False, Position = 6, ValueFromPipeline=$true)]
        [Switch]
        $NoUsers,
        
        [Parameter (Mandatory=$False, Position = 7, ValueFromPipeline=$true)]
        [Switch]
        $NoShares,
        
        [Parameter (Mandatory=$False, Position = 8, ValueFromPipeline=$true)]
        [Switch]
        $NoLocalAdminAccess,
        
        [Parameter (Mandatory=$False, Position = 9, ValueFromPipeline=$true)]
        [Switch]
        $NoACLs,
        
        [Parameter (Mandatory=$False, Position = 10, ValueFromPipeline=$true)]
        [Switch]
        $NoGPOs,
        
        [Parameter (Mandatory=$False, Position = 11, ValueFromPipeline=$true)]
        [Switch]
        $NoFindDomainUserLocation

    )
    
    if($Domain){
	if($Server){}
	else{
		$Server = Get-DomainController -Domain $Domain | Where-Object {$_.Roles -like "RidRole"} | Select-Object -ExpandProperty Name
		if($Server){}
		else{$ServerParam = [Parameter(Mandatory=$True, Position=2, ValueFromPipeline=$true)][String]$Server}
	}
    }

    elseif($Server){
	$DomainParam = [Parameter(Mandatory=$True, Position=1, ValueFromPipeline=$true)][String]$Domain
	#$ServerParam = [Parameter(Mandatory=$True, Position=2, ValueFromPipeline=$true)][String]$Server
    }

    $ErrorActionPreference = "SilentlyContinue"
    $WarningPreference = "SilentlyContinue"
    
    # Set the path and filename for the output file
    if($Output){$OutputFilePath = $Output}
    elseif($Domain){$OutputFilePath = "$pwd\Invoke-ADEnum_$Domain.txt"}
    else{$OutputFilePath = "$pwd\Invoke-ADEnum_$($env:USERDNSDOMAIN.ToLower()).txt"}
    
    # Start capturing the script's output and save it to the file
    Start-Transcript -Path $OutputFilePath
    
    clear
    
    Write-Host "  _____                 _                      _____  ______                       " -ForegroundColor Red
    Write-Host " |_   _|               | |               /\   |  __ \|  ____|                      " -ForegroundColor Red
    Write-Host "   | |  _ ____   _____ | | _____ ______ /  \  | |  | | |__   _ __  _   _ _ __ ___  " -ForegroundColor Red
    Write-Host "   | | | '_ \ \ / / _ \| |/ / _ \______/ /\ \ | |  | |  __| | '_ \| | | | '_ ' _  \" -ForegroundColor Red
    Write-Host "  _| |_| | | \ V / (_) |   <  __/     / ____ \| |__| | |____| | | | |_| | | | | | |" -ForegroundColor Red
    Write-Host " |_____|_| |_|\_/ \___/|_|\_\___|    /_/    \_\_____/|______|_| |_|\__,_|_| |_| |_|" -ForegroundColor Red
    
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

    else{
    	$AllDomains = $ParentDomain + "`n"
    	$AllDomains = ($AllDomains | Out-String) -split "`n"
        $AllDomains = $AllDomains.Trim()
        $AllDomains = $AllDomains | Where-Object { $_ -ne "" }
    }
    
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
    
    $AllDomains = $AllDomains + "`n"
    
    foreach($TrustTargetName in $TrustTargetNames){
    	$AllDomains += $TrustTargetName + "`n"
    }
    
    $AllDomains = ($AllDomains | Out-String) -split "`n"
    $AllDomains = $AllDomains.Trim()
    $AllDomains = $AllDomains | Where-Object { $_ -ne "" }
    $AllDomains = $AllDomains | Sort-Object -Unique
    
    #$AllDomains += $TrustTargetNames
    $PlaceHolderDomains = $AllDomains
    $AllDomains = $AllDomains | Where-Object { $_ -notin $OutboundTrusts }

    Write-Host ""
    Write-Host "Domain SIDs:" -ForegroundColor Cyan
    if($Domain -AND $Server) {
        $DomainSID = Get-DomainSID -Domain $Domain -Server $Server
        
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
    Write-Host "Trust Accounts:" -ForegroundColor Cyan
    if($Domain -AND $Server) {
	Get-DomainObject -Domain $Domain -Server $Server -LDAPFilter "(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2048)" | Select @{Name="Domain";Expression={$Domain}},samaccountname,objectsid,objectguid,samaccounttype | ft -AutoSize -Wrap
    }
    else{
	foreach($AllDomain in $AllDomains){Get-DomainObject -Domain $AllDomain -LDAPFilter "(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2048)" | Select @{Name="Domain";Expression={$AllDomain}},samaccountname,objectsid,objectguid,samaccounttype | ft -AutoSize -Wrap}
    }

    Write-Host ""
    Write-Host "Trusted Domain Object GUIDs:" -ForegroundColor Cyan
    if($Domain -AND $Server) {
	$TDOTargetNames = Get-DomainTrust -Domain $Domain -Server $Server | Where-Object { $_.TrustDirection -eq 'Outbound' } | Select-Object -ExpandProperty TargetName
	$TDOTrustDirection = "Outbound"
	$TDOTargetNames = ($TDOTargetNames | Out-String) -split "`n"
	$TDOTargetNames = $TDOTargetNames.Trim()
	$TDOTargetNames = $TDOTargetNames | Where-Object { $_ -ne "" }
	$TDOSourceDomainName = "DC=" + $Domain.Split(".")
	$TDOSourceDomainName = $TDOSourceDomainName -replace " ", ",DC="
	foreach($TDOTargetName in $TDOTargetNames){
		Get-DomainObject -Domain $Domain -Server $Server -Identity "CN=$TDOTargetName,CN=System,$TDOSourceDomainName" | select @{Name="SourceName";Expression={$Domain}},@{Name="TargetName";Expression={$TDOTargetName}},@{Name="TrustDirection";Expression={$TDOTrustDirection}},objectGuid | ft -AutoSize -Wrap
	}
    }
	
    else{
	$TDOTargetNames = foreach($AllDomain in $AllDomains){Get-DomainTrust -Domain $AllDomain | Where-Object { $_.TrustDirection -eq 'Outbound' } | Select-Object -ExpandProperty TargetName}
	$TDOTrustDirection = "Outbound"
	$TDOTargetNames = ($TDOTargetNames | Out-String) -split "`n"
	$TDOTargetNames = $TDOTargetNames.Trim()
	$TDOTargetNames = $TDOTargetNames | Where-Object { $_ -ne "" }
	foreach($AllDomain in $AllDomains){
		$TDOSourceDomainName = "DC=" + $AllDomain.Split(".")
		$TDOSourceDomainName = $TDOSourceDomainName -replace " ", ",DC="
		foreach($TDOTargetName in $TDOTargetNames){
			Get-DomainObject -Domain $AllDomain -Identity "CN=$TDOTargetName,CN=System,$TDOSourceDomainName" | select @{Name="SourceName";Expression={$AllDomain}},@{Name="TargetName";Expression={$TDOTargetName}},@{Name="TrustDirection";Expression={$TDOTrustDirection}},objectGuid | ft -AutoSize -Wrap
		}
	}
    }

    Write-Host ""
    Write-Host "Domain Controllers:" -ForegroundColor Cyan
    if($Domain -AND $Server) {
        $domainControllers = Get-DomainController -Domain $Domain -Server $Server
    	foreach ($dc in $domainControllers) {
        	$isPrimaryDC = $dc.Roles -like "RidRole"
        	$primaryDC = if($isPrimaryDC) {"YES"} else {"NO"}
        	$dc | Select-Object Name, Forest, Domain, IPAddress, @{Name="PrimaryDC";Expression={$primaryDC}} | ft -Autosize -Wrap
    	}
    }
    else{
        foreach($AllDomain in $AllDomains){
		$domainControllers = Get-DomainController -Domain $AllDomain
        	foreach ($dc in $domainControllers) {
            		$isPrimaryDC = $dc.Roles -like "RidRole"
            		$primaryDC = if($isPrimaryDC) {"YES"} else {"NO"}
            		$dc | Select-Object Name, Forest, Domain, IPAddress, @{Name="PrimaryDC";Expression={$primaryDC}} | ft -Autosize -Wrap
        	}
	}
    }
    
    Write-Host ""
    Write-Host "Groups the current user is part of:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Current User: $env:USERNAME"
    if($Domain -AND $Server) {
    	Get-DomainGroup -Domain $Domain -Server $Server -UserName $env:USERNAME | select samaccountname, objectsid, @{Name='Members of this group:';Expression={(Get-DomainGroupMember -Domain $Domain -Server $Server -Recurse -Identity $_.samaccountname).MemberName -join ' - '}} | ft -Autosize -Wrap
    }
    else{
    	foreach($AllDomain in $AllDomains){Get-DomainGroup -Domain $AllDomain -UserName $env:USERNAME | select samaccountname, objectsid, @{Name='Members of this group:';Expression={(Get-DomainGroupMember -Domain $AllDomain -Recurse -Identity $_.samaccountname).MemberName -join ' - '}} | ft -Autosize -Wrap}
    }
    
    Write-Host ""
    Write-Host "Enterprise Administrators:" -ForegroundColor Cyan
    if($Domain -AND $Server) {
        Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Enterprise Admins" -Recurse | select MemberName,MemberSID,GroupDomain | ft -Autosize -Wrap
    }
    else{
        foreach($AllDomain in $AllDomains){Get-DomainGroupMember -Domain $AllDomain -Identity "Enterprise Admins" -Recurse | select MemberName,MemberSID,GroupDomain | ft -Autosize -Wrap}
    }

    Write-Host ""
    Write-Host "Domain Administrators:" -ForegroundColor Cyan
    if($Domain -AND $Server) {
        Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Domain Admins" -Recurse | select MemberName,MemberSID,GroupDomain | ft -Autosize -Wrap
    }
    else{
        foreach($AllDomain in $AllDomains){Get-DomainGroupMember -Domain $AllDomain -Identity "Domain Admins" -Recurse | select MemberName,MemberSID,GroupDomain | ft -Autosize -Wrap}
    }
    
    Write-Host ""
    Write-Host "Users with AdminCount set to 1:" -ForegroundColor Cyan
    if($Domain -AND $Server) {
        Get-DomainUser -Domain $Domain -Server $Server -AdminCount | select-object samaccountname, @{Name="Domain";Expression={$Domain}}, @{Name="Group Membership";Expression={(Get-DomainGroup -Domain $Domain -Server $Server -UserName $_.samaccountname).Name -join ' - '}} | Format-Table -AutoSize -Wrap
    }
    else{
        foreach ($AllDomain in $AllDomains) {Get-DomainUser -Domain $AllDomain -AdminCount | select-object samaccountname, @{Name="Domain";Expression={$AllDomain}}, @{Name="Group Membership";Expression={(Get-DomainGroup -Domain $AllDomain -UserName $_.samaccountname).Name -join ' - '}} | Format-Table -AutoSize -Wrap}
    }
    
    Write-Host ""
    Write-Host "Groups with AdminCount set to 1:" -ForegroundColor Cyan
    if($Domain -AND $Server) {
		Get-DomainGroup -Domain $Domain -Server $Server -AdminCount | Select-Object samaccountname,objectsid,@{Name="Domain";Expression={$Domain}},@{Name="Membership";Expression={(Get-DomainGroupMember -Domain $Domain -Server $Server -Identity $_.samaccountname -Recurse | Select-Object -ExpandProperty MemberName) -join ', ' }} | ft -Autosize -Wrap
    }
    else{
       foreach($AllDomain in $AllDomains){Get-DomainGroup -Domain $AllDomain -AdminCount | Select-Object samaccountname,objectsid,@{Name="Domain";Expression={$AllDomain}},@{Name="Membership";Expression={(Get-DomainGroupMember -Domain $AllDomain -Identity $_.samaccountname -Recurse | Select-Object -ExpandProperty MemberName) -join ', ' }} | ft -Autosize -Wrap}
    }
    
    Write-Host ""
    Write-Host "Machine accounts in privileged groups:" -ForegroundColor Cyan
    if($Domain -AND $Server) {
        Get-DomainGroup -Domain $Domain -Server $Server -AdminCount | Get-DomainGroupMember -Domain $Domain -Server $Server -Recurse | ?{$_.MemberName -like '*$'} | Select-Object GroupDomain,GroupName,MemberDomain,MemberName,MemberObjectClass,MemberSID | ft -Autosize -Wrap
    }
    else{
        foreach($AllDomain in $AllDomains){Get-DomainGroup -Domain $AllDomain -AdminCount | Get-DomainGroupMember -Recurse | ?{$_.MemberName -like '*$'} | Select-Object GroupDomain,GroupName,MemberDomain,MemberName,MemberObjectClass,MemberSID | ft -Autosize -Wrap}
    }
    
    Write-Host ""
    Write-Host "Members of Pre-Windows 2000 Compatible Access group:" -ForegroundColor Cyan
    if($Domain -AND $Server) {
		Get-DomainGroup -Domain $Domain -Server $Server -Identity "Pre-Windows 2000 Compatible Access" | Select-Object samaccountname,objectsid,@{Name="Domain";Expression={$Domain}},@{Name="Membership";Expression={(Get-DomainGroupMember -Domain $Domain -Server $Server -Identity $_.samaccountname -Recurse | Where-Object { $_.MemberName -ne "Authenticated Users" } | Select-Object -ExpandProperty MemberName) -join ', ' }} | ft -Autosize -Wrap
    }
    else{
       foreach($AllDomain in $AllDomains){Get-DomainGroup -Domain $AllDomain -Identity "Pre-Windows 2000 Compatible Access" | Select-Object samaccountname,objectsid,@{Name="Domain";Expression={$AllDomain}},@{Name="Membership";Expression={(Get-DomainGroupMember -Domain $AllDomain -Identity $_.samaccountname -Recurse | Where-Object { $_.MemberName -ne "Authenticated Users" } | Select-Object -ExpandProperty MemberName) -join ', ' }} | ft -Autosize -Wrap}
    }
    
    Write-Host ""
    Write-Host "Service Accounts:" -ForegroundColor Cyan
    if($Domain -AND $Server) {
        Get-DomainUser -SPN -Domain $Domain -Server $Server | select samaccountname, description, @{Name='Groups';Expression={(Get-DomainGroup -Domain $Domain -Server $Server -UserName $_.samaccountname).Name -join ' - '}}, @{Name="Domain";Expression={$Domain}} | ft -Autosize -Wrap
    }
    else{
        foreach($AllDomain in $AllDomains){Get-DomainUser -SPN -Domain $AllDomain | select samaccountname, description, @{Name='Groups';Expression={(Get-DomainGroup -Domain $AllDomain -UserName $_.samaccountname).Name -join ' - '}}, @{Name="Domain";Expression={$AllDomain}} | ft -Autosize -Wrap}
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
    Write-Host "Service accounts in 'Enterprise Admins':" -ForegroundColor Cyan
    if($Domain -AND $Server) {
        Get-DomainUser -Domain $Domain -Server $Server -SPN | ?{$_.memberof -match 'Enterprise Admins'} | Select-Object samaccountname, @{Name="Domain";Expression={$Domain}} | Format-Table -AutoSize -Wrap
    }
    else{
        foreach($AllDomain in $AllDomains){Get-DomainUser -Domain $AllDomain -SPN | ?{$_.memberof -match 'Enterprise Admins'} | Select-Object samaccountname, @{Name="Domain";Expression={$AllDomain}} | Format-Table -AutoSize -Wrap}
    }
    
    Write-Host ""
    Write-Host "Group Managed Service Accounts (GMSA):" -ForegroundColor Cyan
    if($Domain -AND $Server) {
    	Get-DomainObject -Domain $Domain -Server $Server | Where-Object { $_.ObjectClass -eq 'msDS-GroupManagedServiceAccount' } | Select-Object samaccountname, dnshostname, samaccounttype, serviceprincipalname, msds-managedpasswordinterval, pwdlastset, distinguishedname, objectcategory, objectclass, @{Name="Domain";Expression={$Domain}} | fl
    }
    else{
    	foreach($AllDomain in $AllDomains){Get-DomainObject -Domain $AllDomain | Where-Object { $_.ObjectClass -eq 'msDS-GroupManagedServiceAccount' } | Select-Object samaccountname, dnshostname, samaccounttype, serviceprincipalname, msds-managedpasswordinterval, pwdlastset, distinguishedname, objectcategory, objectclass, @{Name="Domain";Expression={$AllDomain}} | fl}
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
        Get-DomainGroupMember 'Domain Admins' -Domain $Domain -Server $Server | %{Get-DomainUser $_.membername -Domain $Domain -Server $Server -LDAPFilter '(displayname=*)'} | %{$a=$_.displayname.split(' ')[0..1] -join ' '; Get-DomainUser -Domain $Domain -Server $Server -LDAPFilter "(displayname=*$a*)" -Properties displayname,samaccountname} | Select-Object samaccountname, displayname, @{Name="Domain";Expression={$Domain}} | Format-Table -AutoSize -Wrap
    }
    else{
        foreach($AllDomain in $AllDomains){Get-DomainGroupMember 'Domain Admins' -Domain $AllDomain | %{Get-DomainUser $_.membername -LDAPFilter '(displayname=*)'} | %{$a=$_.displayname.split(' ')[0..1] -join ' '; Get-DomainUser -Domain $AllDomain -LDAPFilter "(displayname=*$a*)" -Properties displayname,samaccountname} | Select-Object samaccountname, displayname, @{Name="Domain";Expression={$AllDomain}} | Format-Table -AutoSize -Wrap}
    }
    
    #Write-Host ""
    #Write-Host "All Groups:" -ForegroundColor Cyan
    #foreach($AllDomain in $AllDomains){Get-DomainGroup -Domain $AllDomain | select SamAccountName, objectsid, @{Name='Members';Expression={(Get-DomainGroupMember -Recurse -Identity $_.SamAccountname).MemberDistinguishedName -join ' - '}} | ft -Autosize -Wrap}
    
    Write-Host ""
    Write-Host "Domain Password Policy:" -ForegroundColor Cyan
    if($Domain -AND $Server) {
		(Get-DomainPolicy -Domain $Domain -Server $Server).SystemAccess | fl @{Name="Domain"; Expression={$Domain}}, MinimumPasswordAge, MaximumPasswordAge, MinimumPasswordLength, PasswordComplexity, PasswordHistorySize, LockoutBadCount, ResetLockoutCount, LockoutDuration, RequireLogonToChangePassword
    }
    else{
        foreach($AllDomain in $AllDomains){(Get-DomainPolicy -Domain $AllDomain).SystemAccess | fl @{Name="Domain"; Expression={$AllDomain}}, MinimumPasswordAge, MaximumPasswordAge, MinimumPasswordLength, PasswordComplexity, PasswordHistorySize, LockoutBadCount, ResetLockoutCount, LockoutDuration, RequireLogonToChangePassword}
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
    Write-Host "LM Compatibility Level:" -ForegroundColor Cyan
	
    $policySettings = @{
        "0" = "Send LM & NTLM responses"
        "1" = "Send LM & NTLM - use NTLMv2 session security if negotiated"
        "2" = "Send NTLM response only"
        "3" = "Send NTLMv2 response only"
        "4" = "Send NTLMv2 response only. Refuse LM"
        "5" = "Send NTLMv2 response only. Refuse LM & NTLM"
    }
	
    if($Domain -AND $Server) {
        $gpoResult = Get-DomainGPO -Domain $Domain -Server $Server -LDAPFilter "(name=*)" -Properties gpcfilesyspath, displayname |
            ForEach-Object {
                $gpoPath = $_.gpcfilesyspath.TrimStart("[").TrimEnd("]")
                $gpoDisplayName = $_.displayname
                $gpoSetting = (Get-Content -Path "$gpoPath\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" -Raw |
                    Select-String -Pattern "LmCompatibilityLevel" | Select-Object -Last 1).Line
                $gpoSetting = ($gpoSetting | Out-String) -split "`n"
                $gpoSetting = $gpoSetting | Select-String -Pattern "LmCompatibilityLevel"
                $gpoSetting = ($gpoSetting | Out-String) -split "`n"
                $gpoSetting = $gpoSetting.Trim()
                $gpoSetting = $gpoSetting | Where-Object { $_ -ne "" }
				
                if ($gpoSetting) {
                    $settingValue = ($gpoSetting -split "=")[-1].Trim().Split(",")[-1].Trim()
                    $policySetting = $policySettings[$settingValue]

                    [PSCustomObject]@{
                        GPODisplayName = $gpoDisplayName
                        LMCompatibilityLevel = $settingValue
                        "Policy Settings" = $policySetting
                    }
                }
            }
        $gpoResult | Format-Table -AutoSize -Wrap
    }

    else{
        foreach($AllDomain in $AllDomains){
            $gpoResult = Get-DomainGPO -Domain $AllDomain -LDAPFilter "(name=*)" -Properties gpcfilesyspath, displayname |
                ForEach-Object {
                    $gpoPath = $_.gpcfilesyspath.TrimStart("[").TrimEnd("]")
                    $gpoDisplayName = $_.displayname
                    $gpoSetting = (Get-Content -Path "$gpoPath\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" -Raw |
                        Select-String -Pattern "LmCompatibilityLevel" | Select-Object -Last 1).Line
                    $gpoSetting = ($gpoSetting | Out-String) -split "`n"
                    $gpoSetting = $gpoSetting | Select-String -Pattern "LmCompatibilityLevel"
                    $gpoSetting = ($gpoSetting | Out-String) -split "`n"
                    $gpoSetting = $gpoSetting.Trim()
                    $gpoSetting = $gpoSetting | Where-Object { $_ -ne "" }
					
                    if ($gpoSetting) {
                        $settingValue = ($gpoSetting -split "=")[-1].Trim().Split(",")[-1].Trim()
                        $policySetting = $policySettings[$settingValue]

                        [PSCustomObject]@{
                            GPODisplayName = $gpoDisplayName
                            LMCompatibilityLevel = $settingValue
                            "Policy Settings" = $policySetting
                        }
                    }
                }
            $gpoResult | Format-Table -AutoSize -Wrap
        }
    }
	
	
    Write-Host ""
    Write-Host "Misconfigured Certificate Templates (do not rely solely on this output):" -ForegroundColor Cyan

    if($Domain -AND $Server) {
        $CertDomainName = "DC=" + $Domain.Split(".")
        $CertDomainName = $CertDomainName -replace " ", ",DC="
        $vulncertusers = Get-DomainObjectACL -Domain $Domain -Server $Server -SearchBase "CN=Configuration,$CertDomainName" -LDAPFilter "(objectclass=pkicertificatetemplate)" -ResolveGUIDs | %{ $_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID -Domain $Domain -Server $Server $_.SecurityIdentifier.value) -Force; $_ } |  ?{ $_.Identity -match "Domain Users" }
        $vulncertcomputers = Get-DomainObjectACL -Domain $Domain -Server $Server -SearchBase "CN=Configuration,$CertDomainName" -LDAPFilter "(objectclass=pkicertificatetemplate)" -ResolveGUIDs | %{ $_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID -Domain $Domain -Server $Server $_.SecurityIdentifier.value) -Force; $_ } |  ?{ $_.Identity -match "Domain Computers" }
        Get-DomainObject -Domain $Domain -Server $Server -SearchBase "CN=Configuration,$CertDomainName" -LDAPFilter "(objectclass=pkicertificatetemplate)" | Where-Object {($_."mspki-certificate-name-flag" -eq "1" -and $_.pkiextendedkeyusage -like "1.3.6.1.5.5.7.3.2") -and (($vulncertusers.ObjectDN -contains $_.distinguishedname) -or ($vulncertcomputers.ObjectDN -contains $_.distinguishedname))} | Select-Object @{Name="Cert Template";Expression={$_.cn}}, @{Name="pkiextendedkeyusage";Expression={"Client Authentication"}}, @{Name="Flag";Expression={"ENROLLEE_SUPPLIES_SUBJECT"}},@{Name="Enrollment Rights";Expression={"Domain Users"}}, @{Name="Domain";Expression={$Domain}} | ft -AutoSize -Wrap
        $vulncertcomputers | Where-Object {($_.ActiveDirectoryRights -match "WriteDacl") -or ($_.ActiveDirectoryRights -match "WriteOwner")} | Select-Object @{Name="Cert Template";Expression={$_.ObjectDN.Split(',')[0] -replace 'CN='}}, @{Name="Identity";Expression={"Domain Computers"}}, @{Name="ActiveDirectoryRights";Expression={"WriteDacl WriteOwner"}}, @{Name="Domain";Expression={$Domain}} | ft -AutoSize -Wrap
        $vulncertusers | Where-Object {($_.ActiveDirectoryRights -match "WriteDacl") -or ($_.ActiveDirectoryRights -match "WriteOwner")} | Select-Object @{Name="Cert Template";Expression={$_.ObjectDN.Split(',')[0] -replace 'CN='}}, @{Name="Identity";Expression={"Domain Users"}}, @{Name="ActiveDirectoryRights";Expression={"WriteDacl WriteOwner"}}, @{Name="Domain";Expression={$Domain}} | ft -AutoSize -Wrap
    }

    else {
        foreach($AllDomain in $AllDomains){
            $CertDomainName = "DC=" + $AllDomain.Split(".")
            $CertDomainName = $CertDomainName -replace " ", ",DC="
            $vulncertusers = Get-DomainObjectACL -Domain $AllDomain -SearchBase "CN=Configuration,$CertDomainName" -LDAPFilter "(objectclass=pkicertificatetemplate)" -ResolveGUIDs | %{ $_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID -Domain $AllDomain $_.SecurityIdentifier.value) -Force; $_ } |  ?{ $_.Identity -match "Domain Users" }
            $vulncertcomputers = Get-DomainObjectACL -Domain $AllDomain -SearchBase "CN=Configuration,$CertDomainName" -LDAPFilter "(objectclass=pkicertificatetemplate)" -ResolveGUIDs | %{ $_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID -Domain $AllDomain $_.SecurityIdentifier.value) -Force; $_ } |  ?{ $_.Identity -match "Domain Computers" }
            Get-DomainObject -Domain $AllDomain -SearchBase "CN=Configuration,$CertDomainName" -LDAPFilter "(objectclass=pkicertificatetemplate)" | Where-Object {($_."mspki-certificate-name-flag" -eq "1" -and $_.pkiextendedkeyusage -like "1.3.6.1.5.5.7.3.2") -and (($vulncertusers.ObjectDN -contains $_.distinguishedname) -or ($vulncertcomputers.ObjectDN -contains $_.distinguishedname))} | Select-Object @{Name="Cert Template";Expression={$_.cn}}, @{Name="pkiextendedkeyusage";Expression={"Client Authentication"}}, @{Name="Flag";Expression={"ENROLLEE_SUPPLIES_SUBJECT"}},@{Name="Enrollment Rights";Expression={"Domain Users"}}, @{Name="Domain";Expression={$AllDomain}} | ft -AutoSize -Wrap
            $vulncertcomputers | Where-Object {($_.ActiveDirectoryRights -match "WriteDacl") -or ($_.ActiveDirectoryRights -match "WriteOwner")} | Select-Object @{Name="Cert Template";Expression={$_.ObjectDN.Split(',')[0] -replace 'CN='}}, @{Name="Identity";Expression={"Domain Computers"}}, @{Name="ActiveDirectoryRights";Expression={"WriteDacl WriteOwner"}}, @{Name="Domain";Expression={$AllDomain}} | ft -AutoSize -Wrap
            $vulncertusers | Where-Object {($_.ActiveDirectoryRights -match "WriteDacl") -or ($_.ActiveDirectoryRights -match "WriteOwner")} | Select-Object @{Name="Cert Template";Expression={$_.ObjectDN.Split(',')[0] -replace 'CN='}}, @{Name="Identity";Expression={"Domain Users"}}, @{Name="ActiveDirectoryRights";Expression={"WriteDacl WriteOwner"}}, @{Name="Domain";Expression={$AllDomain}} | ft -AutoSize -Wrap
        }
    }
    
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
        Get-DomainGroup -Domain $Domain -Server $Server -Identity *SQL* | % { Get-DomainGroupMember -Domain $Domain -Server $Server -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$Domain}} } | ft -Autosize -Wrap
        Get-DomainGroup -Domain $Domain -Server $Server -Identity *Exchange* | % { Get-DomainGroupMember -Domain $Domain -Server $Server -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$Domain}} } | ft -Autosize -Wrap
        Get-DomainGroup -Domain $Domain -Server $Server -Identity *Desktop* | % { Get-DomainGroupMember -Domain $Domain -Server $Server -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$Domain}} } | ft -Autosize -Wrap
        Get-DomainGroup -Domain $Domain -Server $Server -Identity *VEEAM* | % { Get-DomainGroupMember -Domain $Domain -Server $Server -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$Domain}} } | ft -Autosize -Wrap
        Get-DomainGroup -Domain $Domain -Server $Server -Identity *PSM* | % { Get-DomainGroupMember -Domain $Domain -Server $Server -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$Domain}} } | ft -Autosize -Wrap
        Get-DomainGroup -Domain $Domain -Server $Server -Identity *Password* | % { Get-DomainGroupMember -Domain $Domain -Server $Server -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$Domain}} } | ft -Autosize -Wrap
    }
    else{
        foreach($AllDomain in $AllDomains){
            Get-DomainGroup -Domain $AllDomain -Identity *SQL* | % { Get-DomainGroupMember -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$AllDomain}} } | ft -Autosize -Wrap
            Get-DomainGroup -Domain $AllDomain -Identity *Exchange* | % { Get-DomainGroupMember -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$AllDomain}} } | ft -Autosize -Wrap
            Get-DomainGroup -Domain $AllDomain -Identity *Desktop* | % { Get-DomainGroupMember -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$AllDomain}} } | ft -Autosize -Wrap
            Get-DomainGroup -Domain $AllDomain -Identity *VEEAM* | % { Get-DomainGroupMember -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$AllDomain}} } | ft -Autosize -Wrap
            Get-DomainGroup -Domain $AllDomain -Identity *PSM* | % { Get-DomainGroupMember -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$AllDomain}} } | ft -Autosize -Wrap
            Get-DomainGroup -Domain $AllDomain -Identity *Password* | % { Get-DomainGroupMember -Identity $_.distinguishedname | Select-Object groupname, membername, @{Name="Domain";Expression={$AllDomain}} } | ft -Autosize -Wrap
        }
    }

    if($NoUsers){}
    else{
        if($Domain -AND $Server) {
            Write-Host ""
            Write-Host "Enabled Users:" -ForegroundColor Cyan
            Get-DomainUser -UACFilter NOT_ACCOUNTDISABLE -Domain $Domain -Server $Server | select samaccountname, objectsid, @{Name='Domain';Expression={$Domain}}, @{Name='Groups';Expression={(Get-DomainGroup -Domain $Domain -Server $Server -UserName $_.samaccountname).Name -join ' - '}}, description | ft -Autosize -Wrap


            Write-Host ""
            Write-Host "Disabled Users:" -ForegroundColor Cyan
            Get-DomainUser -UACFilter ACCOUNTDISABLE -Domain $Domain -Server $Server | select samaccountname, objectsid, @{Name='Domain';Expression={$Domain}}, @{Name='Groups';Expression={(Get-DomainGroup -Domain $Domain -Server $Server -UserName $_.samaccountname).Name -join ' - '}}, description | ft -Autosize -Wrap
        }
        else{
            Write-Host ""
            Write-Host "Enabled Users:" -ForegroundColor Cyan
            foreach($AllDomain in $AllDomains){Get-DomainUser -UACFilter NOT_ACCOUNTDISABLE -Domain $AllDomain | select samaccountname, objectsid, @{Name='Domain';Expression={$AllDomain}}, @{Name='Groups';Expression={(Get-DomainGroup -Domain $AllDomain -UserName $_.samaccountname).Name -join ' - '}}, description | ft -Autosize -Wrap}


            Write-Host ""
            Write-Host "Disabled Users:" -ForegroundColor Cyan
            foreach($AllDomain in $AllDomains){Get-DomainUser -UACFilter ACCOUNTDISABLE -Domain $AllDomain | select samaccountname, objectsid, @{Name='Domain';Expression={$AllDomain}}, @{Name='Groups';Expression={(Get-DomainGroup -Domain $AllDomain -UserName $_.samaccountname).Name -join ' - '}}, description | ft -Autosize -Wrap}
        }
    }
    
    if($NoServers){}
    else{
        Write-Host ""
        Write-Host "Servers:" -ForegroundColor Cyan
        if($Domain -AND $Server) {
            Get-DomainComputer -Properties name, samaccountname, DnsHostName, operatingsystem -Domain $Domain -Server $Server -OperatingSystem "*Server*" | sort -Property DnsHostName | Select-Object -Property name, samaccountname, @{n='ipv4address';e={(Resolve-DnsName -Name $_.DnsHostName -Type A).IPAddress}}, DnsHostName, operatingsystem | ft -Autosize -Wrap
        }
        else{
            foreach($AllDomain in $AllDomains){Get-DomainComputer -Properties name, samaccountname, DnsHostName, operatingsystem -Domain $AllDomain -OperatingSystem "*Server*" | sort -Property DnsHostName | Select-Object -Property name, samaccountname, @{n='ipv4address';e={(Resolve-DnsName -Name $_.DnsHostName -Type A).IPAddress}}, DnsHostName, operatingsystem | ft -Autosize -Wrap}
        }
    }
    
    if($NoWorkstations){}
    else{
        Write-Host ""
        Write-Host "Workstations:" -ForegroundColor Cyan
        if($Domain -AND $Server) {
            Get-DomainComputer -Properties name, samaccountname, DnsHostName, operatingsystem -Domain $Domain -Server $Server | Where-Object { $_.OperatingSystem -notlike "*Server*" } | sort -Property DnsHostName | Select-Object -Property name, samaccountname, @{n='ipv4address';e={(Resolve-DnsName -Name $_.DnsHostName -Type A).IPAddress}}, DnsHostName, operatingsystem | ft -Autosize -Wrap
        }
        else{
            foreach($AllDomain in $AllDomains){Get-DomainComputer -Properties name, samaccountname, DnsHostName, operatingsystem -Domain $AllDomain | Where-Object { $_.OperatingSystem -notlike "*Server*" } | sort -Property DnsHostName | Select-Object -Property name, samaccountname, @{n='ipv4address';e={(Resolve-DnsName -Name $_.DnsHostName -Type A).IPAddress}}, DnsHostName, operatingsystem | ft -Autosize -Wrap}
        }
    }
    
    if($NoUnsupportedOS){}
    else{
        Write-Host ""
        Write-Host "Hosts running Unsupported OS:" -ForegroundColor Cyan
        if($Domain -AND $Server) {
            Get-DomainComputer -Properties name, samaccountname, DnsHostName, operatingsystem -Domain $Domain -Server $Server | where-object {($_.OperatingSystem -like "Windows Me*") -or ($_.OperatingSystem -like "Windows NT*") -or ($_.OperatingSystem -like "Windows 95*") -or ($_.OperatingSystem -like "Windows 98*") -or ($_.OperatingSystem -like "Windows XP*") -or ($_.OperatingSystem -like "Windows 7*") -or ($_.OperatingSystem -like "Windows Vista*") -or ($_.OperatingSystem -like "Windows 2000*") -or ($_.OperatingSystem -like "Windows 8*") -or ($_.OperatingSystem -like "Windows Server 2008*") -or ($_.OperatingSystem -like "Windows Server 2003*") -or ($_.OperatingSystem -like "Windows Server 2000*")} | sort -Property DnsHostName | Select-Object -Property name, samaccountname, @{n='ipv4address';e={(Resolve-DnsName -Name $_.DnsHostName -Type A).IPAddress}}, DnsHostName, operatingsystem | ft -Autosize -Wrap
        }
        else{
            foreach($AllDomain in $AllDomains){Get-DomainComputer -Properties name, samaccountname, DnsHostName, operatingsystem -Domain $AllDomain | where-object {($_.OperatingSystem -like "Windows Me*") -or ($_.OperatingSystem -like "Windows NT*") -or ($_.OperatingSystem -like "Windows 95*") -or ($_.OperatingSystem -like "Windows 98*") -or ($_.OperatingSystem -like "Windows XP*") -or ($_.OperatingSystem -like "Windows 7*") -or ($_.OperatingSystem -like "Windows Vista*") -or ($_.OperatingSystem -like "Windows 2000*") -or ($_.OperatingSystem -like "Windows 8*") -or ($_.OperatingSystem -like "Windows Server 2008*") -or ($_.OperatingSystem -like "Windows Server 2003*") -or ($_.OperatingSystem -like "Windows Server 2000*")} | sort -Property DnsHostName | Select-Object -Property name, samaccountname, @{n='ipv4address';e={(Resolve-DnsName -Name $_.DnsHostName -Type A).IPAddress}}, DnsHostName, operatingsystem | ft -Autosize -Wrap}
        }
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
	    
	    $members = @()
	    if ($users) { $members += $users }
	    if ($computers) { $members += $computers.Name }
	    
            [PSCustomObject]@{
                Name = $ou.Name
                Members = $members -join ' - '
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
		
		$members = @()
		if ($users) { $members += $users }
		if ($computers) { $members += $computers.Name }
		
                [PSCustomObject]@{
                    Name = $ou.Name
                    Members = $members -join ' - '
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

    if($NoGPOs){}
    else{
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
    Write-Host "AppLocker GPOs:" -ForegroundColor Cyan
    if($Domain -AND $Server) {
        Get-DomainGPO -Domain $Domain -Server $Server | ? { $_.DisplayName -like "*AppLocker*" } | select displayname, gpcfilesyspath | Format-Table -AutoSize -Wrap
        $AppLockerGPOLocation = Get-DomainGPO -Domain $Domain -Server $Server | ? { $_.DisplayName -like "*AppLocker*" } | select-object -ExpandProperty GPCFileSysPath
        $AppLockerGPOLocation = ($AppLockerGPOLocation | Out-String) -split "`n"
        $AppLockerGPOLocation = $AppLockerGPOLocation.Trim()
        $AppLockerGPOLocation = $AppLockerGPOLocation | Where-Object { $_ -ne "" }
        foreach($AppLockerGPOLoc in $AppLockerGPOLocation){
            Write-Host "GPO: $AppLockerGPOLoc" -ForegroundColor Yellow
            Write-Host ""
            $AppLockerinputString = (type $AppLockerGPOLoc\Machine\Registry.pol | Out-String)
            $AppLockersplitString = ($AppLockerinputString -split '\<|\>').Where{$_ -ne ''}
            $AppLockersplitString = ($AppLockersplitString -split '\[|\]').Where{$_ -ne ''}
            $AppLockersplitString | Format-Table -AutoSize -Wrap
        }
    }
    else{
        foreach ($AllDomain in $AllDomains){
            Get-DomainGPO -Domain $AllDomain | ? { $_.DisplayName -like "*AppLocker*" } | select displayname, gpcfilesyspath | Format-Table -AutoSize -Wrap
            $AppLockerGPOLocation = Get-DomainGPO -Domain $AllDomain | ? { $_.DisplayName -like "*AppLocker*" } | select-object -ExpandProperty GPCFileSysPath
            $AppLockerGPOLocation = ($AppLockerGPOLocation | Out-String) -split "`n"
            $AppLockerGPOLocation = $AppLockerGPOLocation.Trim()
            $AppLockerGPOLocation = $AppLockerGPOLocation | Where-Object { $_ -ne "" }
            foreach($AppLockerGPOLoc in $AppLockerGPOLocation){
                Write-Host "GPO: $AppLockerGPOLoc" -ForegroundColor Yellow
                Write-Host ""
                $AppLockerinputString = (type $AppLockerGPOLoc\Machine\Registry.pol | Out-String)
                $AppLockersplitString = ($AppLockerinputString -split '\<|\>').Where{$_ -ne ''}
                $AppLockersplitString = ($AppLockersplitString -split '\[|\]').Where{$_ -ne ''}
                $AppLockersplitString | Format-Table -AutoSize -Wrap
            }
        }
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
        Select Computer_Object, ActiveDirectoryRights, ObjectAceType, Account | Out-String
    }
    else{
        foreach ($AllDomain in $AllDomains){
            $domainSID = Get-DomainSID $AllDomain 
            Get-DomainComputer -Domain $AllDomain | Get-DomainObjectAcl -ResolveGUIDs | 
            ? { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and $_.SecurityIdentifier -match "$domainSID-[\d]{4,10}" -and $_.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]) -notmatch "IIS_IUSRS|Certificate Service DCOM Access|Cert Publishers|Public Folder Management|Group Policy Creator Owners|Windows Authorization Access Group|Denied RODC Password Replication Group|Organization Management|Exchange Servers|Exchange Trusted Subsystem|Managed Availability Servers|Exchange Windows Permissions" } | 
            Select-Object @{Name='Computer_Object';Expression={([System.Security.Principal.SecurityIdentifier]$_.ObjectSID).Translate([System.Security.Principal.NTAccount])}},ActiveDirectoryRights,ObjectAceType,@{Name='Account';Expression={([System.Security.Principal.SecurityIdentifier]$_.SecurityIdentifier).Translate([System.Security.Principal.NTAccount])}} -ExcludeProperty ObjectDN | 
            Select Computer_Object, ActiveDirectoryRights, ObjectAceType, Account | Out-String
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
    Write-Host "Privileged users that are marked as 'sensitive and not allowed for delegation':" -ForegroundColor Cyan
    if($Domain -AND $Server) {
        Get-DomainUser -Domain $Domain -Server $Server -DisallowDelegation -AdminCount | select-object samaccountname, @{Name="Domain";Expression={$Domain}} | Format-Table -AutoSize -Wrap
    }
    else{
        foreach ($AllDomain in $AllDomains) {Get-DomainUser -Domain $AllDomain -DisallowDelegation -AdminCount | select-object samaccountname, @{Name="Domain";Expression={$AllDomain}} | Format-Table -AutoSize -Wrap}
    }
    
    Write-Host ""
    Write-Host "Privileged users that are not marked as 'sensitive and not allowed for delegation':" -ForegroundColor Cyan
    if($Domain -AND $Server) {
        Get-DomainUser -Domain $Domain -Server $Server -AllowDelegation -AdminCount | select-object samaccountname, @{Name="Domain";Expression={$Domain}} | Format-Table -AutoSize -Wrap
    }
    else{
        foreach ($AllDomain in $AllDomains) {Get-DomainUser -Domain $AllDomain -AllowDelegation -AdminCount | select-object samaccountname, @{Name="Domain";Expression={$AllDomain}} | Format-Table -AutoSize -Wrap}
    }
    
    if($NoGPOs){}
    else{
        Write-Host ""
        Write-Host "GPOs that modify local group memberships through Restricted Groups or Group Policy Preferences:" -ForegroundColor Cyan
        if($Domain -AND $Server) {
            Get-DomainGPOLocalGroup -Domain $Domain -Server $Server | select GPODisplayName, GroupName | Format-Table -AutoSize -Wrap
        }
        else{
            foreach($AllDomain in $AllDomains){Get-DomainGPOLocalGroup -Domain $AllDomain | select GPODisplayName, GroupName | Format-Table -AutoSize -Wrap}
        }
    }

    Write-Host ""
    Write-Host "Machines where a specific domain user/group is a member of the Administrators local group:" -ForegroundColor Cyan
    if($Domain -AND $Server) {
        Get-DomainGPOUserLocalGroupMapping -Domain $Domain -Server $Server -LocalGroup Administrators | Select-Object ObjectName, GPODisplayName, ContainerName, ComputerName | Format-Table -AutoSize -Wrap
    }
    else{
        foreach($AllDomain in $AllDomains){Get-DomainGPOUserLocalGroupMapping -Domain $AllDomain -LocalGroup Administrators | Select-Object ObjectName, GPODisplayName, ContainerName, ComputerName | Format-Table -AutoSize -Wrap}
    }
    
    if($NoGPOs){}
    else{
        Write-Host ""
        Write-Host "Users which are in a local group of a machine using GPO:" -ForegroundColor Cyan
        if($Domain -AND $Server) {
            Get-DomainComputer -Domain $Domain -Server $Server | Find-GPOComputerAdmin -Domain $Domain -Server $Server | Select-Object ComputerName, ObjectName, ObjectSID, IsGroup, GPODisplayName, GPOPath | Format-Table -AutoSize -Wrap
        }
        else{
            foreach($AllDomain in $AllDomains){Get-DomainComputer -Domain $AllDomain | Find-GPOComputerAdmin | Select-Object ComputerName, ObjectName, ObjectSID, IsGroup, GPODisplayName, GPOPath | Format-Table -AutoSize -Wrap}
        }
    }

    Write-Host ""
    Write-Host "Machines where a user is member of a specific group:" -ForegroundColor Cyan
    if($Domain -AND $Server) {
        Get-DomainUser -Domain $Domain -Server $Server | Find-GPOLocation -Domain $Domain -Server $Server | Select-Object ObjectName, ObjectSID, Domain, IsGroup, GPODisplayName, GPOPath | Format-Table -AutoSize -Wrap
    }
    else{
        foreach($AllDomain in $AllDomains){Get-DomainUser -Domain $AllDomain | Find-GPOLocation | Select-Object ObjectName, ObjectSID, Domain, IsGroup, GPODisplayName, GPOPath | Format-Table -AutoSize -Wrap}
    }
    
    if($NoLocalAdminAccess){}
    else{
        Write-Host ""
        Write-Host "Find Local Admin Access:" -ForegroundColor Cyan
        if($Domain -AND $Server) {
            Find-LocalAdminAccess -Server $Server -CheckShareAccess -Threads 100 -Delay 1 | Out-String
        }
        else{
            foreach($AllDomain in $AllDomains){Find-LocalAdminAccess -Domain $AllDomain -CheckShareAccess -Threads 100 -Delay 1 | Out-String}
        }
    }
    
    if($NoFindDomainUserLocation){}
    else{
        Write-Host ""
        Write-Host "Find Domain User Location:" -ForegroundColor Cyan
        if($Domain -AND $Server) {
            Find-DomainUserLocation -Domain $Domain -Server $Server -Delay 1 | select UserName, SessionFromName | Out-String
        }
        else{
            foreach($AllDomain in $AllDomains){Find-DomainUserLocation -Domain $AllDomain -Delay 1 | select UserName, SessionFromName | Out-String}
        }
    }

<# 	Write-Host ""
    Write-Host "Audit the permissions of AdminSDHolder, resolving GUIDs:" -ForegroundColor Cyan
    if($Domain -AND $Server) {
        $dcName = "dc=" + $Domain.Split("."); $dcName = $dcName -replace " ", ",dc="; Get-DomainObjectAcl -Domain $Domain -Server $Server -SearchBase "CN=AdminSDHolder,CN=System,$dcName" -ResolveGUIDs | select ObjectDN,AceQualifier,ActiveDirectoryRights,ObjectAceType | Out-String
    }
    else{
        foreach($AllDomain in $AllDomains){$dcName = "dc=" + $AllDomain.Split("."); $dcName = $dcName -replace " ", ",dc="; Get-DomainObjectAcl -Domain $AllDomain -SearchBase "CN=AdminSDHolder,CN=System,$dcName" -ResolveGUIDs | select ObjectDN,AceQualifier,ActiveDirectoryRights,ObjectAceType | Out-String}
    } #>
    
    if($NoShares){}
    else{
        Write-Host ""
        Write-Host "Find Domain Shares:" -ForegroundColor Cyan
        if($Domain -AND $Server) {
            Find-DomainShare -ComputerDomain $Domain -Server $Server -CheckShareAccess -Threads 100 -Delay 1 | Select Name,ComputerName,Remark | Format-Table -AutoSize -Wrap
        }
        
        else{
            foreach($AllDomain in $AllDomains){Find-DomainShare -ComputerDomain $AllDomain -CheckShareAccess -Threads 100 -Delay 1 | Select Name,ComputerName,Remark | Format-Table -AutoSize -Wrap}
        }

        Write-Host ""
        Write-Host "Find Interesting Domain Share Files:" -ForegroundColor Cyan
        if($Domain -AND $Server) {
            Find-InterestingDomainShareFile -Server $Server -Threads 100 -Delay 1 | Select Owner,CreationTime,LastAccessTime,LastWriteTime,Path | Format-Table -AutoSize -Wrap
        }
        else{
            foreach($AllDomain in $AllDomains){Find-InterestingDomainShareFile -ComputerDomain $AllDomain -Threads 100 -Delay 1 | Select Owner,CreationTime,LastAccessTime,LastWriteTime,Path | Format-Table -AutoSize -Wrap}
        }
        
        Write-Host ""
        Write-Host "Second run (more file extensions):"
        if($Domain -AND $Server) {
            Find-InterestingDomainShareFile -Server $Server -Include *.doc*, *.txt*, *.xls*, *.csv, *.ppt*, *.msi*, *.wim* -Threads 100 -Delay 1 | Select Owner,CreationTime,LastAccessTime,LastWriteTime,Path | Format-Table -AutoSize -Wrap
        }
        else{
            foreach($AllDomain in $AllDomains){Find-InterestingDomainShareFile -ComputerDomain $AllDomain -Include *.doc*, *.txt*, *.xls*, *.csv, *.ppt*, *.msi*, *.wim* -Threads 100 -Delay 1 | Select Owner,CreationTime,LastAccessTime,LastWriteTime,Path | Format-Table -AutoSize -Wrap}
        }
    }
    
    if($NoACLs){}
    else{
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
    
    # Stop capturing the output and display it on the console
    Stop-Transcript
    
    # Clean up error lines from output
    (Get-Content $OutputFilePath) | Where-Object { $_ -notmatch 'TerminatingError' } | Set-Content $OutputFilePath
    (Get-Content $OutputFilePath) | Where-Object { $_ -notmatch 'Parameter name: binaryForm""' } | Set-Content $OutputFilePath
    (Get-Content $OutputFilePath) | Where-Object { $_ -notmatch 'PSEdition:' } | Set-Content $OutputFilePath
    (Get-Content $OutputFilePath) | Where-Object { $_ -notmatch 'PSCompatibleVersions:' } | Set-Content $OutputFilePath
    (Get-Content $OutputFilePath) | Where-Object { $_ -notmatch 'BuildVersion:' } | Set-Content $OutputFilePath
    (Get-Content $OutputFilePath) | Where-Object { $_ -notmatch 'CLRVersion:' } | Set-Content $OutputFilePath
    (Get-Content $OutputFilePath) | Where-Object { $_ -notmatch 'WSManStackVersion:' } | Set-Content $OutputFilePath
    (Get-Content $OutputFilePath) | Where-Object { $_ -notmatch 'PPSRemotingProtocolVersion:' } | Set-Content $OutputFilePath
    (Get-Content $OutputFilePath) | Where-Object { $_ -notmatch 'SerializationVersion:' } | Set-Content $OutputFilePath
    (Get-Content $OutputFilePath) | Where-Object { $_ -notmatch 'End time:' } | Set-Content $OutputFilePath
    (Get-Content $OutputFilePath) | Where-Object { $_ -notmatch 'Windows PowerShell transcript end' } | Set-Content $OutputFilePath
    (Get-Content $OutputFilePath) | Where-Object { $_ -notmatch 'PSVersion:' } | Set-Content $OutputFilePath
    (Get-Content $OutputFilePath) | Where-Object { $_ -notmatch 'Process ID:' } | Set-Content $OutputFilePath
    (Get-Content $OutputFilePath) | Where-Object { $_ -notmatch 'Host Application:' } | Set-Content $OutputFilePath
    (Get-Content $OutputFilePath) | Where-Object { $_ -notmatch 'Configuration Name:' } | Set-Content $OutputFilePath
    (Get-Content $OutputFilePath) | Where-Object { $_ -notmatch 'Start time:' } | Set-Content $OutputFilePath
    (Get-Content $OutputFilePath) | Where-Object { $_ -notmatch 'Windows PowerShell transcript start' } | Set-Content $OutputFilePath
    (Get-Content $OutputFilePath) | Where-Object { $_ -notmatch 'Transcript started, output file is' } | Set-Content $OutputFilePath
    (Get-Content $OutputFilePath) | Where-Object { $_ -notmatch 'Parameter name: enumType""' } | Set-Content $OutputFilePath
    
}
