#------------------------------------------------------------------------------
# NetworkPSModule.psm1
#
# Powershell cmdlets to work with network information
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# Function Get-NIC
#
# Returns info on ALL NICs installed in computer
#------------------------------------------------------------------------------

Function Get-NIC

{
	Param ( [String]$ComputerName = ".",
			[switch]$Physical,
			[Switch]$Wireless,
			[Switch]$Wired,
			[Switch]$Debug )
			
		
	$NICs = @()
	if ( $Physical ) {											# ----- Get the Physical NICs
			if ( $Debug ) { Write-Host "Getting Physical NICs..." -ForegroundColor Cyan }
			$NICs = Get-WmiObject win32_networkadapter -ComputerName $ComputerName | where { ($_.AdapterTypeID -eq 0) -and ($_.Manufacturer -ne 'VMWare, Inc.') -and ($_.Manufacturer -ne 'Microsoft') }
		}
		else { 					# ----- Get ALL the NICs
			if ( $Debug ) { Write-Host "Getting All NICs..." -ForegroundColor Cyan }
			$NICs = Get-WmiObject win32_networkadapter -ComputerName $ComputerName 
	}
	
	if ( $Wireless ) { 											# ----- Get the Wireless NICs
		if ( $Debug ) { Write-Host "Getting Wireless NICs..." -ForegroundColor Cyan }
		$N = @()
			foreach ($NIC in $NICs ) { 
				if ($NIC.NetConnectionID  -match "Wireless") { 
					 $N += $NIC
				} 
			}
			
			$NICs = $N
	}
	if ( $Wired ) { 											# ----- Get the Wired NICs
		if ( $Debug ) { Write-Host "Getting Wired NICs..." -ForegroundColor Cyan }
		$N = @()
			foreach ($NIC in $NICs ) { 
				if ($NIC.NetConnectionID -notmatch "Wireless") { 
					 $N += $NIC
				} 
			}
			
			$NICs = $N
	}

	Return $NICs
}

#------------------------------------------------------------------------------
# Function Get-WLAN
#
# Returns a list of the Wireless networks found by computer
#    http://defaultset.blogspot.com/2010/04/powershell-wireless-network-scan-script.html
#-----------------------------------------------------------------------------

Function Get-WLAN

{
	param ( $ComputerName,		#Name of remote computer, $Null if local computer
			$IFName = "" ) 		#Interface Name helpful if more than one NIC.  Leave blank to display all wireless interfaces.
	
	# ----- Housekeeping
	# ---------- Vista or Higher
	if  ((gwmi win32_operatingsystem).Version.Split(".")[0] -lt 6) {
        throw "This script works on Windows Vista or higher."
		break
	}
	# ---------- WLANService Running
	if ((gsv "wlansvc").Status -ne "Running" ) {
        throw "WLAN AutoConfig service must be running."
		break
	}
	
	if ( $ComputerName -eq $null ) {
			$WirelessInterfacesTxt = (netsh wlan show interfaces)
			$WLANNet = netsh wlan show network mode=bssid
		}
		else {
			$WirelessInterfacesTxt = Invoke-Command -computername $ComputerName -ScriptBlock {netsh wlan show interfaces}
			$WLANNet = Invoke-Command -computername $ComputerName -ScriptBlock {netsh wlan show network mode=bsssid}
	}
	
	$WirelessInterfaces = @()
	$ActiveNetworks = @()
	$BSSID = @()
	$WIF = $AN = $BSSIDInfo = $Null
	
	foreach ($TxtLine in $WLANNet ) {
		
		if ( $TxtLine -match "Interface name" ) {
			# ---- Add Interface to $WirelessInterfaces if info has been collected already
			if ( $WIF -ne $null ) {
				$WIF | Add-Member -type NoteProperty -Name ActiveNetworks -Value $ActiveNetworks
				$ActiveNetworks = @()
				$AN = $Null
				$WirelessInterfaces += $WIF
			}
			$CurrentIfName = [regex]::Match($TxtLine.Replace(  "Interface name : ","" ), '.*').ToString()
			if (($CurrentIfName.ToLower() -eq $ifname.ToLower()) -or ($ifname.length -eq 0)) {
					$WIF = New-Object system.object
					$WIF | Add-Member -type NoteProperty -Name InterFaceName -Value $CurrentIFName
					
                    $GetInterfaceInfo = $true
				} else { 
					$GetInterfaceInfo = $False
			}
		}
		$buf = [regex]::replace($TxtLine,"[ ]","")

		if ( $GetInterfaceInfo ) {
			
	
			if ([regex]::IsMatch($buf,"^SSID\d{1,}(.)*")) {
				
				if ( $AN -ne $null ) { 
					if ( $BSSIDInfo -ne $null ) { $BSSID += $BSSIDInfo }
					$AN | Add-member -type NoteProperty -Name BSSID -Value $BSSID -passthru | out-null
					$BSSID = @()
					$BSSIDInfo = $Null
					$ActiveNetworks += $AN 
					
				} 
				
                $AN = New-Object system.object
			    $AN | Add-member -type NoteProperty -Name SSID -Value ([regex]::Replace($buf,"^SSID\d{1,}:",""))
        	}
			if ([regex]::IsMatch($buf,"Networktype")) {
	            $AN | Add-member -type NoteProperty -Name NetType -Value $buf.Replace("Networktype:","")
	        }
			 if ([regex]::IsMatch($buf,"Authentication")) {
                $AN | add-member -type Noteproperty -Name Auth -value $buf.Replace("Authentication:","")
        	}
			if ([regex]::IsMatch($buf,"Encryption")) {
                $AN | add-member -type Noteproperty -Name Encryption -Value $buf.Replace("Encryption:","")
        	}
			
			if ([regex]::IsMatch($buf,"BSSID\d{1,}")) {
				if ( $BSSIDInfo -ne $null ) { $BSSID += $BSSIDInfo }
				$BSSIDInfo = New-Object System.Object	
                $BSSIDInfo | add-member -type Noteproperty -Name BSSID -Value $buf.Replace("BSSID\d{1,1}:","")
			}
	        if ([regex]::IsMatch($buf,"Signal")) {
	            $BSSIDInfo | add-member -type Noteproperty -Name Signal -value $buf.Replace("Signal:","")
	        }
	        if ([regex]::IsMatch($buf,"Radiotype")) {
	            $BSSIDInfo | add-member -type Noteproperty -Name Radiotype -Value $buf.Replace("Radiotype:","")
	        }
	        if ([regex]::IsMatch($buf,"Channel")) {
	            $BSSIDInfo | add-member -type Noteproperty -Name Channel -Value $buf.Replace("Channel:","")
	        }
		}
	}
	if ( $BSSIDInfo -ne $null ) { $BSSID += $BSSIDInfo }
		
	if ( $AN -ne $null ) { 
		if ( $BSSIDInfo -ne $null ) { $BSSID += $BSSIDInfo }
		$AN | Add-member -type NoteProperty -Name BSSID -Value $BSSID
		$ActiveNetworks += $AN 
	} 

	if ( $WIF -ne $null ) {
		$WIF | Add-Member -type NoteProperty -Name ActiveNetworks -Value $ActiveNetworks
		$WirelessInterfaces += $WIF
	}
	
	if ( ($CurrentIfName.ToLower() -eq $ifname.ToLower()) -or ($ifname.length -eq 0) ) {
	        if (( $WirelessInterfaces -ne $Null )) {
#                	$ActiveNetworks | Sort-Object Signal -Descending | ft @{Label = "BSSID"; Expression={$_.BSSID };width=18},@{Label = "Channel"; Expression={$_.Channel};width=8},@{Label = "Signal"; Expression={$_.Signal};width=7},@{Label = "Encryption"; Expression={$_.Encryption};width=11},@{Label = "Authentication"; Expression={$_.Auth};width=15},SSID
					return $WirelessInterfaces
				} 
				else {
		           Write-host "`n No active networks found.`n"
	        }
		} 
		else {
			Write-host -ForegroundColor Red "`n Could not find interface: "$ifname"`n"
	}

	
}

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

Export-ModuleMember -Function Get-WLAN, Get-NIC