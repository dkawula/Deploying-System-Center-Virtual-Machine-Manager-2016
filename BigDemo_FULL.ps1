<#
Created:	 2018-02-01
Version:	 1.0
Author       Dave Kawula MVP and Thomas Rayner MVP
Homepage:    http://www.checkyourlogs.net

Disclaimer:
This script is provided "AS IS" with no warranties, confers no rights and 
is not supported by the authors or CheckyourLogs or MVPDays Publishing

Author - Dave Kawula
    Twitter: @DaveKawula
    Blog   : http://www.checkyourlogs.net

Author - Thomas Rayner
    Twitter: @MrThomasRayner
    Blog   : http://workingsysadmin.com


    .Synopsis
    Creates a big demo lab.
    .DESCRIPTION
    Huge Thank you to Ben Armstrong @VirtualPCGuy for giving me the source starter code for this :)
    This script will build a sample lab configruation on a single Hyper-V Server:

    It includes in this version 2 Domain Controllers, 1 x DHCP Server, 1 x MGMT Server, 16 x S2D Nodes

    It is fully customizable as it has been created with base functions.

    The Parameters at the beginning of the script will setup the domain name, organization name etc.

    You will need to change the <ProductKey> Variable as it has been removed for the purposes of the print in this book.

    .EXAMPLE
    TODO: Dave, add something more meaningful in here
    .PARAMETER WorkingDir
    Transactional directory for files to be staged and written
    .PARAMETER Organization
    Org that the VMs will belong to
    .PARAMETER Owner
    Name to fill in for the OSs Owner field
    .PARAMETER TimeZone
    Timezone used by the VMs
    .PARAMETER AdminPassword
    Administrative password for the VMs
    .PARAMETER DomainName
    AD Domain to setup/join VMs to
    .PARAMETER DomainAdminPassword
    Domain recovery/admin password
    .PARAMETER VirtualSwitchName
    Name of the vSwitch for Hyper-V
    .PARAMETER Subnet
    The /24 Subnet to use for Hyper-V networking
#>

#region - 001-005 Parameters
[cmdletbinding()]
param
( 
    [Parameter(Mandatory)]
    [ValidateScript({ $_ -match '[^\\]$' })] #ensure WorkingDir does not end in a backslash, otherwise issues are going to come up below
    [string]
    $WorkingDir = 'c:\ClusterStoreage\Volume1\DCBuild',

    [Parameter(Mandatory)]
    [string]
    $Organization = 'MVP Rockstars',

    [Parameter(Mandatory)]
    [string]
    $Owner = 'Dave Kawula',

    [Parameter(Mandatory)]
    [ValidateScript({ $_ -in ([System.TimeZoneInfo]::GetSystemTimeZones()).ID })] #ensure a valid TimeZone was passed
    [string]
    $Timezone = 'Pacific Standard Time',

    [Parameter(Mandatory)]
    [string]
    $adminPassword = 'P@ssw0rd',

    [Parameter(Mandatory)]
    [string]
    $domainName = 'MVPDays.Com',

    [Parameter(Mandatory)]
    [string]
    $domainAdminPassword = 'P@ssw0rd',

    [Parameter(Mandatory)]
    [string]
    $virtualSwitchName = 'Dave MVP Demo',

    [Parameter(Mandatory)]
    [ValidatePattern('(\d{1,3}\.){3}')] #ensure that Subnet is formatted like the first three octets of an IPv4 address
    [string]
    $Subnet = '172.16.200.',

    [Parameter(Mandatory)]
    [string]
    $virtualNATSwitchName = 'Dave MVP Demo',


    [Parameter(Mandatory)]
    [string]
    $ExtraLabfilesSource = 'C:\ClusterStorage\Volume1\DCBuild\Extralabfiles'


)
#endregion

#region - 006 Functions

function Wait-PSDirect {
     param
     (
         [string]
         $VMName,

         [Object]
         $cred
     )

    Write-Log $VMName "Waiting for PowerShell Direct (using $($cred.username))"
    while ((Invoke-Command -VMName $VMName -Credential $cred {
                'Test'
    } -ea SilentlyContinue) -ne 'Test') 
    {
        Start-Sleep -Seconds 1
    }
}

Function Wait-Sleep {
	param (
		[int]$sleepSeconds = 60,
		[string]$title = "... Waiting for $sleepSeconds Seconds... Be Patient",
		[string]$titleColor = "Yellow"
	)
	Write-Host -ForegroundColor $titleColor $title
	for ($sleep = 1; $sleep -le $sleepSeconds; $sleep++ ) {
		Write-Progress -ParentId -1 -Id 42 -Activity "Sleeping for $sleepSeconds seconds" -Status "Slept for $sleep Seconds:" -percentcomplete (($sleep / $sleepSeconds) * 100)
		Start-Sleep 1
	}
    Write-Progress -Completed -Id 42 -Activity "Done Sleeping"
    }
    
function Restart-DemoVM {
     param
     (
         [string]
         $VMName
     )

    Write-Log $VMName 'Rebooting'
    stop-vm $VMName
    start-vm $VMName
}

function Confirm-Path {
    param
    (
        [string] $path
    )
    if (!(Test-Path $path)) 
    {
        $null = mkdir $path
    }
}

function Write-Log {
    param
    (
        [string]$systemName,
        [string]$message
    )

    Write-Host -Object (Get-Date).ToShortTimeString() -ForegroundColor Cyan -NoNewline
    Write-Host -Object ' - [' -ForegroundColor White -NoNewline
    Write-Host -Object $systemName -ForegroundColor Yellow -NoNewline
    Write-Host -Object "]::$($message)" -ForegroundColor White
}

function Clear-File {
    param
    (
        [string] $file
    )
    
    if (Test-Path $file) 
    {
        $null = Remove-Item $file -Recurse
    }
}

function Get-UnattendChunk {
    param
    (
        [string] $pass, 
        [string] $component, 
        [xml] $unattend
    ) 
    
    return $unattend.unattend.settings |
    Where-Object -Property pass -EQ -Value $pass `
    |
    Select-Object -ExpandProperty component `
    |
    Where-Object -Property name -EQ -Value $component
}

function New-UnattendFile {
    param
    (
        [string] $filePath
    ) 

    # Reload template - clone is necessary as PowerShell thinks this is a "complex" object
    $unattend = $unattendSource.Clone()
     
    # Customize unattend XML
    Get-UnattendChunk 'specialize' 'Microsoft-Windows-Shell-Setup' $unattend | ForEach-Object -Process {
        $_.RegisteredOrganization = 'Azure Sea Class Covert Trial' #TR-Egg
    }
    Get-UnattendChunk 'specialize' 'Microsoft-Windows-Shell-Setup' $unattend | ForEach-Object -Process {
        $_.RegisteredOwner = 'Thomas Rayner - @MrThomasRayner - workingsysadmin.com' #TR-Egg
    }
    Get-UnattendChunk 'specialize' 'Microsoft-Windows-Shell-Setup' $unattend | ForEach-Object -Process {
        $_.TimeZone = $Timezone
    }
    Get-UnattendChunk 'oobeSystem' 'Microsoft-Windows-Shell-Setup' $unattend | ForEach-Object -Process {
        $_.UserAccounts.AdministratorPassword.Value = $adminPassword
    }
    Get-UnattendChunk 'specialize' 'Microsoft-Windows-Shell-Setup' $unattend | ForEach-Object -Process {
        $_.ProductKey = $WindowsKey
    }

    Clear-File $filePath
    $unattend.Save($filePath)
}

function New-UnattendFile1 {
    param
    (
        [string] $filePath
    ) 

    # Reload template - clone is necessary as PowerShell thinks this is a "complex" object
    $unattend = $unattendSource.Clone()
     
    # Customize unattend XML
    Get-UnattendChunk 'specialize' 'Microsoft-Windows-Shell-Setup' $unattend | ForEach-Object -Process {
        $_.RegisteredOrganization = 'Azure Sea Class Covert Trial' #TR-Egg
    }
    Get-UnattendChunk 'specialize' 'Microsoft-Windows-Shell-Setup' $unattend | ForEach-Object -Process {
        $_.RegisteredOwner = 'Thomas Rayner - @MrThomasRayner - workingsysadmin.com' #TR-Egg
    }
    Get-UnattendChunk 'specialize' 'Microsoft-Windows-Shell-Setup' $unattend | ForEach-Object -Process {
        $_.TimeZone = $Timezone
    }
    Get-UnattendChunk 'oobeSystem' 'Microsoft-Windows-Shell-Setup' $unattend | ForEach-Object -Process {
        $_.UserAccounts.AdministratorPassword.Value = $adminPassword
    }
    

    Clear-File $filePath
    $unattend.Save($filePath)
}

Function Initialize-BaseImage {



    Mount-DiskImage $ServerISO
    $DVDDriveLetter = (Get-DiskImage $ServerISO | Get-Volume).DriveLetter
    Copy-Item -Path "$($DVDDriveLetter):\NanoServer\NanoServerImageGenerator\Convert-WindowsImage.ps1" -Destination "$($WorkingDir)\Convert-WindowsImage.ps1" -Force
    Import-Module -Name "$($DVDDriveLetter):\NanoServer\NanoServerImagegenerator\NanoServerImageGenerator.psm1" -Force
   
 
            if (!(Test-Path "$($BaseVHDPath)\NanoBase.vhdx")) 
            {
            New-NanoServerImage -MediaPath "$($DVDDriveLetter):\" -BasePath $BaseVHDPath -TargetPath "$($BaseVHDPath)\NanoBase.vhdx" -Edition Standard -DeploymentType Guest -Compute -Clustering -AdministratorPassword (ConvertTo-SecureString $adminPassword -AsPlainText -Force)
           # New-NanoServerImage -MediaPath "$($DVDDriveLetter):\" -BasePath $BaseVDHPath -TargetPath "$($BaseVHDPath)\NanoBase.vhdx" -GuestDrivers -DeploymentType Guest -Edition Standard -Compute -Clustering -Defender -Storage -AdministratorPassword (ConvertTo-SecureString $adminPassword -AsPlainText -Force)

            
            }
    

    #Copy-Item -Path '$WorkingDir\Convert-WindowsImage.ps1' -Destination "$($WorkingDir)\Convert-WindowsImage.ps1" -Force
    New-UnattendFile "$WorkingDir\unattend.xml"
    New-UnattendFile1 "$WorkingDir\unattend1.xml"


    #Build the Windows 2016 Core Base VHDx for the Lab
    
            if (!(Test-Path "$($BaseVHDPath)\VMServerBaseCore.vhdx")) 
                        {
            

            Set-Location $workingdir 
            #Watch the Editions --> 17079 is SERVERDATACENTERACORE and 2016 is SERVERDATACENTERCORE
            # Load (aka "dot-source) the Function 
            . .\Convert-WindowsImage.ps1 
            # Prepare all the variables in advance (optional) 
            $ConvertWindowsImageParam = @{  
                SourcePath          = $ServerISO1
                RemoteDesktopEnable = $True  
                Passthru            = $True  
                Edition    = "SERVERDATACENTERACORE"
                VHDFormat = "VHDX"
                SizeBytes = 60GB
                WorkingDirectory = $workingdir
                VHDPath = "$($BaseVHDPath)\VMServerBaseCore.vhdx"
                DiskLayout = 'UEFI'
                UnattendPath = "$($workingdir)\unattend1.xml" 
            }

            $VHDx = Convert-WindowsImage @ConvertWindowsImageParam

            }


            #Build the Windows 2016 Full UI Base VHDx for the Lab
    
            if (!(Test-Path "$($BaseVHDPath)\VMServerBase.vhdx")) 
                        {
            

            Set-Location $workingdir 

            # Load (aka "dot-source) the Function 
            . .\Convert-WindowsImage.ps1 
            # Prepare all the variables in advance (optional) 
            $ConvertWindowsImageParam = @{  
                SourcePath          = $ServerISO
                RemoteDesktopEnable = $True  
                Passthru            = $True  
                Edition    = "ServerDataCenter"
                VHDFormat = "VHDX"
                SizeBytes = 60GB
                WorkingDirectory = $workingdir
                VHDPath = "$($BaseVHDPath)\VMServerBase.vhdx"
                DiskLayout = 'UEFI'
                UnattendPath = "$($workingdir)\unattend.xml" 
                Package = @(  
                            "$($BaseVHDPath)\windows10.0-kb3213986-x64_a1f5adacc28b56d7728c92e318d6596d9072aec4.msu"  
                            )  


            }

            $VHDx = Convert-WindowsImage @ConvertWindowsImageParam

            }
            
    
    Clear-File "$($BaseVHDPath)\unattend.xml"
    Clear-File "$($BaseVHDPath)\unattend1.xml"
    Dismount-DiskImage $ServerISO
    Dismount-DiskImage $ServerISO1 
    #Clear-File "$($WorkingDir)\Convert-WindowsImage.ps1"

}

function Download-BaseImageUpdates {

 
            if (!(Test-Path "$($BaseVHDPath)\windows10.0-kb3213986-x64_a1f5adacc28b56d7728c92e318d6596d9072aec4.msu")) 
                        {
    Invoke-WebRequest -Uri http://download.windowsupdate.com/d/msdownload/update/software/secu/2016/12/windows10.0-kb3213986-x64_a1f5adacc28b56d7728c92e318d6596d9072aec4.msu -OutFile "$($BaseVHDPath)\windows10.0-kb3213986-x64_a1f5adacc28b56d7728c92e318d6596d9072aec4.msu" -Verbose
    }
    }

function Invoke-DemoVMPrep {
    param
    (
        [string] $VMName, 
        [string] $GuestOSName, 
        [switch] $FullServer
    ) 

    Write-Log $VMName 'Removing old VM'
    get-vm $VMName -ErrorAction SilentlyContinue |
    stop-vm -TurnOff -Force -Passthru |
    remove-vm -Force
    Clear-File "$($VMPath)\$($GuestOSName).vhdx"
   
    Write-Log $VMName 'Creating new differencing disk'
    if ($FullServer) 
    {
        $null = New-VHD -Path "$($VMPath)\$($GuestOSName).vhdx" -ParentPath "$($BaseVHDPath)\VMServerBase.vhdx" -Differencing
    }

    else 
    {
        $null = New-VHD -Path "$($VMPath)\$($GuestOSName).vhdx" -ParentPath "$($BaseVHDPath)\VMServerBaseCore.vhdx" -Differencing
    }

    Write-Log $VMName 'Creating virtual machine'
    new-vm -Name $VMName -MemoryStartupBytes 4GB -SwitchName $virtualSwitchName `
    -Generation 2 -Path "$($VMPath)\" | Set-VM -ProcessorCount 2 

    Set-VMFirmware -VMName $VMName -SecureBootTemplate MicrosoftUEFICertificateAuthority
    Set-VMFirmware -Vmname $VMName -EnableSecureBoot off
    Add-VMHardDiskDrive -VMName $VMName -Path "$($VMPath)\$($GuestOSName).vhdx" -ControllerType SCSI
    Write-Log $VMName 'Starting virtual machine'
    Enable-VMIntegrationService -Name 'Guest Service Interface' -VMName $VMName
    start-vm $VMName
}

function Create-DemoVM {
    param
    (
        [string] $VMName, 
        [string] $GuestOSName, 
        [string] $IPNumber = '0'
    ) 
  
    Wait-PSDirect $VMName -cred $localCred

    Invoke-Command -VMName $VMName -Credential $localCred {
        param($IPNumber, $GuestOSName,  $VMName, $domainName, $Subnet)
        if ($IPNumber -ne '0') 
        {
            Write-Output -InputObject "[$($VMName)]:: Setting IP Address to $($Subnet)$($IPNumber)"
            $null = New-NetIPAddress -IPAddress "$($Subnet)$($IPNumber)" -InterfaceAlias 'Ethernet' -PrefixLength 24
            Write-Output -InputObject "[$($VMName)]:: Setting DNS Address"
            Get-DnsClientServerAddress | ForEach-Object -Process {
                Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses "$($Subnet)1"
            }
        }
        Write-Output -InputObject "[$($VMName)]:: Renaming OS to `"$($GuestOSName)`""
        Rename-Computer -NewName $GuestOSName
        Write-Output -InputObject "[$($VMName)]:: Configuring WSMAN Trusted hosts"
        Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value "*.$($domainName)" -Force
        Set-Item WSMan:\localhost\client\trustedhosts "$($Subnet)*" -Force -concatenate
        Enable-WSManCredSSP -Role Client -DelegateComputer "*.$($domainName)" -Force
    } -ArgumentList $IPNumber, $GuestOSName, $VMName, $domainName, $Subnet

    Restart-DemoVM $VMName
    
    Wait-PSDirect $VMName -cred $localCred
}

function Invoke-NodeStorageBuild {
  param
  (
    [string]$VMName, 
    [string]$GuestOSName
  )

  Create-DemoVM $VMName $GuestOSName
  Clear-File "$($VMPath)\$($GuestOSName) - Data 1.vhdx"
  Clear-File "$($VMPath)\$($GuestOSName) - Data 2.vhdx"
  Get-VM $VMName | Stop-VM 
  Add-VMNetworkAdapter -VMName $VMName -SwitchName $virtualSwitchName
  New-VHD -Path "$($VMPath)\$($GuestOSName) - Data 1.vhdx" -Dynamic -SizeBytes 200GB 
  Add-VMHardDiskDrive -VMName $VMName -Path "$($VMPath)\$($GuestOSName) - Data 1.vhdx" -ControllerType SCSI
  New-VHD -Path "$($VMPath)\$($GuestOSName) - Data 2.vhdx" -Dynamic -SizeBytes 200GB
  Add-VMHardDiskDrive -VMName $VMName -Path "$($VMPath)\$($GuestOSName) - Data 2.vhdx" -ControllerType SCSI
  Set-VMProcessor -VMName $VMName -Count 2 -ExposeVirtualizationExtensions $True
  Add-VMNetworkAdapter -VMName $VMName -SwitchName $virtualSwitchName
  Add-VMNetworkAdapter -VMName $VMName -SwitchName $virtualSwitchName
  Add-VMNetworkAdapter -VMName $VMName -SwitchName $virtualSwitchName
  Get-VMNetworkAdapter -VMName $VMName | Set-VMNetworkAdapter -AllowTeaming On
  Get-VMNetworkAdapter -VMName $VMName | Set-VMNetworkAdapter -MacAddressSpoofing on
  Start-VM $VMName
  Wait-PSDirect $VMName -cred $localCred

  Invoke-Command -VMName $VMName -Credential $localCred {
    param($VMName, $domainCred, $domainName)
    Write-Output -InputObject "[$($VMName)]:: Installing Clustering"
    $null = Install-WindowsFeature -Name File-Services, Failover-Clustering, Hyper-V -IncludeManagementTools
    Write-Output -InputObject "[$($VMName)]:: Joining domain as `"$($env:computername)`""
    
    while (!(Test-Connection -ComputerName $domainName -BufferSize 16 -Count 1 -Quiet -ea SilentlyContinue)) 
    {
      Start-Sleep -Seconds 1
    }
    
    do 
    {
      Add-Computer -DomainName $domainName -Credential $domainCred -ea SilentlyContinue
    }
    until ($?)
  } -ArgumentList $VMName, $domainCred, $domainName

  Wait-PSDirect $VMName -cred $domainCred

  Invoke-Command -VMName $VMName -Credential $domainCred {
    Rename-NetAdapter -Name 'Ethernet' -NewName 'LOM-P0'
    Rename-NetAdapter -Name 'Ethernet 2' -NewName 'LOM-P1'
    Rename-NetAdapter -Name 'Ethernet 3' -NewName 'Riser-P0'
    Get-NetAdapter -Name 'Ethernet 5' | Rename-NetAdapter -NewName 'Riser-P1'
     }

  Restart-DemoVM $VMName
  #Wait-PSDirect $VMName -cred $domainCred

  
  }

function Invoke-DemoVMPrepESXi {
    param
    (
        [string] $VMName, 
        [string] $GuestOSName
        
    ) 

    Write-Log $VMName 'Removing old VM'
    get-vm $VMName -ErrorAction SilentlyContinue |
    stop-vm -TurnOff -Force -Passthru |
    remove-vm -Force
    Clear-File "$($VMPath)\$($GuestOSName).vhdx"
   
    Write-Log $VMName 'Creating virtual machine'
    new-vm -Name $VMName -MemoryStartupBytes 4GB -SwitchName $virtualSwitchName  `
    -Generation 1 -Path "$($VMPath)\" | Set-VMProcessor -ExposeVirtualizationExtensions $True -Count 2
    Get-VMNetworkAdapter -VMName $VMname | Remove-VMNetworkAdapter
    Add-VMNetworkAdapter -VMName $VMName -IsLegacy $true -SwitchName $virtualSwitchName

    #Set-VMFirmware -VMName $VMName -SecureBootTemplate MicrosoftUEFICertificateAuthority
    #Set-VMFirmware -Vmname $VMName -EnableSecureBoot off
    New-VHD -Path "$($VMPath)\$($GuestOSName) - Boot.vhdx" -Dynamic -SizeBytes 10GB 
    Add-VMHardDiskDrive -VMName $VMName -Path "$($VMPath)\$($GuestOSName) - Boot.vhdx" -ControllerType IDE
    New-VHD -Path "$($VMPath)\$($GuestOSName) - Data 1.vhdx" -Dynamic -SizeBytes 200GB 
    Add-VMHardDiskDrive -VMName $VMName -Path "$($VMPath)\$($GuestOSName) - Data 1.vhdx" -ControllerType IDE
    Write-Log $VMName 'Starting virtual machine'
    Enable-VMIntegrationService -Name 'Guest Service Interface' -VMName $VMName
    start-vm $VMName
}

Function Install-WSUS {
  #Installs WSUS to the Target VM in the Lab
  #Script core functions from Eric @XenAppBlog
  param
  (
    [string]$VMName, 
    [string]$GuestOSName
  )

    #Adding WSUS Drive 

    New-VHD -Path "$($VMPath)\$($GuestOSName) - WSUS Data 1.vhdx" -Dynamic -SizeBytes 400GB 
    Mount-VHD -Path "$($VMPath)\$($GuestOSName) - WSUS Data 1.vhdx"
    $DiskNumber = (Get-Diskimage -ImagePath "$($VMPath)\$($GuestOSName) - WSUS Data 1.vhdx").Number
    Initialize-Disk -Number $DiskNumber -PartitionStyle GPT 
    Get-Disk -Number $DiskNumber | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem NTFS -NewFileSystemLabel "WSUS" -Confirm:$False
    Dismount-VHD -Path "$($VMPath)\$($GuestOSName) - WSUS Data 1.vhdx"
    Add-VMHardDiskDrive -VMName $VMName -Path "$($VMPath)\$($GuestOSName) - WSUS Data 1.vhdx" -ControllerType SCSI
  



    icm -VMName $VMName -Credential $domainCred {

    Get-Disk | Where OperationalStatus -EQ "Offline" | Set-Disk -IsOffline $False 
    Get-Disk | Where Number -NE "0" |  Set-Disk -IsReadOnly $False
    $Driveletter = get-wmiobject -class "Win32_Volume" -namespace "root\cimv2" | where-object {$_.Label -like "WSUS*"}
    $WSUSDrive = $Driveletter.DriveLetter
    
    Install-WindowsFeature -Name UpdateServices -IncludeManagementTools
    Install-WindowsFeature -Name UpdateServices-Ui
    New-Item -Path $WSUSDrive -Name WSUS -ItemType Directory
    CD "C:\Program Files\Update Services\Tools"
    .\wsusutil.exe postinstall "CONTENT_DIR=$($WSUSDrive)\WSUS"
    Write-Verbose "Get WSUS Server Object" -Verbose
    $wsus = Get-WSUSServer

    Write-Verbose "Connect to WSUS server configuration" -Verbose
    $wsusConfig = $wsus.GetConfiguration()

    Write-Verbose "Set to download updates from Microsoft Updates" -Verbose
    Set-WsusServerSynchronization -SyncFromMU

    Write-Verbose "Set Update Languages to English and save configuration settings" -Verbose
    $wsusConfig.AllUpdateLanguagesEnabled = $false           
    $wsusConfig.SetEnabledUpdateLanguages("en")           
    $wsusConfig.Save()

    Write-Verbose "Get WSUS Subscription and perform initial synchronization to get latest categories" -Verbose
    $subscription = $wsus.GetSubscription()
    $subscription.StartSynchronizationForCategoryOnly()

	    While ($subscription.GetSynchronizationStatus() -ne 'NotProcessing') {
		    Write-Host "." -NoNewline
		    Start-Sleep -Seconds 5
	    }

    Write-Verbose "Sync is Done" -Verbose

    Write-Verbose "Disable Products" -Verbose
    Get-WsusServer | Get-WsusProduct | Where-Object -FilterScript { $_.product.title -match "Office" } | Set-WsusProduct -Disable
    Get-WsusServer | Get-WsusProduct | Where-Object -FilterScript { $_.product.title -match "Windows" } | Set-WsusProduct -Disable
						
    Write-Verbose "Enable Products" -Verbose
    Get-WsusServer | Get-WsusProduct | Where-Object -FilterScript { $_.product.title -match "Windows Server 2016" } | Set-WsusProduct

    Write-Verbose "Disable Language Packs" -Verbose
    Get-WsusServer | Get-WsusProduct | Where-Object -FilterScript { $_.product.title -match "Language Packs" } | Set-WsusProduct -Disable

    Write-Verbose "Configure the Classifications" -Verbose

	    Get-WsusClassification | Where-Object {
		    $_.Classification.Title -in (
			    'Critical Updates',
			    'Definition Updates',
			    'Feature Packs',
			    'Security Updates',
			    'Service Packs',
			    'Update Rollups',
			    'Updates')
		    } | Set-WsusClassification

    Write-Verbose "Configure Synchronizations" -Verbose
    $subscription.SynchronizeAutomatically=$true

    Write-Verbose "Set synchronization scheduled for midnight each night" -Verbose
    $subscription.SynchronizeAutomaticallyTimeOfDay= (New-TimeSpan -Hours 0)
    $subscription.NumberOfSynchronizationsPerDay=1
    $subscription.Save()

    Write-Verbose "Kick Off Synchronization" -Verbose
    $subscription.StartSynchronization()

    Write-Verbose "Monitor Progress of Synchronisation" -Verbose

    <#>Start-Sleep -Seconds 60 # Wait for sync to start before monitoring
	    while ($subscription.GetSynchronizationProgress().ProcessedItems -ne $subscription.GetSynchronizationProgress().TotalItems) {
		    #$subscription.GetSynchronizationProgress().ProcessedItems * 100/($subscription.GetSynchronizationProgress().TotalItems)
		    Start-Sleep -Seconds 5
   
	}
    </#>
    }


    #Restart-DemoVM $VMName
    
    #Wait-PSDirect $VMName -cred $DomainCred

    icm -VMName $VMName -Credential $domainCred {
    #Change server name and port number and $True if it is on SSL

    $Computer = $env:COMPUTERNAME
    [String]$updateServer1 = $Computer
    [Boolean]$useSecureConnection = $False
    [Int32]$portNumber = 8530

    # Load .NET assembly

    [void][reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")

    $count = 0

    # Connect to WSUS Server

    $updateServer = [Microsoft.UpdateServices.Administration.AdminProxy]::getUpdateServer($updateServer1,$useSecureConnection,$portNumber)

    write-host "<<<Connected sucessfully >>>" -foregroundcolor "yellow"

    $updatescope = New-Object Microsoft.UpdateServices.Administration.UpdateScope

    $u=$updateServer.GetUpdates($updatescope )

    foreach ($u1 in $u )

    {

    if ($u1.IsSuperseded -eq 'True')

    {

    write-host Decline Update : $u1.Title

    $u1.Decline()

    $count=$count + 1

    }

    }

    write-host Total Declined Updates: $count

    trap

    {

    write-host "Error Occurred"

    write-host "Exception Message: "

    write-host $_.Exception.Message

    write-host $_.Exception.StackTrace

    exit

    }

    # EOF


    }
    }
    
Function Install-NetNat {
   param
  (
    [string]$VMName, 
    [string]$GuestOSName
  )

    Write-Output -InputObject "[$($VMName)]:: Configuring NAT on the Hyper-V Internal Switch `"$($env:computername)`""
    $CheckNATSwitch = get-vmswitch | where Name -eq $virtualNATSwitchName | Select Name

    If ($CheckNATSwitch -ne $null) {
    write-Host "Internal NAT Switch Found"}
    Else {
    
    write-Host "Not Found"
    Write-Host "Creating NAT Switch"

    New-VMSwitch -SwitchName $virtualNATSwitchName -SwitchType Internal 
    $ifindex = Get-NetAdapter | Where Name -like *$virtualNATSwitchName* |  New-NetIPAddress 192.168.10.1 -PrefixLength 24 
    
    Get-Netnat | Remove-NetNat -confirm:$false
    New-NetNat -Name $virtualNATSwitchName -InternalIPInterfaceAddressPrefix 192.168.10.0/24
               
    }
    }

Function Install-RRAS{
    param
    (
        [string] $VMName, 
        [string] $GuestOSName,
        [string] $IPAddress
    ) 

    Add-VMNetworkAdapter -VMName $VMName -SwitchName $virtualNATSwitchName

    Invoke-Command -VMName $VMName -Credential $domainCred {
    Write-Output -InputObject "[$($VMName)]:: Setting InternetIP Address to 192.168.10.254"


  
    $null = New-NetIPAddress -IPAddress "192.168.10.254" -InterfaceAlias 'Ethernet 2' -PrefixLength 24
    $newroute = '192.168.10.1'
    Write-Output -InputObject "[$($VMName)]:: Configuring Default Gateway"
    $null = Get-Netroute | Where DestinationPrefix -eq "0.0.0.0/0" | Remove-NetRoute -Confirm:$False
    #$null = Test-NetConnection localhost
    new-netroute -InterfaceAlias "Ethernet 2" -NextHop $newroute  -DestinationPrefix '0.0.0.0/0' -verbose
    $null = Get-NetAdapter | where name -EQ "Ethernet" | Rename-NetAdapter -NewName CorpNet
    $null = Get-NetAdapter | where name -EQ "Ethernet 2" | Rename-NetAdapter -NewName Internet
    Write-Output -InputObject "[$($VMName)]:: Installing RRAS"
    $null = Install-WindowsFeature -Name RemoteAccess,Routing,RSAT-RemoteAccess-Mgmt 
    #$null =  Stop-Service -Name WDSServer -ErrorAction SilentlyContinue
    #$null = Set-Service -Name WDSServer -StartupType Disabled -ErrorAction SilentlyContinue

    $ExternalInterface="Internet"
    $InternalInterface="CorpNet"
    Write-Output -InputObject "[$($VMName)]:: Coniguring RRAS - Adding Internal and External Adapters"
    $null = Start-Process -Wait:$true -FilePath "netsh" -ArgumentList "ras set conf ENABLED"
    $null = Set-Service -Name RemoteAccess -StartupType Automatic
    $null = Start-Service -Name RemoteAccess

     Write-Output -InputObject "[$($VMName)]:: Configuring NAT - Lab is now Internet Enabled"
    $null = Start-Process -Wait:$true -FilePath "netsh" -ArgumentList "routing ip nat install"
    $null = Start-Process -Wait:$true -FilePath "netsh" -ArgumentList "routing ip nat add interface ""CorpNet"""
    $null = Test-NetConnection 192.168.10.1
    $null = Test-NetConnection 4.2.2.2
    $null = cmd.exe /c "netsh routing ip nat add interface $externalinterface"
    $null = cmd.exe /c "netsh routing ip nat set interface $externalinterface mode=full"
    $null = Test-NetConnection 192.168.10.1
   # $null = Test-NetConnection $($Subnet)1
    $null = Test-NetConnection 4.2.2.2
     Write-Output -InputObject "[$($VMName)]:: Disable FireWall"
    $null = cmd.exe /c "netsh firewall set opmode disable"
      
    
    }
}

Function Create-SQLInstallFile {
#You will need to modify this for your environment accounts
#I have defaulted to MVPDays\svc_SQL and a password of P@ssw0rd
#If you are changing in your lab adjust acordingly 
#I will automate this later on.

Write-Output -InputObject "[$($VMName)]:: Creating SQL Install INI File"
$functionText = @"
;SQL Server 2016 Configuration File
[OPTIONS]
; Specifies a Setup work flow, like INSTALL, UNINSTALL, or UPGRADE. This is a required parameter. 
ACTION="Install"
; Specifies that SQL Server Setup should not display the privacy statement when ran from the command line. 
SUPPRESSPRIVACYSTATEMENTNOTICE="True"
IACCEPTSQLSERVERLICENSETERMS="True"
; By specifying this parameter and accepting Microsoft R Open and Microsoft R Server terms, you acknowledge that you have read and understood the terms of use. 
IACCEPTROPENLICENSETERMS="True"
; Use the /ENU parameter to install the English version of SQL Server on your localized Windows operating system. 
ENU="True"
; Setup will not display any user interface. 
QUIET="True"
; Setup will display progress only, without any user interaction. 
QUIETSIMPLE="False"
; Parameter that controls the user interface behavior. Valid values are Normal for the full UI,AutoAdvance for a simplied UI, and EnableUIOnServerCore for bypassing Server Core setup GUI block. 
;UIMODE="Normal"
; Specify whether SQL Server Setup should discover and include product updates. The valid values are True and False or 1 and 0. By default SQL Server Setup will include updates that are found. 
UpdateEnabled="True"
; If this parameter is provided, then this computer will use Microsoft Update to check for updates. 
USEMICROSOFTUPDATE="True"
; Specifies features to install, uninstall, or upgrade. The list of top-level features include SQL, AS, RS, IS, MDS, and Tools. The SQL feature will install the Database Engine, Replication, Full-Text, and Data Quality Services (DQS) server. The Tools feature will install shared components. 
FEATURES=SQLENGINE,RS,FULLTEXT
; Specify the location where SQL Server Setup will obtain product updates. The valid values are "MU" to search Microsoft Update, a valid folder path, a relative path such as .\MyUpdates or a UNC share. By default SQL Server Setup will search Microsoft Update or a Windows Update service through the Window Server Update Services. 
UpdateSource="MU"
; Displays the command line parameters usage 
HELP="False"
; Specifies that the detailed Setup log should be piped to the console. 
INDICATEPROGRESS="False"
; Specifies that Setup should install into WOW64. This command line argument is not supported on an IA64 or a 32-bit system. 
X86="False"
; Specify a default or named instance. MSSQLSERVER is the default instance for non-Express editions and SQLExpress for Express editions. This parameter is required when installing the SQL Server Database Engine (SQL), Analysis Services (AS), or Reporting Services (RS). 
INSTANCENAME="MSSQLSERVER"
; Specify the root installation directory for shared components.  This directory remains unchanged after shared components are already installed. 
INSTALLSHAREDDIR="E:\Program Files\Microsoft SQL Server"
; Specify the root installation directory for the WOW64 shared components.  This directory remains unchanged after WOW64 shared components are already installed. 
INSTALLSHAREDWOWDIR="E:\Program Files (x86)\Microsoft SQL Server"
; Specify the Instance ID for the SQL Server features you have specified. SQL Server directory structure, registry structure, and service names will incorporate the instance ID of the SQL Server instance. 
INSTANCEID="MSSQLSERVER"
; Specifies which mode report server is installed in.  
; Default value: “FilesOnly”  
RSINSTALLMODE="FilesOnlyMode"
; TelemetryUserNameConfigDescription 
SQLTELSVCACCT="NT Service\SQLTELEMETRY"
; TelemetryStartupConfigDescription 
SQLTELSVCSTARTUPTYPE="Automatic"
; Specify the installation directory. 
INSTANCEDIR="E:\Program Files\Microsoft SQL Server"
; Agent account name 
AGTSVCACCOUNT="MVPDAYS\SVC_SQL"
AGTSVCPASSWORD="P@ssw0rd"
; Auto-start service after installation.  
AGTSVCSTARTUPTYPE="Automatic"
; CM brick TCP communication port 
COMMFABRICPORT="0"
; How matrix will use private networks 
COMMFABRICNETWORKLEVEL="0"
; How inter brick communication will be protected 
COMMFABRICENCRYPTION="0"
; TCP port used by the CM brick 
MATRIXCMBRICKCOMMPORT="0"
; Startup type for the SQL Server service. 
SQLSVCSTARTUPTYPE="Automatic"
; Level to enable FILESTREAM feature at (0, 1, 2 or 3). 
FILESTREAMLEVEL="0"
; Set to "1" to enable RANU for SQL Server Express. 
ENABLERANU="False"
; Specifies a Windows collation or an SQL collation to use for the Database Engine. 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
; Account for SQL Server service: Domain\User or system account. 
SQLSVCACCOUNT="MVPDAYS\SVC_SQL"
SQLSVCPASSWORD="P@ssw0rd"
; Set to "True" to enable instant file initialization for SQL Server service. If enabled, Setup will grant Perform Volume Maintenance Task privilege to the Database Engine Service SID. This may lead to information disclosure as it could allow deleted content to be accessed by an unauthorized principal. 
SQLSVCINSTANTFILEINIT="True"
; Windows account(s) to provision as SQL Server system administrators. 
SQLSYSADMINACCOUNTS="MVPDays\Domain Admins"
; The number of Database Engine TempDB files. 
SQLTEMPDBFILECOUNT="2"
; Specifies the initial size of a Database Engine TempDB data file in MB. 
SQLTEMPDBFILESIZE="8"
; Specifies the automatic growth increment of each Database Engine TempDB data file in MB. 
SQLTEMPDBFILEGROWTH="64"
; Specifies the initial size of the Database Engine TempDB log file in MB. 
SQLTEMPDBLOGFILESIZE="8"
; Specifies the automatic growth increment of the Database Engine TempDB log file in MB. 
SQLTEMPDBLOGFILEGROWTH="64"
; Provision current user as a Database Engine system administrator for %SQL_PRODUCT_SHORT_NAME% Express. 
ADDCURRENTUSERASSQLADMIN="False"
; Specify 0 to disable or 1 to enable the TCP/IP protocol. 
TCPENABLED="1"
; Specify 0 to disable or 1 to enable the Named Pipes protocol. 
NPENABLED="0"
; Startup type for Browser Service. 
BROWSERSVCSTARTUPTYPE="Disabled"
; Specifies which account the report server NT service should execute under.  When omitted or when the value is empty string, the default built-in account for the current operating system.
; The username part of RSSVCACCOUNT is a maximum of 20 characters long and
; The domain part of RSSVCACCOUNT is a maximum of 254 characters long. 
RSSVCACCOUNT="MVPDAYS\SVC_SQL"
RSSVCPASSWORD="P@ssw0rd"
; Specifies how the startup mode of the report server NT service.  When 
; Manual - Service startup is manual mode (default).
; Automatic - Service startup is automatic mode.
; Disabled - Service is disabled 
RSSVCSTARTUPTYPE="Automatic"
FTSVCACCOUNT="MVPDAYS\SVC_SQL"
"@

New-Item "$($WorkingDir)\SqlInstall.ini" -type file -force -value $functionText

}

Function Install-SQLDPM{
 <#
Created:	 2018-02-01
Version:	 1.0
Author       Dave Kawula MVP
Homepage:    http://www.checkyourlogs.net

Disclaimer:
This script is provided "AS IS" with no warranties, confers no rights and 
is not supported by the authors or CheckyourLogs or MVPDays Publishing

Author - Dave Kawula
    Twitter: @DaveKawula
    Blog   : http://www.checkyourlogs.net


    .Synopsis
    Deploys System Center SQL Server 2016 Instance to  a Hyper-V Lab VM
    .DESCRIPTION
    This Script was part of my BIGDemo series and I have broken it out into a standalone function

    You will need to have a SVC_SQL Pre-Created and SQL 2016 Media for this lab to work
    The Script will prompt for the path of the Files Required
    The Script will prompt for an Admin Account which will be used in $DomainCred
    If your File names are different than mine adjust accordingly.

    We will use PowerShell Direct to setup the Veeam Server in Hyper-V

    The Source Hyper-V Virtual Machine needs to be Windows Server 2016

    .EXAMPLE
    TODO: Dave, add something more meaningful in here
    .PARAMETER WorkingDir
    Transactional directory for files to be staged and written
    .PARAMETER VMname
    The name of the Virtual Machine
    .PARAMETER VMPath
    The Path to the VM Working Folder - We create a new VHDx for the DPM Install
    .PARAMETER GuestOSName
    Name of the Guest Operating System Name
    

    Usage: Install-DPM -Vmname YOURVM -GuestOS VEEAMSERVER -VMpath f:\VMs\SCVMM -WorkingDir f:\Temp 
#>
  #Installs SCVMM 1801 for your lab

 param
  (
    [string]$VMName, 
    [string]$GuestOSName,
    [string]$VMPath
   

  )
     

     #$DomainCred = Get-Credential
     #$VMName = 'DPM01'
     #$GuestOSname = 'DPM01'
     #$VMPath = 'f:\dcbuild_Test\VMs'
     #$SQL = 'VMM01\MSSQLSERVER'
     #$SCOMDrive = 'd:'

   
     
      icm -VMName $VMName -Credential $DomainCred {

      Write-Output -InputObject "[$($VMName)]:: Configure DPM Service Account as a Local Admin"

   # Add-LocalGroupMember -Group Administrators -Member $DPMServiceAcct

    
     Write-Output -InputObject "[$($VMName)]:: Enable .Net Framework 3.5"

     Dism.exe /Online /Enable-Feature /FeatureName:NetFx3 /All /Source:$setup1\sources\sxs

     
     }

    Restart-DemoVM -VMName $VMname
    Wait-PSDirect -VMName $VMName -cred $DomainCred



    Write-Output -InputObject "[$($VMName)]:: Adding Drive for DPM Install"

    New-VHD -Path "$($VMPath)\$($GuestOSName) - SQL Data 2.vhdx" -Dynamic -SizeBytes 50GB 
    Mount-VHD -Path "$($VMPath)\$($GuestOSName) - SQL Data 2.vhdx" 
    $DiskNumber = (Get-Diskimage -ImagePath "$($VMPath)\$($GuestOSName) - SQL Data 2.vhdx").Number
    Initialize-Disk -Number $DiskNumber -PartitionStyle GPT 
    Get-Disk -Number $DiskNumber | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem NTFS -NewFileSystemLabel "SQL" -Confirm:$False
    $Driveletter = get-wmiobject -class "Win32_Volume" -namespace "root\cimv2" | where-object {$_.Label -like "SQL*"}
    $SQLDriveLetter = $DriveLetter.DriveLetter
    Write-Output -InputObject "[$($VMName)]:: Copying SQL ISO to the new VHDx"
    Copy-Item -Path "$($WorkingDir)\en_sql_server_2016_standard_with_service_pack_1_x64_dvd_9540929.iso" -Destination "$($SQLDriveLetter)\en_sql_server_2016_standard_with_service_pack_1_x64_dvd_9540929.iso" -Force
    Write-Output -InputObject "[$($VMName)]:: Copying SSMS to the new VHDx"
    Copy-Item -Path "$($WorkingDir)\SSMS-Setup-ENU-16.5.exe" -Destination "$($SQLDriveLetter)\SSMS-Setup-ENU.exe" -Force
    Dismount-VHD -Path "$($VMPath)\$($GuestOSName) - SQL Data 2.vhdx"
    Add-VMHardDiskDrive -VMName $VMName -Path "$($VMPath)\$($GuestOSName) - SQL Data 2.vhdx" -ControllerType SCSI
  


    icm -VMName $VMName -Credential $domainCred {
      
    Write-Output -InputObject "[$($VMName)]:: Adding the new VHDx for the SQL Install"
    Get-Disk | Where OperationalStatus -EQ "Offline" | Set-Disk -IsOffline $False 
    Get-Disk | Where Number -NE "0" |  Set-Disk -IsReadOnly $False
    $Driveletter = get-wmiobject -class "Win32_Volume" -namespace "root\cimv2" | where-object {$_.Label -like "SQL*"}
    $SQLDrive = $Driveletter.DriveLetter

    Write-Output -InputObject "[$($VMName)]:: Mounting SQL ISO"

    $iso = Get-ChildItem -Path "$($SQLDrive)\en_sql_server_2016_standard_with_service_pack_1_x64_dvd_9540929.iso"  #CHANGE THIS!

    Mount-DiskImage $iso.FullName

    $setup = $(Get-DiskImage -ImagePath $iso.FullName | Get-Volume).DriveLetter +':' 
    $setup

    Write-Output -InputObject "[$($VMName)]:: Mounting WS2016 ISO"

    $iso = Get-ChildItem -Path "$($DPMDrive)\en_windows_server_2016_x64_dvd_9718492.iso"  #CHANGE THIS!

    Mount-DiskImage $iso.FullName

    $setup1 = $(Get-DiskImage -ImagePath $iso.FullName | Get-Volume).DriveLetter +':' 
    $setup1
    

#You will need to modify this for your environment accounts
#I have defaulted to MVPDays\svc_SQL and a password of P@ssw0rd
#If you are changing in your lab adjust acordingly 
#I will automate this later on.

Write-Output -InputObject "[$($VMName)]:: Creating SQL Install INI File"
$functionText = @"
;SQL Server 2016 Configuration File
[OPTIONS]
; Specifies a Setup work flow, like INSTALL, UNINSTALL, or UPGRADE. This is a required parameter. 
ACTION="Install"
; Specifies that SQL Server Setup should not display the privacy statement when ran from the command line. 
SUPPRESSPRIVACYSTATEMENTNOTICE="True"
IACCEPTSQLSERVERLICENSETERMS="True"
; By specifying this parameter and accepting Microsoft R Open and Microsoft R Server terms, you acknowledge that you have read and understood the terms of use. 
IACCEPTROPENLICENSETERMS="True"
; Use the /ENU parameter to install the English version of SQL Server on your localized Windows operating system. 
ENU="True"
; Setup will not display any user interface. 
QUIET="True"
; Setup will display progress only, without any user interaction. 
QUIETSIMPLE="False"
; Parameter that controls the user interface behavior. Valid values are Normal for the full UI,AutoAdvance for a simplied UI, and EnableUIOnServerCore for bypassing Server Core setup GUI block. 
;UIMODE="Normal"
; Specify whether SQL Server Setup should discover and include product updates. The valid values are True and False or 1 and 0. By default SQL Server Setup will include updates that are found. 
UpdateEnabled="True"
; If this parameter is provided, then this computer will use Microsoft Update to check for updates. 
USEMICROSOFTUPDATE="True"
; Specifies features to install, uninstall, or upgrade. The list of top-level features include SQL, AS, RS, IS, MDS, and Tools. The SQL feature will install the Database Engine, Replication, Full-Text, and Data Quality Services (DQS) server. The Tools feature will install shared components. 
FEATURES=SQLENGINE,RS,FULLTEXT
; Specify the location where SQL Server Setup will obtain product updates. The valid values are "MU" to search Microsoft Update, a valid folder path, a relative path such as .\MyUpdates or a UNC share. By default SQL Server Setup will search Microsoft Update or a Windows Update service through the Window Server Update Services. 
UpdateSource="MU"
; Displays the command line parameters usage 
HELP="False"
; Specifies that the detailed Setup log should be piped to the console. 
INDICATEPROGRESS="False"
; Specifies that Setup should install into WOW64. This command line argument is not supported on an IA64 or a 32-bit system. 
X86="False"
; Specify a default or named instance. MSSQLSERVER is the default instance for non-Express editions and SQLExpress for Express editions. This parameter is required when installing the SQL Server Database Engine (SQL), Analysis Services (AS), or Reporting Services (RS). 
INSTANCENAME="MSSQLSERVER"
; Specify the root installation directory for shared components.  This directory remains unchanged after shared components are already installed. 
INSTALLSHAREDDIR="$SQLDrive\Program Files\Microsoft SQL Server"
; Specify the root installation directory for the WOW64 shared components.  This directory remains unchanged after WOW64 shared components are already installed. 
INSTALLSHAREDWOWDIR="$SQLDrive\Program Files (x86)\Microsoft SQL Server"
; Specify the Instance ID for the SQL Server features you have specified. SQL Server directory structure, registry structure, and service names will incorporate the instance ID of the SQL Server instance. 
INSTANCEID="MSSQLSERVER"
; Specifies which mode report server is installed in.  
; Default value: “FilesOnly”  
RSINSTALLMODE="DefaultNativeMode"
; TelemetryUserNameConfigDescription 
SQLTELSVCACCT="NT Service\SQLTELEMETRY"
; TelemetryStartupConfigDescription 
SQLTELSVCSTARTUPTYPE="Automatic"
; Specify the installation directory. 
INSTANCEDIR="$SQLDrive\Program Files\Microsoft SQL Server"
; Agent account name 
AGTSVCACCOUNT="MVPDAYS\SVC_SQL"
AGTSVCPASSWORD="P@ssw0rd"
; Auto-start service after installation.  
AGTSVCSTARTUPTYPE="Automatic"
; CM brick TCP communication port 
COMMFABRICPORT="0"
; How matrix will use private networks 
COMMFABRICNETWORKLEVEL="0"
; How inter brick communication will be protected 
COMMFABRICENCRYPTION="0"
; TCP port used by the CM brick 
MATRIXCMBRICKCOMMPORT="0"
; Startup type for the SQL Server service. 
SQLSVCSTARTUPTYPE="Automatic"
; Level to enable FILESTREAM feature at (0, 1, 2 or 3). 
FILESTREAMLEVEL="0"
; Set to "1" to enable RANU for SQL Server Express. 
ENABLERANU="False"
; Specifies a Windows collation or an SQL collation to use for the Database Engine. 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
; Account for SQL Server service: Domain\User or system account. 
SQLSVCACCOUNT="MVPDAYS\SVC_SQL"
SQLSVCPASSWORD="P@ssw0rd"
; Set to "True" to enable instant file initialization for SQL Server service. If enabled, Setup will grant Perform Volume Maintenance Task privilege to the Database Engine Service SID. This may lead to information disclosure as it could allow deleted content to be accessed by an unauthorized principal. 
SQLSVCINSTANTFILEINIT="True"
; Windows account(s) to provision as SQL Server system administrators. 
SQLSYSADMINACCOUNTS="MVPDays\Domain Admins"
; The number of Database Engine TempDB files. 
SQLTEMPDBFILECOUNT="2"
; Specifies the initial size of a Database Engine TempDB data file in MB. 
SQLTEMPDBFILESIZE="8"
; Specifies the automatic growth increment of each Database Engine TempDB data file in MB. 
SQLTEMPDBFILEGROWTH="64"
; Specifies the initial size of the Database Engine TempDB log file in MB. 
SQLTEMPDBLOGFILESIZE="8"
; Specifies the automatic growth increment of the Database Engine TempDB log file in MB. 
SQLTEMPDBLOGFILEGROWTH="64"
; Provision current user as a Database Engine system administrator for %SQL_PRODUCT_SHORT_NAME% Express. 
ADDCURRENTUSERASSQLADMIN="False"
; Specify 0 to disable or 1 to enable the TCP/IP protocol. 
TCPENABLED="1"
; Specify 0 to disable or 1 to enable the Named Pipes protocol. 
NPENABLED="0"
; Startup type for Browser Service. 
BROWSERSVCSTARTUPTYPE="Disabled"
; Specifies which account the report server NT service should execute under.  When omitted or when the value is empty string, the default built-in account for the current operating system.
; The username part of RSSVCACCOUNT is a maximum of 20 characters long and
; The domain part of RSSVCACCOUNT is a maximum of 254 characters long. 
RSSVCACCOUNT="MVPDAYS\SVC_SQL"
RSSVCPASSWORD="P@ssw0rd"
; Specifies how the startup mode of the report server NT service.  When 
; Manual - Service startup is manual mode (default).
; Automatic - Service startup is automatic mode.
; Disabled - Service is disabled 
RSSVCSTARTUPTYPE="Automatic"
FTSVCACCOUNT="MVPDAYS\SVC_SQL"
"@

New-Item "$($SQLDrive)\SqlInstall.ini" -type file -force -value $functionText

Write-Output -InputObject "[$($VMName)]:: Configuring WIndows Firewall for SQL New Rules"
    New-NetFirewallRule -DisplayName "SQL 2016 Exceptions-TCP" -Direction Inbound -Protocol TCP -Profile Domain -LocalPort 135,1433,1434,4088,80,443 -Action Allow
 

        Write-Output -InputObject "[$($VMName)]:: Running SQL Unattended Install"

        $setup = $(Get-DiskImage -ImagePath $iso.FullName | Get-Volume).DriveLetter +':' 
        $setup
        cmd.exe /c "$($Setup)\setup.exe /ConfigurationFile=$($SQLDrive)\SqlInstall.ini"
        

        # run installer with arg-list built above, including config file and service/SA accounts

        #Start-Process -Verb runas -FilePath $setup -ArgumentList $arglist -Wait


        # Write-Output -InputObject "[$($VMName)]:: Downloading SSMS"
         #Invoke-Webrequest was REALLY SLOW
         #Invoke-webrequest -uri https://go.microsoft.com/fwlink/?linkid=864329 -OutFile "$($SQLDrive)\SSMS-Setup-ENU.exe"
         #Changing to System.Net.WebClient
        # (New-Object System.Net.WebClient).DownloadFile("https://go.microsoft.com/fwlink/?linkid=864329","$($SQLDrive)\SSMS-Setup-ENU.exe")    



        # You can grab SSMS here:    https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms



        Start-Transcript -Path "$($SQLDrive)\SSMS-Install.log"



        $StartDateTime = get-date

        Write-Output -InputObject "[$($VMName)]:: Script started at $StartDateTime"

        #$setupfile = "$($VMMDrive)\SSMS-Setup-ENU.exe"
        Write-Output -InputObject "[$($VMName)]:: Installing SSMS"

        cmd.exe /c "$($SQLDrive)\SSMS-Setup-ENU.exe /install /quiet /norestart /log $($SQLDrive)\ssmssetup.log"

        Stop-Transcript

        # un-mount the install image when done after waiting 1 second (just for kicks)

        Start-Sleep -Seconds 1

        Dismount-DiskImage $iso.FullName
    
    }

   Restart-DemoVM -VMName $VMName
   Wait-PSDirect -VMName $VMName -cred $DomainCred

}

Function Install-SQL {
  #Installs SQL Server 2016 in the Lab
  param
  (
    [string]$VMName, 
    [string]$GuestOSName
  )

    Write-Output -InputObject "[$($VMName)]:: Adding Drive for SQL Install"

    New-VHD -Path "$($VMPath)\$($GuestOSName) - SQL Data 1.vhdx" -Dynamic -SizeBytes 400GB 
    Mount-VHD -Path "$($VMPath)\$($GuestOSName) - SQL Data 1.vhdx"
    $DiskNumber = (Get-Diskimage -ImagePath "$($VMPath)\$($GuestOSName) - SQL Data 1.vhdx").Number
    Initialize-Disk -Number $DiskNumber -PartitionStyle GPT 
    Get-Disk -Number $DiskNumber | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem NTFS -NewFileSystemLabel "SQL" -Confirm:$False
    $Driveletter = get-wmiobject -class "Win32_Volume" -namespace "root\cimv2" | where-object {$_.Label -like "SQL*"}
    $SQLDriveLetter = $DriveLetter.DriveLetter
    Write-Output -InputObject "[$($VMName)]:: Copying SQL ISO to the new VHDx"
    Copy-Item -Path "$($WorkingDir)\en_sql_server_2016_standard_with_service_pack_1_x64_dvd_9540929.iso" -Destination "$($SQLDriveLetter)\en_sql_server_2016_standard_with_service_pack_1_x64_dvd_9540929.iso" -Force
    Write-Output -InputObject "[$($VMName)]:: Copying SQLInstall.ini to the new VHDx"
    Copy-Item -Path "$($WorkingDir)\SQLInstall.ini" -Destination "$($SQLDriveLetter)\SQLInstall.ini" -Force
    Write-Output -InputObject "[$($VMName)]:: Copying SSMS to the new VHDx"
    Copy-Item -Path "$($WorkingDir)\SSMS-Setup-ENU.exe" -Destination "$($SQLDriveLetter)\SSMS-Setup-ENU.exe" -Force
    Dismount-VHD -Path "$($VMPath)\$($GuestOSName) - SQL Data 1.vhdx"
    Add-VMHardDiskDrive -VMName $VMName -Path "$($VMPath)\$($GuestOSName) - SQL Data 1.vhdx" -ControllerType SCSI
  

     
    icm -VMName $VMName -Credential $domainCred {

    Write-Output -InputObject "[$($VMName)]:: Adding the new VHDx for the SQL Install"
    Get-Disk | Where OperationalStatus -EQ "Offline" | Set-Disk -IsOffline $False 
    Get-Disk | Where Number -NE "0" |  Set-Disk -IsReadOnly $False
    $Driveletter = get-wmiobject -class "Win32_Volume" -namespace "root\cimv2" | where-object {$_.Label -like "SQL*"}
    $SQLDrive = $Driveletter.DriveLetter
    $SQLDrive

    Write-Output -InputObject "[$($VMName)]:: Mounting SQL ISO"

    $iso = Get-ChildItem -Path "$($SQLDrive)\en_sql_server_2016_standard_with_service_pack_1_x64_dvd_9540929.iso"  #CHANGE THIS!

    Mount-DiskImage $iso.FullName

    Write-Output -InputObject "[$($VMName)]:: Configuring WIndows Firewall for SQL New Rules"
    New-NetFirewallRule -DisplayName "SQL 2016 Exceptions-TCP" -Direction Inbound -Protocol TCP -Profile Domain -LocalPort 135,1433,1434,4088,80,443 -Action Allow
 

        Write-Output -InputObject "[$($VMName)]:: Running SQL Unattended Install"

        $setup = $(Get-DiskImage -ImagePath $iso.FullName | Get-Volume).DriveLetter +':' 
        $setup
        cmd.exe /c "$($Setup)\setup.exe /ConfigurationFile=$($SQLDrive)\SqlInstall.ini"
        }

        # run installer with arg-list built above, including config file and service/SA accounts

        #Start-Process -Verb runas -FilePath $setup -ArgumentList $arglist -Wait


         Write-Output -InputObject "[$($VMName)]:: Downloading SSMS"
         #Invoke-Webrequest was REALLY SLOW
         #Invoke-webrequest -uri https://go.microsoft.com/fwlink/?linkid=864329 -OutFile "$($SQLDrive)\SSMS-Setup-ENU.exe"
         #Changing to System.Net.WebClient
        # (New-Object System.Net.WebClient).DownloadFile("https://go.microsoft.com/fwlink/?linkid=864329","$($SQLDrive)\SSMS-Setup-ENU.exe")    



        # You can grab SSMS here:    https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms



        Start-Transcript -Path "$($SQLDrive)\SSMS-Install.log"



        $StartDateTime = get-date

        Write-Output -InputObject "[$($VMName)]:: Script started at $StartDateTime"

        #$setupfile = "$($VMMDrive)\SSMS-Setup-ENU.exe"
        Write-Output -InputObject "[$($VMName)]:: Installing SSMS"

        cmd.exe /c "$($SQLDrive)\SSMS-Setup-ENU.exe /install /quiet /norestart /log .\ssmssetup.log"

        Stop-Transcript

        # un-mount the install image when done after waiting 1 second (just for kicks)

        Start-Sleep -Seconds 1

        Dismount-DiskImage $iso.FullName
    
    }
    
Function Install-VMM {
  #Installs VMM 1801 in the Lab
  param
  (
    [string]$VMName, 
    [string]$GuestOSName,
    [string]$VMMDomain
  )

    Write-Output -InputObject "[$($VMName)]:: Adding Drive for VMM Install"

    New-VHD -Path "$($VMPath)\$($GuestOSName) - VMM Data 2.vhdx" -Dynamic -SizeBytes 50GB 
    Mount-VHD -Path "$($VMPath)\$($GuestOSName) - VMM Data 2.vhdx" 
    $DiskNumber = (Get-Diskimage -ImagePath "$($VMPath)\$($GuestOSName) - VMM Data 2.vhdx").Number
    Initialize-Disk -Number $DiskNumber -PartitionStyle GPT 
    Get-Disk -Number $DiskNumber | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem NTFS -NewFileSystemLabel "VMM" -Confirm:$False
    $Driveletter = get-wmiobject -class "Win32_Volume" -namespace "root\cimv2" | where-object {$_.Label -like "VMM*"}
    $VMMDriveLetter = $DriveLetter.DriveLetter
    Write-Output -InputObject "[$($VMName)]:: Copying VMM 1801 EXE to the new VHDx"
    Copy-Item -Path "$($WorkingDir)\SCVMM_1801.exe" -Destination "$($VMMDriveLetter)\SCVMM_1801.exe" -Force
    Write-Output -InputObject "[$($VMName)]:: Copying ADK to the new VHDx"
    Copy-Item -Path "$($WorkingDir)\adksetup.exe" -Destination "$($VMMDriveLetter)\adksetup.exe" -Force
    Dismount-VHD -Path "$($VMPath)\$($GuestOSName) - VMM Data 2.vhdx"
    Add-VMHardDiskDrive -VMName $VMName -Path "$($VMPath)\$($GuestOSName) - VMM Data 2.vhdx" -ControllerType SCSI
  

      icm -VMName $VMName -Credential $domainCred {

    Write-Output -InputObject "[$($VMName)]:: Adding the new VHDx for the VMM Install"
    Get-Disk | Where OperationalStatus -EQ "Offline" | Set-Disk -IsOffline $False 
    Get-Disk | Where Number -NE "0" |  Set-Disk -IsReadOnly $False
    $Driveletter = get-wmiobject -class "Win32_Volume" -namespace "root\cimv2" | where-object {$_.Label -like "VMM*"}
    $VMMDrive = $Driveletter.DriveLetter

     Write-Output -InputObject "[$($VMName)]:: Downloading ADK"
     #Invoke-webrequest -uri https://go.microsoft.com/fwlink/p/?linkid=859206 -OutFile "$($VMMDrive)\adksetup.exe"
    # (New-Object System.Net.WebClient).DownloadFile("https://go.microsoft.com/fwlink/p/?linkid=859206","f:\iso\adksetup.exe")

     #Sample ADK install



        # You can grab ADK here:     https://msdn.microsoft.com/en-us/windows/hardware/dn913721.aspx



        Start-Transcript -Path "$($VMMDrive)\ADK_Install.log"



        $StartDateTime = get-date

        Write-Output -InputObject "[$($VMName)]:: Script started at $StartDateTime"

        $setupfile = "$($VMMDrive)\ADKsetup.exe"
        
        Write-Output -InputObject "[$($VMName)]:: Installing ADK..."

        Write-Output -InputObject "[$($VMName)]:: ADK Is being installed..."
  
        Start-Process -Wait -FilePath $setupfile -ArgumentList "/features OptionID.DeploymentTools OptionID.WindowsPreinstallationEnvironment /quiet"

        Write-Output -InputObject "[$($VMName)]:: ADK install finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"

        
        Stop-Transcript

        

        Start-Transcript -Path "$($VMmDrive)\SCVMM_Install.log"



        $StartDateTime = get-date

       $null = Get-Service MSSQLServer | Start-Service

       $Null = cmd.exe /c "$($VMMDrive)\SCVMM_1801.exe /dir=$($vmmdrive)\SCVMM /silent"

       Write-Output -InputObject "[$($VMName)]:: Waiting for VMM Install to Extract"
       Start-Sleep 120

       $setupfile = "$($VMMDrive)\SCVMM\setup.exe"
       Write-Output -InputObject "[$($VMName)]:: Installing VMM"

        



        ###Get workdirectory###

        #Install VMM
        $unattendFile = New-Item "$($VMMDrive)\VMServer.ini" -type File

     $FileContent = @"
        [OPTIONS]

        CompanyName=MVPDays

        CreateNewSqlDatabase=1

        SqlInstanceName=MSSQLSERVER

        SqlDatabaseName=VirtualManagerDB

        SqlMachineName=VMM01

        LibrarySharePath=$($VMMDrive)\MSCVMMLibrary

        ProgramFiles=$($VMMDrive)\Program Files\Microsoft System Center\Virtual Machine Manager

        LibraryShareName=MSSCVMMLibrary

        SQMOptIn = 1

        MUOptIn = 1
"@
        
        Set-Content $unattendFile $fileContent

        Write-Output -InputObject "[$($VMName)]:: VMM Is Being Installed"

        Get-Service MSSQLServer | Start-Service -WarningAction SilentlyContinue

        #02/13/2018 - DK $VMMDomain isn't quite working yet so I hard coded to MVPDays for now to get it working.

        cmd.exe /c "$vmmdrive\scvmm\setup.exe /server /i /f $VMMDrive\VMServer.ini /IACCEPTSCEULA /VmmServiceDomain MVPDays /VmmServiceUserName SVC_VMM /VmmServiceUserPassword P@ssw0rd"

        do{

        Start-Sleep 1

        }until ((Get-Process | Where-Object {$_.Description -eq "SetupVM"} -ErrorAction SilentlyContinue) -eq $null)

        Write-Output -InputObject "[$($VMName)]:: VMM has been Installed"



        Stop-Transcript

       
    }

 }

Function Install-SCOM {

  #Installs VMM 1801 in the Lab
  param
  (
    [string]$VMName, 
    [string]$GuestOSName,
    [string]$VMMDomain
  )

    Write-Output -InputObject "[$($VMName)]:: Adding Drive for SCOM Install"

    New-VHD -Path "$($VMPath)\$($GuestOSName) - SCOM Data 1.vhdx" -Dynamic -SizeBytes 50GB 
    Mount-VHD -Path "$($VMPath)\$($GuestOSName) - SCOM Data 1.vhdx" 
    $DiskNumber = (Get-Diskimage -ImagePath "$($VMPath)\$($GuestOSName) - SCOM Data 1.vhdx").Number
    Initialize-Disk -Number $DiskNumber -PartitionStyle GPT 
    Get-Disk -Number $DiskNumber | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem NTFS -NewFileSystemLabel "SCOM" -Confirm:$False
    $Driveletter = get-wmiobject -class "Win32_Volume" -namespace "root\cimv2" | where-object {$_.Label -like "SCOM*"}
    $SCOMDriveLetter = $DriveLetter.DriveLetter
    Write-Output -InputObject "[$($VMName)]:: Copying SCOM 1801 EXE to the new VHDx"
    Copy-Item -Path "$($WorkingDir)\SCOM_1801_EN.exe" -Destination "$($SCOMDriveLetter)\SCOM_1801_EN.exe" -Force
    Dismount-VHD -Path "$($VMPath)\$($GuestOSName) - SCOM Data 1.vhdx"    
    Add-VMHardDiskDrive -VMName $VMName -Path "$($VMPath)\$($GuestOSName) - SCOM Data 1.vhdx" -ControllerType SCSI
  

    icm -VMName $VMName -Credential $domainCred {

    Write-Output -InputObject "[$($VMName)]:: Adding the new VHDx for the SCOM Install"
    Get-Disk | Where OperationalStatus -EQ "Offline" | Set-Disk -IsOffline $False 
    Get-Disk | Where Number -NE "0" |  Set-Disk -IsReadOnly $False
    $Driveletter = get-wmiobject -class "Win32_Volume" -namespace "root\cimv2" | where-object {$_.Label -like "SCOM*"}
    $SCOMDrive = $Driveletter.DriveLetter



     Write-Output -InputObject "[$($VMName)]:: Downloading SQLSysCLRTypes.MSI"

    #  SQLSysClrTypes: https://download.microsoft.com/download/1/3/0/13089488-91FC-4E22-AD68-5BE58BD5C014/ENU/x64/SQLSysClrTypes.msi
    Invoke-webrequest -uri https://download.microsoft.com/download/1/3/0/13089488-91FC-4E22-AD68-5BE58BD5C014/ENU/x64/SQLSysClrTypes.msi -OutFile "$($SCOMDrive)\SQLSysClrTypes.msi"


      Write-Output -InputObject "[$($VMName)]:: Downloading ReportViewer.msi"
    #ReportViewer: http://download.microsoft.com/download/F/B/7/FB728406-A1EE-4AB5-9C56-74EB8BDDF2FF/ReportViewer.msi

    Invoke-webrequest -uri http://download.microsoft.com/download/A/1/2/A129F694-233C-4C7C-860F-F73139CF2E01/ENU/x86/ReportViewer.msi -OutFile "$($SCOMDrive)\ReportViewer.msi"
     #Invoke-webrequest -uri https://go.microsoft.com/fwlink/p/?linkid=859206 -OutFile "$($VMMDrive)\adksetup.exe"
    # (New-Object System.Net.WebClient).DownloadFile("https://go.microsoft.com/fwlink/p/?linkid=859206","f:\iso\adksetup.exe")

     #Sample ADK install


    Write-Output -InputObject "[$($VMName)]:: Enabling Feature AuthManager"
    dism /online /enable-feature /featurename:AuthManager 

    Write-Output -InputObject "[$($VMName)]:: Enabling Other Features for SCOM 1801"
    Add-WindowsFeature Web-Static-Content,Web-Default-Doc,Web-Dir-Browsing,Web-Http-Errors,Web-Http-Logging,Web-Request-Monitor,Web-Filtering,Web-Stat-Compression,Web-Metabase,Web-Asp-Net,Web-Windows-Auth,Web-ASP,Web-CGI


    Add-WindowsFeature NET-WCF-HTTP-Activation45

    Write-Output -InputObject "[$($VMName)]:: Installing SQLSYSCLRTypes"
    cmd.exe /c "msiexec /i $SCOMDrive\SQLSysClrTypes.msi /q"

    Write-Output -InputObject "[$($VMName)]:: Installing ReportViewer"
    cmd.exe /c "msiexec /i $SCOMDrive\ReportViewer.msi /q"


    Write-Output -InputObject "[$($VMName)]:: Extracting SCOM 1801"
    $Null = cmd.exe /c "$($SCOMDrive)\SCOM_1801_EN.exe /dir=$($SCOMdrive)\SCOM /silent"

    Write-Output -InputObject "[$($VMName)]:: Installing SCOM 1801"
    cmd.exe /c "$SCOMDrive\SCOM\setup.exe /install /components:OMServer,OMWebConsole,OMConsole /ManagementGroupName:MVPDays /SqlServerInstance:VMM01\MSSQLSERVER /DatabaseName:OperationsManager /DWSqlServerInstance:VMM01\MSSQLSERVER /DWDatabaseName:OperationsManagerDW /ActionAccountUser:MVPDays\svc_omsvc /ActionAccountPassword:P@ssw0rd /DASAccountUser:MVPDays\svc_omaccess /DASAccountPassword:P@ssw0rd /DataReaderUser:MVPDays\svc_omreader /DataReaderPassword:P@ssw0rd /DataWriterUser:MVPDays\svc_omwriter /DataWriterPassword:P@ssw0rd /WebSiteName:""Default Web Site"" /WebConsoleAuthorizationMode:Mixed /EnableErrorReporting:Always /SendCEIPReports:1 /UseMicrosoftUpdate:1 /AcceptEndUserLicenseAgreement:1 /silent "

     }
     }

Function Install-DPM {

  <#
Created:	 2018-02-01
Version:	 1.0
Author       Dave Kawula MVP
Homepage:    http://www.checkyourlogs.net

Disclaimer:
This script is provided "AS IS" with no warranties, confers no rights and 
is not supported by the authors or CheckyourLogs or MVPDays Publishing

Author - Dave Kawula
    Twitter: @DaveKawula
    Blog   : http://www.checkyourlogs.net


    .Synopsis
    Deploys System Center Data Protection Manager (DPM )1801 Server to a Hyper-V Lab VM
    .DESCRIPTION
    This Script was part of my BIGDemo series and I have broken it out into a standalone function

    You will need to have a SCVMM Service Accounts Pre-Created and DPM 1801 Trial Media for this lab to work
    The Script will prompt for the path of the Files Required
    The Script will prompt for an Admin Account which will be used in $DomainCred
    If your File names are different than mine adjust accordingly.

    We will use PowerShell Direct to setup the Veeam Server in Hyper-V

    The Source Hyper-V Virtual Machine needs to be Windows Server 2016

    .EXAMPLE
    TODO: Dave, add something more meaningful in here
    .PARAMETER WorkingDir
    Transactional directory for files to be staged and written
    .PARAMETER VMname
    The name of the Virtual Machine
    .PARAMETER VMPath
    The Path to the VM Working Folder - We create a new VHDx for the DPM Install
    .PARAMETER GuestOSName
    Name of the Guest Operating System Name
    

    Usage: Install-DPM -Vmname YOURVM -GuestOS VEEAMSERVER -VMpath f:\VMs\SCVMM -WorkingDir f:\Temp 
#>
  #Installs SCVMM 1801 for your lab

  
 param
  (
    [string]$VMName, 
    [string]$GuestOSName,
    [string]$VMPath
   

  )
     

     #$DomainCred = Get-Credential
     #$VMName = 'DPM01'
     #$GuestOSname = 'DPM01'
     #$VMPath = 'f:\dcbuild_Test\VMs'
     #$SQL = 'VMM01\MSSQLSERVER'
     #$SCOMDrive = 'd:'


     icm -VMName $VMName -Credential $DomainCred {

      Write-Output -InputObject "[$($VMName)]:: Configure DPM Service Account as a Local Admin"

   # Add-LocalGroupMember -Group Administrators -Member $DPMServiceAcct

    
     Write-Output -InputObject "[$($VMName)]:: Disable Server Manager"

     Get-ScheduledTask -Taskname Servermanager | Disable-ScheduledTask

     Write-Output -InputObject "[$($VMName)]:: Enable Netadapter RSS"

     Enable-NetAdapterRss -Name *

      Write-Output -InputObject "[$($VMName)]:: Add Hyper-V PowerShell Features"

     Dism.exe /Online /Enable-Feature /FeatureName:Microsoft-Hyper-V /FeatureName:microsoft-Hyper-V-Management-PowerShell /quiet 


     }

    Restart-DemoVM -VMName $VMname
    Wait-PSDirect -VMName $VMName -cred $DomainCred


    Write-Output -InputObject "[$($VMName)]:: Adding Drive for DPM Install"

    New-VHD -Path "$($VMPath)\$($GuestOSName) - DPM Data 5.vhdx" -Dynamic -SizeBytes 50GB 
    Mount-VHD -Path "$($VMPath)\$($GuestOSName) - DPM Data 5.vhdx" 
    $DiskNumber = (Get-Diskimage -ImagePath "$($VMPath)\$($GuestOSName) - DPM Data 5.vhdx").Number
    Initialize-Disk -Number $DiskNumber -PartitionStyle GPT 
    Get-Disk -Number $DiskNumber | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem NTFS -NewFileSystemLabel "DPM" -Confirm:$False
    $Driveletter = get-wmiobject -class "Win32_Volume" -namespace "root\cimv2" | where-object {$_.Label -like "DPM*"}
    $DPMDriveLetter = $DriveLetter.DriveLetter
    Write-Output -InputObject "[$($VMName)]:: Copying SCDPM 1801 EXE to the new VHDx"
    Copy-Item -Path "$($Workingdir)\SCDPM_1801.exe" -Destination "$($DPMDriveLetter)\SCDPM_1801.exe" -Force
    Dismount-VHD -Path "$($VMPath)\$($GuestOSName) - DPM Data 5.vhdx"
    Add-VMHardDiskDrive -VMName $VMName -Path "$($VMPath)\$($GuestOSName) - DPM Data 5.vhdx" -ControllerType SCSI
  

    icm -VMName $VMName -Credential $domainCred {
      
    Write-Output -InputObject "[$($VMName)]:: Adding the new VHDx for the DPM Install"
    Get-Disk | Where OperationalStatus -EQ "Offline" | Set-Disk -IsOffline $False 
    Get-Disk | Where Number -NE "0" |  Set-Disk -IsReadOnly $False
    $Driveletter = get-wmiobject -class "Win32_Volume" -namespace "root\cimv2" | where-object {$_.Label -like "DPM*"}
    $DPMDrive = $Driveletter.DriveLetter

        
    Write-Output -InputObject "[$($VMName)]:: Configuring WIndows Firewall for DPM"
    Set-NetFirewallRule -DisplayName 'File and Printer Sharing (Echo Request - ICMPv4-In)' -Profile Domain -Enabled True -Direction Inbound -Action Allow
    Set-NetFirewallRule -DisplayName 'File and Printer Sharing (Echo Request - ICMPv6-In)' -Profile Domain -Enabled True -Direction Inbound -Action Allow
    Set-NetFirewallRule -DisplayName 'File and Printer Sharing (SMB-In)' -Profile Domain -Enabled True -Direction Inbound -Action Allow
    Set-NetFirewallRule -DisplayName 'Remote Desktop - User Mode (TCP-In)' -Profile Domain -Enabled True -Direction Inbound -Action Allow
    Set-NetFirewallRule -DisplayName 'Remote Desktop - User Mode (UDP-In)' -Profile Domain -Enabled True -Direction Inbound -Action Allow

    Write-Output -InputObject "[$($VMName)]:: Configuring WIndows Firewall for DPM New Rules"
    New-NetFirewallRule -DisplayName "SCDPM-TCP" -Direction Inbound -Protocol TCP -Profile Domain -LocalPort 135,5718,5719,6075,88,389,139,445 -Action Allow
    New-NetFirewallRule -DisplayName "SCDPM-UDP" -Direction Inbound -Protocol UDP -Profile Domain -LocalPort 53,88,389,137,138 -Action Allow
    New-NetFirewallRule -DisplayName "Remote-SQL Server TCP" -Direction Inbound -Protocol TCP -Profile Domain -LocalPort 80,1433 -Action Allow
    New-NetFirewallRule -DisplayName "Remote-SQL Server UDP" -Direction Inbound -Protocol UDP -Profile Domain -LocalPort 1434 -Action Allow


       $Driveletter = get-wmiobject -class "Win32_Volume" -namespace "root\cimv2" | where-object {$_.Label -eq "DPM"}
       $DPMDriveLetter1 = $DriveLetter.DriveLetter
       
      #Install VMM
      $unattendFile = New-Item "$($DPMriveletter1)\DPMSetup.ini" -type File

     $FileContent = @"
        [OPTIONS]

        CompanyName=MVPDays

        UserName=MVPDays\SVC_DPM

        ProgramFiles=$DPMDrive\Program Files

        DatabaseFiles=$DPMDrive\Program Files

        IntegratedInstallSource=$DPMDrive\SCDPM

        SQLMachineName=DPM01

        SQLInstanceName=MSSQLSERVER

        SQLMachineUserName=MVPDays\SVC_SQL

        SQLMachinePassword=P@ssw0rd

        SQLMachineDomainName=MVPDays

        SQLAccountPassword=P@ssw0rd

        ReportingMachineName=DPM01

        ReportingInstanceName=MSSQLSERVER

        ReportingMachineUserName=MVPDays\SVC_SQL

        ReportingMachinePassword=P@ssw0rd

        ReportingMachineDOmainName=MVPDays

        
"@
        
        Set-Content $unattendFile $fileContent -Force

        copy-item c:\dpmsetup.ini $DPMDriveLetter1\dpmsetup.ini -Force



         
    #I was having some issues with the path for $DPMdriveLetter Getting lost
    
    Write-Output -InputObject "[$($VMName)]:: Extracting SCDPM 1801"
    $DPMDriveletter1

    cmd.exe /c "$DPMDriveletter1\SCDPM_1801.exe /dir=$DPMdriveletter1\SCDPM /silent"
    
    Get-Service MSSQLSERVER | Start-Service
    Get-Service SQLSERVERAGENT | Start-Service
  
    Write-Output -InputObject "[$($VMName)]:: Installing DPM 1801"
    cmd.exe /c "$DPMDriveletter1\SCDPM\setup.exe /i /f $dpmdriveletter1\DPMSetup.ini /l $DPMdriveletter1\dpmlog.txt"
    
     }

     }
  
Function Install-Veeam  {

  #Installs Veeam 9.5 and UR 3
  param
  (
    [string]$VMName, 
    [string]$GuestOSName,
    [string]$VMPath,
    [string]$WorkingDir
  )

    Write-Output -InputObject "[$($VMName)]:: Adding Drive for Veeam Install"

    New-VHD -Path "$($VMPath)\$($GuestOSName) - Veeam Data 1.vhdx" -Dynamic -SizeBytes 60GB 
    Mount-VHD -Path "$($VMPath)\$($GuestOSName) - Veeam Data 1.vhdx"
    $DiskNumber = (Get-Diskimage -ImagePath "$($VMPath)\$($GuestOSName) - Veeam Data 1.vhdx").Number
    Initialize-Disk -Number $DiskNumber -PartitionStyle GPT 
    Get-Disk -Number $DiskNumber | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem NTFS -NewFileSystemLabel "Veeam" -Confirm:$False
    $Driveletter = get-wmiobject -class "Win32_Volume" -namespace "root\cimv2" | where-object {$_.Label -like "Veeam*"}
    $VeeamDriveLetter = $DriveLetter.DriveLetter
    
    
    Write-Output -InputObject "[$($VMName)]:: Copying Veeam ISO and Rollups into the new VHDx"
    Copy-Item -Path "$($WorkingDir)\VeeamBackup&Replication_9.5.0.1536.Update3.iso" -Destination "$($VeeamDriveLetter)\VeeamBackup&Replication_9.5.0.1536.Update3.iso" -Force
    Write-Output -InputObject "[$($VMName)]:: Copying Veeam license and Rollups into the new VHDx"
    Copy-Item -Path "$($WorkingDir)\veeam_backup_nfr_0_12.lic" -Destination "$($VeeamDriveLetter)\veeam_backup_nfr_0_12.lic" -Force
    Dismount-VHD -Path "$($VMPath)\$($GuestOSName) - Veeam Data 1.vhdx"
    Add-VMHardDiskDrive -VMName $VMName -Path "$($VMPath)\$($GuestOSName) - Veeam Data 1.vhdx" -ControllerType SCSI
  

    #$DomainCred = Get-Credential 
    icm -VMName $VMName -Credential $domainCred {



    Write-Output -InputObject "[$($VMName)]:: Adding the new VHDx for the Veeam Install"
    Get-Disk | Where OperationalStatus -EQ "Offline" | Set-Disk -IsOffline $False 
    Get-Disk | Where Number -NE "0" |  Set-Disk -IsReadOnly $False
    $Driveletter = get-wmiobject -class "Win32_Volume" -namespace "root\cimv2" | where-object {$_.Label -like "Veeam*"}
    $VeeamDrive = $Driveletter.DriveLetter
    $VeeamDrive

    Write-Output -InputObject "[$($VMName)]:: Mounting Veeam ISO"

    $iso = Get-ChildItem -Path "$($VeeamDrive)\VeeamBackup&Replication_9.5.0.1536.Update3.iso"  #CHANGE THIS!

    Mount-DiskImage $iso.FullName

    Write-Output -InputObject "[$($VMName)]:: Installing Veeam Unattended"

        $setup = $(Get-DiskImage -ImagePath $iso.FullName | Get-Volume).DriveLetter +':' 
        $setup
       
    <#>   
        ===========================================================================

    Original Source Created by: Markus Kraus

    Twitter: @VMarkus_K

    Private Blog: mycloudrevolution.com
    #Source PowerShell Code from https://gist.githubusercontent.com/mycloudrevolution/b176f5ab987ff787ba4fce5c177780dc/raw/f20a78dc9b7c1085b1fe4d243de3fcb514970d70/VeeamBR95-Silent.ps1

    ===========================================================================
    </#>

            # Requires PowerShell 5.1
        # Requires .Net 4.5.2 and Reboot
        

        #region: Variables
        $source = $setup
        $licensefile = "$($VeeamDrive)\veeam_backup_nfr_0_12.lic"
        $username = "svc_veeam"
        $fulluser = "MVPDays\svc_Veeam"
        $password = "P@ssw0rd"
        $CatalogPath = "$($VeeamDrive)\VbrCatalog"
        $vPowerPath = "$($VeeamDrive)\vPowerNfs"
        #endregion

        #region: logdir
        $logdir = "$($VeeamDrive)\logdir"
        $trash = New-Item -ItemType Directory -path $logdir  -ErrorAction SilentlyContinue
        #endregion

        ### Optional .Net 4.5.2
        <#
        Write-Host "    Installing .Net 4.5.2 ..." -ForegroundColor Yellow
        $Arguments = "/quiet /norestart"
        Start-Process "$source\Redistr\NDP452-KB2901907-x86-x64-AllOS-ENU.exe" -ArgumentList $Arguments -Wait -NoNewWindow
        Restart-Computer -Confirm:$true
        #>

        ### Optional PowerShell 5.1
        <#
        Write-Host "    Installing PowerShell 5.1 ..." -ForegroundColor Yellow
        $Arguments = "C:\_install\Win8.1AndW2K12R2-KB3191564-x64.msu /quiet /norestart"
        Start-Process "wusa.exe" -ArgumentList $Arguments -Wait -NoNewWindow
        Restart-Computer -Confirm:$true
        #>

        #region: Installation
        #  Info: https://www.veeam.com/unattended_installation_ds.pdf

        ## Global Prerequirements
        Write-Host "Installing Global Prerequirements ..." -ForegroundColor Yellow
        ### 2012 System CLR Types
        Write-Host "    Installing 2012 System CLR Types ..." -ForegroundColor Yellow
        $MSIArguments = @(
            "/i"
            "$source\Redistr\x64\SQLSysClrTypes.msi"
            "/qn"
            "/norestart"
            "/L*v"
            "$logdir\01_CLR.txt"
        )
        Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow

        if (Select-String -path "$logdir\01_CLR.txt" -pattern "Installation success or error status: 0.") {
            Write-Host "    Setup OK" -ForegroundColor Green
            }
            else {
                throw "Setup Failed"
                }

        ### 2012 Shared management objects
        Write-Host "    Installing 2012 Shared management objects ..." -ForegroundColor Yellow
        $MSIArguments = @(
            "/i"
            "$source\Redistr\x64\SharedManagementObjects.msi"
            "/qn"
            "/norestart"
            "/L*v"
            "$logdir\02_Shared.txt"
        )
        Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow

        if (Select-String -path "$logdir\02_Shared.txt" -pattern "Installation success or error status: 0.") {
            Write-Host "    Setup OK" -ForegroundColor Green
            }
            else {
                throw "Setup Failed"
                }

        ### SQL Express
        ### Info: https://msdn.microsoft.com/en-us/library/ms144259.aspx
        Write-Host "    Installing SQL Express ..." -ForegroundColor Yellow
        $Arguments = "/HIDECONSOLE /Q /IACCEPTSQLSERVERLICENSETERMS /ACTION=install /FEATURES=SQLEngine,SNAC_SDK /INSTANCENAME=VEEAMSQL2012 /SQLSVCACCOUNT=`"NT AUTHORITY\SYSTEM`" /SQLSYSADMINACCOUNTS=`"$fulluser`" `"Builtin\Administrators`" /TCPENABLED=1 /NPENABLED=1 /UpdateEnabled=0"
        Start-Process "$source\Redistr\x64\SQLEXPR_x64_ENU.exe" -ArgumentList $Arguments -Wait -NoNewWindow

        ## Veeam Backup & Replication
        Write-Host "Installing Veeam Backup & Replication ..." -ForegroundColor Yellow
        ### Backup Catalog
        Write-Host "    Installing Backup Catalog ..." -ForegroundColor Yellow
        $trash = New-Item -ItemType Directory -path $CatalogPath -ErrorAction SilentlyContinue
        $MSIArguments = @(
            "/i"
            "$source\Catalog\VeeamBackupCatalog64.msi"
            "/qn"
            "/L*v"
            "$logdir\04_Catalog.txt"
            "VM_CATALOGPATH=$CatalogPath"
            "VBRC_SERVICE_USER=$fulluser"
            "VBRC_SERVICE_PASSWORD=$password"
        )
        Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow

        if (Select-String -path "$logdir\04_Catalog.txt" -pattern "Installation success or error status: 0.") {
            Write-Host "    Setup OK" -ForegroundColor Green
            }
            else {
                throw "Setup Failed"
                }

        ### Backup Server
        Write-Host "    Installing Backup Server ..." -ForegroundColor Yellow
        $trash = New-Item -ItemType Directory -path $vPowerPath -ErrorAction SilentlyContinue
        $MSIArguments = @(
            "/i"
            "$source\Backup\Server.x64.msi"
            "/qn"
            "/L*v"
            "$logdir\05_Backup.txt"
            "ACCEPTEULA=YES"
            "VBR_LICENSE_FILE=$licensefile"
            "VBR_SERVICE_USER=$fulluser"
            "VBR_SERVICE_PASSWORD=$password"
            "PF_AD_NFSDATASTORE=$vPowerPath"
            "VBR_SQLSERVER_SERVER=$env:COMPUTERNAME\VEEAMSQL2012"
        )
        Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow

        if (Select-String -path "$logdir\05_Backup.txt" -pattern "Installation success or error status: 0.") {
            Write-Host "    Setup OK" -ForegroundColor Green
            }
            else {
                throw "Setup Failed"
                }

        ### Backup Console
        Write-Host "    Installing Backup Console ..." -ForegroundColor Yellow
        $MSIArguments = @(
            "/i"
            "$source\Backup\Shell.x64.msi"
            "/qn"
            "/L*v"
            "$logdir\06_Console.txt"
            "ACCEPTEULA=YES"
        )
        Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow

        if (Select-String -path "$logdir\06_Console.txt" -pattern "Installation success or error status: 0.") {
            Write-Host "    Setup OK" -ForegroundColor Green
            }
            else {
                throw "Setup Failed"
                }

        ### Explorers
        Write-Host "    Installing Explorer For ActiveDirectory ..." -ForegroundColor Yellow
        $MSIArguments = @(
            "/i"
            "$source\Explorers\VeeamExplorerForActiveDirectory.msi"
            "/qn"
            "/L*v"
            "$logdir\07_ExplorerForActiveDirectory.txt"
            "ACCEPTEULA=YES"
        )
        Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow

        if (Select-String -path "$logdir\07_ExplorerForActiveDirectory.txt" -pattern "Installation success or error status: 0.") {
            Write-Host "    Setup OK" -ForegroundColor Green
            }
            else {
                throw "Setup Failed"
                }

        Write-Host "    Installing Explorer For Exchange ..." -ForegroundColor Yellow
        $MSIArguments = @(
            "/i"
            "$source\Explorers\VeeamExplorerForExchange.msi"
            "/qn"
            "/L*v"
            "$logdir\08_VeeamExplorerForExchange.txt"
            "ACCEPTEULA=YES"
        )
        Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow

        if (Select-String -path "$logdir\08_VeeamExplorerForExchange.txt" -pattern "Installation success or error status: 0.") {
            Write-Host "    Setup OK" -ForegroundColor Green
            }
            else {
                throw "Setup Failed"
                }

        Write-Host "    Installing Explorer For SQL ..." -ForegroundColor Yellow
        $MSIArguments = @(
            "/i"
            "$source\Explorers\VeeamExplorerForSQL.msi"
            "/qn"
            "/L*v"
            "$logdir\09_VeeamExplorerForSQL.txt"
            "ACCEPTEULA=YES"
        )
        Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow

        if (Select-String -path "$logdir\09_VeeamExplorerForSQL.txt" -pattern "Installation success or error status: 0.") {
            Write-Host "    Setup OK" -ForegroundColor Green
            }
            else {
                throw "Setup Failed"
                }

        Write-Host "    Installing Explorer For Oracle ..." -ForegroundColor Yellow
        $MSIArguments = @(
            "/i"
            "$source\Explorers\VeeamExplorerForOracle.msi"
            "/qn"
            "/L*v"
            "$logdir\10_VeeamExplorerForOracle.txt"
            "ACCEPTEULA=YES"
        )
        Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow

        if (Select-String -path "$logdir\10_VeeamExplorerForOracle.txt" -pattern "Installation success or error status: 0.") {
            Write-Host "    Setup OK" -ForegroundColor Green
            }
            else {
                throw "Setup Failed"
                }

        Write-Host "    Installing Explorer For SharePoint ..." -ForegroundColor Yellow
        $MSIArguments = @(
            "/i"
            "$source\Explorers\VeeamExplorerForSharePoint.msi"
            "/qn"
            "/L*v"
            "$logdir\11_VeeamExplorerForSharePoint.txt"
            "ACCEPTEULA=YES"
        )
        Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow

        if (Select-String -path "$logdir\11_VeeamExplorerForSharePoint.txt" -pattern "Installation success or error status: 0.") {
            Write-Host "    Setup OK" -ForegroundColor Green
            }
            else {
                throw "Setup Failed"
                }

        ## Enterprise Manager
        Write-Host "Installing Enterprise Manager ..." -ForegroundColor Yellow
        ### Enterprise Manager Prereqirements
        Write-Host "    Installing Enterprise Manager Prereqirements ..." -ForegroundColor Yellow
        $trash = Install-WindowsFeature Web-Default-Doc,Web-Dir-Browsing,Web-Http-Errors,Web-Static-Content,Web-Windows-Auth -Restart:$false -WarningAction SilentlyContinue
        $trash = Install-WindowsFeature Web-Http-Logging,Web-Stat-Compression,Web-Filtering,Web-Net-Ext45,Web-Asp-Net45,Web-ISAPI-Ext,Web-ISAPI-Filter,Web-Mgmt-Console -Restart:$false  -WarningAction SilentlyContinue

        $MSIArguments = @(
            "/i"
            "$source\Redistr\x64\rewrite_amd64.msi"
            "/qn"
            "/norestart"
            "/L*v"
            "$logdir\12_Rewrite.txt"
        )
        Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow

        if (Select-String -path "$logdir\12_Rewrite.txt" -pattern "Installation success or error status: 0.") {
            Write-Host "    Setup OK" -ForegroundColor Green
            }
            else {
                throw "Setup Failed"
                }

        ### Enterprise Manager Web
        Write-Host "    Installing Enterprise Manager Web ..." -ForegroundColor Yellow
        $MSIArguments = @(
            "/i"
            "$source\EnterpriseManager\BackupWeb_x64.msi"
            "/qn"
            "/L*v"
            "$logdir\13_EntWeb.txt"
            "ACCEPTEULA=YES"
            "VBREM_LICENSE_FILE=$licensefile"
            "VBREM_SERVICE_USER=$fulluser"
            "VBREM_SERVICE_PASSWORD=$password"
            "VBREM_SQLSERVER_SERVER=$env:COMPUTERNAME\VEEAMSQL2012"
        )
        Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow

        if (Select-String -path "$logdir\13_EntWeb.txt" -pattern "Installation success or error status: 0.") {
            Write-Host "    Setup OK" -ForegroundColor Green
            }
            else {
                throw "Setup Failed"
                }

        ### Enterprise Manager Cloud Portal
        Write-Host "    Installing Enterprise Manager Cloud Portal ..." -ForegroundColor Yellow
        <#
        $MSIArguments = @(
            "/i"
            "$source\Cloud Portal\BackupCloudPortal_x64.msi"
            "/L*v"
            "$logdir\14_EntCloudPortal.txt"
            "/qn"
            "ACCEPTEULA=YES"
        )
        Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow
        #>
        Start-Process "msiexec.exe" -ArgumentList "/i `"$source\Cloud Portal\BackupCloudPortal_x64.msi`" /l*v $logdir\14_EntCloudPortal.txt /qn ACCEPTEULA=`"YES`"" -Wait -NoNewWindow

        if (Select-String -path "$logdir\14_EntCloudPortal.txt" -pattern "Installation success or error status: 0.") {
            Write-Host "    Setup OK" -ForegroundColor Green
            }
            else {
                throw "Setup Failed"
                }

        ### Update 3
        Write-Host "Installing Update 3 ..." -ForegroundColor Yellow
        $Arguments = "/silent /noreboot /log $logdir\15_update.txt VBR_AUTO_UPGRADE=1"
        Start-Process "$source\Updates\veeam_backup_9.5.0.1536.update3_setup.exe" -ArgumentList $Arguments -Wait -NoNewWindow
        #endregion

 }
 }
#endregion

#region - 007 Variable Init
$BaseVHDPath = "$($WorkingDir)\BaseVHDs"
$VMPath = "$($WorkingDir)\VMs"

$localCred = New-Object -TypeName System.Management.Automation.PSCredential `
-ArgumentList 'Administrator', (ConvertTo-SecureString -String $adminPassword -AsPlainText -Force)

$domainCred = New-Object -TypeName System.Management.Automation.PSCredential `
-ArgumentList "$($domainName)\Administrator", (ConvertTo-SecureString -String $domainAdminPassword -AsPlainText -Force)

$SQLCred = New-Object -TypeName System.Management.Automation.PSCredential `
-ArgumentList "$($domainName)\SVC_SQL", (ConvertTo-SecureString -String $domainAdminPassword -AsPlainText -Force)

$VeeamCred = New-Object -TypeName System.Management.Automation.PSCredential `
-ArgumentList "$($domainName)\SVC_Veeam", (ConvertTo-SecureString -String $domainAdminPassword -AsPlainText -Force)

#$ServerISO = "D:\DCBuild\10586.0.151029-1700.TH2_RELEASE_SERVER_OEMRET_X64FRE_EN-US.ISO"
#$ServerISO = "d:\DCBuild\14393.0.160808-1702.RS1_Release_srvmedia_SERVER_OEMRET_X64FRE_EN-US.ISO"
#ServerISO = 'D:\DCBuild\en_windows_server_2016_technical_preview_5_x64_dvd_8512312.iso'
#$ServerISO = 'c:\ClusterStorage\Volume1\DCBuild\en_windows_server_2016_x64_dvd_9327751.iso' #Updated for RTM Build 2016
$ServerISO = 'f:\dcbuild_Insider\en_windows_server_2016_x64_dvd_9718492.iso' #THIS NEEDS to be Modified for your Lab
$ServerISO1 = 'F:\DCBuild_Insider\Windows_InsiderPreview_Server_17079.iso' #THIS NEEDS to be Modified for your Lab


$WindowsKey = '<ProductKey>' #Dave's Technet KEY Remove for Publishing of Book

$unattendSource = [xml]@"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <servicing></servicing>
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ComputerName>*</ComputerName>
            <ProductKey><ProductKEY></ProductKey> 
            <RegisteredOrganization>Organization</RegisteredOrganization>
            <RegisteredOwner>Owner</RegisteredOwner>
            <TimeZone>TZ</TimeZone>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideLocalAccountScreen>true</HideLocalAccountScreen>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <NetworkLocation>Work</NetworkLocation>
                <ProtectYourPC>1</ProtectYourPC>
            </OOBE>
            <UserAccounts>
                <AdministratorPassword>
                    <Value>password</Value>
                    <PlainText>True</PlainText>
                </AdministratorPassword>
            </UserAccounts>
        </component>
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <InputLocale>en-us</InputLocale>
            <SystemLocale>en-us</SystemLocale>
            <UILanguage>en-us</UILanguage>
            <UILanguageFallback>en-us</UILanguageFallback>
            <UserLocale>en-us</UserLocale>
        </component>
    </settings>
</unattend>
"@
#endregion

#region - 008 Building Base Gold Images...
Write-Log 'Host' 'Getting started...'

Confirm-Path $BaseVHDPath
Confirm-Path $VMPath
Write-Log 'Host' 'Building Base Images'
Write-Log 'Host' 'Downloading January 2018 CU for Windows Server 2016'

if (!(Test-Path -Path "$($BaseVHDPath)\windows10.0-kb3213986-x64_a1f5adacc28b56d7728c92e318d6596d9072aec4.msu")) 
{
    . Download-BaseImageUpdates
}

if (!(Test-Path -Path "$($BaseVHDPath)\VMServerBase.vhdx")) 
{
    . Initialize-BaseImage
}

if (!(Test-Path -Path "$($BaseVHDPath)\VMServerBaseCore.vhdx")) 
{
    . Initialize-BaseImage
}

if ((Get-VMSwitch | Where-Object -Property name -EQ -Value $virtualSwitchName) -eq $null)
{
    New-VMSwitch -Name $virtualSwitchName -SwitchType Private
}

#endregion

#region - 009 Building LAB VMs....

Invoke-DemoVMPrep 'DC01' 'DC01' -FullServer
Invoke-DemoVMPrep 'DHCP01' 'DHCP01'-FullServer
Invoke-DemoVMPrep 'Management01' 'Management01' -FullServer
Invoke-DemoVMPrep 'Router01' 'Router01' -FullServer
Invoke-DemoVMPrep 'VMM01' 'VMM01' -FullServer
Invoke-DemoVMPrep 'SCOM01' 'SCOM01' -FullServer
Invoke-DemoVMPrep 'DPM01' 'DPM01' -FullServer
#endregion

#region - 010 Building DC01

$VMName = 'DC01'
$GuestOSName = 'DC01'
$IPNumber = '1'

Create-DemoVM $VMName $GuestOSName $IPNumber

Invoke-Command -VMName $VMName -Credential $localCred  {
    param($VMName, $domainName, $domainAdminPassword)

    $newroute = '172.16.100.254'
    Write-Output -InputObject "[$($VMName)]:: Configuring Default Gateway"
    $null = Get-Netroute | Where DestinationPrefix -eq "0.0.0.0/0" | Remove-NetRoute -Confirm:$False
    $null = Test-NetConnection localhost
    new-netroute -InterfaceAlias "Ethernet" -NextHop $newroute  -DestinationPrefix '0.0.0.0/0' -verbose

    Write-Output -InputObject "[$($VMName)]:: Installing AD"
    $null = Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
    Write-Output -InputObject "[$($VMName)]:: Enabling Active Directory and promoting to domain controller"
    Install-ADDSForest -DomainName $domainName -InstallDNS -NoDNSonNetwork -NoRebootOnCompletion `
    -SafeModeAdministratorPassword (ConvertTo-SecureString -String $domainAdminPassword -AsPlainText -Force) -confirm:$false
} -ArgumentList $VMName, $domainName, $domainAdminPassword



Restart-DemoVM $VMName 

Wait-PSDirect $VMName -cred $domainCred

Invoke-Command -VMName $VMName -Credential $domainCred {
    param($VMName, $domainName, $domainAdminPassword)

    Write-Output -InputObject "[$($VMName)]:: Installing ADCS"
    $null = Install-WindowsFeature AD-Certificate -IncludeAllSubFeature -IncludeManagementTools
       } -ArgumentList $VMName, $domainName, $domainAdminPassword

Restart-DemoVM $VMName 

#endregion

#region - 011 Building DHCP01...

$VMName = 'DHCP01'
$GuestOSName = 'DHCP01'
$IPNumber = '3'

Create-DemoVM $VMName $GuestOSName $IPNumber

Invoke-Command -VMName $VMName -Credential $localCred {
    param($VMName, $domainCred, $domainName)

    $newroute = '172.16.100.254'
    Write-Output -InputObject "[$($VMName)]:: Configuring Default Gateway"
    $null = Get-Netroute | Where DestinationPrefix -eq "0.0.0.0/0" | Remove-NetRoute -Confirm:$False
    $null = Test-NetConnection localhost
    new-netroute -InterfaceAlias "Ethernet" -NextHop $newroute  -DestinationPrefix '0.0.0.0/0' -verbose
    
    Write-Output -InputObject "[$($VMName)]:: Installing DHCP"
    $null = Install-WindowsFeature DHCP -IncludeManagementTools
    Write-Output -InputObject "[$($VMName)]:: Joining domain as `"$($env:computername)`""
    while (!(Test-Connection -ComputerName $domainName -BufferSize 16 -Count 1 -Quiet -ea SilentlyContinue)) 
    {
        Start-Sleep -Seconds 1
    }
    do 
    {
        Add-Computer -DomainName $domainName -Credential $domainCred -ea SilentlyContinue
    }
    until ($?)
} -ArgumentList $VMName, $domainCred, $domainName

Restart-DemoVM $VMName
Wait-PSDirect $VMName -cred $domainCred

Invoke-Command -VMName $VMName -Credential $domainCred {
    param($VMName, $domainName, $Subnet, $IPNumber)

    Write-Output -InputObject "[$($VMName)]:: Waiting for name resolution"

    while ((Test-NetConnection -ComputerName $domainName).PingSucceeded -eq $false) 
    {
        Start-Sleep -Seconds 1
    }

    Write-Output -InputObject "[$($VMName)]:: Configuring DHCP Server"    
    Set-DhcpServerv4Binding -BindingState $true -InterfaceAlias Ethernet
    Add-DhcpServerv4Scope -Name 'IPv4 Network' -StartRange "$($Subnet)10" -EndRange "$($Subnet)200" -SubnetMask 255.255.255.0
    Set-DhcpServerv4OptionValue -OptionId 6 -value "$($Subnet)1"
    Set-DhcpServerv4OptionValue -OptionId 3 -value "$($Subnet)254"
    Add-DhcpServerInDC -DnsName "$($env:computername).$($domainName)"
    foreach($i in 1..99) 
    {
        $mac = '00-b5-5d-fe-f6-' + ($i % 100).ToString('00')
        $ip = $Subnet + '1' + ($i % 100).ToString('00')
        $desc = 'Container ' + $i.ToString()
        $scopeID = $Subnet + '0'
        Add-DhcpServerv4Reservation -IPAddress $ip -ClientId $mac -Description $desc -ScopeId $scopeID
    }
} -ArgumentList $VMName, $domainName, $Subnet, $IPNumber

Stop-VM -VMName $VMName
Set-VMMemory -VMName $VMName -StartupBytes 2GB
Set-VMProcessor -VMName $VMName -Count 2
Start-VM -VMName $VMName
Wait-PSDirect -VMName $VMName -cred $domainCred

#endregion

#region - 012 Configuring Users in AD....
$VMName = 'DC01'
$GuestOSName = 'DC01'
$IPNumber = '1'

Wait-PSDirect $VMName -cred $domainCred

Invoke-Command -VMName $VMName -Credential $domainCred {
    param($VMName, $password)

    Write-Output -InputObject "[$($VMName)]:: Creating user account for Dave"
    do 
    {
        Start-Sleep -Seconds 5
        New-ADUser `
        -Name 'Dave' `
        -SamAccountName  'Dave' `
        -DisplayName 'Dave' `
        -AccountPassword (ConvertTo-SecureString -String $password -AsPlainText -Force) `
        -ChangePasswordAtLogon $false  `
        -Enabled $true -ea 0
    }
    until ($?)
    Add-ADGroupMember -Identity 'Domain Admins' -Members 'Dave'
} -ArgumentList $VMName, $domainAdminPassword

Invoke-Command -VMName $VMName -Credential $domainCred {
    param($VMName, $password)

    Write-Output -InputObject "[$($VMName)]:: Creating user account for SVC_SQL"
    do 
    {
        Start-Sleep -Seconds 5
        New-ADUser `
        -Name 'SVC_SQL' `
        -SamAccountName  'SVC_SQL' `
        -DisplayName 'SVC_SQL' `
        -AccountPassword (ConvertTo-SecureString -String $password -AsPlainText -Force) `
        -ChangePasswordAtLogon $false  `
        -Enabled $true -ea 0
    }
    until ($?)
    Add-ADGroupMember -Identity 'Domain Admins' -Members 'SVC_SQL'
} -ArgumentList $VMName, $domainAdminPassword

Invoke-Command -VMName $VMName -Credential $domainCred {
    param($VMName, $password)

    Write-Output -InputObject "[$($VMName)]:: Creating user account for SVC_DPM"
    do 
    {
        Start-Sleep -Seconds 5
        New-ADUser `
        -Name 'SVC_DPM' `
        -SamAccountName  'SVC_DPM' `
        -DisplayName 'SVC_DPM' `
        -AccountPassword (ConvertTo-SecureString -String $password -AsPlainText -Force) `
        -ChangePasswordAtLogon $false  `
        -Enabled $true -ea 0
    }
    until ($?)
    Add-ADGroupMember -Identity 'Domain Admins' -Members 'SVC_DPM'
} -ArgumentList $VMName, $domainAdminPassword

Invoke-Command -VMName $VMName -Credential $domainCred {
    param($VMName, $password)

    Write-Output -InputObject "[$($VMName)]:: Creating user account for SVC_VMM"
    do 
    {
        Start-Sleep -Seconds 5
        New-ADUser `
        -Name 'SVC_VMM' `
        -SamAccountName  'SVC_VMM' `
        -DisplayName 'SVC_VMM' `
        -AccountPassword (ConvertTo-SecureString -String $password -AsPlainText -Force) `
        -ChangePasswordAtLogon $false  `
        -Enabled $true -ea 0
    }
    until ($?)
    Add-ADGroupMember -Identity 'Domain Admins' -Members 'SVC_VMM'
} -ArgumentList $VMName, $domainAdminPassword

Invoke-Command -VMName $VMName -Credential $domainCred {
    param($VMName, $password)

    Write-Output -InputObject "[$($VMName)]:: Creating user account for SVC_OMSVC"
    do 
    {
        Start-Sleep -Seconds 5
        New-ADUser `
        -Name 'SVC_OMSVC' `
        -SamAccountName  'SVC_OMSVC' `
        -DisplayName 'SVC_OMSVC' `
        -AccountPassword (ConvertTo-SecureString -String $password -AsPlainText -Force) `
        -ChangePasswordAtLogon $false  `
        -Enabled $true -ea 0
    }
    until ($?)
    Add-ADGroupMember -Identity 'Domain Admins' -Members 'SVC_OMSVC'
} -ArgumentList $VMName, $domainAdminPassword

Invoke-Command -VMName $VMName -Credential $domainCred {
    param($VMName, $password)

    Write-Output -InputObject "[$($VMName)]:: Creating user account for SVC_OMACCESS"
    do 
    {
        Start-Sleep -Seconds 5
        New-ADUser `
        -Name 'SVC_OMACCESS' `
        -SamAccountName  'SVC_OMACCESS' `
        -DisplayName 'SVC_OMACCESS' `
        -AccountPassword (ConvertTo-SecureString -String $password -AsPlainText -Force) `
        -ChangePasswordAtLogon $false  `
        -Enabled $true -ea 0
    }
    until ($?)
    Add-ADGroupMember -Identity 'Domain Admins' -Members 'SVC_OMACCESS'
 } -ArgumentList $VMName, $domainAdminPassword

 Invoke-Command -VMName $VMName -Credential $domainCred {
    param($VMName, $password)

    Write-Output -InputObject "[$($VMName)]:: Creating user account for SVC_OMREADER"
    do 
    {
        Start-Sleep -Seconds 5
        New-ADUser `
        -Name 'SVC_OMREADER' `
        -SamAccountName  'SVC_OMREADER' `
        -DisplayName 'SVC_OMREADER' `
        -AccountPassword (ConvertTo-SecureString -String $password -AsPlainText -Force) `
        -ChangePasswordAtLogon $false  `
        -Enabled $true -ea 0
    }
    until ($?)
 } -ArgumentList $VMName, $domainAdminPassword

  Invoke-Command -VMName $VMName -Credential $domainCred {
    param($VMName, $password)

    Write-Output -InputObject "[$($VMName)]:: Creating user account for SVC_OMWRITER"
    do 
    {
        Start-Sleep -Seconds 5
        New-ADUser `
        -Name 'SVC_OMWRITER' `
        -SamAccountName  'SVC_OMWRITER' `
        -DisplayName 'SVC_OMWRITER' `
        -AccountPassword (ConvertTo-SecureString -String $password -AsPlainText -Force) `
        -ChangePasswordAtLogon $false  `
        -Enabled $true -ea 0
    }
    until ($?)
 } -ArgumentList $VMName, $domainAdminPassword

Invoke-Command -VMName $VMName -Credential $domainCred {
    param($VMName, $password)

    Write-Output -InputObject "[$($VMName)]:: Creating user account for SVC_Veeam"
    do 
    {
        Start-Sleep -Seconds 5
        New-ADUser `
        -Name 'SVC_Veeam' `
        -SamAccountName  'SVC_Veeam' `
        -DisplayName 'SVC_Veeam' `
        -AccountPassword (ConvertTo-SecureString -String $password -AsPlainText -Force) `
        -ChangePasswordAtLogon $false  `
        -Enabled $true -ea 0
    }
    until ($?)
    Add-ADGroupMember -Identity 'Domain Admins' -Members 'SVC_Veeam'
} -ArgumentList $VMName, $domainAdminPassword

Invoke-Command -VMName $VMName -Credential $domainCred {
    param($VMName, $password)

    Write-Output -InputObject "[$($VMName)]:: Creating user account for MVPDays-Admin"
    do 
    {
        Start-Sleep -Seconds 5
        New-ADUser `
        -Name 'MVPDays-Admin' `
        -SamAccountName  'MVPDays-Admin' `
        -DisplayName 'MVPDays-Admin' `
        -AccountPassword (ConvertTo-SecureString -String $password -AsPlainText -Force) `
        -ChangePasswordAtLogon $false  `
        -Enabled $true -ea 0
    }
    until ($?)
    Add-ADGroupMember -Identity 'Domain Admins' -Members 'MVPDays-Admin'
} -ArgumentList $VMName, $domainAdminPassword


#endregion 

#region - 013 Configuring ADCS...

Write-Output -InputObject "[$($VMName)]:: Enabling Active Directory Certificate Enterprise Root CA with SHA 256"
icm -vmname $VMName -Credential $DomainCred {Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName "ECDSA_P256#Microsoft Software Key Storage Provider" -KeyLength 256 -HashAlgorithmName SHA256 -confirm:$False -verbose}
Stop-VM -VMName $VMName
Set-VMMemory -VMName $VMName -StartupBytes 2GB
Set-VMProcessor -VMName $VMName -Count 2
Start-VM -VMName $VMName
Wait-PSDirect -VMName $VMName -cred $domainCred


#icm -vmname DC01 -Credential $DomainCred {Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName "ECDSA_P256#Microsoft Software Key Storage Provider" -KeyLength 256 -HashAlgorithmName SHA256 -confirm:$False -verbose}

<#>  
Invoke-Command -VMName $VMName -Credential $domainCred {
    param($VMName, $domainName, $domainAdminPassword)

    Write-Output -InputObject "[$($VMName)]:: Enabling Active Directory Certificate Enterprise Root CA with SHA 256"
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName "ECDSA_P256#Microsoft Software Key Storage Provider" -KeyLength 256 -HashAlgorithmName SHA256 -confirm:$False -verbose
    } -ArgumentList $VMName, $domainName, $domainAdminPassword

    </#>

#endregion

#region - 014 Building the Router for the Lab ...

$VMName = 'Router01'
$GuestOSName = 'Router01'
$IPNumber = '254'

Install-NetNat

Create-DemoVM $VMName $GuestOSName $IPNumber

Invoke-Command -VMName $VMName -Credential $localCred {
    param($VMName, $domainCred, $domainName)
    Write-Output -InputObject "[$($VMName)]:: Joining domain as `"$($env:computername)`""
    while (!(Test-Connection -ComputerName $domainName -BufferSize 16 -Count 1 -Quiet -ea SilentlyContinue)) 
    {
        Start-Sleep -Seconds 1
    }
    do 
    {
        Add-Computer -DomainName $domainName -Credential $domainCred -ea SilentlyContinue
    }
    until ($?)
} -ArgumentList $VMName, $domainCred, $domainName

Install-RRAS -VMName $VMName
write-Output -InputObject "[$($VMName)]:: Adjusting RAM and Processors"
Stop-VM -VMName $VMName
Set-VMMemory -VMName $VMName -StartupBytes 2GB
Set-VMProcessor -VMName $VMName -Count 2
Start-VM -VMName $VMName

#endregion

#region - 015 Building Management Server - With Veeam...

$VMName = 'Management01'
$GuestOSName = 'Management01'

Create-DemoVM $VMName $GuestOSName

Invoke-Command -VMName $VMName -Credential $localCred {
    param($VMName, $domainCred, $domainName)
    Write-Output -InputObject "[$($VMName)]:: Management tools"
    $null = Install-WindowsFeature RSAT-Clustering, RSAT-Hyper-V-Tools
    Write-Output -InputObject "[$($VMName)]:: Joining domain as `"$($env:computername)`""
    while (!(Test-Connection -ComputerName $domainName -BufferSize 16 -Count 1 -Quiet -ea SilentlyContinue)) 
    {
        Start-Sleep -Seconds 1
    }
    do 
    {
        Add-Computer -DomainName $domainName -Credential $domainCred -ea SilentlyContinue
    }
    until ($?)
} -ArgumentList $VMName, $domainCred, $domainName

Restart-DemoVM $VMName
Install-Veeam -VMName $VMName

#endregion

#region - 016 Building SCVMM 1801 Server w/WSUS + SQL 2016...

$VMName = 'VMM01'
$GuestOSName = 'VMM01'

Create-DemoVM $VMName $GuestOSName

Invoke-Command -VMName $VMName -Credential $localCred {
    param($VMName, $domainCred, $domainName)
    write-Output -InputObject "[$($VMName)]:: Management tools"
    $null = Install-WindowsFeature RSAT-Clustering, RSAT-Hyper-V-Tools
    Write-Output -InputObject "[$($VMName)]:: Joining domain as `"$($env:computername)`""
    while (!(Test-Connection -ComputerName $domainName -BufferSize 16 -Count 1 -Quiet -ea SilentlyContinue)) 
    {
        Start-Sleep -Seconds 1
    }
    do 
    {
        Add-Computer -DomainName $domainName -Credential $domainCred -ea SilentlyContinue
    }
    until ($?)
} -ArgumentList $VMName, $domainCred, $domainName

Install-WSUS -VMName $VMName

write-Output -InputObject "[$($VMName)]:: Adjusting RAM and Processors"
Stop-VM -VMName $VMName
Set-VMMemory -VMName $VMName -StartupBytes 8GB
Set-VMProcessor -VMName $VMName -Count 2 -ExposeVirtualizationExtensions $True
Start-VM -VMName $VMName
Wait-PSDirect -VMName $VMName -cred $domainCred

Create-SQLInstallFile
Install-SQL -VMName $VMName
Restart-DemoVM -VMName $VMName
Wait-PSDirect -VMName $VMName -cred $domainCred
#Install-VMM -VMName $VMName -VMMDomain MVPDays
#Install-WSUS -VMName $VMName

#endregion

#region - 017 Building SCOM 1801...

$VMName = 'SCOM01'
$GuestOSName = 'SCOM01'

Create-DemoVM $VMName $GuestOSName

Invoke-Command -VMName $VMName -Credential $localCred {
    param($VMName, $domainCred, $domainName)
    write-Output -InputObject "[$($VMName)]:: Management tools"
    $null = Install-WindowsFeature RSAT-Clustering, RSAT-Hyper-V-Tools
    Write-Output -InputObject "[$($VMName)]:: Joining domain as `"$($env:computername)`""
    while (!(Test-Connection -ComputerName $domainName -BufferSize 16 -Count 1 -Quiet -ea SilentlyContinue)) 
    {
        Start-Sleep -Seconds 1
    }
    do 
    {
        Add-Computer -DomainName $domainName -Credential $domainCred -ea SilentlyContinue
    }
    until ($?)
} -ArgumentList $VMName, $domainCred, $domainName

Install-SCOM -VMName $VMName

#endregion

#region - 018 Building DPM 1801....

$VMName = 'DPM01'
$GuestOSName = 'DPM01'

Create-DemoVM $VMName $GuestOSName

Invoke-Command -VMName $VMName -Credential $localCred {
    param($VMName, $domainCred, $domainName)
    write-Output -InputObject "[$($VMName)]:: Management tools"
    $null = Install-WindowsFeature RSAT-Clustering, RSAT-Hyper-V-Tools
    Write-Output -InputObject "[$($VMName)]:: Joining domain as `"$($env:computername)`""
    while (!(Test-Connection -ComputerName $domainName -BufferSize 16 -Count 1 -Quiet -ea SilentlyContinue)) 
    {
        Start-Sleep -Seconds 1
    }
    do 
    {
        Add-Computer -DomainName $domainName -Credential $domainCred -ea SilentlyContinue
    }
    until ($?)
} -ArgumentList $VMName, $domainCred, $domainName

Install-SQLDPM -VMName $VMName
Install-DPM -VMName $VMName

#Install-DPM -VMName $VMName
#endregion
#region - Try Installing VMM 01 Later

write-Output -InputObject "[$($VMName)]:: Installing VMM"
$VMName = 'VMM01'
$GuestOSName = 'VMM01'
Install-VMM -VMName $VMName
#endregion

#region - 019 Adding Nested S2D Nodes and S2D....

1..4 | ForEach-Object -Process {
  Invoke-DemoVMPrep "S2D$_" "S2D$_" -FullServer
}

Wait-PSDirect 'S2D4' -cred $localCred

$VMName = 'S2D1'
$GuestOSName = 'S2D1'

1..4 | ForEach-Object -Process {
  Invoke-NodeStorageBuild "S2D$_" "S2D$_"
}

Wait-PSDirect 'S2D4' -cred $domainCred

Invoke-Command -VMName 'S2D1' -Credential $domainCred {
  param ($domainName)
  do 
  {
    New-Cluster -Name S2DCluster -Node S2D1, S2D2, S2D3, S2D4 -NoStorage
  }
  until ($?)
  
  while (!(Test-Connection -ComputerName "S2DCluster.$($domainName)" -BufferSize 16 -Count 1 -Quiet -ea SilentlyContinue)) 
  {
    ipconfig.exe /flushdns
    Start-Sleep -Seconds 1
  }
} -ArgumentList $domainName

Invoke-Command -VMName 'S2D1' -Credential $domainCred {
  param ($domainName)
  Enable-ClusterStorageSpacesDirect -PoolFriendlyName S2DPool -confirm:$false

  # This will match the configuration that was done in the book
  New-Volume -StoragePoolFriendlyName S2DPool -FriendlyName CSV01 -FileSystem CSVFS_REFS -Size 200GB -PhysicalDiskRedundancy 1 
  New-Volume -StoragePoolFriendlyName S2DPool -FriendlyName CSV02 -FileSystem CSVFS_REFS -Size 200GB -PhysicalDiskRedundancy 1
} -ArgumentList $domainName

<#>
1..4 | ForEach-Object -Process {
  Invoke-DemoVMPrep "HyperV$_" "HyperV$_" -FullServer
}
</#>

#endregion


Write-Log 'Done' 'Done!'


