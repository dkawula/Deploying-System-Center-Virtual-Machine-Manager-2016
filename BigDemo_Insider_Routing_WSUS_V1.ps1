﻿<#
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

#region Parameters
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


#region Functions

function Wait-PSDirect
{
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
    

function Restart-DemoVM
{
     param
     (
         [string]
         $VMName
     )

    Write-Log $VMName 'Rebooting'
    stop-vm $VMName
    start-vm $VMName
}

function Confirm-Path
{
    param
    (
        [string] $path
    )
    if (!(Test-Path $path)) 
    {
        $null = mkdir $path
    }
}

function Write-Log 
{
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

function Clear-File
{
    param
    (
        [string] $file
    )
    
    if (Test-Path $file) 
    {
        $null = Remove-Item $file -Recurse
    }
}

function Get-UnattendChunk 
{
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

function New-UnattendFile 
{
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

function New-UnattendFile1 
{
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

Function Initialize-BaseImage
{



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

function Download-BaseImageUpdates
{

 
            if (!(Test-Path "$($BaseVHDPath)\windows10.0-kb3213986-x64_a1f5adacc28b56d7728c92e318d6596d9072aec4.msu")) 
                        {
    Invoke-WebRequest -Uri http://download.windowsupdate.com/d/msdownload/update/software/secu/2016/12/windows10.0-kb3213986-x64_a1f5adacc28b56d7728c92e318d6596d9072aec4.msu -OutFile "$($BaseVHDPath)\windows10.0-kb3213986-x64_a1f5adacc28b56d7728c92e318d6596d9072aec4.msu" -Verbose
    }
    }

function Invoke-DemoVMPrep 
{
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

function Create-DemoVM 
{
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

function Invoke-NodeStorageBuild 
{
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

    Start-Sleep -Seconds 60 # Wait for sync to start before monitoring
	    while ($subscription.GetSynchronizationProgress().ProcessedItems -ne $subscription.GetSynchronizationProgress().TotalItems) {
		    #$subscription.GetSynchronizationProgress().ProcessedItems * 100/($subscription.GetSynchronizationProgress().TotalItems)
		    Start-Sleep -Seconds 5
	}

    }


    Restart-DemoVM $VMName
    
    Wait-PSDirect $VMName -cred $localCred

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

    $null = Install-WindowsFeature -Name RemoteAccess,Routing,RSAT-RemoteAccess-Mgmt 
    #$null =  Stop-Service -Name WDSServer -ErrorAction SilentlyContinue
    #$null = Set-Service -Name WDSServer -StartupType Disabled -ErrorAction SilentlyContinue

    $null = Start-Process -Wait:$true -FilePath "netsh" -ArgumentList "ras set conf ENABLED"
    $null = Set-Service -Name RemoteAccess -StartupType Automatic
    $null = Start-Service -Name RemoteAccess
    $null = Start-Process -Wait:$true -FilePath "netsh" -ArgumentList "routing ip nat install"
    $null = Start-Process -Wait:$true -FilePath "netsh" -ArgumentList "routing ip nat add interface ""CorpNet"""
    $null = Test-NetConnection 192.168.10.1
    $null = Test-NetConnection 4.2.2.2
    $null = Start-Process -Wait:$true -FilePath "netsh" -ArgumentList "routing ip nat add interface ""Internet""full"
    $null = Test-NetConnection 192.168.10.1
   # $null = Test-NetConnection $($Subnet)1
    $null = Test-NetConnection 4.2.2.2
      
    
    }
}


 
#endregion

#region Variable Init
$BaseVHDPath = "$($WorkingDir)\BaseVHDs"
$VMPath = "$($WorkingDir)\VMs"

$localCred = New-Object -TypeName System.Management.Automation.PSCredential `
-ArgumentList 'Administrator', (ConvertTo-SecureString -String $adminPassword -AsPlainText -Force)

$domainCred = New-Object -TypeName System.Management.Automation.PSCredential `
-ArgumentList "$($domainName)\Administrator", (ConvertTo-SecureString -String $domainAdminPassword -AsPlainText -Force)

#$ServerISO = "D:\DCBuild\10586.0.151029-1700.TH2_RELEASE_SERVER_OEMRET_X64FRE_EN-US.ISO"
#$ServerISO = "d:\DCBuild\14393.0.160808-1702.RS1_Release_srvmedia_SERVER_OEMRET_X64FRE_EN-US.ISO"
#ServerISO = 'D:\DCBuild\en_windows_server_2016_technical_preview_5_x64_dvd_8512312.iso'
#$ServerISO = 'c:\ClusterStorage\Volume1\DCBuild\en_windows_server_2016_x64_dvd_9327751.iso' #Updated for RTM Build 2016
$ServerISO = 'f:\dcbuild_Insider\en_windows_server_2016_x64_dvd_9718492.iso' #THIS NEEDS to be Modified for your Lab
$ServerISO1 = 'F:\DCBuild_Insider\Windows_InsiderPreview_Server_17079.iso' #THIS NEEDS to be Modified for your Lab


$WindowsKey = '<Productkey>' #Dave's Technet KEY Remove for Publishing of Book

$unattendSource = [xml]@"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <servicing></servicing>
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ComputerName>*</ComputerName>
            <ProductKey><ProductKey></ProductKey> 
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

Invoke-DemoVMPrep 'DC01' 'DC01' -FullServer
Invoke-DemoVMPrep 'DHCP01' 'DHCP01'-FullServer
Invoke-DemoVMPrep 'Management01' 'Management01' -FullServer
Invoke-DemoVMPrep 'Router01' 'Router01' -FullServer
Invoke-DemoVMPrep 'VMM01' 'VMM01' -FullServer


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

Restart-DemoVM $VMName

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


Write-Output -InputObject "[$($VMName)]:: Enabling Active Directory Certificate Enterprise Root CA with SHA 256"
icm -vmname $VMName -Credential $DomainCred {Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName "ECDSA_P256#Microsoft Software Key Storage Provider" -KeyLength 256 -HashAlgorithmName SHA256 -confirm:$False -verbose}
#icm -vmname DC01 -Credential $DomainCred {Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName "ECDSA_P256#Microsoft Software Key Storage Provider" -KeyLength 256 -HashAlgorithmName SHA256 -confirm:$False -verbose}

<#>  
Invoke-Command -VMName $VMName -Credential $domainCred {
    param($VMName, $domainName, $domainAdminPassword)

    Write-Output -InputObject "[$($VMName)]:: Enabling Active Directory Certificate Enterprise Root CA with SHA 256"
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName "ECDSA_P256#Microsoft Software Key Storage Provider" -KeyLength 256 -HashAlgorithmName SHA256 -confirm:$False -verbose
    } -ArgumentList $VMName, $domainName, $domainAdminPassword

    </#>


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

#Wait-PSDirect 'Router01' -cred $localCred
Write-Log 'Done' 'Done!'



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
<#>
Invoke-Command -VMName 'MGMT1' -Credential $domainCred {
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
  New-Volume -StoragePoolFriendlyName S2DPool -FriendlyName Mirror-2Way -FileSystem CSVFS_REFS -Size 200GB -PhysicalDiskRedundancy 1 
  New-Volume -StoragePoolFriendlyName S2DPool -FriendlyName Mirror-3Way -FileSystem CSVFS_REFS -Size 200GB -PhysicalDiskRedundancy 2
} -ArgumentList $domainName
</#>
Write-Log 'Done' 'Done!'