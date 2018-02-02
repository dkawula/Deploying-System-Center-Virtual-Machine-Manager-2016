<#
Created:	 2018-02-02
Version:	 1.0
Author       Dave Kawula MVP
Homepage:    http://www.checkyourlogs.net

Disclaimer:
This script is provided "AS IS" with no warranties, confers no rights and 
is not supported by the authors or Checkyourlogs or MVPDays Publishing

Author - Dave Kawula
    Twitter: @DaveKawula
    Blog   : http://www.checkyourlogs.net


    .Synopsis
    Sample Script to create the VMM Logical Networks for the Deploying SCVMM Book
    .DESCRIPTION
    
   #>

#Build Script for VMM Networking
#Run from the VMM Server
Import-Module VirtualMachineManager
#For the purpose of this book I haven't put any -VLanID's in... You can modify as you like.
#Cleaned up the Script to use -Name istead of -ID 
#Base Script is just copied from the VMM Console and modified
#region 001 - Build MGMT Logical Network and IP Pool
$logicalNetwork = New-SCLogicalNetwork -Name "MGMT" -LogicalNetworkDefinitionIsolation $false -EnableNetworkVirtualization $false -UseGRE $false -IsPVLAN $false
$allHostGroups = @()
$allHostGroups += Get-SCVMHostGroup -Name "MVPDays HQ"
$allSubnetVlan = @()
$allSubnetVlan += New-SCSubnetVLan -Subnet "172.16.1.0/24" -VLanID 0
New-SCLogicalNetworkDefinition -Name "MGMT_0" -LogicalNetwork $logicalNetwork -VMHostGroup $allHostGroups -SubnetVLan $allSubnetVlan -RunAsynchronously
　
New-SCVMNetwork -Name "MGMT" -IsolationType "NoIsolation" -LogicalNetwork $logicalNetwork
# Get Logical Network 'MGMT'
$logicalNetwork = Get-SCLogicalNetwork -Name "MGMT"
# Get Logical Network Definition 'MGMT_0'
$logicalNetworkDefinition = Get-SCLogicalNetworkDefinition -Name "MGMT_0"
# Network Routes
$allNetworkRoutes = @()
# Gateways
$allGateways = @()
# DNS servers
$allDnsServer = @()
# DNS suffixes
$allDnsSuffixes = @()
# WINS servers
$allWinsServers = @()
New-SCStaticIPAddressPool -Name "MGMT_IP_Pool" -LogicalNetworkDefinition $logicalNetworkDefinition -Subnet "172.16.1.0/24" -IPAddressRangeStart "172.16.1.1" -IPAddressRangeEnd "172.16.1.254" -DefaultGateway $allGateways -DNSServer $allDnsServer -DNSSuffix "" -DNSSearchSuffix $allDnsSuffixes -NetworkRoute $allNetworkRoutes -RunAsynchronously
#endregion
#region 002 - Build Cluster Logical Network and IP Pool
$logicalNetwork = New-SCLogicalNetwork -Name "Cluster" -LogicalNetworkDefinitionIsolation $false -EnableNetworkVirtualization $false -UseGRE $false -IsPVLAN $false
$allHostGroups = @()
$allHostGroups += Get-SCVMHostGroup -Name "MVPDays HQ"
$allSubnetVlan = @()
$allSubnetVlan += New-SCSubnetVLan -Subnet "172.17.1.0/24" -VLanID 0
New-SCLogicalNetworkDefinition -Name "Cluster_0" -LogicalNetwork $logicalNetwork -VMHostGroup $allHostGroups -SubnetVLan $allSubnetVlan -RunAsynchronously
　
New-SCVMNetwork -Name "Cluster" -IsolationType "NoIsolation" -LogicalNetwork $logicalNetwork
# Get Logical Network 'Cluster'
$logicalNetwork = Get-SCLogicalNetwork -Name "Cluster"
# Get Logical Network Definition 'Cluster_0'
$logicalNetworkDefinition = Get-SCLogicalNetworkDefinition -Name "Cluster_0"
# Network Routes
$allNetworkRoutes = @()
# Gateways
$allGateways = @()
# DNS servers
$allDnsServer = @()
# DNS suffixes
$allDnsSuffixes = @()
# WINS servers
$allWinsServers = @()
New-SCStaticIPAddressPool -Name "Cluster_IP_Pool" -LogicalNetworkDefinition $logicalNetworkDefinition -Subnet "172.17.1.0/24" -IPAddressRangeStart "172.17.1.1" -IPAddressRangeEnd "172.17.1.254" -DefaultGateway $allGateways -DNSServer $allDnsServer -DNSSuffix "" -DNSSearchSuffix $allDnsSuffixes -NetworkRoute $allNetworkRoutes -RunAsynchronously
　
#endregion
#region 003 - Build LiveMigration Logical Network and IP Pool
$logicalNetwork = New-SCLogicalNetwork -Name "LiveMigration" -LogicalNetworkDefinitionIsolation $false -EnableNetworkVirtualization $false -UseGRE $false -IsPVLAN $false
$allHostGroups = @()
$allHostGroups += Get-SCVMHostGroup -Name "MVPDays HQ"
$allSubnetVlan = @()
$allSubnetVlan += New-SCSubnetVLan -Subnet "172.18.1.0/24" -VLanID 0
New-SCLogicalNetworkDefinition -Name "LiveMigration_0" -LogicalNetwork $logicalNetwork -VMHostGroup $allHostGroups -SubnetVLan $allSubnetVlan -RunAsynchronously
　
New-SCVMNetwork -Name "LiveMigration" -IsolationType "NoIsolation" -LogicalNetwork $logicalNetwork
# Get Logical Network 'LiveMigration'
$logicalNetwork = Get-SCLogicalNetwork -Name "LiveMigration"
# Get Logical Network Definition 'LiveMigration_0'
$logicalNetworkDefinition = Get-SCLogicalNetworkDefinition -Name "LiveMigration_0"
# Network Routes
$allNetworkRoutes = @()
# Gateways
$allGateways = @()
# DNS servers
$allDnsServer = @()
# DNS suffixes
$allDnsSuffixes = @()
# WINS servers
$allWinsServers = @()
New-SCStaticIPAddressPool -Name "LiveMigration_IP_Pool" -LogicalNetworkDefinition $logicalNetworkDefinition -Subnet "172.18.1.0/24" -IPAddressRangeStart "172.18.1.1" -IPAddressRangeEnd "172.18.1.254" -DefaultGateway $allGateways -DNSServer $allDnsServer -DNSSuffix "" -DNSSearchSuffix $allDnsSuffixes -NetworkRoute $allNetworkRoutes -RunAsynchronously
#endregion
#region 004 - Build Storage Logical Network and IP Pool
$logicalNetwork = New-SCLogicalNetwork -Name "Storage" -LogicalNetworkDefinitionIsolation $false -EnableNetworkVirtualization $false -UseGRE $false -IsPVLAN $false
$allHostGroups = @()
$allHostGroups += Get-SCVMHostGroup -Name "MVPDays HQ"
$allSubnetVlan = @()
$allSubnetVlan += New-SCSubnetVLan -Subnet "172.19.1.0/24" -VLanID 0
New-SCLogicalNetworkDefinition -Name "Storage_0" -LogicalNetwork $logicalNetwork -VMHostGroup $allHostGroups -SubnetVLan $allSubnetVlan -RunAsynchronously
　
New-SCVMNetwork -Name "Storage" -IsolationType "NoIsolation" -LogicalNetwork $logicalNetwork
# Get Logical Network 'Storage'
$logicalNetwork = Get-SCLogicalNetwork -Name "Storage"
# Get Logical Network Definition 'Storage_0'
$logicalNetworkDefinition = Get-SCLogicalNetworkDefinition -Name "Storage_0"
# Network Routes
$allNetworkRoutes = @()
# Gateways
$allGateways = @()
# DNS servers
$allDnsServer = @()
# DNS suffixes
$allDnsSuffixes = @()
# WINS servers
$allWinsServers = @()
New-SCStaticIPAddressPool -Name "Storage_IP_Pool" -LogicalNetworkDefinition $logicalNetworkDefinition -Subnet "172.19.1.0/24" -IPAddressRangeStart "172.19.1.1" -IPAddressRangeEnd "172.19.1.254" -DefaultGateway $allGateways -DNSServer $allDnsServer -DNSSuffix "" -DNSSearchSuffix $allDnsSuffixes -NetworkRoute $allNetworkRoutes -RunAsynchronously
#endregion
#region 005 - Build CorpNet Logical Network and IP Pool ...
$logicalNetwork = New-SCLogicalNetwork -Name "CorpNet" -LogicalNetworkDefinitionIsolation $false -EnableNetworkVirtualization $false -UseGRE $false -IsPVLAN $false
$allHostGroups = @()
$allHostGroups += Get-SCVMHostGroup -Name "MVPDays HQ"
$allSubnetVlan = @()
$allSubnetVlan += New-SCSubnetVLan -Subnet "172.16.100.0/24" -VLanID 0
New-SCLogicalNetworkDefinition -Name "CorpNet_0" -LogicalNetwork $logicalNetwork -VMHostGroup $allHostGroups -SubnetVLan $allSubnetVlan -RunAsynchronously
　
New-SCVMNetwork -Name "CorpNet" -IsolationType "NoIsolation" -LogicalNetwork $logicalNetwork
# Get Logical Network 'CorpNet'
$logicalNetwork = Get-SCLogicalNetwork -Name "CorpNet"
# Get Logical Network Definition 'CorpNet_0'
$logicalNetworkDefinition = Get-SCLogicalNetworkDefinition -Name "CorpNet_0"
# Network Routes
$allNetworkRoutes = @()
# Gateways
$allGateways = @()
$allGateways += New-SCDefaultGateway -IPAddress "172.16.100.254" -Automatic
# DNS servers
$allDnsServer = @("172.16.100.1")
# DNS suffixes
$allDnsSuffixes = @()
# WINS servers
$allWinsServers = @()
New-SCStaticIPAddressPool -Name "CorpNet_IP_Pool" -LogicalNetworkDefinition $logicalNetworkDefinition -Subnet "172.16.100.0/24" -IPAddressRangeStart "172.16.100.150" -IPAddressRangeEnd "172.16.100.200" -DefaultGateway $allGateways -DNSServer $allDnsServer -DNSSuffix "" -DNSSearchSuffix $allDnsSuffixes -NetworkRoute $allNetworkRoutes -RunAsynchronously
#endregion
　
#region 006 - Build Storage Logical Switch
New-SCPortClassification -Name "Storage"
#For this book we are not Using RDMA in the Lab below is a sample with RDMA Enabled
#New-SCVirtualNetworkAdapterNativePortProfile -Name "Storage_Port_Profile" -Description "" -AllowIeeePriorityTagging $false -AllowMacAddressSpoofing $false -AllowTeaming $false -EnableDhcpGuard $false -EnableGuestIPNetworkVirtualizationUpdates $true -EnableIov $false -EnableVrss $false -EnableIPsecOffload $true -EnableRouterGuard $false -EnableVmq $true -EnableRdma $true -MinimumBandwidthWeight "50" -RunAsynchronously
New-SCVirtualNetworkAdapterNativePortProfile -Name "Storage_Port_Profile" -Description "" -AllowIeeePriorityTagging $false -AllowMacAddressSpoofing $false -AllowTeaming $false -EnableDhcpGuard $false -EnableGuestIPNetworkVirtualizationUpdates $true -EnableIov $false -EnableVrss $false -EnableIPsecOffload $true -EnableRouterGuard $false -EnableVmq $true -EnableRdma $false -MinimumBandwidthWeight "50" -RunAsynchronously
　
　
$logicalSwitch = New-SCLogicalSwitch -Name "Storage" -Description "" -EnableSriov $false -SwitchUplinkMode "EmbeddedTeam" -MinimumBandwidthMode "Weight"
# Get Network Port Classification 'Host Cluster Workload'
$portClassification = Get-SCPortClassification -Name "Host Cluster Workload"
# Get Hyper-V Switch Port Profile 'Host management'
$nativeProfile = Get-SCVirtualNetworkAdapterNativePortProfile -Name "Host Management"
New-SCVirtualNetworkAdapterPortProfileSet -Name "Host Cluster Workload" -PortClassification $portClassification -LogicalSwitch $logicalSwitch -RunAsynchronously -VirtualNetworkAdapterNativePortProfile $nativeProfile
# Get Network Port Classification 'High bandwidth'
$portClassification = Get-SCPortClassification -Name "High Bandwidth"
# Get Hyper-V Switch Port Profile 'Cluster'
$nativeProfile = Get-SCVirtualNetworkAdapterNativePortProfile -Name "Cluster"
New-SCVirtualNetworkAdapterPortProfileSet -Name "High bandwidth" -PortClassification $portClassification -LogicalSwitch $logicalSwitch -RunAsynchronously -VirtualNetworkAdapterNativePortProfile $nativeProfile
# Get Network Port Classification 'Live migration workload'
$portClassification = Get-SCPortClassification -Name "Live migration workload"
# Get Hyper-V Switch Port Profile 'Live migration'
$nativeProfile = Get-SCVirtualNetworkAdapterNativePortProfile -Name "Live Migration"
New-SCVirtualNetworkAdapterPortProfileSet -Name "Live migration workload" -PortClassification $portClassification -LogicalSwitch $logicalSwitch -RunAsynchronously -VirtualNetworkAdapterNativePortProfile $nativeProfile
# Get Network Port Classification 'Storage'
$portClassification = Get-SCPortClassification -Name "Storage"
# Get Hyper-V Switch Port Profile 'Storage_Port_Profile'
$nativeProfile = Get-SCVirtualNetworkAdapterNativePortProfile -Name "Storage_Port_Profile"
New-SCVirtualNetworkAdapterPortProfileSet -Name "Storage" -PortClassification $portClassification -LogicalSwitch $logicalSwitch -RunAsynchronously -VirtualNetworkAdapterNativePortProfile $nativeProfile
$definitions = @()
# Get Logical Network Definition 'MGMT_0'
$definitions += Get-SCLogicalNetworkDefinition -Name "MGMT_0"
# Get Logical Network Definition 'Cluster_0'
$definitions += Get-SCLogicalNetworkDefinition -Name "Cluster_0"
# Get Logical Network Definition 'LiveMigration_0'
$definitions += Get-SCLogicalNetworkDefinition -Name "LiveMigration_0"
# Get Logical Network Definition 'Storage_0'
$definitions += Get-SCLogicalNetworkDefinition -Name "Storage_0"
$nativeUppVar = New-SCNativeUplinkPortProfile -Name "VSW01" -Description "Storage Network Virtual Switch" -LogicalNetworkDefinition $definitions -EnableNetworkVirtualization $false -LBFOLoadBalancingAlgorithm "Dynamic" -LBFOTeamMode "SwitchIndependent" -RunAsynchronously
$uppSetVar = New-SCUplinkPortProfileSet -Name "VSW01" -LogicalSwitch $logicalSwitch -NativeUplinkPortProfile $nativeUppVar -RunAsynchronously
# Get VM Network 'Cluster'
$vmNetwork = Get-SCVMNetwork -Name "Cluster"
# Get Network Port Classification 'Host Cluster Workload'
$vNICPortClassification = Get-SCPortClassification -Name "Host Cluster WorkLoad"
# Get Static IP Address Pool 'Cluster_IP_Pool'
$ipV4Pool = Get-SCStaticIPAddressPool -Name "Cluster_IP_Pool"
New-SCLogicalSwitchVirtualNetworkAdapter -Name "Cluster" -UplinkPortProfileSet $uppSetVar -RunAsynchronously -VMNetwork $vmNetwork -VLanEnabled $false -PortClassification $vNICPortClassification -IsUsedForHostManagement $false -IPv4AddressType "Static" -IPv6AddressType "Dynamic" -IPv4AddressPool $ipV4Pool
# Get VM Network 'LiveMigration'
$vmNetwork = Get-SCVMNetwork -Name "LiveMigration"
# Get Network Port Classification 'Live migration workload'
$vNICPortClassification = Get-SCPortClassification -Name "Live Migration Workload"
# Get Static IP Address Pool 'LiveMigration_IP_Pool'
$ipV4Pool = Get-SCStaticIPAddressPool -Name "LiveMigration_IP_Pool"
New-SCLogicalSwitchVirtualNetworkAdapter -Name "LiveMigration" -UplinkPortProfileSet $uppSetVar -RunAsynchronously -VMNetwork $vmNetwork -VLanEnabled $false -PortClassification $vNICPortClassification -IsUsedForHostManagement $false -IPv4AddressType "Static" -IPv6AddressType "Dynamic" -IPv4AddressPool $ipV4Pool
# Get VM Network 'MGMT'
$vmNetwork = Get-SCVMNetwork -Name "MGMT"
# Get Network Port Classification 'High bandwidth'
$vNICPortClassification = Get-SCPortClassification -Name "High bandwidth"
# Get Static IP Address Pool 'MGMT_IP_Pool'
$ipV4Pool = Get-SCStaticIPAddressPool -Name "MGMT_IP_Pool"
New-SCLogicalSwitchVirtualNetworkAdapter -Name "MGMT" -UplinkPortProfileSet $uppSetVar -RunAsynchronously -VMNetwork $vmNetwork -VLanEnabled $false -PortClassification $vNICPortClassification -IsUsedForHostManagement $false -IPv4AddressType "Static" -IPv6AddressType "Dynamic" -IPv4AddressPool $ipV4Pool
# Get VM Network 'Storage'
$vmNetwork = Get-SCVMNetwork -Name "Storage"
# Get Network Port Classification 'Storage'
$vNICPortClassification = Get-SCPortClassification -Name "Storage"
# Get Static IP Address Pool 'Storage_IP_Pool'
$ipV4Pool = Get-SCStaticIPAddressPool -Name "Storage_IP_Pool"
New-SCLogicalSwitchVirtualNetworkAdapter -Name "Storage_1" -UplinkPortProfileSet $uppSetVar -RunAsynchronously -VMNetwork $vmNetwork -VLanEnabled $false -PortClassification $vNICPortClassification -IsUsedForHostManagement $false -IPv4AddressType "Static" -IPv6AddressType "Dynamic" -IPv4AddressPool $ipV4Pool
# Get VM Network 'Storage'
$vmNetwork = Get-SCVMNetwork -Name "Storage"
# Get Network Port Classification 'Storage'
$vNICPortClassification = Get-SCPortClassification -Name "Storage"
# Get Static IP Address Pool 'Storage_IP_Pool'
$ipV4Pool = Get-SCStaticIPAddressPool -Name "Storage_IP_Pool"
New-SCLogicalSwitchVirtualNetworkAdapter -Name "Storage_2" -UplinkPortProfileSet $uppSetVar -RunAsynchronously -VMNetwork $vmNetwork -VLanEnabled $false -PortClassification $vNICPortClassification -IsUsedForHostManagement $false -IPv4AddressType "Static" -IPv6AddressType "Dynamic" -IPv4AddressPool $ipV4Pool
#endregion
#region 007 - Build CorpNet Logical Switch...
　
$logicalSwitch = New-SCLogicalSwitch -Name "CorpNet" -Description "" -EnableSriov $false -SwitchUplinkMode "EmbeddedTeam" -MinimumBandwidthMode "Weight"
# Get Network Port Classification 'High bandwidth'
$portClassification = Get-SCPortClassification -Name "High bandwidth"
# Get Hyper-V Switch Port Profile 'High Bandwidth Adapter'
$nativeProfile = Get-SCVirtualNetworkAdapterNativePortProfile -name "High Bandwidth Adapter"
New-SCVirtualNetworkAdapterPortProfileSet -Name "High bandwidth" -PortClassification $portClassification -LogicalSwitch $logicalSwitch -RunAsynchronously -VirtualNetworkAdapterNativePortProfile $nativeProfile
$definitions = @()
# Get Logical Network Definition 'CorpNet_0'
$definitions += Get-SCLogicalNetworkDefinition -Name "CorpNet_0"
$nativeUppVar = New-SCNativeUplinkPortProfile -Name "CorpNet" -Description "CorpNet Logical Switch" -LogicalNetworkDefinition $definitions -EnableNetworkVirtualization $false -LBFOLoadBalancingAlgorithm "Dynamic" -LBFOTeamMode "SwitchIndependent" -RunAsynchronously
$uppSetVar = New-SCUplinkPortProfileSet -Name "CorpNet" -LogicalSwitch $logicalSwitch -NativeUplinkPortProfile $nativeUppVar -RunAsynchronously
# Get VM Network 'CorpNet'
$vmNetwork = Get-SCVMNetwork -Name "CorpNet"
# Get Network Port Classification 'High bandwidth'
$vNICPortClassification = Get-SCPortClassification -Name "High Bandwidth"
# Get Static IP Address Pool 'CorpNet_IP_Pool'
$ipV4Pool = Get-SCStaticIPAddressPool -Name "CorpNet_IP_Pool"
New-SCLogicalSwitchVirtualNetworkAdapter -Name "CorpNet" -UplinkPortProfileSet $uppSetVar -RunAsynchronously -VMNetwork $vmNetwork -VLanEnabled $false -PortClassification $vNICPortClassification -IsUsedForHostManagement $false -IPv4AddressType "Static" -IPv6AddressType "Dynamic" -IPv4AddressPool $ipV4Pool
#endregion

