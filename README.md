Posh-PVS
========

PowerShell Module for managing Tenable PVS Server. This is a personal project and it is not in any way associated o supported by Tenable Network Inc. 

## Under Development not even Alpha stage

#Basic Usage

Create a PVS Session against one or more PVS Servers:
<pre>
PS C:\Users\Carlos\Documents\Posh-PVS> New-PVSSession -ComputerName 192.168.10.4 -Credentials (Get-Credential admin) -IgnoreSSL


Id          : 0
Token       : 4bf012c85acb7541d53dad106358a4068bba8cae8caf681c
User        : @{name=admin; admin=TRUE}
MSP         : FALSE
ServerUUID  : 
PluginSet   : 
Credentials : System.Management.Automation.PSCredential
IdleTimeOut : 30
Host        : https://192.168.10.4:8835
</pre>

Get PVS server and Feed info:
<pre>
PS C:\Users\Carlos\Documents\Posh-PVS> Get-PVSServerFeedInfo -Id 0


Feed             : Licensed
ServerVersion    : 4.0.1
WebServerVersion : 1.0.2 (Build ID: 201311061)
Expiration       : 2/12/2014 11:13:18 PM
ExpirationTime   : 27
MSP              : FALSE
</pre>

List Results as objects in a given PVS Server:
<pre>
PS C:\Users\Carlos\Documents\Posh-PVS> Show-PVSResult -Id 0 | where {$_.type -eq "PCAP"}


Id         : 3
Name       : Pcap Vulnerability Scanning Report - Jan 14 2014 07:19:00
Status     : completed
LastUpdate : 2014-01-14 07:19:00
SnapshotId : 0
Type       : PCAP
</pre>
