if (!(Test-Path variable:Global:PVSConn ))
{
    $Global:PVSConn = New-Object System.Collections.ArrayList
}
 
<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function New-PVSSession
{
    [CmdletBinding()]
    Param
    (
        # PVS Server FQDN or IP.
        [Parameter(Mandatory=$true,
        Position=0)]
        [string[]]$ComputerName,

        # Credentials for connecting to the Nessus Server
        [Parameter(Mandatory=$true,
        Position=1)]
        [Management.Automation.PSCredential]$Credentials,

        # Port of the PVS server.
        [Parameter(Mandatory=$false,
        Position=2)]
        [Int32]$Port = 8835,

        # Check on the user cotext for the certificate CA
        [switch]$UseUserContext,

        # Ignore SSL certificate validation errors
        [switch]$IgnoreSSL

    )

    Begin
    {
        # Set so only one validation code block can operate at a time.
        [Net.ServicePointManager]::MaxServicePoints = 1
        [Net.ServicePointManager]::MaxServicePointIdleTime = 1
    }
    Process
    {
        foreach($comp in $ComputerName)
        {
            # Make sure that we trust the certificate
            $ConnectString = "https://$comp`:$port"
            $WebRequest = [Net.WebRequest]::Create($ConnectString)
            
            # Random number for sequence request
            $rand = New-Object System.Random
                    
            
       
            if (!$IgnoreSSL)
            {
                # set default proxy settings
                $proxy = [System.Net.WebRequest]::GetSystemWebProxy()
                $proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
                $WebRequest.Proxy = $Proxy

                $status = $true

                $WebRequest.Timeout = 3000
                $WebRequest.AllowAutoRedirect = $true
                Write-Verbose "Checking if SSL Certificate is valid."
                [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
                ## SSL Checking di
                try {$Response = $WebRequest.GetResponse()}
                catch {}

                if ($WebRequest.ServicePoint.Certificate -ne $null) 
                {
                    Write-Verbose "Was able to pull certificate information from host."
                    $Cert = [Security.Cryptography.X509Certificates.X509Certificate2]$WebRequest.ServicePoint.Certificate.Handle
                    try 
                    {
                        $SAN = ($Cert.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.17"}).Format(0) -split ", "
                    }
                    catch 
                    {
                        $SAN = $null
                    }
                    $chain = New-Object Security.Cryptography.X509Certificates.X509Chain -ArgumentList (!$UseUserContext)
                    [void]$chain.ChainPolicy.ApplicationPolicy.Add("1.3.6.1.5.5.7.3.1")
                    $Status = $chain.Build($Cert)
                    [string[]]$ErrorInformation = $chain.ChainStatus | ForEach-Object {$_.Status}
                    $chain.Reset()
                    [Net.ServicePointManager]::ServerCertificateValidationCallback = $null
                    $certinfo = New-Object PKI.Web.WebSSL -Property @{
                        Certificate = $WebRequest.ServicePoint.Certificate;
                        Issuer = $WebRequest.ServicePoint.Certificate.Issuer;
                        Subject = $WebRequest.ServicePoint.Certificate.Subject;
                        SubjectAlternativeNames = $SAN;
                        CertificateIsValid = $Status;
                        ErrorInformation = $ErrorInformation

                    }
                    
                } 
                if (!$Status)
                {
                    Write-Verbose "Certificate is not valid!"
                    Write-Warning "Certificate is not valid and returned errors: $($ErrorInformation)"
                    $certinfo

                    $answer2cert = Read-Host "Do you wish to continue? (Y/N)"
                    if ($answer2cert -eq "n")
                    {
                        return
                    }
                }
            }

            # Set parameters for the connection
            $Header = @{'pvs-session'='false'}
            $Body   =  @{'login'=$Credentials.GetNetworkCredential().UserName;
                         'password'=$Credentials.GetNetworkCredential().Password; 
                         'json'=1}
            $URI    = "https://$($comp):$($Port)/login"

            # Connect
            try
            {
                [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
                $Session = Invoke-WebRequest -Headers $header -Uri $URI -Body $Body -Method Post -ErrorAction Stop
            }
            catch
            {
                Write-Error "Could not connect to server $($URI)"
                break
            }
            $Reply = ConvertFrom-Json -InputObject $Session.Content
            if ($reply.reply.status -eq "OK")
            {
                $PVS_Session = $reply.reply.contents

                # Get current index
                $SessionIndex = $Global:PVSConn.Count

                $SessionProps = [ordered]@{
                    Id          = $SessionIndex
                    Token       = $PVS_Session.token
                    User        = $PVS_Session.user
                    MSP         = $PVS_Session.msp
                    ServerUUID  = $PVS_Session.server_uuid
                    PluginSet   = $PVS_Session.plugin_set
                    Credentials = $Credentials
                    IdleTimeOut = $PVS_Session.idle_timeout
                    Host        = "https://$($comp):$($Port)"
                }
                $PVSSessionObj = [pscustomobject]$SessionProps
                $PVSSessionObj.pstypenames.insert(0,'PVS.Session')

                [void]$Global:PVSConn.Add($PVSSessionObj)

                $PVSSessionObj
            }
            else
            {
                Write-Error $reply.reply.contents
            }
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Remove-PVSSession
{
    [CmdletBinding(DefaultParameterSetName = 'Id')]
    param(

        # Nessus session index
        [Parameter(Mandatory=$true,
        Position=0,
        ParameterSetName = "Id")]
        [int32[]]$Id,

        # Nessus Session Object
        [Parameter(Mandatory=$true,
        Position=0,
        ParameterSetName = "Session",
        ValueFromPipeline=$True)]
        [psobject]$Session
    )
    BEGIN 
    {
        
    }
    PROCESS 
    {
        if ($Id.Length -gt 0)
        {
            foreach($conn in $Global:PVSconn)
            {
                if ($conn.Id -in $Id)
                {
                    $PVSSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "PVS.Session")
        {
                $PVSSession = $Session
        }
        else 
        {
            throw "No PVS.Session was provided"
        }

        if ($PVSSession) 
        {
            Write-Verbose "Performing logoff."
            try
            {
                $Header = @{'pvs-session'='true'
                            'pvs-activated' = 'false'
                            'token'=''
                            'pvs-tk'= "$($PVSSession.token)";
                            'pvs-name'="$($PVSSession.user.name)" 
                            'pvs-admin'="$($PVSSession.user.admin)"
            
                            }

                $Body   =  @{'token'= "$($PVSSession.token)"
                             'seq'= (Get-Random -Maximum 1000)
                             'json'=1}
                $URI    = "https://$($comp):$($Port)/logout"
                $logout = Invoke-WebRequest -Headers $header -Uri $URI -Body $Body -Method Post
            }
            catch
            {
                Write-verbose "Logout failed."
            }
            Write-Verbose "Removing session with Id of $($PVSSession.Id)"
            
            $Global:PVSconn.Remove($PVSSession)
            
            Write-Verbose "Session removed."
            $true
        }
    }

    END {}
}


<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-PVSSession
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Nessus session index.
        [Parameter(Mandatory=$false,
        Position=0)]
        [Int32[]] $Id
    )

    Begin{}
    Process
    {
        if ($Id.Count -gt 0)
        {
            foreach($i in $Id)
            {
                foreach($Connection in $Global:PVSconn)
                {
                    if ($Connection.Index -eq $i)
                    {
                        $Connection
                    }
                }
            }
        }
        else
        {
            # Return all database connections.
            $return_sessions = @()
            foreach($s in $Global:PVSconn){$return_sessions += $s}
            $return_sessions
        }
    }
    End{}
}


<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-PVSServerFeedInfo 
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Nessus session index
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [int32[]]$Id = @(),

        # Nessus session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        Position=0)]
        [psobject]$Session
    )
    BEGIN 
    {
        
    }
    PROCESS 
    {    
        if ($Id.Count -gt 0)
        {
            foreach($conn in $Global:PVSconn)
            {
                if ($conn.id -in $Id)
                {
                    $PVSSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "PVS.Session")
        {
                $PVSSession = $Session
        }
        else 
        {
            throw "PVS.Session was provided"
        }

        $Header = @{ 'pvs-session'='false';
            'token'='';'pvs-tk'= "$($PVSSession.token)";
            'pvs-name'="$($PVSSession.user.name)" 
            'pvs-admin'="$($PVSSession.user.admin)"
        }

        $Body =  @{'token' = "$($PVS_Session.token)"; 
            'seq'= (Get-Random -Maximum 1000) 
            'json'=1
        } 
        
        $server_reply = Invoke-WebRequest -Headers $Header -Body $Body -Uri ($PVSSession.Host + "/feed") -Method Post
        $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
        $info = $server_reply.Content | ConvertFrom-Json
        $FeedDetails = $info.reply.contents
        
        $FeedProps = [ordered]@{
            Feed             = $FeedDetails.feed
            ServerVersion    = $FeedDetails.server_version
            WebServerVersion = $FeedDetails.web_server_version
            Expiration       = $origin.AddSeconds($FeedDetails.expiration)
            ExpirationTime   = $FeedDetails.expiration_time
            MSP              = $FeedDetails.msp
        }
        
        $PVSFeedObj = [pscustomobject]$FeedProps
        $PVSFeedObj.pstypenames.insert(0,'PVS.FeedInfo')
        $PVSFeedObj
     
    }
}


<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Show-PVSResult
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Nessus session index
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [int32[]]$Id = @(),

        # Nessus session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        Position=0)]
        [psobject]$Session
    )
    BEGIN 
    {
        
    }
    PROCESS 
    {    
        if ($Id.Count -gt 0)
        {
            foreach($conn in $Global:PVSconn)
            {
                if ($conn.id -in $Id)
                {
                    $PVSSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "PVS.Session")
        {
                $PVSSession = $Session
        }
        else 
        {
            throw "PVS.Session was provided"
        }
        
        $Header = @{ 
            'pvs-session'='true'
            'token'=''
            'pvs-tk'= "$($PVSSession.token)";
            'pvs-name'="$($PVSSession.user.name)" 
            'pvs-admin'="$($PVSSession.user.admin)"
            'pvs-activated' = 'false'
        }
        
        $Body =  @{'token' = $PVSSession.token; 
            'seq'= 3336 
            'json'=1
        } 
        
        try
        {
            $server_reply = Invoke-WebRequest -Headers $Header -Body $Body -Uri ($PVSSession.Host + "/report/list") -Method Post
        }
        Catch [Net.WebException] 
        {
            Write-Verbose "Connection failed, re-authenticating."
            # Set parameters for the connection
            [System.Net.ServicePointManager]::MaxServicePoints = 0
            $RauthHeader = @{'pvs-session'='false'}
            $ReAuthBody   =  @{'login'=$PVSSession.Credentials.GetNetworkCredential().UserName; 
                        'password'=$PVSSession.Credentials.GetNetworkCredential().Password; 
                        'json'=1}
            $ReAuthURI    = "$($PVSSession.Host)/login"

            $server_reply = Invoke-WebRequest -Headers $RauthHeader -Uri $ReAuthURI -Body $ReAuthBody -Method Post -ErrorAction Stop
            $reply = $server_reply.Content | ConvertFrom-Json
            if ($reply.reply.status -eq "OK")
            {
                Write-Verbose "Authentication successful."
                $PVS_Session = $reply.reply.contents

                Write-Verbose "Updating session"
                Remove-PVSSession -Session $PVSSession | Out-Null
                $PVSSession.Token = $PVS_Session.token
                [void]$Global:PVSConn.Add($PVSSession)

                $Header['pvs-tk'] = $PVS_Session.token
                $Body['token']= $PVS_Session.token
                $PVS_Session.token
                $server_reply = Invoke-WebRequest -Headers $Header -Body $Body -Uri ($PVSSession.Host + "/report/list") -Method Post
                
            }
            else
            {
                Write-Error "Could not authenticate to server. " -ErrorAction Stop
            }
               
        }
        $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0

        [void][System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions")
        $Serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $json = $server_reply.Content 
        $Deserialized = $Serializer.DeserializeObject($json)
        foreach ($report in $Deserialized.reply['contents'].reports.report)
        {
            if ($report.name -like "Pcap*")
            {
                $report_type = "PCAP"
            }
            else
            {
                $report_type = "Snapshot"
            }
            $reportprops = [ordered]@{
                Id         = $report.id
                Name       = $report.name
                Status     = $report.status
                LastUpdate = $report.last_updated_time
                SnapshotId = $report.snapshot_id
                Type       = $report_type
            }
            [psobject]$reportprops

        }
     
    }
}
