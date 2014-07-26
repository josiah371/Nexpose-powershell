function Set-Connection{
    <#
	.SYNOPSIS
	    Setup the connection information to Login to Nexpose.

	.DESCRIPTION
	    The Set-Connection cmdlet setup or initializes a connection infomation string
        to Login a session to the nexpose API.
		
	.PARAMETER User
	    USername used to login. 

	.PARAMETER Password
	    Password used to login

	.PARAMETER Server
	    Nexpose Server

	.PARAMETER Port
	    Port used to connect to		
			
	.PARAMETER Session_id
	    Session_id that is returned on a login
		
	
	
	.EXAMPLE
		PS> Set-Connection
		
	.EXAMPLE
		PS> Set-Connection -User -Password pwd -Server 10.0.0.1 -Port 3780

	.NOTES
		Author: Josiah Inman
		

	.LINK
        
	#>
	[CmdletBinding(
    	SupportsShouldProcess=$True,
        ConfirmImpact="Low"
    )]
  
   Param(
		[String]$User = "",
        [String]$Password = "",
        [String]$Server = "",
        [String]$Port = "",
        [String]$Session_id = "",
        [string]$api_version = '1.1'
	)

add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        #build the login request
        $body = "<LoginRequest synch-id='0' password ='$password' user-id ='$user' ></LoginRequest>"
        # login and get the session id
        $url = "https://${server}:${port}/api/${api_version}/xml"
        $resp = Invoke-WebRequest -URI $url -Body $body -ContentType 'text/xml' -Method post
        $session_id = $resp.content | Select-Xml -XPath '//@session-id' | Select-Object -ExpandProperty Node | foreach-object {$_.'#text'}
        if($session_id) {
            Write-Host "Login Successful"
            Write-Verbose "Session-id: $session_id"
           
					Write-Verbose "Create global variable: $Session_id"
					$global:session_id = $session_id
                    $Global:url = $url
            }
            else
            {
             Write-Warning "There was a problem creating the session"
        }       
    }
  