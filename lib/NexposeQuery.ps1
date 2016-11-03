Function Set-NexURL {
    Param(
        [String]$Server = "1.1.1.1",
        [String]$Port = "3780",
        [string]$api_version = '1.1'
    )
        $Global:url = "https://${server}:${port}/api/${api_version}/xml"
}

function Set-NexConnection{
    <#
	.SYNOPSIS
	    Setup the connection information to Login to Nexpose.

	.DESCRIPTION
	    The Set-Connection cmdlet setup or initializes a connection infomation string
        to Login a session to the nexpose API.	
	
	.EXAMPLE
		PS> Set-Connection

	.NOTES
		Author: Josiah Inman, modifield by Scott Mountjoy
		

	.LINK
        
	#>
	[CmdletBinding(
    	SupportsShouldProcess=$True,
        ConfirmImpact="Low"
    )]
  
   Param(
        [String]$Session_id = ""
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

        if(-NOT $url) { Set-NexURL }

        $cred = Get-Credential -Message "Nexpose Login:"
        #build the login request
        $body = "<LoginRequest synch-id='0' password ='$($cred.GetNetworkCredential().Password)' user-id ='$($cred.UserName)' ></LoginRequest>"
        # login and get the session id
        $resp = Invoke-WebRequest -URI $url -Body $body -ContentType 'text/xml' -Method post
        $session_id = $resp.content | Select-Xml -XPath '//@session-id' | Select-Object -ExpandProperty Node | foreach-object {$_.'#text'}
        if($session_id) {
            Write-Warning "Login Successful, Session-id: $session_id"
           
					Write-Verbose "Create global variable: $Session_id"
					$global:session_id = $session_id
            }
            else
            {
             Write-Warning "There was a problem creating the session"
        }
    }

Function ParseResponse([string]$rawdata){
 
    $base64 = $rawdata -replace '^[\s\S\n]*base64',''
    $base64 = $base64 -replace '\n--.*--',''
    $base64 = $base64.Trim()

    $utf8 = [System.Convert]::FromBase64String($base64)
    $plain = [System.Text.Encoding]::UTF8.GetString($utf8)
    return $plain
}

Function gen_vuln_table([string]$report){
    $a = $report -Split "`n"
    $os_vuln = "SELECT * FROM ( VALUES "
    for($i=1; $i -lt $a.Count; $i++) {
        $b = $a[$i] -split ','
        $item = "("
        $b | %{$item += "'$_',"}
        $item = $item.TrimEnd(',')
        $item += ')'
        $os_vuln += "$item,"
    }
    $os_vuln = $os_vuln.TrimEnd(',')
    $os_vuln += ") AS t ($($a[0]))"
    return $os_vuln
}

#Needs sw_vuln
#Pulls dim_asset_operating_system
function gen_os_map([string]$os_vuln) {
    $os_map = @"
os_map AS (
    SELECT DISTINCT ON (daos.asset_id, v.vulnerability_id) v.title, v.vulnerability_id, daos.asset_id, v.operating_system_id, v.description
    FROM ($os_vuln) v LEFT JOIN sw_vuln sw ON v.vulnerability_id = sw.vulnerability_id, dim_asset_operating_system daos
    WHERE daos.operating_system_id = v.operating_system_id
    AND sw.vulnerability_id is NULL
)
"@
return $os_map
}

function xml_safe([string]$table){
    $query = $query -replace '&','&amp;' # DO THIS FIRST, becase other replace operations *add* an ampersand that needs to remain.
    $query = $query -replace "'",'&apos;'
    $query = $query -replace '"','&quot;'
    $query = $query -replace '<','&lt;'
    $query = $query -replace '>','&gt;'
    return $query
}

function Run_NexQuery{
        Param(
            [String]$query = ""
        )

#$query = xml_safe $query

$body = @"
<ReportAdhocGenerateRequest session-id='${session_id}'>
    <AdhocReportConfig format='sql'>
        <Filters>
            <filter type='version' id='2.0.1'/>
            <filter type='tag' id='454'/>
            <filter type='query' id='$(xml_safe ${query})'/>
        </Filters>
    </AdhocReportConfig>
</ReportAdhocGenerateRequest>
"@

if(-NOT $url) {
    Set-NexURL
}

if(-NOT $session_id){
    Set-NexConnection
}

if ($url -and $session_id){
    $resp = Invoke-WebRequest -URI $url -Body $body -ContentType 'text/xml' -Method post -TimeoutSec 260000
    $report = ParseResponse $resp.RawContent
    #$global:resp = $resp
    #$global:report = $report
    $os_map = gen_os_map $(gen_vuln_table $report)
    Write-Host $os_map
    }
else
    {
    Write-Warning "No Valid Session to use"
    }
}