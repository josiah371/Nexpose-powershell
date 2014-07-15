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

$connection = New-Module {
$script:api_version = '1.1'
     
    function initialize([string]$_ip, [string]$_port, [string]$_user, [string]$_pass,  [int]$_silo_id){
       #TODO: read from file
        $script:server = $_ip
        $script:port = $_port
        $script:username = $_user
        $script:password = $_pass
        $script:silo_id = $_silo_id
        $script:session_id = ''
    }
   
    function login(){
        $connection.initialize('10.0.0.1', '3780', 'nxadmin', 'nxadmin')
        #build the login request
        $script:login_request = "<LoginRequest synch-id='0' password ='$password' user-id ='$username' ></LoginRequest>"
        # login and get the session id
        $resp = $connection.execute($script:login_request)
        $s_id = $resp.content | Select-Xml -XPath '//@session-id' | Select-Object -ExpandProperty Node | foreach-object {$_.'#text'}
       if($s_id) {
       $script:session_id = $s_id
       Write-Warning "Login Successful, Session-id: $s_id"
       }       
    }
    
    function logout(){
        $script:logoff_request = "<LogoutRequest session-id='$script:session_id'/>"
        $resp = $connection.execute($script:logoff_request)
        $message = $resp.content | Select-Xml -XPath '//LogoutResponse' | Select-Object -ExpandProperty Node | Select success
        if ($message){ 
        Write-Warning $message
        }
    }
    
    function execute($body){
        $script:url = "https://${server}:${port}/api/${api_version}/xml"
        $resp = Invoke-WebRequest -URI $url -Body $body -ContentType 'text/xml' -Method post
        $message = $resp.content | Select-Xml -XPath '//message' | Select-Object -ExpandProperty Node | foreach-object {$_.'#text'}
        if ($message){ 
        Write-Warning $message
        }
        return $resp
    } 

} -AsCustomObject


