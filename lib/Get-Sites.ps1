function Get-Sites{
<#
	.SYNOPSIS
	    Gets a list of sites from a nexpose console

	.DESCRIPTION
	    The Get-Sites cmdlet gets a list of sites from nexpose using the API
		
	.EXAMPLE
		PS> Get-Sites
		
	.EXAMPLE
		PS> Get-Connection -session_id $sessionid

	.NOTES
		Author: Josiah Inman
		

	.LINK
        
	#>
# Param(
 #       [String]$session_id = "",
  #      [String]$url = ""
	#)
# Get a list of Sites
if ($url -and $session_id){
    $sites_request = "<SiteListingRequest session-id='${session_id}'/>"
    $resp = Invoke-WebRequest -URI $url -Body $sites_request -ContentType 'text/xml' -Method post
    $sites =  $resp.content | Select-XMl -XPath '//@name' | Select-Object -ExpandProperty Node | foreach-object {$_.'#text'}
    Write-Output $sites
    }
else
    {
    Write-Warning "No Valid Session to use"
    }
}