function Invoke-Sign {
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $binaryPath
    )
    $signtool=ls -Force -Recurse -ErrorAction SilentlyContinue -Path 'C:\Program Files (x86)\Windows Kits\' -include "signtool.exe"  -File | select -ExpandProperty fullname | select-string -pattern "x64"
if(test-path .\selfsignedcert1.ps1){
    & "$signtool" sign /v /f selfsigncert1.pfx /t http://timestamp.digicert.com /fd sha256 /p my_passowrd $binaryPath
    return
}

$cert = New-SelfSignedCertificate -DnsName www.micat.com -Subject "CN=Microsoft" -Type CodeSigning -CertStoreLocation "cert:\LocalMachine\My"
$CertPassword = ConvertTo-SecureString -String "my_passowrd" -Force -AsPlainText 
export-PfxCertificate -Cert "cert:\LocalMachine\My\$($cert.Thumbprint)" -FilePath "selfsigncert1.pfx" -Password $CertPassword 
& "$signtool" sign /v /f selfsigncert1.pfx /t http://timestamp.digicert.com /fd sha256 /p my_passowrd $binaryPath
}
