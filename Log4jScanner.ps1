#Script wil scan for the following:
# CVE-2021-44228 Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI Score: 10.0 CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
# CVE-2021-45046 Apache Log4j 2.15.0 Score: 9.0 (AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H)
# CVE-2021-45105 Apache Log4j2 versions 2.0-alpha1 through 2.16.0 Score: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
#intial script created by https://github.com/Maelstromage/Log4jSherlock and edited by @JoranSlingerland

#load assembly
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

# Config
$filetypes = @('*.JAR','*.WAR','*.EAR','*.JPI','*.HPI')


#Init
$global:Errors = @()
$global:vulnerabilityresults = @()
$global:debuglog = @()

#Functions
function Get-Version{
    param($version,$hasJNDI)

    $CVE = 'CVE-2021-44228'
    $CVSSScore = '10.0'
    $FixedVersion = $false
    if($hasJNDI -eq $false){$CVE = $null; $CVSSScore = $null; $FixedVersion = $false}
    if($version -eq 'version=2.15.0'){$CVE = 'CVE-2021-45046'; $CVSSScore = '9.0'; $FixedVersion = $false}
    if($version -eq 'version=2.16.0'){$CVE = 'CVE-2021-45105'; $CVSSScore = '7.5'; $FixedVersion = $false}
    if($version -eq 'version=2.17.0'){$CVE = $null; $CVSSScore = $null; $FixedVersion = $true}
    if($version -eq 'version=2.12.2'){$CVE = 'CVE-2021-45105'; $CVSSScore = '7.5'; $FixedVersion = $false}
    $return = @{CVE = $CVE; CVSSScore = $CVSSScore; fixedversion = $fixedversion} 

    return $return
}


function Get-FileVunStatus{
    param($path)
    $path = $path.fullname
    $hasJNDI = $false
    try{
        $nestedfiles = ([System.IO.Compression.ZipArchive]([System.IO.Compression.ZipFile]::OpenRead($path))).Entries | Where-Object {$_.name -eq 'jndiLookup.class'}
    }catch{
        $global:Errors += @{Error=$_.exception.Message;path=$path}
    }
    foreach($nestedfile in $nestedfiles) {
        if ($nestedfile.name -eq 'JndiLookup.class'){
            $hasJNDI = $true
            $JNDIfile = $nestedfile.fullname
        }
    }
    try{
        $zip = [io.compression.zipfile]::OpenRead($path)
    }catch{
        $global:Errors += @{Error=$_.exception.Message;path=$path}
    }
    $file = $zip.Entries | where-object { $_.Name -eq "pom.properties" -and $_.FullName -match 'log4j'}
    if($null -ne $file){
        $stream = $file.Open()
        $reader = New-Object IO.StreamReader($stream)
        $text = $reader.ReadToEnd()
        $version = -split $text | select-string -Pattern "Version"
        $reader.Close()
        $stream.Close()
        $zip.Dispose()
    }
    $versionCVE = (Get-Version -version $version.line -hasJNDI $hasJNDI)

    if ($hasJNDI -and !($versionCVE.fixedversion)){
        $vuln = $true
    } else {
        $vuln = $false
    }
    $return = @{
        path = $path;
            version = $version.line;
            text=$text;
            pomLocation=$file.FullName;
            hasJNDI=$hasJNDI;
            JNDILocation=$JNDIfile
            CVE = $versionCVE.CVE
            CVSSScore = $versionCVE.CVSSScore
            FixedVersion = $versionCVE.fixedversion
            Vulnerable = $vuln
            ComputerName = $env:COMPUTERNAME
    }
    return $return
}

function Get-SelectedFiles{
    param($filetypes)
    $scannedfiles =@()
    $Drives = (Get-PSDrive -PSProvider FileSystem | Select-Object Root, DisplayRoot | Where-Object {$null -eq $_.DisplayRoot}).root
    foreach ($Drive in $Drives) {
        $searchingmessage = "Searching Drive $drive on host $env:ComputerName..."
        $global:vulnerabilityresults += $searchingmessage
        $javaFiles = Get-ChildItem $Drive -Recurse -ErrorVariable DriveError -include $filetypes -ErrorAction SilentlyContinue #| out-null
        foreach ($javaFile in $javaFiles){
            $scannedfiles += [pscustomobject](Get-FileVunStatus $javaFile)
        }
    }
    $global:Errors += @{Error=$DriveError.exception.message}
    $scannedfiles += $global:Errors
    $vuncheck = $scannedfiles | where-object {$_.Vulnerable -eq $true}
    if ($null -eq $vuncheck){
        $vulnerable = $false
    } else {
        $vulnerable = $true
    }
    $scannedfiles = convertto-json $scannedfiles
    return $scannedfiles, $vulnerable
}

#Main function
Function Main{
    If(!(Test-Path "$env:SystemDrive\Log4jScanner")) { New-Item -ItemType Directory "$env:SystemDrive\Log4jScanner" -Force }
    $date = get-date -Format "yyyy-MM-dd_hh-mm-ss"
    $results, $vulnerable = Get-SelectedFiles -filetypes $filetypes

    $jsonpath = "$env:SystemDrive\Log4jScanner\Log4jScanner $date.json"
    set-content -path $jsonpath -value $results
    return $results, $vulnerable
}

#run main function
$results, $vulnerable = Main