<#

.SYNOPSIS

Get any user whose password has changed since the last runtime, then sync that user's password to the new domain via ADMT/Password Sync Server.



.DESCRIPTION

This script is intended to be run on a semi-regular basis to sync passwords from one environment to another.
The script will find any user whose account has changed recently, and then if their password change time is newer than the last run time of the script,
sync their passwords to another domain.


.EXAMPLE


.NOTES

This script has to be run from an elevated command promt. This means you need to run your ISE as administrator, or run
a powershell comand prompt as an administrator. In most cases, this means logging in as your migration user, and then
right clicking, and running as admin. The 'Run As' even though it often *should* elevate past UAC permissions, doesn't.

# This only adds a user to the password sync file, if an exact match happens in the target domain
# This script requires the active directory module locally

Import-Module ServerManager
Add-WindowsFeature RSAT-AD-PowerShell

Topology Notes:
- Corp, JazzUSA
- PES is on DC1-ITAR (JazzUSA)
- Cert is from a DC in Corp <- not how it should be, but we're going with it
    - admt key /option:create /sourcedomain:jazzusa.ad /keyfile:"c:\PES Key\PES.pes" /keypassword:<password>
- Cert is imported onto the ADMT box in CORP (NPBCORPADMT) <- it was created here as well, but we still have to import it
    - admt.exe key /option:import /sourcedomain:jazzusa.ad /keyfile:�c:\PES Key\PES.pes� /keypassword:<password>
- Cert is used to install the PES on the DC in JazzUSA (DC1-ITAR)

Todo:
- Add runLog code to keep track of which accounts have/havent been migrated, and only use password migration where needed

#>


# Variables
$tempDir = 'C:\tmp'
$lastRunFile = 'LastRun.txt'
$admtImportFile = 'admtimport.csv'
$runFullMigration = $false
$userOutputObjArray = @()
$sourceDomain = 'jazzusa.ad'
$sourceOU = "OU=JazzUSA,OU=Users,OU=NPB,DC=corp,DC=towersemi,DC=com"
$targetDomain = 'corp.towersemi.com'
$targetDomainDC = 'npbcorpdc2.corp.towersemi.com'
$passwordExportServer = 'dc1-itar.jazzusa.ad'
$targetDomainAdminUsername = 'jazzusa\passmig'
$targetDomainAdminPassword = '$ushiBTP'

#event logging vars
$scriptEventLogName = 'IdentityAutomation'
$scriptEventLogSource = 'Password Sync'

# Register the script with the eventlog
if (-not([System.Diagnostics.EventLog]::SourceExists($scriptEventLogSource))) 
{ 
    New-EventLog -LogName $scriptEventLogName -Source $scriptEventLogSource
    Limit-EventLog -LogName $scriptEventLogName -MaximumSize 100MB
    Limit-EventLog -LogName $scriptEventLogName -OverflowAction OverwriteAsNeeded
}

# Create credential in the target domain
$targetDomainAdminPassword_secure = ConvertTo-SecureString $targetDomainAdminPassword -AsPlainText -Force
$targetDomainAdminCred = New-Object System.Management.Automation.PSCredential ($targetDomainAdminUsername, $targetDomainAdminPassword_secure)

Write-EventLog -LogName $scriptEventLogName -Source $scriptEventLogSource -EventId 4200 -EntryType Information -Message ('Start Password Migration Script' + "`r`n")

# Import modules
import-module ActiveDirectory

<# Last Run Code - Deprecated Due to Small Scale

# Make sure temp dir extists, if not, make it
if (!(Test-Path -PathType Container -Path $tempDir)) {
    New-Item -ItemType Directory -Force -Path $tempDir
}

# If the file with a previous date exists, rock with it
if (test-path -PathType Any -Path ($tempDir + '/' + $lastRunFile)) {
    # Read in last run
    [datetime]$lastRunDate_Local = (Get-Content ($tempDir + '/' + $lastRunFile))
}
else {
    # We need to do a full run, set a flag so we can do this later
    $runFullMigration = $true
}


# Set last run time back
get-date -format s | Out-File ($tempDir + '/' + $lastRunFile)

#>

# Commented out the above, and added this here so we don't always have to delete the last run file to test.
# We can always bring the above code back if we need to.
$runFullMigration = $true
if ($runFullMigration -eq $true) {
    # Get all the users specified in an OU. This is the first time we're running this, and don't want to sync service accounts too
    $recentAdUserChange = get-aduser -Filter * -Properties PasswordLastSet -SearchBase $sourceOU -searchscope onelevel -server $passwordExportServer
}
else {
    # Get any user whose object has changed since the last run time
    # I'm not sure if this is fast enough, i may want to pad this a few seconds
    # This is happening in the local domain (JazzUSA)
    $recentAdUserChange = get-aduser -Filter 'WhenChanged -gt $lastRunDate_Local' -SearchBase $sourceOU -Properties PasswordLastSet -searchscope onelevel -server $passwordExportServer
}


# Loop through all the users with changes
foreach ($adUser in $recentAdUserChange){
    # Get any user whose password has changed since the last run time
    # I'm not sure if this is fast enough, i may want to pad this a few seconds
    if (($adUser.PasswordLastSet -ge $lastRunDate_Local) -or ($runFullMigration -eq $true))
    {
        write-host 'user has changed password recently or this user has never been synced'
        write-host $adUser.name

        # Make a psobject to write out to csv that ADMT can use
        $userOutputObj = New-Object psobject
        Add-Member -InputObject $userOutputObj -MemberType NoteProperty -Name SourceName -Value $adUser.SAMAccountName
        Add-Member -InputObject $userOutputObj -MemberType NoteProperty -Name TargetName -Value $adUser.SamAccountName
        $userOutputObjArray += $userOutputObj
    }
}

# Test and make sure there's actually something to do at this point
if (($userOutputObjArray | Measure-Object).count -ge 1){

    $admtIncludeFileFullPath = ($tempDir + '\' + $admtImportFile)

    # Output the object array to a csv
    $userOutputObjArray | export-csv -NoTypeInformation -Path $admtIncludeFileFullPath

    #start the password export service on the PES server/DC in the source domain - this is using the current running credentials to do the remote call, they should be an admin on the other box as well
    Invoke-Command { Start-Service -Name 'PesSvc' } -ComputerName $passwordExportServer
    Start-Sleep -Seconds 5
    
    # Sync passwords to the new domain using the csv that we wrote out, we need to sync the user objects first, it's weird like that
    Invoke-Expression "admt user /includefile:$admtIncludeFileFullPath /conflictoptions:merge /passwordoption:copy /userpropertiestoexclude:* /SD:$sourceDomain /TD:$targetDomain /PS:$passwordExportServer"

    # We do it a second time to make sure the passwords sync, one the users are in the DB as migrated at least one time
    Invoke-Expression "admt password /includefile:$admtIncludeFileFullPath /SD:$sourceDomain /TD:$targetDomain /PS:$passwordExportServer"

    #stop the password export service on the PES server/DC in the source domain - this is using the current running credentials to do the remote call, they should be an admin on the other box as well
    Invoke-Command { Stop-Service -Name 'PesSvc' } -ComputerName $passwordExportServer
    start-sleep -Seconds 5

    # Remote out to whatever domain I need to be in and set the flag for the users that were changed so they *don't* need to change their password on login
    foreach ($adUser in $recentAdUserChange){
        # This is happening in the target domain (CORP)
        Set-ADUser -server $targetDomainDC -credential $targetDomainAdminCred -Identity $adUser.SamAccountName -ChangePasswordAtLogon $false
    }
}

Write-EventLog -LogName $scriptEventLogName -Source $scriptEventLogSource -EventId 4200 -EntryType Information -Message ('End Password Migration Script' + "`r`n")

# Delete import file, uncomment in production so I don't leave files floating around?
# Remove-Item ($tempDir + '\' + $admtImportFile)

# Remove modules
remove-module ActiveDirectory