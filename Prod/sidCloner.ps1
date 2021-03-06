<#

.SYNOPSIS

Clone SID's from one domain to the next. This will clone the sids of all users in one OU to all matching users in another OU.
If no match is found, it won't clone



.DESCRIPTION

This script is intended to be run on a semi-regular basis to sync SIDs from one environment to another.
The script will find any user in a specific ou, and write their current sid to the sidHistory attribute of a user
in another domain.


.EXAMPLE

B@dWol
.NOTES

- the source dc *has* to be the primary DC, so that's why its discovered programatically 

Future Things To Do
- Allow this to take an input file with CN's of users and clone those from source to target if they exist
- put the clone within a try/catch


#>

 
#Variables 
#
$targetDomain = "jazzusa.ad"
$targetDC = "dc1-itar.jazzusa.ad"
$targetOU = "OU=ITAR Users,DC=jazzusa,DC=ad"
$targetDomainAdminUsername = 'jazzusa\passmig'
$targetDomainAdminPassword = '$ushiBTP'
#
$sourceDomain = "corp.towersemi.com"
$sourceDC = "mhvmcorpdc1.corp.towersemi.com"
$sourceOU = "OU=JazzUSA,OU=Users,OU=NPB,DC=corp,DC=towersemi,DC=com"
$sourceDomainAdminUsername = 'corp\npbadmin'
$sourceDomainAdminPassword = 'B@dWolf'

#
$sidClonerDLLFullPath = "C:\sidCloner\sidCloner.dll"
$sidClonerLogFullPath = "C:\sidCloner\Logs\CloneFailed.csv"

#event logging vars
$scriptEventLogName = 'IdentityAutomation'
$scriptEventLogSource = 'Sid Cloner'

# Create credential in the target domain
$targetDomainAdminPassword_secure = ConvertTo-SecureString $targetDomainAdminPassword -AsPlainText -Force
$targetDomainAdminCred = New-Object System.Management.Automation.PSCredential ($targetDomainAdminUsername, $targetDomainAdminPassword_secure)

# Create credential in the source domain
$sourceDomainAdminPassword_secure = ConvertTo-SecureString $sourceDomainAdminPassword -AsPlainText -Force
$sourceDomainAdminCred = New-Object System.Management.Automation.PSCredential ($sourceDomainAdminUsername, $sourceDomainAdminPassword_secure)

Write-EventLog -LogName $scriptEventLogName -Source $scriptEventLogSource -EventId 4200 -EntryType Information -Message ('Start Sid Cloner Script' + "`r`n")

# Load sidCloner C++ Module
[System.Reflection.Assembly]::LoadFile("$sidClonerDLLFullPath") | Out-Null 

# Load Active Directory Module
Import-Module ActiveDirectory

 
# Clear the log file if it exists
if((Test-Path $sidClonerLogFullPath) -eq $true) { 
    Remove-Item -path $sidClonerLogFullPath
} 


# Read the members of an ou from the source domain and put into an array
$sourceUsersToClone = Get-ADUser -Server $sourceDC -Credential $sourceDomainAdminCred -SearchBase $sourceOU -SearchScope OneLevel -Filter * | Select SamAccountName



foreach ($sourceSAMAccountName in $sourceUsersToClone) {

    $sourceSAMAccountName = $sourceSAMAccountName.SamAccountName
    $targetSAMAccountName = $sourceSAMAccountName

    # Check and make sure account exists in target domain
    $userTest = $NULL
    try {
        $userTest = get-aduser -Server $targetDC -credential $targetDomainAdminCred -Identity $targetSAMAccountName -ErrorAction SilentlyContinue
    }
    catch {
        $userTest = $null
    }

    if ($userTest -ne $null) {

        try{
            # The user account exists, now do the migration
            [wintools.sidcloner]::CloneSid( 
                $sourceSAMAccountName, 
                $sourceDomain, 
                $sourceDC, 
                $sourceDomainAdminCred.UserName, 
                $sourceDomainAdminCred.Password, 
                $targetSAMAccountName, 
                $targetDomain,
                $targetDC,
                $targetDomainAdminCred.UserName,
                $targetDomainAdminCred.Password 
            )
 
            Write-Host "Account $($sourceDomain)\$($sourceSAMAccountName) cloned"
        }
        catch{
            Write-EventLog -LogName $scriptEventLogName -Source $scriptEventLogSource -EventId 4201 -EntryType Error -Message ($_ + "`r`n")
        }
    } 
}

Write-EventLog -LogName $scriptEventLogName -Source $scriptEventLogSource -EventId 4200 -EntryType Information -Message ('End Sid Cloner Script' + "`r`n")