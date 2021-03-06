<#

.SYNOPSIS

Converts a 'user mailbox' to a 'linked mailbox' in Exchange 2010 based on a list of users from an OU.



.DESCRIPTION

This script is intended to be run on a semi-regular basis to ensure users in a specific OU have their mailboxes provisioned as 'linked' for an Exchange resource forest deployment.
The script will read an OU of users, and obtain their samAccountNames. Using that list as the source list, the script will ensure those users have a mailbox, and if so,
proceed to attempt to link those users to a user of the same name in a target, or non-resource, domain.

This is intended to be run *after* users have been created or migrated in the target domain, as it will not create a user in that target domain.


.EXAMPLE


.NOTES

To change back to user mailbox for testing: Set-User -Identity “user” -LinkedMasterAccount $null


#>

#Variables

$exchAdminUsername = 'corp\npbadmin'
$exchServerPSURL = 'http://npbvmexhub.corp.towersemi.com/PowerShell/'
$linkedMailboxesOU = "OU=JazzUSA,OU=Users,OU=NPB,DC=corp,DC=towersemi,DC=com"
$nonResourceDomain = 'jazzusa.ad'
$nonResourceDomainController = 'dc3-itar.jazzusa.ad'
$nonSecurePass = 'B@dWolf'

#event logging vars
$scriptEventLogName = 'IdentityAutomation'
$scriptEventLogSource = 'Exchange Linked Mailbox'
$errorObjectArray = @()



#Create Credentials
#exchange in *this* domain
$exchAdminPassword_secure = ConvertTo-SecureString $nonSecurePass -AsPlainText -Force
$exchCred = New-Object System.Management.Automation.PSCredential ($exchAdminUsername, $exchAdminPassword_secure)


# Register the script with the eventlog
if (-not([System.Diagnostics.EventLog]::SourceExists($scriptEventLogSource))) 
{ 
    New-EventLog -LogName $scriptEventLogName -Source $scriptEventLogSource
    Limit-EventLog -LogName $scriptEventLogName -MaximumSize 100MB
    Limit-EventLog -LogName $scriptEventLogName -OverflowAction OverwriteAsNeeded
}

Write-EventLog -LogName $scriptEventLogName -Source $scriptEventLogSource -EventId 4200 -EntryType Information -Message ('Start Exchange Linked Mailbox Script' + "`r`n")

# Reach out to AD and find all users in the OU that we'll need to created linked mailboxes for
Import-Module ActiveDirectory

# Read the members of an ou from the source domain and put into an array
$usersWhoNeedLinkedMailboxes = Get-ADUser -SearchBase $linkedMailboxesOU -Filter * -SearchScope OneLevel | Select SamAccountName

# Reach out to exchange and make a new remote powershell session
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $exchServerPSURL -Authentication Kerberos -Credential $exchCred

# Import that session to get access to all the exchange commandlets
Import-PSSession $Session

foreach ($user in $usersWhoNeedLinkedMailboxes){
    
    $userSAM = $user.SamAccountName
    $nonResourceDomainUser = $nonResourceDomain + '\' + $userSAM

    # Confirm that a mailbox exists for the user in question
    $mailbox = $null
    try {
        $mailbox = Get-Mailbox -Identity $userSAM -ErrorAction SilentlyContinue
    }
    catch {
        # No mailbox exists, don't do anything to this user
        $mailboxError = $_
    }

    if ($mailbox -ne $null){
        
        # Get the mailbox to make sure the mailbox isn't already linked
        $exchUser = $null
        try {
            $exchUser = get-user -id $userSAM -erroraction Stop
        }
        catch{
            # The user doesn't exist, don't do anything to this user
            $mailboxError = $_
        }

        # Test and make sure the mailbox isn't already linked
        if ($exchUser.RecipientTypeDetails -ne 'LinkedMailbox'){

            $userTest = $null
            # Make sure the remote user actually exists - It should, so if it doesn't we want to log this error
            try {
                #$userTest = Get-ADUser -Server $nonResourceDomainController -Credential $nonResourceDomainAdminCred -Identity $userSAM -ErrorAction SilentlyContinue
                ## Ezra and Jay - The line above is what was failing before. The user specified in the Credential object was locked out of the remote domain
                ## That meant that this command failed, so there was never a valid object in $userTest, which meant the mailbox was never fully converted.
                ## I removed the credential since we don't need it for just a 'get-aduser' lookup, and changed the syntax of the command to better handle errors
                $userTest = Get-ADUser -Filter {SAMAccountName -eq $userSAM} -Server $nonResourceDomainController
            }
            catch {
                $nonResourceDomainError = $_

                $errorString = 'Error on checking remote user: ' + $userSam + "`r`n" + 'Additional Information:' + "`n" + 'AD Error: ' + $nonResourceDomainError
                $errorObjectArray += $errorString
            }

            if ($userTest -ne $null) {
                # Convert the mailbox from a user mailbox, to a linked one to the target domain user
                Set-User -id $userSAM -LinkedMasterAccount $nonResourceDomainUser -LinkedDomainController $nonResourceDomainController -LinkedCredential $nonResourceDomainAdminCred

                # Adjust the mailbox permissions once we've linked the mailbox so the linked user can login
                Add-MailboxPermission -Identity $mailbox.name -User $nonResourceDomainUser -AccessRight Fullaccess -InheritanceType All
            }
        }
    }
}

Write-EventLog -LogName $scriptEventLogName -Source $scriptEventLogSource -EventId 4200 -EntryType Information -Message ('End Exchange Linked Mailbox Script' + "`r`n")

#log erors to event log
foreach ($error in $errorObjectArray){
    Write-EventLog -LogName $scriptEventLogName -Source $scriptEventLogSource -EventId 4201 -EntryType Error -Message ($error + "`r`n")
}

#remove the session to close it
Remove-PSSession $Session
Remove-Module ActiveDirectory