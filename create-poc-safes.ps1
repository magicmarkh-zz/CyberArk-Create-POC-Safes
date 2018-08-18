###########################################################################
#
# NAME: Create POC Safes
#
# AUTHOR:  Mark Hurter
#
# COMMENT:
# This script will retreive credentials to login using the API and create safes for a POC
#
# VERSION HISTORY:
# 1.0 8/14/2018 - Initial release
#
###########################################################################

[CmdletBinding(DefaultParametersetName="Create")]
param
(
	[Parameter(Mandatory=$true,HelpMessage="Please enter your PVWA address (For example: https://pvwa.mydomain.com)")]
	[Alias("url")]
	[String]$PVWAURL,

    [Parameter(Mandatory=$true,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true)]
	[Alias("SearchIn")]
	[String]$SearchInValue,

    [Parameter(Mandatory=$false,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true)]
	[ValidateScript({Test-Path $_})]
	[Alias("path")]
	[String]$CsvPath,

	# Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory=$false)]
	[Switch]$DisableSSLVerify
)

# Get Script Location
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path

# Set Log file path
$LOG_FILE_PATH = "$ScriptLocation\Account_Onboarding_Utility.log"

$InDebug = $PSBoundParameters.Debug.IsPresent
$InVerbose = $PSBoundParameters.Verbose.IsPresent

# Global URLS
# -----------
$URL_PVWAWebServices = $PVWAURL+"/PasswordVault/WebServices"
$URL_PVWABaseAPI = $URL_PVWAWebServices+"/PIMServices.svc"
$URL_CyberArkLogon = $PVWAURL+"/PasswordVault/api/auth/cyberark/logon"
$URL_CyberArkLogoff = $PVWAURL+"/PasswordVault/api/auth/logoff"

# URL Methods
# -----------
$URL_Safes = $URL_PVWABaseAPI+"/Safes"
$URL_SafeDetails = $URL_PVWABaseAPI+"/Safes/{0}"
$URL_SafeMembers = $URL_PVWABaseAPI+"/Safes/{0}/Members"

# Initialize Script Variables
# ---------------------------
$g_LogonHeader = ""

#region Functions
Function Test-CommandExists
{
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try {if(Get-Command $command){RETURN $true}}
    Catch {Write-Host "$command does not exist"; RETURN $false}
    Finally {$ErrorActionPreference=$oldPreference}
} #end function test-CommandExists

Function Add-LogMsg
{
<#
.SYNOPSIS
	Method to log a message on screen and in a log file
.DESCRIPTION
	Logging The input Message to the Screen and the Log File.
	The Message Type is presented in colours on the screen based on the type
.PARAMETER MSG
	The message to log
.PARAMETER Header
	Adding a header line before the message
.PARAMETER SubHeader
	Adding a Sub header line before the message
.PARAMETER Footer
	Adding a footer line after the message
.PARAMETER Type
	The type of the message to log (Info, Warning, Error, Debug)
#>
	param(
		[Parameter(Mandatory=$true)]
		[AllowEmptyString()]
		[String]$MSG,
		[Parameter(Mandatory=$false)]
		[Switch]$Header,
		[Parameter(Mandatory=$false)]
		[Switch]$SubHeader,
		[Parameter(Mandatory=$false)]
		[Switch]$Footer,
		[Parameter(Mandatory=$false)]
		[ValidateSet("Info","Warning","Error","Debug","Verbose")]
		[String]$type = "Info"
	)

	If ($Header) {
		"=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH
		Write-Host "======================================="
	}
	ElseIf($SubHeader) {
		"------------------------------------" | Out-File -Append -FilePath $LOG_FILE_PATH
		Write-Host "------------------------------------"
	}

    $msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
	$writeToFile = $true
	# Replace empty message with 'N/A'
	if([string]::IsNullOrEmpty($Msg)) { $Msg = "N/A" }
	# Check the message type
	switch ($type)
	{
		"Info" {
			Write-Host $MSG.ToString()
			$msgToWrite += "[INFO]`t$Msg"
		}
		"Warning" {
			Write-Host $MSG.ToString() -ForegroundColor DarkYellow
			$msgToWrite += "[WARNING]`t$Msg"
		}
		"Error" {
            if($safeCheck -ne $true){
			Write-Host $MSG.ToString() -ForegroundColor Red
		    }
        	$msgToWrite += "[ERROR]`t$Msg"
		}
		"Debug" {
			if($InDebug)
			{
				Write-Debug $MSG
				$msgToWrite += "[DEBUG]`t$Msg"
			}
			else { $writeToFile = $False }
		}
		"Verbose" {
			if($InVerbose)
			{
				Write-Verbose $MSG
				$msgToWrite += "[VERBOSE]`t$Msg"
			}
			else { $writeToFile = $False }
		}
	}

	If($writeToFile) { $msgToWrite | Out-File -Append -FilePath $LOG_FILE_PATH }
	If ($Footer) {
		"=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH
		Write-Host "======================================="
	}
}

#region opens file dialog for CSV import (not used)
Function Open-FileDialog($initialDirectory)
{
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null

    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.filter = "CSV (*.csv)| *.csv"
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filename
}
#endregion

Function Invoke-Rest
{
	param ($Command, $URI, $Header, $Body, $ErrorAction="Continue")
	
	$restResponse = ""
	try{
		Add-LogMsg -Type Verbose -MSG "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body"
		$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -Body $Body
	} catch {
		If($null -ne $_.Exception.Response.StatusDescription)
		{
            if($_.Exception.Response.StatusDescription.Substring(0,14) -eq "ITATS373E Safe"){
            Add-LogMsg -Type Debug -MSG $_.Exception.Response.StatusDescription -ErrorAction $ErrorAction
            }
            else{
			Add-LogMsg -Type Error -MSG $_.Exception.Response.StatusDescription -ErrorAction $ErrorAction
            }
		}
		else
		{
			Add-LogMsg -Type Error -Msg "StatusCode: $_.Exception.Response.StatusCode.value__"
		}
		$restResponse = $null
	}
	Add-LogMsg -Type Verbose -MSG $restResponse
	return $restResponse
}


Function Get-Safe
{
	param ($safeName)
	$_safe = $null
	try{
		$accSafeURL = $URL_SafeDetails -f $safeName
		$_safe = $(Invoke-Rest -Uri $accSafeURL -Header $g_LogonHeader -Command "Get" -ErrorAction "SilentlyContinue")
	}
	catch
	{
		Add-LogMsg -Type Error -MSG $_.Exception.Response.StatusDescription
	}
	return $_safe.GetSafeResult
}
Function Test-Safe
{
	param (
		[Parameter(Mandatory=$true)]
		[String]$safeName
		)

	try{
		If ($null -eq $(Get-Safe -safeName $safeName))
		{
			# Safe does not exist
			Add-LogMsg -Type Warning -MSG "Safe $safeName does not exist"
			return $false
		}
		else
		{
			# Safe exists
			Add-LogMsg -Type Info -MSG "Safe $safeName exists"
			return $true
		}
	}
	catch
	{
		Add-LogMsg -Type Error -MSG $_.Exception
	}
}

Function New-Safe
{
	param (
		[Parameter(Mandatory=$true)]
		[String]$safeName,
		[Parameter(Mandatory=$true)]
		[String]$cpmName,
		[Parameter(Mandatory=$true)]
		[String]$safeDescription
		)

	# Create the Target Safe
	Add-LogMsg -Type Info -MSG "Creating Safe $safeName"
	$bodySafe = @{ SafeName=$safeName;Description=$safeDescription;OLACEnabled=$false;ManagingCPM=$cpmName;NumberOfDaysRetention=7 }
	$restBody = @{ safe=$bodySafe } | ConvertTo-Json -Depth 3

	$createSafeResult = $(Invoke-Rest -Uri $URL_Safes -Header $g_LogonHeader -Command "Post" -Body $restBody)
	if ($createSafeResult)
	{
		Add-LogMsg -Type Error -MSG "Safe $($row.Safe) created"
		return $true
	}
	else {
		# Safe creation failed
		Add-LogMsg -Type Error -MSG "Safe Creation failed - Should Skip Account Creation"
		return $false
	}
}
Function Get-LogonHeader
{
	param($User, $Password)
	# Create the POST Body for the Logon
    # ----------------------------------
    $logonBody = @{ username=$User;password=$Password } | ConvertTo-Json
	try{
	    # Logon
	    $logonResult = Invoke-RestMethod -Uri $URL_CyberArkLogon -Method Post -ContentType application/json -Body $logonBody
        ##$logonResult = Invoke-Rest -URI $URL_CyberArkLogon -Command Post -Body $logonBody
	    # Save the Logon Result - The Logon Token
	    $logonToken = $logonResult
		Add-LogMsg -Type Debug -MSG "Got logon token: $logonToken"
	}
	catch
	{
		Add-LogMsg -Type Error -MSG $_.Exception.Response.StatusDescription
		$logonToken = ""
	}
    If ([string]::IsNullOrEmpty($logonToken))
    {
        Add-LogMsg -Type Error -MSG "Logon Token is Empty - Cannot login"
        exit
    }

    # Create a Logon Token Header (This will be used through out the whole script)
    # ---------------------------
    $logonHeader =  New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $logonHeader.Add("Authorization", $logonToken)

	return $logonHeader
}


#endregion

# Check if to disable SSL verification
If($DisableSSLVerify)
{
	try{
		#Write-Warning "It is not Recommended to disable SSL verification" -WarningAction Inquire
		# Using Proxy Default credentials if the Sevrer needs Proxy credentials
		[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
		# Using TLS 1.2 as security protocol verification
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
		# Disable SSL Verification
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $DisableSSLVerify }
	} catch {
		Add-LogMsg -Type Error -MSG "Could not change SSL validation"
		Add-LogMsg -Type Error -MSG $_.Exception
		exit
	}
}

Function Add-Owner
{
	param ($safeName, $restBody)
	$urlOwnerAdd = $URL_SafeMembers -f $safeName
	# Add the Safe Owner
    Invoke-Rest -Uri $urlOwnerAdd -Header $g_LogonHeader -Command "Post" -Body $restBody
}

If ((Test-CommandExists Invoke-RestMethod) -eq $false)
{
   Add-LogMsg -Type Error -MSG  "This script requires Powershell version 3 or above"
   exit
}

# Check that the PVWA URL is OK
If (![string]::IsNullOrEmpty($PVWAURL))
{
	If ($PVWAURL.Substring($PVWAURL.Length-1) -eq "/")
	{
		$PVWAURL = $PVWAURL.Substring(0,$PVWAURL.Length-1)
	}

	try{
		# Validate PVWA URL is OK
		Add-LogMsg -Type Debug -MSG  "Trying to validate URL: $PVWAURL"
		Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $PVWAURL -Method 'Head' -TimeoutSec 30 | Out-Null
	} catch [System.Net.WebException] {
		If(![string]::IsNullOrEmpty($_.Exception.Response.StatusCode.Value__))
		{
			Add-LogMsg -Type Error -MSG $_.Exception.Response.StatusCode.Value__
		}
	}
	catch {
		Add-LogMsg -Type Error -MSG "PVWA URL could not be validated"
		Add-LogMsg -Type Error -MSG $_.Exception
	}
}
else
{
	Add-LogMsg -Type Error -MSG "PVWA URL can not be empty"
	exit
}


#region [Logon]
	# Get Credentials to Login
	# ------------------------
	$caption = "POC Safe Creation Utility"
	$msg = "Enter your User name and Password";
	$creds = $Host.UI.PromptForCredential($caption,$msg,"","")
	if ($null -ne $creds)
	{
		$UserName = $creds.username.Replace('\','');
		$UserPassword = $creds.GetNetworkCredential().password
	}
	else {
		Add-LogMsg -Type Error -MSG "No Credentials were entered" -Footer
		exit
    }
	$g_LogonHeader = $(Get-LogonHeader -User $UserName -Password $UserPassword)
#endregion



If([string]::IsNullOrEmpty($CsvPath))
	{
		$CsvPath = Open-FileDialog($g_CsvDefaultPath)
	}
	$safesCSV = Import-CSV $csvPath

	ForEach ($row in $safesCSV)
	{
        # Create some internal variables
		$safeExists = $false
		$safeCreated = $false
		$safeDesc = ""

		if ([string]::IsNullOrEmpty($row.safedescription))
		{
			$safeDesc = "Created via API"
		}
        else{
        $safeDesc = $row.safedescription
        }

        #Check to see if the safe already exists
        $safeExists = $(Test-Safe -safeName $row.safename)

        #Add Safe
		If ($safeExists -eq $false)
		{
			try{
               $safeCreated = New-Safe -safeName $row.safename -cpmName $row.cpmname -safeDescription $safeDesc
               
			}
			catch{
                Add-LogMsg -Type Debug -MSG "There was an error creating Safe $($row.safename)"
			}
		}

        #Add Safe members
        if ($safeCreated -eq $true)
        {
            $restSafeAdmin = @{member =
                @{MemberName = $row.safeowner
                  SearchIn = $SearchInValue
                  MembershipExpirationDate = ""
                  Permissions = @(
                                   @{Key = "UseAccounts"
                  Value = $true},
                  @{Key = "RetrieveAccounts"
                  Value = $true},
                  @{Key = "ListAccounts"
                  Value = $true},
                  @{Key = "AddAccounts"
                  Value = $true},
                  @{Key = "UpdateAccountContent"
                  Value = $true},
                  @{Key = "UpdateAccountProperties"
                  Value = $true},
                  @{Key = "InitiateCPMAccountManagementOperations"
                  Value = $true},
                  @{Key = "SpecifyNextAccountContent"
                  Value = $true},
                  @{Key = "RenameAccounts"
                  Value = $true},
                  @{Key = "DeleteAccounts"
                  Value = $true},
                  @{Key = "UnlockAccounts"
                  Value = $true},
                  @{Key = "ManageSafe"
                  Value = $true},
                  @{Key = "ManageSafeMembers"
                  Value = $true},
                  @{Key = "BackupSafe"
                  Value = $true},
                  @{Key = "ViewAuditLog"
                  Value = $true},
                  @{Key = "ViewSafeMembers"
                  Value = $true},
                  @{Key = "RequestsAuthorizationLevel"
                  Value = 1},
                  @{Key = "AccessWithoutConfirmation"
                  Value = $true},
                  @{Key = "CreateFolders"
                  Value = $true},
                  @{Key = "DeleteFolders"
                  Value = $true},
                  @{Key = "MoveAccountsAndFolders"
                  Value = $true}
                  )
                }
                } | ConvertTo-Json -Depth 3
                try{
                    Add-Owner -safeName $row.safename -restBody $restSafeAdmin
                }
                catch{
                    Add-LogMsg -Type Error -MSG "Failed to add Owner " + $row.safeowner + "to safe " + $safeName + " with error:" + $_.Exception.Response.StatusDescription
                }

            $restSafeUser = @{member =
                @{MemberName = $row.safeuser
                  SearchIn = $SearchInValue
                  MembershipExpirationDate = ""
                  Permissions = @(
                  @{Key = "UseAccounts"
                  Value = $true},
                  @{Key = "RetrieveAccounts"
                  Value = $true},
                  @{Key = "ListAccounts"
                  Value = $true},
                  @{Key = "AddAccounts"
                  Value = $false},
                  @{Key = "UpdateAccountContent"
                  Value = $false},
                  @{Key = "UpdateAccountProperties"
                  Value = $false},
                  @{Key = "InitiateCPMAccountManagementOperations"
                  Value = $false},
                  @{Key = "SpecifyNextAccountContent"
                  Value = $false},
                  @{Key = "RenameAccounts"
                  Value = $false},
                  @{Key = "DeleteAccounts"
                  Value = $false},
                  @{Key = "UnlockAccounts"
                  Value = $false},
                  @{Key = "ManageSafe"
                  Value = $false},
                  @{Key = "ManageSafeMembers"
                  Value = $false},
                  @{Key = "BackupSafe"
                  Value = $false},
                  @{Key = "ViewAuditLog"
                  Value = $true},
                  @{Key = "ViewSafeMembers"
                  Value = $true},
                  @{Key = "RequestsAuthorizationLevel"
                  Value = 1},
                  @{Key = "AccessWithoutConfirmation"
                  Value = $false},
                  @{Key = "CreateFolders"
                  Value = $false},
                  @{Key = "DeleteFolders"
                  Value = $false},
                  @{Key = "MoveAccountsAndFolders"
                  Value = $false}
                  )
                }
                } | ConvertTo-Json -Depth 3
                try{
                    Add-Owner -safeName $row.safename -restBody $restSafeUser
                }
                catch{
                    Add-LogMsg -Type Error -MSG "Failed to add Owner " + $row.safeowner + "to safe " + $safeName + " with error:" + $_.Exception.Response.StatusDescription
                }
        }
    }
#region [Logoff]
	# Logoff the session
    # ------------------
    Invoke-Rest -Uri $URL_CyberArkLogoff -Header $g_LogonHeader -Command "Post"
	# Footer
#endregion