# CyberArk-Create-POC-Safes

This will load safes needed for POC. You can assign either named users or groups for admins and users. Currently only one from each group can be added. 

## Requirements

1. CyberArk PAS v10.1 or later
2. Credentials for a vault administrator that can create safes

## Before Using

1. Only put the base URL for your PVWA for the PVWA Parameter
2. The SearchInValue should be the friendly name of your AD that was set during setup. If you are searching for CyberArk groups, you would enter              "CyberArk" here
3. Use the safes-template.csv file from this repository as a template

## How To Use

1. Download the ps1 file and place it on a machine that has access to the pvwa URL
2. Start the script using ./create-poc-safes.ps1 -PVWAURL https://myPVWA.yourCompany.com -SearchInValue ActiveDirectory -CsvPath PathToYourCSV
