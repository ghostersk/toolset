# Lists all app packages on system {-AllUsers > will return all apps, even not logged users}
#Get-AppxPackage -AllUsers | Select Name, PackageFullName

# Removes the app from Windows
#Get-AppxPackage Microsoft.XboxApp | Remove-AppxPackage

# Lists all app packages on system, and stores the result in csv file
#Get-AppxPackage -AllUsers | Select Name, PackageFullName | export-csv -Path c:\apps.csv -NoTypeInformation

$unwanted = [
    "Microsoft.GetHelp", 
    "Microsoft.Getstarted", 
    "Microsoft.MicrosoftOfficeHub", 
    "Microsoft.MicrosoftSolitaireCollection", 
    "Microsoft.MicrosoftStickyNotes", 
    "Microsoft.MixedReality.Portal", 
    "Microsoft.Office.OneNote", 
    "Microsoft.People", 
    "Microsoft.Wallet", 
    "Microsoft.WindowsAlarms", 
    "Microsoft.WindowsFeedbackHub", 
    "Microsoft.WindowsMaps", 
    "Microsoft.Xbox.TCUI", 
    "Microsoft.XboxApp", 
    "Microsoft.XboxGameOverlay", 
    "Microsoft.XboxApp", 
    "Microsoft.XboxIdentityProvider", 
    "Microsoft.XboxSpeechToTextOverlay", 
    "Microsoft.YourPhone", 
    "Microsoft.ZuneMusic", 
    "Microsoft.ZuneVideo", 
    "Microsoft.BingWeather", 
    "Microsoft.Microsoft3DViewer"
    ]

# Creates Function for clean up
function CleanUp {
	Get-AppxPackage | Select Name | ForEach-Object {
		$AppName = $_.Name # Creates variable from Object <Name>
		if($unwanted -contains $AppName) {		
			Write-Host Removing: $AppName
			Get-AppxPackage $AppName -AllUsers | Remove-AppxPackage -AllUsers
		}
		elseif($AppName -contains "Microsoft.549981C3F5F10") {
			Write-Host Removing: Cortana
			Get-AppxPackage $AppName -AllUsers | Remove-AppxPackage -AllUsers
		}
	}
	Write-Host "**** All useless apps been deleted :) ****"
	Write-Host "**** Window will close now ****"

# Waits 5 seconds
	Start-Sleep -s 5

# Exits the Powershell
	stop-process -Id $PID
}
# Runs the Function Clean up
CleanUp 

