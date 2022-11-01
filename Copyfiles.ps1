

<#This script is to Unicopy the files from Old version/Previous PC/Laptop to new PC/Laptop
To Perform this task both the machine should be connected to VPN/Should be in the same network.
Please keep ready with Hostname,IP address and the user which you want to copy.
To get hostname - open comand prompt - type hostname - enter - copy the computer name
The script creates a log file in the format of year-month-date-hours-minute(for reference)

Author -  slingappa - 1/17/2019

#>


Function Check-Credential {
    <#
    .SYNOPSIS
        Takes a PSCredential object and validates it against the domain (or local machine, or ADAM instance).

    .PARAMETER cred
        A PScredential object with the username/password you wish to test. Typically this is generated using the Get-Credential cmdlet. Accepts pipeline input.

    .PARAMETER context
        An optional parameter specifying what type of credential this is. Possible values are 'Domain','Machine',and 'ApplicationDirectory.' The default is 'Domain.'

    .OUTPUTS
        A boolean, indicating whether the credentials were successfully validated.

    #>
    param(
        [parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [System.Management.Automation.PSCredential]$credential,
        [parameter()][validateset('Domain','Machine','ApplicationDirectory')]
        [string]$context = 'Domain'
    )
    begin {
        Add-Type -assemblyname system.DirectoryServices.accountmanagement
        $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::$context) 
    }
    process {
        $DS.ValidateCredentials($credential.UserName, $credential.GetNetworkCredential().password)
    }
}
Function Test-Ping {
    [cmdletbinding()]
 
    Param(
    [Parameter(Position=0,Mandatory,HelpMessage = "Enter a computername",ValueFromPipeline)]
    [ValidateNotNullorEmpty()]
    [string]$Computername
    )
 
    Begin {
        Write-Verbose -Message "Starting $($MyInvocation.Mycommand)"  
         } #begin
 
    Process {
      Write-Verbose -Message "Testing $computername"
      Try {
        $r = Test-Connection $Computername  -ErrorAction Stop
        $True 
      }
      Catch {
        Write-Verbose $_.Exception.Message
        $False
 
      }
 
    } #Process
 
    End {
        Write-Verbose -Message "Ending $($MyInvocation.Mycommand)"
        } #end
 
}
function Put_it_back {
     
     #$LocalUser = Check-Credential
     #if($LocalUser -eq "true"){

    robocopy "\\$Computername\c$\users\$Username\desktop" "%userprofile%\desktop" /Move  /E
    #if(!(Test-Path "%userprofile%\desktop\DesktopOK_x64.exe")) {write-host "No file found "}else{DEL /F "%userprofile%\desktop\DesktopOK_x64.exe"}

    robocopy "\\$Computername\c$\Users\$Username\Documents" "%userprofile%\documents" /Move /E
    robocopy "\\$Computername\c$\Users\$Username\Downloads" "%userprofile%\downloads" /Move  /E
    robocopy "\\$Computername\c$\Users\$Username\Music" "%userprofile%\Music" /Move /E
    robocopy "\\$Computername\c$\Users\$Username\Pictures" "%userprofile%\Pictures" /Move  /E
    robocopy "\\$Computername\c$\Users\$Username\Videos" "%userprofile%\Videos" /Move  /E
    robocopy "\\$Computername\c$\Users\$Username\Pictures" "%userprofile%\OneDrive" /Move  /E
    robocopy "\\$Computername\c$\Users\$Username\Videos" "%userprofile%\Searches" /Move /E

    robocopy "\\$Computername\c$\Users\$Username\Favorites" "%userprofile%\favorites" /E
    robocopy "\\$Computername\c$\Users\$Username\Links" "%userprofile%\Links" /E
    #userpinned
    #robocopy "\\$Computername\c$\Users\$Username\userpinned" "%userprofile%\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar" /E
    robocopy "\\$Computername\c$\Users\$Username\AppData\Roaming\Microsoft\Windows\Recent" "%userprofile%\AppData\Roaming\Microsoft\windows\Recent" /E
    robocopy "\\$Computername\c$\Users\$Username\\\$Computername\c$\Users\$Username\AppData\Roaming\Microsoft\Windows\recent\AutomaticDestinations" "%userprofile%\AppData\Roaming\Microsoft\windows\Recent\AutomaticDestinations" /E

   if ( !(test-path "%userprofile%\AppData\Roaming\Microsoft\Signatures") -eq "true"){mkdir "%userprofile%\AppData\Roaming\Microsoft\Signatures"}
    robocopy "\\$Computername\c$\Users\$Username\AppData\Roaming\Microsoft\Signatures" "%userprofile%\AppData\Roaming\Microsoft\Signatures" /E

    if ( !(test-path "%userprofile%\AppData\Local\Microsoft\OneNote")){ mkdir "%userprofile%\AppData\Local\Microsoft\OneNote"}
    if( !(test-path 'OneNote') ) {robocopy "OneNote" "%userprofile%\AppData\Roaming\Microsoft\OneNote" /E}

    if ( !(test-path  "%userprofile%\AppData\Local\Microsoft\Excel") -eq "true"){mkdir "%userprofile%\AppData\Local\Microsoft\Excel"}
    robocopy "\\$Computername\c$\Users\$Username\AppData\Roaming\Microsoft\Excel" "%userprofile%\AppData\Roaming\Microsoft\Excel" /E

    if(!(test-path "%userprofile%\AppData\Local\Microsoft\Templates") -eq "true"){mkdir "%userprofile%\AppData\Local\Microsoft\Templates"}
    robocopy "\\$Computername\c$\Users\$Username\AppData\Roaming\Microsoft\Templates" "%userprofile%\AppData\Roaming\Microsoft\Templates" /E

    if(!(test-path  "%userprofile%\AppData\Local\Microsoft\Word") -eq "true"){mkdir "%userprofile%\AppData\Local\Microsoft\Word"}
    robocopy "\\$Computername\c$\Users\$Username\AppData\Roaming\Microsoft\Word" "%userprofile%\AppData\Roaming\Microsoft\Word" /E

    if(!(test-path "\\$Computername\c$\Users\$Username\AppData\Roaming\Microsoft\Sticky Notes")){write-host "folder already exist"} else{ mkdir "%userprofile%\AppData\Roaming\Microsoft\Sticky Notes"}
    if ((test-path  "\\$Computername\c$\Users\$Username\AppData\Roaming\Microsoft\Sticky Notes") -eq "true" ){mkdir "%LocalAppData%\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\Legacy"}
    #Copy-Item -path "\\$Computername\c$\Users\$Username\AppData\Roaming\Microsoft\Sticky Notes\StickyNotes.snt" -destination "%userprofile%\AppData\Roaming\Microsoft\Sticky Notes\ThresholdNotes.snt"
    if ((test-path "\\$Computername\c$\Users\$Username\AppData\Roaming\Microsoft\Sticky Notes")-eq "true") {robocopy "\\$Computername\c$\Users\$Username\AppData\Roaming\Microsoft\Sticky Notes" "%userprofile%\AppData\Roaming\Microsoft\Sticky Notes" /E}
    if ((test-path "\\$Computername\c$\Users\$Username\AppData\Roaming\Microsoft\Sticky Notes")-eq "true") {robocopy "\\$Computername\c$\Users\$Username\AppData\Roaming\Microsoft\Sticky Notes""%LocalAppData%\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\Legacy"}

    if(!(test-path "%userprofile%\AppData\Local\VirtualStore\Program Files (x86)\DataTreeClient") -eq "true"){mkdir "%userprofile%\AppData\Local\VirtualStore\Program Files (x86)\DataTreeClient"}
    #robocopy "%CD%" "%userprofile%\AppData\Local\VirtualStore\Program Files (x86)\DataTreeClient" "dtclient.ini"
    #robocopy "dtclient-VirtualStore" "%userprofile%\AppData\Local\VirtualStore\Program Files (x86)\DataTreeClient" "dtclient.ini"

    if(!(test-path "%userprofile%\AppData\Roaming\DTS2\") -eq "true"){mkdir "%userprofile%\AppData\Roaming\DTS2\"}
    robocopy "%CD%" "%userprofile%\AppData\Roaming\DTS2" "Dts2LoginUser.Config"
    if ((test-path "\\$Computername\c$\Users\$Username\AppData\Roaming\DTS3_uat") -eq "true") {mkdir "%userprofile%\AppData\Roaming\DTS3_uat\"}
    if ((test-path "\\$Computername\c$\Users\$Username\AppData\Roaming\DTS3_uat")-eq "true"){ robocopy "DTS3_uat" "%userprofile%\AppData\Roaming\DTS3_uat" "Dts2LoginUser.Config"}
    if ((test-path  "\\$Computername\c$\Users\$Username\AppData\Roaming\DTS2_staging")-eq "true"){ mkdir "%userprofile%\AppData\Roaming\DTS2_staging\"}
    if ((test-path "\\$Computername\c$\Users\$Username\AppData\Roaming\DTS2_staging")-eq "true"){ robocopy "\\$Computername\c$\Users\$Username\AppData\Roaming\DTS2_staging" "%userprofile%\AppData\Roaming\DTS2_staging" "Dts2LoginUser_dtsstage.Config"}
    if(!(test-path "%userprofile%\AppData\Local\Google\Chrome\User Data\Default")){
    mkdir "%userprofile%\AppData\Local\Google\Chrome\User Data\Default"}
    robocopy "\\$Computername\c$\Users\$Username\AppData\Local\Google\Chrome" "%userprofile%\AppData\Local\Google\Chrome\User Data\Default"
    if(!(test-path \\$Computername\c$\temp\SimplyScanning)){
    mkdir \\$Computername\c$\temp\SimplyScanning}
    robocopy "\\$Computername\c$\temp\SimplyScanning" "\\$Computername\c$\temp\SimplyScanning" /E

    if ((test-path  "\\$Computername\c$\Users\$Username\AppData\Roaming\filezilla")-eq "true"){ mkdir "%userprofile%\AppData\Roaming\filezilla\"}
    if ((test-path  "\\$Computername\c$\Users\$Username\AppData\Roaming\filezilla" )-eq "true"){robocopy "filezilla" "%userprofile%\AppData\Roaming\filezilla" /E}

    if ((test-path  "\\$Computername\c$\Users\$Username\AppData\Roaming\alamode")-eq "true"){ mkdir "%userprofile%\AppData\Local\alamode"}
    if ((test-path  "\\$Computername\c$\Users\$Username\AppData\Roaming\alamode")-eq "true"){ robocopy "alamode" "%userprofile%\AppData\Local\alamode" /E }
    }
Function Admin {
    
        #$check =  Check-Credential 

        #if ($check -eq "true"){

            if(!(test-path C:\Scans)){
                del C:\Scans
                New-Item -ItemType Directory -path C:\Scans}
            net share scans /delete /y | out-null
            net share scans=c:\Scans
            $Acl1 = Get-Acl "c:\scans"
           
            $Ar1 = New-Object  system.security.accesscontrol.filesystemaccessrule("corp\tine-sa-copier","FullControl","Allow")
            $Ar2 = New-Object  system.security.accesscontrol.filesystemaccessrule("corp\NPRD-SA-SCAN2FOLDER","FullControl","Allow")
            $Ar3 = New-Object  system.security.accesscontrol.filesystemaccessrule("corp\FAHQ-AG-DesktopLocalAdmin-A","FullControl","Allow")
            #$Ar4 = New-Object  system.security.accesscontrol.filesystemaccessrule("corp\FAHQ-AG-DT_Desktop Admins","FullControl","Allow")
            $Acl1.SetAccessRule($Ar1)
            $Acl1.SetAccessRule($Ar2)
            $Acl1.SetAccessRule($Ar3)
            #$Acl1.SetAccessRule($Ar4)
            Set-Acl "c:\scans" $Acl1
             Copy-Item -Path C:\Scripts\Unicopy-2pc\utils\subinacl.exe -Destination C:\Scans\
           #$Acl2 = Get-Acl "C:\scans\subinacl.exe"
            #$Ar1 = New-Object  system.security.accesscontrol.filesystemaccessrule("corp\tine-sa-copier","FullControl","Allow")
            #$Ar2 = New-Object  system.security.accesscontrol.filesystemaccessrule("corp\NPRD-SA-SCAN2FOLDER","FullControl","Allow")
            #$Ar3 = New-Object  system.security.accesscontrol.filesystemaccessrule("corp\FAHQ-AG-DesktopLocalAdmin-A","FullControl","Allow")
            #$Ar4 = New-Object  system.security.accesscontrol.filesystemaccessrule("corp\FAHQ-AG-DT_Desktop Admins","FullControl","Allow")
            #$Acl2.SetAccessRule($Ar1)
            #$Acl2.SetAccessRule($Ar2)
            #$Acl2.SetAccessRule($Ar3)
            #$Acl2.SetAccessRule($Ar4)
            #Set-Acl "C:\scans\subinacl.exe" $Acl2
            #-can be done in ps -  c:\scripts\Unicopy-2pc\utils\subinacl.exe /share \\%computername%\scans /revoke=Everyone
            cd C:\Scripts\Unicopy-2pc\utils
            if((Test-Path "DTS3_uat" )-eq "true"){ xcopy /E "C:\Program Files (x86)\Data Trace\DTS2" "C:\Program Files (x86)\Data Trace\DTS3-UAT\"}
            if((Test-Path "DTS2_staging" )-eq "true"){xcopy /E "C:\Program Files (x86)\Data Trace\DTS2" "C:\Program Files (x86)\Data Trace\DTS3-Staging\"}
            if((Test-Path "DTS3_uat" )-eq "true") {robocopy "utils\DTS3_uat" "C:\Program Files (x86)\Data Trace\DTS3-UAT" "Atlas.exe.config"}
            if((Test-Path "DTS3_uat" )-eq "true"){robocopy "utils\DTS3_uat" "C:\Program Files (x86)\Data Trace\DTS3-UAT" "Updater.config"}
            if((Test-Path "DTS2_staging" )-eq "true"){ robocopy "utils\DTS2_staging" "C:\Program Files (x86)\Data Trace\DTS3-Staging" "Atlas.exe.config"}
            if((Test-Path "DTS2_staging" )-eq "true"){ robocopy "utils\DTS2_staging" "C:\Program Files (x86)\Data Trace\DTS3-Staging" "Updater.config"}
   

    }
Function Test-Administrator  
{  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

$Auth = Check-Credential #checking credential
if ($Auth -eq 'True'){
    $ComputerName = Read-Host "enter PC Name or VPN IP address Old PC/laptop to be backed up"
    $Date = get-date -Format "yyyyMMdd-hhmm-$Computername"
    
    Start-Transcript -Path $PSScriptRoot\$Date-logs.csv -IncludeInvocationHeader

    #Checks if the Computer is connected to VPN
    $Ping = Test-Ping $ComputerName
    #psexec.exe \\$ComputerName -s powershell Enable-PSRemoting -Force
    if ($Ping -eq "true"){
        $UserName = Read-Host "Please enter the Username which you want to take the backup"
        $CheckPath = Test-Path "\\$ComputerName\c$\Users\$UserName"
        $Date = Get-Date -Format  "ddMMyyy"

        if ($CheckPath -eq 'true'){
           
            if(!(Test-Path -Path c:\Temp\$date-$UserName-bkup )){

                 New-Item -ItemType directory -Path c:\Temp\$date-$UserName-bkup

                 }
        robocopy "$PSScriptRoot\utils" c:\Temp\$date-$UserName-bkup
        $CIPCSEP1 = Invoke-Command -ComputerName $Computername -ScriptBlock{(Get-ItemProperty "HKCU:\Software\Cisco Systems, Inc.\Communicator\Device\device.deregistration.alarm.info.0" -Name VAL4).val4}
        $CIPCSEP2 = Invoke-Command -ComputerName $Computername -ScriptBlock{(Get-ItemProperty "HKCU:\Software\Cisco Systems, Inc.\Communicator\Device\device.deregistration.alarm.info.0" -Name VAL29).val29}
        $Logs =  new-object -TypeName psobject -Property @{
                       PC = $ComputerName
                       Username = $UserName
                       Home_altIP= $IPadress
                       CIPCSEP1 = $CIPCSEP1
                       CIPCSEP2 = $CIPCSEP2
            
            }
            
             if(!(test-path c:\Temp\$date-$UserName-bkup\logs)){
                New-Item -ItemType Directory -Path c:\Temp\$date-$UserName-bkup\logs
                }
          $Logs | Export-Csv  c:\Temp\$date-$UserName-bkup\logs\$ComputerName-logs.csv -NoTypeInformation
            
          #$DataTree = Invoke-Command -ComputerName $computername -ScriptBlock{(Get-ItemProperty "HKCU:\Software\DataTree\Client\Settings")}
           

         $TestConnection = Read-host "Check if both the PC are in VPN Now ? y or n"
         ipconfig /all | findstr "IPv4"
         $IPadress = Read-Host "what is the IP address of  old PC (VPN Local Home IP 192.168...)" 
            if ($TestConnection -eq 'y' -or $TestConnection -eq 'Y'){
         $Value = Read-host "Do you want to backup printer and WIFI ?? y or n"
         if ($Value -eq 'y'){
             cd c:\Temp\$date-$UserName-bkup
             netsh wlan export profile key=clear folder="c:\Temp\$date-$UserName-bkup"
             write-host "Backing up printers"
             Copy-Item -Path \\$Computername\C$\Windows\System32\spool\tools\Printbrm.exe -Destination C:\Temp\$date-$UserName-bkup\pntr-$date.printerExport}
          elseif($TestConnection -eq 'n' -or $TestConnection -eq 'N'){
             
              Write-Host "Please make sure that both the PCs be in VPN"
             
                 }

          else{
             
               Write-Host "Please enter the right alphabet y or n"

                 }
           #ipconfig /all | out-file C:\Temp\$date-$UserName-bkup\ipconfig-all.txt
          Copy-Item -Path $PSScriptRoot\utils\DesktopOK_x64.exe -Destination C:\users\$username\Desktop 
         # robocopy C:\Scripts\Unicopy-2pc\utils \C:\Temp /E


          net use w: /delete /y
          net use W: "\\$ComputerName\C$"
                    

          if(!(test-path "w:\Users\$Username\AppData\Roaming\DTS2" )){write-host '"w:\Users\$Username\AppData\Roaming\DTS2" was not found'}else{robocopy "w:\Users\$Username\AppData\Roaming\DTS2" "C:\Temp\$Date-$Username-bkup" "*.Config" } 

          if(!(test-path "w:\Users\$Username\AppData\Roaming\DTS3_uat" )){write-host '"w:\Users\$Username\AppData\Roaming\DTS3_uat" the path was not found'}else{robocopy "w:\Users\$Username\AppData\Roaming\DTS3_uat" "C:\Temp\$date-$Username-bkup\DTS3_uat" "*.Config"} 
          if(!(test-path "w:\Users\$Username\AppData\Roaming\DTS2_staging" )){write-host ' "w:\Users\$Username\AppData\Roaming\DTS2_staging" the path was not found'}else{robocopy  "w:\Users\$Username\AppData\Roaming\DTS2_staging" "C:\Temp\$date-$Username-bkup\DTS2_staging" "*.Config"}
          if(!(test-path "w:\Program Files (x86)\Data Trace\DTS2")){write-host '"w:\Program Files (x86)\Data Trace\DTS2" the path was not found'}else{robocopy "w:\Program Files (x86)\Data Trace\DTS2" "c:\Temp\$date-$Username-bkup" "*.config" }
          if(!(test-path "w:\Program Files (x86)\Data Trace" )){write-host '"w:\Program Files (x86)\Data Trace" the path was not found'}else{robocopy "w:\Program Files (x86)\Data Trace" "c:\Temp\$date-$Username-bkup" "*.config"}
          if(!(test-path "w:\Program Files (x86)\Data Trace\DTS3-UAT")){write-host '"w:\Program Files (x86)\Data Trace\DTS3-UAT" the path was not found'}else{robocopy "w:\Program Files (x86)\Data Trace\DTS3-UAT" "c:\Temp\$date-$Username-bkup\DTS3_uat" "*.config"}
          if(!(test-path "w:\Program Files (x86)\Data Trace\DTS3-Staging")){write-host '"w:\Program Files (x86)\Data Trace\DTS3-Staging" the path was not found'}else{robocopy "w:\Program Files (x86)\Data Trace\DTS3-Staging" "c:\Temp\$date-$Username-bkup\DTS2_staging" "*.config" }

          if(!(test-path "w:\Program Files (x86)\LandexRemote")){write-host '"w:\Program Files (x86)\LandexRemote"  the path was not found'}else{robocopy "w:\Program Files (x86)\LandexRemote" "c:\Temp\$date-$Username-bkup" "LANDEXRemote.cfg"}

          if(!(test-path "w:\Program Files (x86)\DataTreeClient" )){write-host '"w:\Program Files (x86)\DataTreeClient" the path was not found'}else{robocopy "w:\Program Files (x86)\DataTreeClient" "c:\Temp\$date-$Username-bkup" "dtclient.ini"  }
          if(!(test-path "w:\Program Files (x86)\PhraseExpress")){write-host '"w:\Program Files (x86)\PhraseExpress" the path was not found'}else{robocopy "w:\Program Files (x86)\PhraseExpress" "c:\Temp\$date-$Username-bkup" "MyPhrases.*"}
          if(!(test-path "w:\Program Files (x86)\ImageAny")){write-host '"w:\Program Files (x86)\ImageAny" the path was not found'}else{robocopy "w:\Program Files (x86)\ImageAny" "c:\Temp\$date-$Username-bkup" "*.ini"}
          if(!(test-path "w:\Users\$Username\AppData\Local\VirtualStore\Program Files (x86)\DataTreeClient")){write-host '"w:\Users\$Username\AppData\Local\VirtualStore\Program Files (x86)\DataTreeClient" the path was not found'}else{robocopy "w:\Users\$Username\AppData\Local\VirtualStore\Program Files (x86)\DataTreeClient" "c:\Temp\$date-$Username-bkup\dtclient-VirtualStore" "dtclient.ini"}
          if(!(test-path "w:\WIN2DATA")){write-host '"w:\WIN2DATA" the path was not found'}else{robocopy "w:\WIN2DATA" "c:\Temp\$date-$Username-bkup" "ONLINE.CFG"}
          if(!(test-path "w:\Users\$Username\AppData\Local\Google\Chrome\User Data\Default")){write-host '"w:\Users\$Username\AppData\Local\Google\Chrome\User Data\Default" the path was not found'}else{robocopy "w:\Users\$Username\AppData\Local\Google\Chrome\User Data\Default" "c:\Temp\$date-$Username-bkup\chrome" "Bookmarks.bak"}
          if(!(test-path "w:\Users\$Username\AppData\Local\Google\Chrome\User Data\Default")){write-host '"w:\Users\$Username\AppData\Local\Google\Chrome\User Data\Default" the path was not found'}else{robocopy "w:\Users\$Username\AppData\Local\Google\Chrome\User Data\Default" "c:\Temp\$date-$Username-bkup\chrome" "Bookmarks"}

          #Win10 doesnt use quick launch 
          #if(!(test-path "w:\Users\$Username\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar" )){write-host '"w:\Users\$Username\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar" the path was not found'}else{robocopy "w:\Users\$Username\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"  "c:\Temp\$date-$Username-bkup\userpinned" }

          if(!(test-path "w:\Users\$Username\AppData\Local\Microsoft\OneNote")){write-host '"w:\Users\$Username\AppData\Local\Microsoft\OneNote" the path was not found'}else{robocopy "w:\Users\$Username\AppData\Local\Microsoft\OneNote" "c:\Temp\$date-$Username-bkup\OneNote" }
          if(!(test-path "w:\Users\$Username\AppData\Roaming\filezilla")){write-host '"w:\Users\$Username\AppData\Roaming\filezilla" the path was not found'}else{robocopy "w:\Users\$Username\AppData\Roaming\filezilla" "c:\Temp\$date-$Username-bkup\Filezilla" /MIR}
          if(!(test-path "w:\Users\$Username\AppData\Roaming\Microsoft\Sticky Notes")){write-host '"w:\Users\$Username\AppData\Roaming\Microsoft\Sticky Notes" the path was not found'}else{robocopy "w:\Users\$Username\AppData\Roaming\Microsoft\Sticky Notes" "c:\Temp\$date-$Username-bkup\Sticky Notes" }
          if(!(test-path "w:\Users\$Username\AppData\Roaming\Microsoft\Signatures")){write-host '"w:\Users\$Username\AppData\Roaming\Microsoft\Signatures" the path was not found'}else{robocopy "w:\Users\$Username\AppData\Roaming\Microsoft\Signatures" "c:\Temp\$date-$Username-bkup\Signatures" }
          if(!(test-path "w:\Users\$Username\desktop")){write-host '"w:\Users\$Username\desktop" the path was not found'}else{robocopy "w:\Users\$Username\desktop" "c:\Temp\$date-$Username-bkup\Desktop" /E /XD "W:\Users\$Username\Desktop\$RECYCLE.BIN"}
          if(!(test-path "w:\Users\$Username\downloads")){write-host '"w:\Users\$Username\downloads" the path was not found'}else{robocopy "w:\Users\$Username\downloads" "c:\Temp\$date-$Username-bkup\downloads" /MIR}
          if(!(test-path "w:\Users\$Username\favorites")){write-host '"w:\Users\$Username\favorites" the path was not found'}else{robocopy "w:\Users\$Username\favorites" "c:\Temp\$date-$Username-bkup\favorites" /MIR}
          if(!(test-path "w:\Users\$Username\links")){write-host '"w:\Users\$Username\links" the path was not found'}else{robocopy "w:\Users\$Username\links" "c:\Temp\$date-$Username-bkup\links" /MIR}
          if(!(test-path "w:\Users\$Username\OneDrive" )){write-host '"w:\Users\$Username\OneDrive" the path was not found'}else{robocopy "w:\Users\$Username\OneDrive" "c:\Temp\$date-$Username-bkup\OneDrive" /MIR}
          if(!(test-path "w:\Users\$Username\Searches")){write-host '"w:\Users\$Username\Searches" the path was not found'}else{robocopy "w:\Users\$Username\Searches" "c:\Temp\$date-$Username-bkup\Searches" /MIR}
          if(!(test-path "w:\Users\$Username\documents")){write-host '"w:\Users\$Username\documents"  the path was not found'}else{robocopy "w:\Users\$Username\documents" "c:\Temp\$date-$Username-bkup\documents" /E /XD "W:\Users\$Username\documents\My Music" "W:\Users\$Username\documents\My Pictures" "W:\Users\$Username\documents\My Videos"}
          if(!(test-path "w:\Users\$Username\AppData\Roaming\Microsoft\Windows\Recent")){write-host '"w:\Users\$Username\AppData\Roaming\Microsoft\Windows\Recent" the path was not found'}else{robocopy "w:\Users\$Username\AppData\Roaming\Microsoft\Windows\Recent" "c:\Temp\$date-$Username-bkup\recent" }
          if(!(test-path "w:\Temp\SimplyScanning" )){write-host '"w:\Temp\SimplyScanning" the path was not found'}else{robocopy "w:\Temp\SimplyScanning" "c:\Temp\$date-$Username-bkup\SimplyScanning" /MIR}

          if(!(test-path "w:\ProgramData\TechSmith\Snagit 12")){write-host '"w:\ProgramData\TechSmith\Snagit 12" the path was not found'}else{robocopy "w:\ProgramData\TechSmith\Snagit 12" "c:\Temp\$date-$Username-bkup" "*.ini"}
          if(!(test-path "w:\ProgramData\TechSmith\Snagit 11")){write-host '"w:\ProgramData\TechSmith\Snagit 11" the path was not found'}else{robocopy "w:\ProgramData\TechSmith\Snagit 11" "c:\Temp\$date-$Username-bkup" "*.ini"}
          if(!(test-path "w:\ProgramData\TechSmith\Snagit 10" )){write-host '"w:\ProgramData\TechSmith\Snagit 10" the path was not found'}else{robocopy "w:\ProgramData\TechSmith\Snagit 10" "c:\Temp\$date-$Username-bkup" "*.ini"}
          if(!(test-path "w:\Program Files\PhraseExpress")){write-host '"w:\Program Files\PhraseExpress" the path was not found'}else{robocopy "w:\Program Files\PhraseExpress" "c:\Temp\$date-$Username-bkup" "MyPhrases.*"}

          if(!(test-path "w:\PhraseExpress")){write-host '"w:\PhraseExpress" the path was not found'}else{robocopy "w:\PhraseExpress" "c:\Temp\$date-$Username-bkup" "MyPhrases.*"}
          if(!(test-path "w:\Program Files\ImageAny")){write-host '"w:\Program Files\ImageAny" the path was not found'}else{robocopy "w:\Program Files\ImageAny" "c:\Temp\$date-$Username-bkup" "*.ini"}

          if(!(test-path "w:\Users\$Username\AppData\Roaming\Microsoft\Excel" )){write-host '"w:\Users\$Username\AppData\Roaming\Microsoft\Excel" the path was not found'}else{robocopy "w:\Users\$Username\AppData\Roaming\Microsoft\Excel" "c:\Temp\$date-$Username-bkup\Excel" }
          if(!(test-path "w:\Users\$Username\AppData\Roaming\Microsoft\Templates" )){write-host '"w:\Users\$Username\AppData\Roaming\Microsoft\Templates"  the path was not found'}else{robocopy "w:\Users\$Username\AppData\Roaming\Microsoft\Templates" "c:\Temp\$date-$Username-bkup\Templates" }
          if(!(test-path "w:\Users\$Username\AppData\Roaming\Microsoft\Word")){write-host '"w:\Users\$Username\AppData\Roaming\Microsoft\Word" the path was not found'}else{robocopy "w:\Users\$Username\AppData\Roaming\Microsoft\Word" "c:\Temp\$date-$Username-bkup\word" }
          if(!(test-path "w:\Users\Public\Desktop")){write-host '"w:\Users\Public\Desktop" the path was not found'}else{robocopy "w:\Users\Public\Desktop" "c:\Temp\$date-$Username-bkup\Public\Desktop" }
          if(!(test-path "w:\Users\Public\Documents")){write-host '"w:\Users\Public\Documents" the path was not found'}else{robocopy "w:\Users\Public\Documents" "c:\Temp\$date-$Username-bkup\Public\Documents" /E /XD "w:\Users\Public\Documents\My Music" "w:\Users\Public\Documents\My Pictures" "w:\Users\Public\Documents\My Videos" "w:\Users\Public\Documents\KCS Pro"  "w:\Users\Public\Documents\EPSON"}
          if(!(test-path "w:\Program Files\wIntegrate\Session")){write-host '"w:\Program Files\wIntegrate\Session" the path was not found'}else{robocopy "w:\Program Files\wIntegrate\Session" "c:\Temp\$date-$Username-bkup\wIntegrate\Session" }
          if(!(test-path "w:\Program Files (x86)\wIntegrate\Session")){write-host '"w:\Program Files (x86)\wIntegrate\Session" the path was not found'}else{robocopy "w:\Program Files (x86)\wIntegrate\Session" "c:\Temp\$date-$Username-bkup\wIntegrate\Session" }
          if(!(test-path "w:\scans")){write-host '"w:\scans" the path was not found'}else{robocopy "w:\scans" "c:\Temp\$date-$Username-bkup\scans" }
          if(!(test-path "w:\Temp\$date-$Username-bkup")){write-host '"w:\Temp\$date-$Username-bkup" the path was not found'}else{robocopy "w:\Temp\$date-$Username-bkup" "c:\Temp\$date-$Username-bkup" /E}
          if(!(test-path  "w:\DSI")){write-host ' "w:\DSI"  the path was not found'}else{robocopy "w:\DSI" "c:\Temp\$date-$Username-bkup\DSI" }

          #rem Docstar ini
          if(!(test-path "w:\DOCSTAR" )){write-host ' "w:\DOCSTAR" the path was not found'}else{robocopy  "w:\DOCSTAR" "c:\Temp\$date-$Username-bkup" "DOCSTAR.INI"}

          #rem Copying for the folders - ACI Total
          if(!(test-path  "w:\program files(x86)\ACI32")){write-host ' "w:\program files(x86)\ACI32" the path was not found'}else{robocopy  "w:\program files(x86)\ACI32" "c:\Temp\$date-$Username-bkup\ACI32" }
          if(!(test-path "w:\ProgramData\alamode")){write-host '"w:\ProgramData\alamode" the path was not found'}else{robocopy "w:\ProgramData\alamode" "c:\Temp\$date-$Username-bkup\ProgramData\alamode" }
          if(!(test-path "w:\Users\$Username\AppData\Local\alamode")){write-host ' "w:\Users\$Username\AppData\Local\alamode" the path was not found'}else{robocopy  "w:\Users\$Username\AppData\Local\alamode" "c:\Temp\$date-$Username-bkup\alamode" }
}
    #the below commands must be running with -A account
    #Requires -RunAsAdministrator
    
        write-host "Please enter local user account"
        Put_it_back
        write-host "Please enter -A account 'username-a' "
        admin
       #if(!(test-path "C:\Temp\logs")){
       # New-Item  -ItemType Directory -path "C:\Temp\logs"}
        $NetworkDrive = Get-WmiObject -ComputerName "$ComputerName" -Class Win32_MappedLogicalDisk | select Name, ProviderName,Size #| Export-Csv C:\Temp\logs\$date-$UserName-network.csv -NoTypeInformation
        write-host " network drive  - $NetworkDrive"
        Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
        echo  updating policy 
        gpupdate /force   
        
        
        }
    
    
    
    
     else{
        write-host " Please enter the username which needs to backed up "
        Invoke-Item -Path \\$ComputerName\c$\Users

        }
   

  }
    else{

        Write-host "Please enter the correct VPN IP address Old PC/laptop to be backed up "
    
    
    }




}

else{
  
    Write-host "Please enter the correct credential!!"
  
  
  }


Stop-Transcript
#New-PSDrive -Name S -PSProvider FileSystem -Root \\corp.firstam.com\vdi\Reports\Unicopy
Copy-Item -Path $PSScriptRoot\$Date-logs.csv -Destination "your network path file"
