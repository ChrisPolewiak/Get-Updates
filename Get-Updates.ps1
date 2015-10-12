<#

.SYNOPSIS
Get-WaitingUpdates.ps1 - Report Windows Update status from several computers

.DESCRIPTION
Check status of Windows Update on computers and send report HTML.
Search for computers by Active Directory LDAP query.

.PARAMETER verbose
Show Debug messages

.PARAMETER Filter
Active Directory LDAP Filter String

.PARAMETER SearchBase
Active Directory OU Container

.PARAMETER Limit
Limit items from LDAP Query (default no limit)

.PARAMETER ShowNoticeDayLimit
Limit days to show notice in report. Updates older than amount of days from this parameter will be marked RED
Default value 14 days

.PAREMETER SMTPConfigFile
Path to XML file with SMTP Config Values
Using this path will send report by Mail

.PAREMETER ReportFile
Path to file for final report
Default: ./updates-report.html

.PAREMETER LogFile
LogFilename (deault .\Get-Update-log.txt)

.EXAMPLE 
Get-WaitingUpdates.ps1 -verbose -SearchBase "DC=domain,DC=local" -Filter "*" -LogFile ".\log.txt"


.NOTES
Written By: Chris Polewiak
Website:	http://blog.polewiak.pl

Change Log
V1.00, 03/03/2014 - Initial version
V1.01, 20/03/2015 - Add parameters, clean code
V1.02, 19/06/2015 - Small fixes

#>
#----------------------------------------------------------------------------------------------------------------
# Input parameters
#--------------------------------------------------------------------------------------------------------------
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]
    $Filter,

    [string]
    $SearchBase,

    [Int]
    $Limit=1000000,

    [Int]
    $ShowNoticeDayLimit=14,

    [String]
    [ValidateScript({if (Test-Path $_) { $True } else { Throw "`n'$_' not valid path" }})]
    $SMTPConfigFile,
    
    [String]
    $ReportFile,

    [string]
    $LogFile = "$(split-path $SCRIPT:MyInvocation.MyCommand.Path)\Get-Update-log.txt"
)
#---------------------------------------------------------------------------------------------------------------

#----------------------------------------------------------------------------------------------------------------
#
# Main Process
#
#--------------------------------------------------------------------------------------------------------------
Process
{
    if($ReportFile -eq "")
    {
        $ReportFile = "$(split-path $SCRIPT:MyInvocation.MyCommand.Path)\Updates-Report.html"
    }

    $ReportHTML = @()
    $HostName   = $($env:COMPUTERNAME)
    $HostDomain = $($env:USERDNSDOMAIN)
    $HostFQDN   = $($HostName+"."+$HostDomain)

    $SMTPConfig = ""
    if($SMTPConfigFile)
    {
        [xml]$configdata = Get-Content $SMTPConfigFile
        $SMTPConfig = @{
            To         = $configdata.SMTPConfig.To
            From       = $configdata.SMTPConfig.From
            SmtpServer = $configdata.SMTPConfig.SmtpServer
            Subject    = $configdata.SMTPConfig.Subject
        }
    }

    LogWrite "" ""
    LogWrite "VERB" "Script start --------------------------------------------------"

    LogWrite "INFO" "Load hostnames from Active Directory"
    if($SearchBase) {
        LogWrite "VERB" "LDAP Query: searchbase='($SearchBase)', Filter='($Filter)'"
        $Computers = Get-ADComputer -Filter {(cn -like $Filter)} -SearchBase $SearchBase -ResultSetSize $Limit -Properties * | ? {$_.Description -notlike "Failover Cluster*"} | Sort-Object -Property DNSHostName
    }
    else {
        LogWrite "VERB" "LDAP Query: Filter='($Filter)'"
        $Computers = Get-ADComputer -Filter {(cn -like $Filter)} -ResultSetSize $Limit -Properties * | ? {$_.Description -notlike "Failover Cluster*"} | Sort-Object -Property DNSHostName
    }

    if ($Computers.Count -eq 0) 
    {
        LogWrite "ERR" "No one computer found."
        exit
    }
    else
    {
        LogWrite "INFO" "Found $($Computers.Count) Computer(s)"
    }


    $Report = @()
    foreach ($Computer in $Computers)
    {
        
        $ComputerFQDNName = $Computer.DNSHostName

        $Item = New-Object -Type PSObject

        $Data = ""

        LogWrite "INFO" "Searching for updates in $($Computer.DNSHostName)" .\Get-Updates.cmd
        # Internal invoke command without ComputerName
        if( $HostName -ne $Computer.Name )
        {
            LogWrite "VERB" "Invoke Command on remote computer $($Computer.DNSHostName)"
            if( (Test-NetConnection -ComputerName $Computer.DNSHostName -Port 5985  -InformationLevel Quiet) -or (Test-NetConnection -ComputerName $Computer.DNSHostName -Port 5986 -InformationLevel Quiet) )
            {
                $Data = Invoke-Command -ScriptBlock $CheckWaitingUpdate -ComputerName $Computer.DNSHostName -ErrorAction SilentlyContinue -ErrorVariable ErrorStr
                if( $ErrorStr )
                {
                    LogWrite "WARN" "Invoke PS Command on remote computer $($Computer.DNSHostName) failed"
                    $Item | Add-Member -NotePropertyName HostName -NotePropertyValue $Computer.Name -Force
                    $Item | Add-Member -NotePropertyName ErrorStr -NotePropertyValue "Invoke-Command failed" -Force
                    $Report += $Item
                }
            }
            else
            {
                 LogWrite "WARN" "Connection to RPC on remote computer $($Computer.DNSHostName) failed"
                 $Item | Add-Member -NotePropertyName HostName -NotePropertyValue $Computer.Name -Force
                 $Item | Add-Member -NotePropertyName ErrorStr -NotePropertyValue "RPC Connection failed" -Force
                 $Report += $Item
            }
        }
        else
        {
            LogWrite "VERB" "Invoke Command local"
            $Data = Invoke-Command -ScriptBlock $CheckWaitingUpdate -ErrorVariable ErrorStr
            if( $ErrorStr )
            {
                LogWrite "WARN" "Connection to remote computer $($Computer.DNSHostName) failed"
                $Item | Add-Member -NotePropertyName HostName -NotePropertyValue $Computer.Name -Force
                $Item | Add-Member -NotePropertyName ErrorStr -NotePropertyValue "Connection failed" -Force
                $Report += $Item
            }
        }

        if( $Data.UpdateList.Count -gt 0 )
        {
            LogWrite "INFO" "Found $($Data.UpdateList.Count) waiting updates in $($Computer.Name)"
            $LastDate = ($Data.UpdateList| Sort-Object LastDeploymentChangeTime | SELECT -First 1 LastDeploymentChangeTime).LastDeploymentChangeTime
            $Item | Add-Member -NotePropertyName HostName -NotePropertyValue $Computer.Name -Force
            $Item | Add-Member -NotePropertyName Waiting -NotePropertyValue $Data.UpdateList.Count -Force
            $Item | Add-Member -NotePropertyName LastDate -NotePropertyValue $LastDate.Date -Force
            $Item | Add-Member -NotePropertyName OS -NotePropertyValue $Data.SystemOS -Force
            $Item | Add-Member -NotePropertyName Arch -NotePropertyValue $Data.SystemArch -Force
            LogWrite "VERB" "Result from $($Computer.Name): Waiting updates $($Data.UpdateList.Count), Last Update from: $($LastDate.Date|Get-Date -Format u)"
            $Report += $Item
        }
        elseif( ! $ErrorStr )
        {
            LogWrite "INFO" "No updates found in $($Computer.Name)"
            $Item | Add-Member -NotePropertyName HostName -NotePropertyValue $Computer.Name -Force
            $Item | Add-Member -NotePropertyName OS -NotePropertyValue $Data.SystemOS -Force
            $Item | Add-Member -NotePropertyName Arch -NotePropertyValue $Data.SystemArch -Force
            $Item | Add-Member -NotePropertyName ErrorStr -NotePropertyValue "OK - No updates found" -Force
            $Report += $Item
        }
    }

    LogWrite "VERB" "Generate HTML Report"
    $ReportHTML = "
<html>
<style>
html,body,p,td,h1,h2,h3,h4,h5,h6 { font-family: verdana,arial,sans-serif; font-size: 11px; }
h1 { font-size: 15px; }
h2 { font-size: 13px; }
table { font-size:11px; color:#333333; border-width: 1px; border-color: #999999; border-collapse: collapse; }
table th { background-color:#c3dde0; border-width: 1px; padding: 8px; border-style: solid; border-color: #a9c6c9; }
table tr { background-color:#e8f7f9; }
table tr.notice td { color: #c00; }
table td { border-width: 1px; padding: 8px; border-style: solid; border-color: #a9c6c9; white-space: nowrap; }
</style>
<body>
<h1>Windows Update Report for $($HostDomain)</h1>
<h2>LDAP Search Query: '$($Filter)' in OU '$($SearchBase)'</h2>
<p>Created on $(Get-Date -Format u)'</p>
<table class='table'>
  <thead>
    <tr>
      <th>Computer</th>
      <th title='Waiting Updates'>Wait Upd.</th>
      <th>Last Update</th>
      <th>Operating System</th>
      <th>CPU Arch</th>
      <th>Error</th>
    </tr>
  </thead>
  <tbody>
"

    Foreach($item IN $Report)
    {

        $LastDate = ""
        $ShowNoticeClass = ""
        if( $item.LastDate )
        {
            if( $item.LastDate.AddDays( $ShowNoticeDayLimit ) -lt (Get-Date) ) { $ShowNoticeClass = "notice" }
            $LastDate = $($item.LastDate|Get-Date -Format 'yyyy-MM-dd')
        }

        $ReportHTML += "
    <tr class='$($ShowNoticeClass)'>
      <td>$($item.HostName)</td>
      <td>$($item.Waiting)</td>
      <td>$LastDate</td>
      <td>$($item.OS)</td>
      <td>$($item.Arch)</td>
      <td>$($item.ErrorStr)</td>
    </tr>
";
    }

    # TRACE
    $trace_end = Get-Date

    $ReportHTML += "
  </tbody>
</table>
Generated on $($HostName).$($HostDomain) in $( ($trace_end - $trace_start).Minutes ) min.
</body>
</html>
";

    LogWrite "INFO" "Report output to file $($ReportFile)"
    $ReportHTML|Out-File -FilePath $ReportFile

    if ( $SMTPConfig )
    {
        LogWrite "INFO" "Send Mail"
        Send-MailMessage @SMTPConfig -BodyAsHtml $ReportHTML -ErrorVariable $ErrorMsg
        if( $ErrorMsg )
        {
            LogWrite "ERR" "Send Mail with Error $($ErrorMsg)"
        }
    }

}

#----------------------------------------------------------------------------------------------------------------
#
# Functions
#
#--------------------------------------------------------------------------------------------------------------
Begin {

    # Install-WindowsFeature RSAT-AD-PowerShell
    if(! (Get-Module ActiveDirectory) )
    {
        if (! (Get-Module -ListAvailable| ? {$_.Name -eq "ActiveDirectory" }) )
        {
            Throw "You have to install 'RSAT-AD-PowerShell' First`n`nCommand: Install-WindowsFeature RSAT-AD-PowerShell -IncludeAllSubFeature"
        }
        else {
            Import-Module ActiveDirectory
        }
    }

    $trace_start = Get-Date

    # Remote Script for check Updates
    $CheckWaitingUpdate = {
        $Data = @{}
        $Session = New-Object -ComObject "Microsoft.Update.Session"
        $Data.UpdateList = $Session.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software' and IsHidden=0").Updates
        $Data.SystemOS = (Get-WmiObject -class Win32_OperatingSystem).Caption
        if( [Environment]::Is64BitProcess ) {
            $Data.SystemArch = "64"
        } else {
            $Data.SystemArch = "32"
        }
        Write-Output $Data
    }

    # Function for Write log
    Function LogWrite
    {
        Param (
            [string]$logtype,
            [string]$logstring
        )

        if( $logtype -eq "ERR")
        {
            Write-Host -ForegroundColor Red $("ERROR: "+$logstring)
        }
        elseif( $logtype -eq "WARN")
        {
            Write-Warning $logstring
        }
        elseif( $logtype -eq "VERB")
        {
            Write-Verbose $logstring
        }
        else
        {
            Write-Host -ForegroundColor Yellow $logstring
        }
        $ProcessID = ([System.Diagnostics.Process]::GetCurrentProcess()).Id
        Add-content $Logfile -value "$(Get-Date -Format s)`t$($ProcessID)`t$($logtype)`t$($logstring)"
    }

}
