# Get-Updates
Detect waiting updates on remote servers and workstations in whole domain.

Feel free to download, use this code.
You can also change and redistribute changed version. Please remember to add information about author of this script and url to my blog https://blog.polewiak.pl - Thanks in advance... :)

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
