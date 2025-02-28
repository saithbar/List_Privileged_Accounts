function Add-Zip
# Funtion to zip a file
{
	param([string]$zipfilename)

	if (-not (test-path($zipfilename)))
	{
		set-content $zipfilename ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18))
		(dir $zipfilename).IsReadOnly = $false	
	}
	
	$shellApplication = new-object -com shell.application
	$zipPackage = $shellApplication.NameSpace($zipfilename)
	
	foreach($file in $input) 
	{
        $zipPackage.CopyHere($file.FullName)
        Start-sleep -milliseconds 500
	}
}

Function LoadConfigFile
# Function used to read an ini file
{
    param ($file)

    $ini = @{}
    $ok = $true
    switch -regex -file $file
    {
        "^\[(.+)\]$" {
                $section = $matches[1].ToLower()
                $ini[$section] = @{}
                $i = 0
        }
        "^([^=]+)={1}([^=]*)$" {
                $name, $value = $matches[1..2]
                $ini[$section][$name.Trim().ToLower()] = $value.Trim()
                $ok = $false
        }
        "^[^\[].*[^\]]$" {
            if ($ok) {
                $value = $matches[0]
                $ini[$section][$i] = $value.Trim()
                $i++
            }
        }
        default {
            $ok = $true
        }
    }
    return $ini
}

Function get-myadgroupmember
{
    param ($groupSID) # can be either the SID or the name of the group
    
    $Returnedlist = @()
    $Mygroup = get-adgroup -identity $groupSID -properties *
    if ($Mygroup.members.count -gt 0)
        {
        foreach ($member in $Mygroup.members) `
            {
            $externalaccount = $false
            if ($member.Contains("ForeignSecurityPrincipals"))
                {
                $externalaccount = $true
                $securityPrincipalObject = New-Object System.Security.Principal.SecurityIdentifier($member.split("=,")[1])
                $member = $securityPrincipalObject.Translate([System.Security.Principal.NTAccount]).value
                }

            if ($externalaccount) #$member.Contains("\")) # should be an object from an other forest
                {
                $Returnedlist += $member
                }
            else # should be an object of the current domain or a parent domain
                {
                $myobject = $(try {get-adobject -identity $member -ErrorAction SilentlyContinue} catch{$null})
                if (!$myobject) {$Returnedlist += $member} # The object is not in the current domain
                else
                    {
                    if ($myobject.ObjectClass -eq "user")
                        {$Returnedlist += $member}
                    elseif ($myobject.ObjectClass -eq "computer")
                        {$Returnedlist += $member}
                    else
                        {
                        $tempmembers = get-adgroupmember -identity $member -recursive
                        foreach ($tempmember in $tempmembers) {$Returnedlist += $tempmember.distinguishedname}
                        }
                    }
                }
            }
        }
    return [array]$Returnedlist
}


# Get Arguments name and path
$unattended = $false
for ( $i = 0; $i -lt $args.count; $i++ ) {
 if ($args[$i] -eq "-unattended"){ 
  $unattended = $true
 }
}

# Get Script name and path
set-location $(Split-Path $MyInvocation.InvocationName)
$Mypath=(get-location).path

# Import modules
try{import-module activedirectory -ErrorAction Stop} Catch{write-host failed to import activedirectory module;[Environment]::Exit(1)}

# if unattended  mode , the script run only if DC holds PDCEmulator Role
If (  $unattended -eq $true) {
 $PDCEmulator = $False
 $OperationsMastersRoleList = $(try{(get-ADDomainController).OperationMasterRoles} Catch{write-host failed to get OperationMasterRoles;[Environment]::Exit(1)})
 If ($OperationsMastersRoleList -ne $Null) {ForEach ($OperationsMastersRole In $OperationsMastersRoleList) {If ($OperationsMastersRole -eq 'PDCEmulator') {$PDCEmulator = $True}}}
 if ($PDCEmulator -ne $True) {write-host DC is not holding PDC Emulator Role;[Environment]::Exit(0)}


# Load ini file
$hConfig = LoadConfigFile ("privileged-accounts.ini")

# Get domain information
$mydomain=get-addomain
$mydomainSID=$mydomain.domainSID
$MyDomainNBName=$Mydomain.NetBIOSName
$MyDomainDNName=$Mydomain.distinguishedname

# Count all users in the domain
$searcher = New-Object System.DirectoryServices.DirectorySearcher([adsi]"")
$searcher.filter = "(&(objectCategory=person)(objectclass=user)(sAMAccountName=*)(!useraccountcontrol:1.2.840.113556.1.4.803:=2048))"
$searcher.SearchRoot = $root
$searcher.pagesize = 1000
$userscount = ($searcher.findall()).count

# Initialize well known groups SIDs variables
$MyadministratorsSID="S-1-5-32-544"                  #Administrators
$MyAccountOperatorsSID="S-1-5-32-548"                #Account Operators
$MyBackupOperatorsSID="S-1-5-32-551"                 #Backup Operators
$MyServerOperatorsSID="S-1-5-32-549"                 #Server Operators
$MyNetworkOperatorsSID="S-1-5-32-556"                #Network Operators
$MyPreW2000SID="S-1-5-32-554"						 #Pre Windows 2000
$MyEnterpriseAdminsSID=($mydomainSID.value) + "-519" #Enterprise Admins
$MySchemaAdminsSID=($mydomainSID.value) + "-518"     #Schema Admins
$MyDomainAdminsSID=($mydomainSID.value) + "-512"     #Domain Admins

# Initialize other groups
$TempOthergroups=@()
if (test-path("$Mypath\groups.txt")) {$TempOthergroups=get-content("$Mypath\groups.txt")}
if (-not $TempOthergroups)
    {$Script:Maxgroups=0}
else
    {
    $Othergroups = @()
    $Othergroupspriv = @()
    Foreach ($tt in $TempOthergroups)
        {
        $Othergroups += $tt.split(";")[0]
        $Othergroupspriv += $tt.split(";")[1]
        }
    $Script:Maxgroups=$TempOthergroups.count
    }

# Initialize log file
$COMPAREDATE = GET-DATE
$filedate = '{0:yyyyMMdd.HHmm}' -f $COMPAREDATE
$filepathlog = "$Mypath\$($Mydomain.DNSRoot)_high_privileged_members_" + $filedate + ".csv"
$streamlog = [System.IO.StreamWriter] $filepathlog

[string]$templine = "SamAccountName;First Name;Last Name;Email;Description;Last Logon Timestamp;Creation Date;Account Disabled;Password Not required;Password Never Expire;Password Last Set;Total users;Domain Admins;Administrators;Enterprise Admins;Schema Admins;Account Operators;Backup Operators;Server Operators;Network Operators;Pre-Windows 2000;"
$i=0
while ($i -lt $Maxgroups)
    {
    $templine = $templine + "$($Othergroups[$i]);"
    $i++
    }
$templine = $templine + "SID;DistinguishedName"

$streamlog.Writeline($templine)
$templine=""

# Initialize group counters
$MyadminC=$MyAOC=$MyBOC=$MySOC=$MyNOC=$MyEAC=$MySAC=$MyDAC=$MyPW2000=0

$MyAdministrators = get-myadgroupmember $MyadministratorsSID
$MyadminC = @($MyAdministrators | sort-object -unique).count

$MyNetworkOperators = get-myadgroupmember $MyNetworkOperatorsSID
$MyNOC = @($MyNetworkOperators | sort-object -unique).count

$MyAccountOperators = get-myadgroupmember $MyAccountOperatorsSID
$MyAOC = @($MyAccountOperators | sort-object -unique).count

$MyBackupOperators = get-myadgroupmember $MyBackupOperatorsSID
$MyBOC = @($MyBackupOperators | sort-object -unique).count

$MyServerOperators = get-myadgroupmember $MyServerOperatorsSID
$MySOC = @($MyServerOperators | sort-object -unique).count

$MyDomainAdmins = get-myadgroupmember $MyDomainAdminsSID
$MyDAC = @($MyDomainAdmins | sort-object -unique).count

$MyPreWindows2000 = get-myadgroupmember $MyPreW2000SID
$MyPW2000 = @($MyPreWindows2000 | sort-object -unique).count

$Mytest=$null
$Mytest = $(try {get-adgroup -identity $MyEnterpriseAdminsSID -ErrorAction SilentlyContinue} catch {$null})
if ($Mytest)
    {
    $MyEnterpriseAdmins = get-myadgroupmember $MyEnterpriseAdminsSID -ErrorAction:SilentlyContinue
    $INITEA = "NO"
    $MyEAC = @($MyEnterpriseAdmins | sort-object -unique).count
    }
else
    {
    $INITEA = "N/A"
    $MyEAC = 0
    }

$Mytest=$null
$Mytest = $(try {get-adgroup -identity $MySchemaAdminsSID -ErrorAction SilentlyContinue} catch {$null})
if ($Mytest)
    {
    $MySchemaAdmins = get-myadgroupmember $MySchemaAdminsSID -ErrorAction:SilentlyContinue
    $INITSA = "NO"
    $MySAC = @($MySchemaAdmins | sort-object -unique).count
    }
else
    {
    $INITSA = "N/A"
    $MySAC = 0
    }

$i=0
While ($i -lt $Maxgroups)
    {
    $Mytest=$null
    $Mytest = $(try {get-adgroup $Othergroups[$i] -ErrorAction SilentlyContinue} catch {$null})
    if ($Mytest)
        {
        New-Variable "OtherGroupsMembers_$i" @($(get-myadgroupmember $Othergroups[$i] -ErrorAction SilentlyContinue)) -force
        New-Variable "INITOtherGroupsMembers_$i" "NO" -force
        }
    else
        {
        New-variable "OtherGroupsMembers_$i" @() -force
        New-Variable "INITOtherGroupsMembers_$i" "N/A" -force
        }
	[int](Set-Variable OtherGroups_count_$i 0)
    $i++
    }
# Create an array of built-in admin accounts and count them uniquely
$MyAll = ($MyDomainAdmins + $MyBackupOperators + $MySchemaAdmins + $MyEnterpriseAdmins + $MyServerOperators + $MyAccountOperators + $MyAdministrators + $MyNetworkOperators + $MyPreW2000SID)
$MyBuiltInAdminCount = ($MyAll | sort-object -unique).count

# Add the members of the other groups if the group is privileged
$i=0
while ($i -lt $Maxgroups)
    {
    if ([int]$Othergroupspriv[$i]) {$MyAll = ($MyAll + (Get-variable Othergroupsmembers_$i).value)}
    $i++
    }
$MyAll = $MyAll | sort-object -unique

Foreach ($MyOne in $MyAll)
    {
    # Variables initialization
    $DA = "NO"					# Domain Admins
    $ADM = "NO"					# Builtin Administrators
    $EA = $INITEA				# Enterprise Admins
    $SA = $INITSA				# Schema Admins
    $AO = "NO"					# Account Operators
    $BO = "NO"					# Backup Operators
    $NO = "NO"					# Network Operators
    $SO = "NO"					# Server Operators
	$PW = "NO"					# Pre Windows 2000
    $i=0
    While ($i -lt $Maxgroups)
        {
        New-variable "OtherGroupsMembersYN_$i" (Get-variable INITOtherGroupsMembers_$i).value -force
        $i++
        }
    $objuser=$false
    $objcomputer=$false
	$MyoneDN = $null

    # Get memberships
    Foreach ($temp in $MyDomainAdmins)
        {
        if ($temp -eq $MyOne) {$DA = "YES"}
        }
    Foreach ($temp in $MySchemaAdmins)
        {
        if ($temp -eq $MyOne) {$SA = "YES"}
        }
    Foreach ($temp in $MyEnterpriseAdmins)
        {
        if ($temp -eq $MyOne) {$EA = "YES"}
        }
    Foreach ($temp in $MyServerOperators)
        {
        if ($temp -eq $MyOne) {$SO = "YES"}
        }
    Foreach ($temp in $MyAccountOperators)
        {
        if ($temp -eq $MyOne) {$AO = "YES"}
        }
    Foreach ($temp in $MyAdministrators)
        {
        if ($temp -eq $MyOne) {$ADM = "YES"}
        }
    Foreach ($temp in $MyBackupOperators)
        {
        if ($temp -eq $MyOne) {$BO = "YES"}
        }
    Foreach ($temp in $MyNetworkOperators)
        {
        if ($temp -eq $MyOne) {$NO = "YES"}
        }
    Foreach ($temp in $MyPreWindows2000)
        {
        if ($temp -eq $MyOne) {$PW = "YES"}
        }

    $i=0
    While ($i -lt $Maxgroups)
        {
        if ((Get-variable OtherGroupsMembers_$i).value)
            {
            Foreach ($temp in (Get-variable OtherGroupsMembers_$i).value)
                {
                if ($temp -eq $MyOne)
					{
					Set-variable OtherGroupsMembersYN_$i "YES"
					Set-variable OtherGroups_count_$i ((get-variable OtherGroups_count_$i).value + 1)
					}
                }
            }
        $i++
        }

    # Test if the object is a user account, a computer account or a group
    if (-not $Myone.Contains($MyDomainDNName))
        {
		$MyoneDN = $Myone
        if (-not $Myone.Contains("\")) {$Myone = $Myone.split("=,")[1]}
        }
    else
        {
        $temp = $(try {get-adobject $MyOne -properties ObjectClass} catch {$false})
        if ($temp.objectclass -eq "user") {$objuser=$true}
        elseif ($temp.objectclass -eq "computer") {$objcomputer=$true}
        else
            {
            $MyoneDN = $Myone
            $Myone = $Myone.split("=,")[1]
            }
        }

    # Bind on user if object is a user in the current domain
    if ($objuser)
        {
        $Myuser = get-aduser $MyOne -properties *

        # Specific User Variables initialization
        $LUP = @{userdisabled="NO"; userPNR="NO"; userPNE="NO"; userPEX="NO"; PasswordSet="never"; Lastlogon="Has never logged on"}
        $LUP["usercreate"]='{0:yyyy/MM/dd HH:mm}' -f $Myuser.createtimestamp
        $LUP["SamAccountName"]=$Myuser.SamAccountName
        $LUP["GivenName"]=$Myuser.GivenName
        $LUP["SurName"]=$Myuser.SurName
        $LUP["mail"]=$Myuser.mail
        $LUP["Description"]=$Myuser.Description
        $LUP["SID"]=$Myuser.SID
        $LUP["DistinguishedName"]=$Myuser.DistinguishedName

        # Get UAC
        $uac = $Myuser.userAccountControl
        if ($uac -band 0x2) {$LUP["userdisabled"]="YES"}
        if ($uac -band 0x20) {$LUP["userPNR"]="YES"}
        if ($uac -band 0x10000) {$LUP["userPNE"]="YES"}
        if ($Myuser.PasswordExpired) {$LUP["userPEX"]="YES"}
        if ($Myuser.PasswordLastSet) {$LUP["PasswordSet"]='{0:yyyy/MM/dd HH:mm}' -f $Myuser.PasswordLastSet}
        if ($Myuser.lastLogonTimestamp) {$LUP["Lastlogon"]='{0:yyyy/MM/dd HH:mm}' -f [datetime]::FromFileTime([int64]::Parse($Myuser.lastLogonTimestamp))}
        }
    elseif ($objcomputer)
        {
        $Myuser = get-adcomputer $MyOne -properties *

        # Specific User Variables initialization
        $LUP = @{userdisabled="NO"; userPNR="NO"; userPNE="NO"; userPEX="NO"; PasswordSet="never"; Lastlogon="Has never logged on"}
        $LUP["usercreate"]='{0:yyyy/MM/dd HH:mm}' -f $Myuser.createtimestamp
        $LUP["SamAccountName"]=$Myuser.SamAccountName
        $LUP["GivenName"]="N/A"
        $LUP["SurName"]="N/A"
        $LUP["mail"]=$Myuser.mail
        $LUP["Description"]=$Myuser.Description
        $LUP["SID"]=$Myuser.SID
        $LUP["DistinguishedName"]=$Myuser.DistinguishedName

        # Get UAC
        $uac = $Myuser.userAccountControl
        if ($uac -band 0x2) {$LUP["userdisabled"]="YES"}
        if ($uac -band 0x20) {$LUP["userPNR"]="YES"}
        if ($uac -band 0x10000) {$LUP["userPNE"]="YES"}
        if ($Myuser.PasswordExpired) {$LUP["userPEX"]="YES"}
        if ($Myuser.PasswordLastSet) {$LUP["PasswordSet"]='{0:yyyy/MM/dd HH:mm}' -f $Myuser.PasswordLastSet}
        if ($Myuser.lastLogonTimestamp) {$LUP["Lastlogon"]='{0:yyyy/MM/dd HH:mm}' -f [datetime]::FromFileTime([int64]::Parse($Myuser.lastLogonTimestamp))}
        }
    else
        {
        # Specific Group Variables initialization
        # Specific User Variables initialization
        $LUP = @{userdisabled="N/A"; userPNR="N/A"; userPNE="N/A"; userPEX="N/A"; PasswordSet="N/A"; Lastlogon="N/A"}
        $LUP["usercreate"]="N/A"
        $LUP["SamAccountName"]=$MyOne
        $LUP["GivenName"]="N/A"
        $LUP["SurName"]="N/A"
        $LUP["mail"]="N/A"
        $LUP["Description"]="N/A"
        $LUP["SID"]="N/A"
        $LUP["DistinguishedName"]=$MyoneDN
        }        
    [string]$templine = "$($LUP[`"SamAccountName`"]);$($LUP[`"GivenName`"]);$($LUP[`"SurName`"]);$($LUP[`"mail`"]);`"$($LUP[`"Description`"])`";$($LUP[`"Lastlogon`"]);$($LUP[`"usercreate`"]);$($LUP[`"userdisabled`"]);$($LUP[`"userPNR`"]);$($LUP[`"userPNE`"]);$($LUP[`"PasswordSet`"]);$userscount;$DA;$ADM;$EA;$SA;$AO;$BO;$SO;$NO;$PW;"
    $i=0
    while ($i -lt $Maxgroups)
        {
        $templine = $templine + (Get-variable OtherGroupsMembersYN_$i).value + ";"
        $i++
        }
    $templine = $templine + "$($LUP[`"SID`"]);$($LUP[`"DistinguishedName`"])"
    $streamlog.Writeline($templine)
    $templine =""
    }
$streamlog.close()

Start-sleep -Seconds 20

$oBody=@()
$oBody+="High Privileged Accounts Report for $MyDomainNBName Domain. Last run on $COMPAREDATE<br>"
$oBody+="Domain SID: $mydomainSID<br>"
$oBody+="Domain NETBIOS Name: $MyDomainNBName<br>"
$oBody+="Domain Distinguished Name: $MyDomainDNName<br>"
$oBody+="Total user account: $userscount<br>"
$oBody+="Total Privileged Accounts (Active Directory Built-in Groups): $MyBuiltInAdminCount<br>"
$oBody+="<br>"
$oBody+="Active Directory Built-in Groups Checked<br>"
$oBody+="Domain Admins count: $MyDAC<br>"
$oBody+="Enterprise Admins count: $MyEAC<br>"
$oBody+="Schema Admins count: $MySAC<br>"
$oBody+="Administrators count: $MyadminC<br>"
$oBody+="Account Operators count: $MyAOC<br>"
$oBody+="Backup Operators count: $MyBOC<br>"
$oBody+="Server Operators count: $MySOC<br>"
$oBody+="Network Operators count: $MyNOC<br>"
$oBody+="Pre-Windows 2000 count: $MyPW2000<br>"
$oBody+="<br>"
$oBody+="Other Groups Checked<br>"
$i=0
While ($i -lt $Maxgroups)
    {
    #$tempcount=$null
    #$tempcount = ((Get-variable OtherGroupsMembers_$i).value).count
    #if (!$tempcount) {$tempcount=0}
    if ([int]$($Othergroupspriv[$i])) {$oBody+="$($OtherGroups[$i]) : $((Get-variable OtherGroups_count_$i).value) (privileged group)<br>"}
    else {$oBody+="$($OtherGroups[$i]) : $((Get-variable OtherGroups_count_$i).value)<br>"}
    $i++
    }
$oTO = get-content $hConfig["mail"]["users"]
$oBCC = get-content $hConfig["mail"]["bcc"]
$oSMTP = $hConfig["config"]["smtp"]
$oFrom = $hConfig["mail"]["from"]
$oSubject = "High Privileged Accounts Report for $MyDomainNBName"
dir $filepathlog | Add-zip ($filepathlog + ".zip")
Start-Sleep -Seconds 20

# if not unattended  mode , Send email
If ($unattended -eq $False) { try{send-mailmessage -from $oFrom -to $oTO -bcc $oBCC -subject $oSubject -body "$oBody" -Attachments ($filepathlog + ".zip") -smtpServer $oSMTP -BodyAsHtml -priority High -ErrorAction Stop} Catch{write-host failed to send email}}

remove-item $filepathlog

Get-ChildItem $Mypath -recurse -include *.zip | Where-object{$_.LastWriteTime -lt (Get-Date).AddMonths(-6)} | Remove-Item

# if unattended  mode , Quit PowerShell
If ($unattended -eq $true) {[Environment]::Exit(0)}
