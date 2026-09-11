<#
.SYNOPSIS
    Joiner automation — provisions new-hire accounts in Microsoft Entra ID from a CSV,
    applying least-privilege group membership based on department/role.

.DESCRIPTION
    Reads a new-hire CSV and, for each row, creates an Entra ID user, forces a
    password change at first sign-on, assigns department attributes, and adds the
    user to the security groups mapped to their role (least privilege). Supports
    -WhatIf so you can dry-run before touching the directory.

    Maps to: NIST 800-53 AC-2 (Account Management), AC-6 (Least Privilege)
             SC-300  : Implement and manage user identities

.PARAMETER CsvPath
    Path to the new-hire CSV. Required columns:
    DisplayName, UserPrincipalName, MailNickname, Department, JobTitle, RoleGroup

.PARAMETER DefaultPassword
    Temporary password issued to each account (must be changed at first sign-in).

.EXAMPLE
    ./New-JmlUser.ps1 -CsvPath ./samples/new_hires.csv -WhatIf
    ./New-JmlUser.ps1 -CsvPath ./samples/new_hires.csv

.NOTES
    Requires: Microsoft.Graph module and a Connect-MgGraph session with scopes
    User.ReadWrite.All, Group.ReadWrite.All, Directory.Read.All
    Author : Kofi Williams   License: MIT
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$CsvPath,

    [string]$DefaultPassword = ("Tmp!" + -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 12 | ForEach-Object { [char]$_ }))
)

# Role -> least-privilege security groups. Central place to govern access.
$RoleGroupMap = @{
    'Helpdesk'   = @('SG-AllStaff', 'SG-Helpdesk-Tools')
    'Finance'    = @('SG-AllStaff', 'SG-Finance-Apps')
    'Engineering'= @('SG-AllStaff', 'SG-Eng-Repos', 'SG-VPN-Users')
    'HR'         = @('SG-AllStaff', 'SG-HR-Apps')
    'Sales'      = @('SG-AllStaff', 'SG-CRM-Users')
}

function Assert-GraphConnection {
    if (-not (Get-MgContext)) {
        throw "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes 'User.ReadWrite.All','Group.ReadWrite.All','Directory.Read.All'"
    }
}

function Resolve-GroupId {
    param([string]$DisplayName)
    $g = Get-MgGroup -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
    if (-not $g) { Write-Warning "  Group not found (skipping): $DisplayName"; return $null }
    return $g.Id
}

# --- main -----------------------------------------------------------------
Assert-GraphConnection
$rows = Import-Csv -Path $CsvPath
Write-Host "Loaded $($rows.Count) new-hire record(s) from $CsvPath" -ForegroundColor Cyan

$results = foreach ($row in $rows) {
    $upn = $row.UserPrincipalName
    Write-Host "`nProcessing: $($row.DisplayName) <$upn>" -ForegroundColor White

    # Skip if the account already exists (idempotent)
    if (Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue) {
        Write-Warning "  User already exists — skipping create."
        continue
    }

    $passwordProfile = @{
        Password                      = $DefaultPassword
        ForceChangePasswordNextSignIn = $true
    }

    $newUserParams = @{
        DisplayName       = $row.DisplayName
        UserPrincipalName = $upn
        MailNickname      = $row.MailNickname
        Department        = $row.Department
        JobTitle          = $row.JobTitle
        AccountEnabled    = $true
        PasswordProfile   = $passwordProfile
    }

    if ($PSCmdlet.ShouldProcess($upn, "Create Entra ID user + assign least-privilege groups")) {
        try {
            $user = New-MgUser @newUserParams
            Write-Host "  Created user object: $($user.Id)" -ForegroundColor Green

            $groups = $RoleGroupMap[$row.RoleGroup]
            if (-not $groups) {
                Write-Warning "  No group mapping for role '$($row.RoleGroup)' — assigned baseline only."
                $groups = @('SG-AllStaff')
            }
            foreach ($gName in $groups) {
                $gid = Resolve-GroupId -DisplayName $gName
                if ($gid) {
                    New-MgGroupMember -GroupId $gid -DirectoryObjectId $user.Id -ErrorAction Stop
                    Write-Host "  + Added to $gName" -ForegroundColor Green
                }
            }
            [pscustomobject]@{ UPN = $upn; Status = 'Provisioned'; Groups = ($groups -join ';') }
        }
        catch {
            Write-Error "  Failed to provision $upn : $_"
            [pscustomobject]@{ UPN = $upn; Status = "Error: $($_.Exception.Message)"; Groups = '' }
        }
    }
    else {
        # -WhatIf path
        $groups = $RoleGroupMap[$row.RoleGroup] ?? @('SG-AllStaff')
        Write-Host "  [WhatIf] Would create $upn and add to: $($groups -join ', ')" -ForegroundColor Yellow
        [pscustomobject]@{ UPN = $upn; Status = 'WhatIf'; Groups = ($groups -join ';') }
    }
}

Write-Host "`n=== Joiner run summary ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize
