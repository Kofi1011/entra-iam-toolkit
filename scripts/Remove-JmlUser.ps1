<#
.SYNOPSIS
    Leaver automation — securely offboards a user from Microsoft Entra ID.

.DESCRIPTION
    Executes the standard IAM termination playbook for a departing user:
      1. Disables the account (blocks sign-in immediately)
      2. Revokes all refresh tokens / active sessions
      3. Removes the user from all security & Microsoft 365 groups
      4. Resets the password to a random value
      5. Writes an audit record of every action for compliance evidence

    Maps to: NIST 800-53 AC-2(3) (Disable inactive accounts), AC-2 (Account Mgmt)
             SC-300  : Manage the identity lifecycle (leaver)

.PARAMETER UserPrincipalName
    UPN of the account to offboard.

.PARAMETER AuditLog
    Path to append a CSV audit record (default: ./offboarding_audit.csv).

.EXAMPLE
    ./Remove-JmlUser.ps1 -UserPrincipalName jdoe@contoso.com -WhatIf
    ./Remove-JmlUser.ps1 -UserPrincipalName jdoe@contoso.com

.NOTES
    Requires scopes: User.ReadWrite.All, Group.ReadWrite.All, Directory.AccessAsUser.All
    Author: Kofi Williams   License: MIT
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$UserPrincipalName,

    [string]$AuditLog = "./offboarding_audit.csv"
)

function Write-Audit {
    param([string]$Action, [string]$Detail, [string]$Status)
    [pscustomobject]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        User         = $UserPrincipalName
        Action       = $Action
        Detail       = $Detail
        Status       = $Status
        Operator     = (Get-MgContext).Account
    } | Export-Csv -Path $AuditLog -Append -NoTypeInformation
}

if (-not (Get-MgContext)) {
    throw "Not connected. Run: Connect-MgGraph -Scopes 'User.ReadWrite.All','Group.ReadWrite.All'"
}

$user = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" -ErrorAction SilentlyContinue
if (-not $user) { throw "User not found: $UserPrincipalName" }
Write-Host "Offboarding: $($user.DisplayName) <$UserPrincipalName> [$($user.Id)]" -ForegroundColor Cyan

# 1) Disable account -------------------------------------------------------
if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Disable account (block sign-in)")) {
    try {
        Update-MgUser -UserId $user.Id -AccountEnabled:$false -ErrorAction Stop
        Write-Host "  [1/4] Account disabled." -ForegroundColor Green
        Write-Audit -Action 'DisableAccount' -Detail 'AccountEnabled=false' -Status 'Success'
    } catch { Write-Audit -Action 'DisableAccount' -Detail $_.Exception.Message -Status 'Error' }
}

# 2) Revoke sessions / refresh tokens -------------------------------------
if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Revoke all sessions")) {
    try {
        Revoke-MgUserSignInSession -UserId $user.Id -ErrorAction Stop | Out-Null
        Write-Host "  [2/4] All sessions revoked." -ForegroundColor Green
        Write-Audit -Action 'RevokeSessions' -Detail 'All refresh tokens invalidated' -Status 'Success'
    } catch { Write-Audit -Action 'RevokeSessions' -Detail $_.Exception.Message -Status 'Error' }
}

# 3) Remove from all groups -----------------------------------------------
if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Remove from all groups")) {
    $memberships = Get-MgUserMemberOf -UserId $user.Id -All |
        Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.group' }
    foreach ($m in $memberships) {
        $gName = $m.AdditionalProperties['displayName']
        try {
            Remove-MgGroupMemberByRef -GroupId $m.Id -DirectoryObjectId $user.Id -ErrorAction Stop
            Write-Host "  - Removed from $gName" -ForegroundColor Green
            Write-Audit -Action 'RemoveGroup' -Detail $gName -Status 'Success'
        } catch {
            # Dynamic groups can't be edited directly — note and continue
            Write-Warning "  Could not remove from $gName (may be dynamic): $($_.Exception.Message)"
            Write-Audit -Action 'RemoveGroup' -Detail "$gName -> $($_.Exception.Message)" -Status 'Skipped'
        }
    }
    Write-Host "  [3/4] Group cleanup complete ($($memberships.Count) group(s))." -ForegroundColor Green
}

# 4) Randomize password ---------------------------------------------------
if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Reset password to random value")) {
    try {
        $rand = -join ((33..126) | Get-Random -Count 20 | ForEach-Object { [char]$_ })
        Update-MgUser -UserId $user.Id -PasswordProfile @{
            Password = $rand; ForceChangePasswordNextSignIn = $true
        } -ErrorAction Stop
        Write-Host "  [4/4] Password randomized." -ForegroundColor Green
        Write-Audit -Action 'ResetPassword' -Detail 'Randomized 20-char password' -Status 'Success'
    } catch { Write-Audit -Action 'ResetPassword' -Detail $_.Exception.Message -Status 'Error' }
}

Write-Host "`nOffboarding complete. Audit trail: $AuditLog" -ForegroundColor Cyan
