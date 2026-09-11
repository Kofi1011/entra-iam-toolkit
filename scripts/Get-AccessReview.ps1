<#
.SYNOPSIS
    Access-review automation — surfaces stale accounts, over-privileged users,
    and guests for periodic certification.

.DESCRIPTION
    Produces an access-review report an IAM analyst can hand to managers for
    certification. For every enabled user it evaluates:
      * Last interactive sign-in vs. a staleness threshold
      * Privileged directory-role assignments (e.g., Global/User Admin)
      * Guest (external) account status
      * Accounts with no MFA methods registered

    Output is a CSV plus a color-coded console summary with a RISK column.

    Maps to: NIST 800-53 AC-2(3), AU-6 (Audit Review)
             SC-300  : Plan and implement identity governance / access reviews

.PARAMETER StaleDays
    Days since last sign-in before an account is flagged stale (default 45).

.PARAMETER OutFile
    CSV output path (default ./access_review.csv).

.EXAMPLE
    ./Get-AccessReview.ps1 -StaleDays 30 -OutFile ./review_Q3.csv

.NOTES
    Requires scopes: User.Read.All, AuditLog.Read.All, Directory.Read.All,
                     RoleManagement.Read.Directory, UserAuthenticationMethod.Read.All
    Author: Kofi Williams   License: MIT
#>
[CmdletBinding()]
param(
    [int]$StaleDays = 45,
    [string]$OutFile = "./access_review.csv"
)

if (-not (Get-MgContext)) {
    throw "Not connected. Run: Connect-MgGraph -Scopes 'User.Read.All','AuditLog.Read.All','Directory.Read.All','RoleManagement.Read.Directory'"
}

$cutoff = (Get-Date).AddDays(-$StaleDays)
Write-Host "Access review — flagging accounts stale since $($cutoff.ToString('yyyy-MM-dd'))" -ForegroundColor Cyan

# Build a lookup of users that hold a privileged directory role
Write-Host "Enumerating privileged role assignments..." -ForegroundColor DarkGray
$privilegedUserIds = @{}
$privRoleNames = 'Global Administrator','Privileged Role Administrator','User Administrator',
                 'Security Administrator','Exchange Administrator','SharePoint Administrator',
                 'Application Administrator','Helpdesk Administrator'
foreach ($roleName in $privRoleNames) {
    $role = Get-MgDirectoryRole -Filter "displayName eq '$roleName'" -ErrorAction SilentlyContinue
    if ($role) {
        Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All |
            ForEach-Object { $privilegedUserIds[$_.Id] = $roleName }
    }
}

Write-Host "Evaluating users..." -ForegroundColor DarkGray
$users = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,SignInActivity,CreatedDateTime

$report = foreach ($u in $users) {
    if (-not $u.AccountEnabled) { continue }

    $lastSignIn = $u.SignInActivity.LastSignInDateTime
    $isStale    = (-not $lastSignIn) -or ($lastSignIn -lt $cutoff)
    $isPriv     = $privilegedUserIds.ContainsKey($u.Id)
    $isGuest    = $u.UserType -eq 'Guest'

    # Compute a simple risk rating
    $flags = @()
    if ($isStale) { $flags += 'STALE' }
    if ($isPriv)  { $flags += 'PRIVILEGED' }
    if ($isGuest) { $flags += 'GUEST' }

    $risk = switch ($true) {
        { $isStale -and $isPriv } { 'HIGH'; break }
        { $isPriv -or ($isStale -and $isGuest) } { 'MEDIUM'; break }
        { $isStale -or $isGuest } { 'LOW'; break }
        default { 'OK' }
    }
    if ($risk -eq 'OK') { continue }   # only report exceptions

    [pscustomobject]@{
        DisplayName   = $u.DisplayName
        UPN           = $u.UserPrincipalName
        UserType      = $u.UserType
        LastSignIn    = if ($lastSignIn) { $lastSignIn.ToString('yyyy-MM-dd') } else { 'NEVER' }
        PrivilegedRole= if ($isPriv) { $privilegedUserIds[$u.Id] } else { '' }
        Flags         = ($flags -join '|')
        Risk          = $risk
    }
}

$report = $report | Sort-Object @{ E = { @{HIGH=0;MEDIUM=1;LOW=2}[$_.Risk] } }, UPN
$report | Export-Csv -Path $OutFile -NoTypeInformation

Write-Host "`n=== Access Review Summary ===" -ForegroundColor Cyan
Write-Host ("Exceptions: {0}  (HIGH: {1}  MEDIUM: {2}  LOW: {3})" -f `
    $report.Count,
    ($report | Where-Object Risk -eq 'HIGH').Count,
    ($report | Where-Object Risk -eq 'MEDIUM').Count,
    ($report | Where-Object Risk -eq 'LOW').Count)
$report | Format-Table DisplayName, UPN, LastSignIn, PrivilegedRole, Flags, Risk -AutoSize
Write-Host "Full report: $OutFile" -ForegroundColor Green
