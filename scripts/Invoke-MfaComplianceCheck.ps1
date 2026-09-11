<#
.SYNOPSIS
    MFA & Conditional Access compliance audit for Microsoft Entra ID.

.DESCRIPTION
    Reports every enabled user's registered authentication methods and flags
    accounts that are NOT protected by strong MFA. Also lists the tenant's
    Conditional Access policies and highlights whether an "MFA for all users"
    style policy is present and enabled.

    Maps to: NIST 800-53 IA-2 (Identification & Authentication), AC-7
             SC-300  : Implement authentication and Conditional Access

.PARAMETER OutFile
    CSV output path (default ./mfa_gaps.csv).

.EXAMPLE
    ./Invoke-MfaComplianceCheck.ps1 -OutFile ./mfa_gaps.csv

.NOTES
    Requires scopes: User.Read.All, UserAuthenticationMethod.Read.All,
                     Policy.Read.All, Directory.Read.All
    Author: Kofi Williams   License: MIT
#>
[CmdletBinding()]
param(
    [string]$OutFile = "./mfa_gaps.csv"
)

if (-not (Get-MgContext)) {
    throw "Not connected. Run: Connect-MgGraph -Scopes 'User.Read.All','UserAuthenticationMethod.Read.All','Policy.Read.All'"
}

# Method types considered "strong" MFA
$strongMethods = @(
    '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod',
    '#microsoft.graph.fido2AuthenticationMethod',
    '#microsoft.graph.phoneAuthenticationMethod',
    '#microsoft.graph.softwareOathAuthenticationMethod',
    '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod'
)

Write-Host "Auditing MFA registration for all enabled users..." -ForegroundColor Cyan
$users = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,AccountEnabled,UserType

$report = foreach ($u in $users) {
    if (-not $u.AccountEnabled) { continue }

    try {
        $methods = Get-MgUserAuthenticationMethod -UserId $u.Id -ErrorAction Stop
    } catch {
        Write-Warning "  Could not read methods for $($u.UserPrincipalName): $($_.Exception.Message)"
        continue
    }

    $types = $methods.AdditionalProperties['@odata.type']
    $methodTypes = $methods | ForEach-Object { $_.AdditionalProperties['@odata.type'] }
    $hasStrong = ($methodTypes | Where-Object { $_ -in $strongMethods }).Count -gt 0
    $onlyPassword = ($methodTypes | Where-Object { $_ -ne '#microsoft.graph.passwordAuthenticationMethod' }).Count -eq 0

    $status = if ($hasStrong) { 'Compliant' } elseif ($onlyPassword) { 'NoMFA' } else { 'WeakOnly' }
    if ($status -eq 'Compliant') { continue }   # only report gaps

    [pscustomobject]@{
        DisplayName = $u.DisplayName
        UPN         = $u.UserPrincipalName
        UserType    = $u.UserType
        Methods     = (($methodTypes | ForEach-Object { $_ -replace '#microsoft.graph.', '' -replace 'AuthenticationMethod','' }) -join ';')
        Status      = $status
        Risk        = if ($status -eq 'NoMFA') { 'HIGH' } else { 'MEDIUM' }
    }
}

$report = $report | Sort-Object @{ E = { @{HIGH=0;MEDIUM=1}[$_.Risk] } }, UPN
$report | Export-Csv -Path $OutFile -NoTypeInformation

Write-Host "`n=== MFA Compliance Gaps ===" -ForegroundColor Cyan
Write-Host ("Users without strong MFA: {0}  (No MFA: {1}  Weak: {2})" -f `
    $report.Count,
    ($report | Where-Object Status -eq 'NoMFA').Count,
    ($report | Where-Object Status -eq 'WeakOnly').Count)
$report | Format-Table DisplayName, UPN, Methods, Status, Risk -AutoSize

# --- Conditional Access posture ------------------------------------------
Write-Host "`n=== Conditional Access Policies ===" -ForegroundColor Cyan
try {
    $caPolicies = Get-MgIdentityConditionalAccessPolicy -All
    if (-not $caPolicies) {
        Write-Warning "No Conditional Access policies found — MFA is likely NOT enforced tenant-wide!"
    } else {
        $caPolicies | Select-Object DisplayName, State,
            @{ N = 'GrantControls'; E = { $_.GrantControls.BuiltInControls -join ',' } } |
            Format-Table -AutoSize
        $mfaPolicy = $caPolicies | Where-Object {
            $_.State -eq 'enabled' -and $_.GrantControls.BuiltInControls -contains 'mfa'
        }
        if ($mfaPolicy) {
            Write-Host "MFA is enforced by: $($mfaPolicy.DisplayName -join ', ')" -ForegroundColor Green
        } else {
            Write-Warning "No ENABLED Conditional Access policy requires MFA. Recommend creating one."
        }
    }
} catch {
    Write-Warning "Could not read Conditional Access policies (needs Policy.Read.All): $($_.Exception.Message)"
}

Write-Host "`nFull MFA gap report: $OutFile" -ForegroundColor Green
