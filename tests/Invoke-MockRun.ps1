<#
.SYNOPSIS
    Offline smoke test: dot-sources the collector, replaces Graph/auth with in-memory mocks and
    asserts on the generated report. No tenant, certificate or network is needed.
    Runs twice: default mode (guests = internal) and -IncludeGuests mode.
    Works on PowerShell 7 (Linux/Windows). The #Requires module line is stripped in a temp copy.
#>
[CmdletBinding()]
param([switch]$IncludeGuests)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("mockrun_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
$copy = Join-Path $tmp 'collector.ps1'
(Get-Content (Join-Path $root 'Get-TeamsExternalInteractions.ps1') -Raw) -replace '(?m)^#Requires -Modules.*$', '' | Set-Content $copy

$home1 = '00000000-0000-0000-0000-000000000001'
$fedT = '99999999-9999-9999-9999-999999999999'
. $copy -TenantId $home1 -ClientId '00000000-0000-0000-0000-0000000000aa' -CertificateThumbprint ('A' * 40) `
    -OutputPath (Join-Path $tmp 'out') -DaysBack 7 -MaxRetries 1 -IncludeGuests:$IncludeGuests

# ---- mocks -----------------------------------------------------------------------------------
function Get-AuthCertificate { [pscustomobject]@{ Thumbprint = 'A' * 40 } }
function Connect-MgGraph { }
function Disconnect-MgGraph { }
function Get-MgContext { [pscustomobject]@{ TenantId = $home1; Scopes = @() } }
$mockEpoch = (Get-Date).ToUniversalTime().AddHours(-3)
function T($min) { $mockEpoch.AddMinutes($min).ToString('yyyy-MM-ddTHH:mm:ss.0000000Z') }
function J($o) { $o | ConvertTo-Json -Depth 10 | ConvertFrom-Json }
function AadMember($id, $name, $tenant, $mail) { @{ '@odata.type' = '#microsoft.graph.aadUserConversationMember'; userId = $id; displayName = $name; tenantId = $tenant; email = $mail } }

function Invoke-MgGraphRequest {
    param($Method, $Uri, $OutputType, $Headers, $ErrorAction)
    switch -Regex ($Uri) {
        '/organization' { return J @{ value = @(@{ id = $home1; verifiedDomains = @(@{ name = 'contoso.com' }, @{ name = 'contoso.onmicrosoft.com' }) }) } }
        '/v1.0/users\?' { return J @{ value = @(
                    @{ id = 'u1'; displayName = 'Alice'; userPrincipalName = 'alice@contoso.com'; mail = 'alice@contoso.com'; userType = 'Member'; accountEnabled = $true },
                    @{ id = 'u2'; displayName = 'Bob'; userPrincipalName = 'bob@contoso.com'; mail = 'bob@contoso.com'; userType = 'Member'; accountEnabled = $true },
                    @{ id = 'g1'; displayName = '=cmd|evil'; userPrincipalName = 'eve_partner.com#EXT#@contoso.onmicrosoft.com'; mail = 'eve@partner.com'; userType = 'Guest'; accountEnabled = $true }) } }
        '/users/u1/chats' { return J @{ value = @(@{ id = 'c1'; chatType = 'oneOnOne'; topic = $null; createdDateTime = (T -600)
                        lastMessagePreview = @{ createdDateTime = (T 10) }
                        members = @((AadMember 'u1' 'Alice' $home1 'alice@contoso.com'), (AadMember 'x9' 'Zed' $fedT $null)) }) } }
        '/users/u2/chats' { return J @{ value = @() } }
        '/chats/c1/messages' { return J @{ value = @(
                    @{ id = 'm1'; messageType = 'message'; createdDateTime = (T 1); from = @{ user = @{ id = 'u1'; displayName = 'Alice'; tenantId = $home1 } }; attachments = @(@{ contentType = 'reference' }) },
                    @{ id = 'm2'; messageType = 'message'; createdDateTime = (T 2); from = @{ user = @{ id = 'x9'; displayName = 'Zed'; tenantId = $fedT } }; attachments = @() },
                    @{ id = 'm4'; messageType = 'message'; createdDateTime = (T 3); from = @{ user = @{ id = 'u1'; displayName = 'Alice'; tenantId = $home1 } }; attachments = @() },
                    @{ id = 'm3'; messageType = 'systemEventMessage'; createdDateTime = (T 4); eventDetail = @{ '@odata.type' = '#microsoft.graph.membersAddedEventMessageDetail'
                            initiator = @{ user = @{ id = 'u1'; tenantId = $home1; displayName = 'Alice' } }; members = @(@{ id = 'g1'; tenantId = $home1; displayName = 'Eve' }) } }) } }
        'tenantRelationships' { return J @{ defaultDomainName = 'fabrikam.onmicrosoft.com' } }
        '/groups\?' { return J @{ value = @(@{ id = 't1'; displayName = 'Project X' }) } }
        '/teams/t1/members' { return J @{ value = @((AadMember 'g1' 'Eve' $home1 'eve@partner.com')) } }
        '/teams/t1/channels/ch1/members' { return J @{ value = @((AadMember 'u1' 'Alice' $home1 'alice@contoso.com'), (AadMember 'x5' 'Sam' '55555555-5555-5555-5555-555555555555' 'sam@shared.org')) } }
        '/teams/t1/channels/ch1/messages/delta' { return J @{ value = @(
                    @{ id = 'cm1'; messageType = 'message'; createdDateTime = (T 5); from = @{ user = @{ id = 'u1'; displayName = 'Alice'; tenantId = $home1 } }; attachments = @() },
                    @{ id = 'cm2'; messageType = 'message'; createdDateTime = (T 6); from = @{ user = @{ id = 'x5'; displayName = 'Sam'; tenantId = '55555555-5555-5555-5555-555555555555' } }; attachments = @(@{ contentType = 'reference' }) }) } }
        '/teams/t1/channels/ch2/messages/delta' { return J @{ value = @() } }
        '/teams/t1/channels' { return J @{ value = @(@{ id = 'ch1'; displayName = 'Shared'; membershipType = 'shared' }, @{ id = 'ch2'; displayName = 'General'; membershipType = 'standard' }) } }
        '/calendarView' {
            $att = @(@{ type = 'required'; emailAddress = @{ name = 'Pat'; address = 'pat@vendor.io' } })
            if ($Uri -match '/users/u2/') { $att += @{ type = 'required'; emailAddress = @{ name = 'Bob'; address = 'bob@contoso.com' } } }
            return J @{ value = @(@{ iCalUId = 'ical1'; subject = 'Sync'; isOnlineMeeting = $true; onlineMeetingProvider = 'teamsForBusiness'; isCancelled = $false
                        start = @{ dateTime = (T 20) }; organizer = @{ emailAddress = @{ name = 'Alice'; address = 'alice@contoso.com' } }; attendees = $att }) }
        }
        'callRecords\?' { return J @{ value = @(@{ id = 'cr1' }) } }
        'callRecords/cr1' { return J @{ id = 'cr1'; type = 'groupCall'; joinWebUrl = 'https://teams.microsoft.com/l/meetup-join/x'; startDateTime = (T 30); endDateTime = (T 60)
                    modalities = @('audio', 'screenSharing')
                    organizer_v2 = @{ identity = @{ user = @{ id = 'u2'; tenantId = $home1; displayName = 'Bob' } } }
                    participants_v2 = @(@{ identity = @{ user = @{ id = 'u2'; tenantId = $home1; displayName = 'Bob' } } },
                        @{ identity = @{ user = @{ id = 'x7'; tenantId = '77777777-7777-7777-7777-777777777777'; displayName = 'Ext Guy' } } }) } }
        default { throw "Unmocked URI: $Uri" }
    }
}

# ---- run -------------------------------------------------------------------------------------
$rc = Invoke-Main
$failures = @()
function Check($name, $cond) { if (-not $cond) { $script:failures += $name }; Write-Host ("{0} {1}" -f $(if ($cond) { 'PASS' } else { 'FAIL' }), $name) }
$out = Join-Path $tmp 'out'
$rows = @(Import-Csv (Get-ChildItem $out -Filter 'TeamsExternalInteractions_*.csv').FullName)
$sum = @(Import-Csv (Get-ChildItem $out -Filter 'TeamsExternalDomainSummary_*.csv').FullName)
$rows | Format-Table InteractionType, ConversationKind, InitiatedBy, InitiatedByType, ExternalUser, ExternalDomain, ExternalRelationship, MessageCount, FilesShared, Calls, ScreenSharing -AutoSize | Out-String | Write-Host
$sum | Format-Table ExternalDomain, Conversations, Messages, FilesShared, ScreenSharingSessions, UniqueInternalUsers -AutoSize | Out-String | Write-Host

Write-Host "=== mode: IncludeGuests=$([bool]$IncludeGuests) ==="
Check 'exit code 0' ($rc -eq 0)
$zed = @($rows | Where-Object { $_.InteractionType -eq 'TeamsChat' -and $_.ExternalUser -eq 'Zed' })
Check 'one chat row for Zed' ($zed.Count -eq 1)
Check 'chat counts 2 internal / 1 external msgs' ($zed[0].MessagesFromInternal -eq 2 -and $zed[0].MessagesFromExternal -eq 1 -and $zed[0].MessageCount -eq 3)
Check 'chat file shared by internal' ($zed[0].FilesSharedByInternal -eq 1 -and $zed[0].FilesShared -eq 1)
Check 'chat initiated by Alice (internal)' ($zed[0].InitiatedBy -eq 'Alice' -and $zed[0].InitiatedByType -eq 'Internal' -and $zed[0].Direction -eq 'InternalToExternal')
Check 'federated domain via tenant lookup' ($zed[0].ExternalDomain -eq 'fabrikam.onmicrosoft.com' -and $zed[0].ExternalRelationship -eq 'Federated')
$sam = @($rows | Where-Object { $_.InteractionType -eq 'TeamsChannel' -and $_.ExternalUser -eq 'Sam' })
Check 'shared-channel row for Sam' ($sam.Count -eq 1 -and $sam[0].ExternalRelationship -eq 'B2BDirectConnect' -and $sam[0].ExternalDomain -eq 'shared.org')
Check 'channel counts + file by external' ($sam[0].MessagesFromExternal -eq 1 -and $sam[0].MessagesFromInternal -eq 1 -and $sam[0].FilesSharedByExternal -eq 1)
$inv = @($rows | Where-Object { $_.InteractionType -eq 'TeamsMeetingInvite' })
Check 'meeting invite de-duplicated, both internals' ($inv.Count -eq 1 -and $inv[0].InternalParticipants -match 'bob@contoso.com' -and $inv[0].ExternalDomain -eq 'vendor.io')
$cr = @($rows | Where-Object { $_.InteractionType -eq 'TeamsMeetingParticipation' -and $_.ExternalUser -eq 'Ext Guy' })
Check 'call-record participation + screen sharing' ($cr.Count -eq 1 -and $cr[0].ScreenSharing -eq 'True')
Check 'no formula injection' (@($rows | Where-Object { $_.InitiatedBy -match '^[=+\-@]' -or $_.ExternalUser -match '^[=+\-@]' -or $_.AddedBy -match '^[=+\-@]' }).Count -eq 0)
Check 'domain summary has sharing totals' (@($sum | Where-Object { $_.ExternalDomain -eq 'shared.org' -and $_.FilesSharedByExternal -eq 1 }).Count -eq 1)
Check 'manifest written' ((Get-ChildItem $out -Filter '*.manifest.json').Count -eq 1)
$guestRows = @($rows | Where-Object { $_.ExternalDomain -eq 'partner.com' })
if ($IncludeGuests) {
    Check 'guest reported external when -IncludeGuests' ($guestRows.Count -eq 2 -and @($guestRows | Where-Object { $_.ExternalRelationship -eq 'Guest' }).Count -eq 2)
    Check 'guest added-by recorded' (@($guestRows | Where-Object { $_.InteractionType -eq 'TeamsChat' -and $_.ExternalAddedBy -eq 'Alice' }).Count -eq 1)
} else {
    Check 'guest treated as internal by default' ($guestRows.Count -eq 0)
}

Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
if ($failures.Count) { Write-Host "FAILED: $($failures -join '; ')" -ForegroundColor Red; exit 1 }
if (-not $IncludeGuests) {
    & (Get-Process -Id $PID).Path -NoProfile -File $PSCommandPath -IncludeGuests
    exit $LASTEXITCODE
}
Write-Host 'All mock checks passed.' -ForegroundColor Green
