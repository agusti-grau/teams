#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0' }
<#
.SYNOPSIS
    Reports every Microsoft Teams interaction between internal users and external parties
    (federated users, shared-channel members, anonymous/ACS/consumer users; B2B guests only with -IncludeGuests).

.DESCRIPTION
    Read-only, certificate-authenticated (app-only) collector built on Microsoft Graph.
    It produces:
      1. Interactions CSV  - ONE ROW PER CONVERSATION x EXTERNAL USER (chat, channel, meeting, call) with
                             interaction type, initiator, external user, external domain, relationship,
                             direction, message/call counts and sharing (files, screen sharing).
      2. Domain summary CSV - one row per external domain (volumes, unique users, relationships,
                             and - optionally - the Teams external-access policy status).
      3. Run manifest JSON  - parameters, per-source status, counts and SHA-256 of the outputs.

    Interaction types (column InteractionType):
      TeamsChat                   1:1 / group / meeting chat that includes an external (counts messages,
                                  calls, files shared, who added the external)
      TeamsChannel                private/shared channel (or team, with -IncludeGuests) with an external member;
                                  rows exist for membership even without activity in the window
      TeamsMeetingInvite          Teams meeting (calendar) with an external attendee/organizer
      TeamsMeetingParticipation   meeting call record (actual attendance) with an external; ScreenSharing flag
      TeamsCall                   call record (peer-to-peer / group call) with an external; ScreenSharing flag

    Sharing: FilesShared* counts file/link attachments (reference attachments) in chat and channel messages;
    ScreenSharing flags call records whose modalities include screen sharing. File names are never read.
    Initiator: first interaction seen in the window (InitiatorBasis tells whether that is the chat's first message).

    Zero-trust design notes:
      - No secrets: certificate-only auth, token cache kept in-process (ContextScope Process).
      - Least privilege: only the application roles needed for the selected -Sources are checked.
      - No message content is requested into the output; only metadata (who/when/where).
      - Every paging link is validated to stay on the expected Graph host before being followed.
      - All strings that originate from external parties are sanitised against CSV/formula injection.
      - Output folder ACL is restricted (SYSTEM, Administrators, current user) when created.
      - Output files are hashed (SHA-256) in the manifest for tamper evidence.

.PARAMETER TenantId            Directory (tenant) GUID of YOUR tenant.
.PARAMETER ClientId            Application (client) GUID of the app registration.
.PARAMETER CertificateThumbprint  SHA-1 thumbprint of the authentication certificate (private key required).
.PARAMETER CertificateStore    LocalMachine (default, for services/scheduled tasks) or CurrentUser.
.PARAMETER Environment         Global (default), USGov, USGovDoD, China.
.PARAMETER DaysBack            Look-back window in days (1-365, default 30). Call records are only retained 30 days by Microsoft.
.PARAMETER Sources             Any of Chats, Channels, Meetings, Calls. Default: all.
.PARAMETER UserPrincipalName   Limit user-based sources (Chats, Meetings) to these UPNs (pilot / scoping).
.PARAMETER IncludeGuests       Report B2B guest accounts as EXTERNAL. Default: guests are treated as internal.
.PARAMETER IncludeDisabledUsers  Also process disabled internal accounts.
.PARAMETER IncludeFederationPolicy  Annotate domains with Teams external-access policy (needs MicrosoftTeams module + Teams role).
.PARAMETER OutputPath          Output folder (default: .\output next to the script).
.PARAMETER MaxRetries          Retries for throttling/transient errors (default 6).

.EXAMPLE
    .\Get-TeamsExternalInteractions.ps1 -TenantId 00000000-0000-0000-0000-000000000000 `
        -ClientId 11111111-1111-1111-1111-111111111111 -CertificateThumbprint 0123456789ABCDEF0123456789ABCDEF01234567

.EXAMPLE
    # Pilot on two users, last 7 days, chats + meetings only
    .\Get-TeamsExternalInteractions.ps1 -TenantId $t -ClientId $c -CertificateThumbprint $thumb `
        -DaysBack 7 -Sources Chats,Meetings -UserPrincipalName alice@contoso.com,bob@contoso.com

.NOTES
    Exit codes: 0 = success, 1 = fatal error, 2 = completed with one or more failed sources/warnings.
    Version 1.1.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$TenantId,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$ClientId,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$CertificateThumbprint,

    [ValidateSet('LocalMachine', 'CurrentUser')]
    [string]$CertificateStore = 'LocalMachine',

    [ValidateSet('Global', 'USGov', 'USGovDoD', 'China')]
    [string]$Environment = 'Global',

    [ValidateRange(1, 365)]
    [int]$DaysBack = 30,

    [ValidateSet('Chats', 'Channels', 'Meetings', 'Calls')]
    [string[]]$Sources = @('Chats', 'Channels', 'Meetings', 'Calls'),

    [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')]
    [string[]]$UserPrincipalName,

    [switch]$IncludeGuests,
    [switch]$IncludeDisabledUsers,
    [switch]$IncludeFederationPolicy,

    [string]$OutputPath = $(if ($PSScriptRoot) { Join-Path $PSScriptRoot 'output' } else { Join-Path (Get-Location).Path 'output' }),

    [ValidateRange(1, 10)]
    [int]$MaxRetries = 6
)

Set-StrictMode -Version 1
$ErrorActionPreference = 'Stop'

$script:ToolVersion = '1.1.0'

# ----------------------------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------------------------
function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    $line = '{0} [{1}] {2}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), $Level, $Message
    switch ($Level) {
        'WARN'  { Write-Host $line -ForegroundColor Yellow; $script:WarningCount++ }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line }
    }
    if ($script:LogFile) {
        try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 } catch { }
    }
}

# ----------------------------------------------------------------------------------------------
# Small utilities
# ----------------------------------------------------------------------------------------------
function Protect-CsvValue {
    # Neutralise control chars and spreadsheet formula injection (values come from EXTERNAL tenants).
    param($Value)
    if ($null -eq $Value) { return $null }
    $s = [string]$Value
    $s = $s -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ''
    if ($s -match '^[=+\-@\t\r]') { $s = "'" + $s }
    return $s
}

function ConvertTo-UtcDate {
    param($Value)
    if ($null -eq $Value -or [string]$Value -eq '') { return $null }
    try {
        if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
        $d = [datetimeoffset]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal)
        return $d.UtcDateTime
    } catch { return $null }
}

function Format-UtcDate {
    param($Date)
    if ($null -eq $Date) { return $null }
    return ([datetime]$Date).ToString('yyyy-MM-ddTHH:mm:ssZ')
}

function Get-EmailDomain {
    param([string]$Email)
    if ([string]::IsNullOrWhiteSpace($Email)) { return $null }
    $at = $Email.LastIndexOf('@')
    if ($at -lt 1 -or $at -eq ($Email.Length - 1)) { return $null }
    $d = $Email.Substring($at + 1).Trim().ToLowerInvariant()
    if ($d -match '^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$') { return $d }
    return $null
}

function Get-GuestMailFromUpn {
    # Guest UPN format: local_domain.tld#EXT#@tenant.onmicrosoft.com
    param([string]$Upn)
    if ($Upn -match '^(?<l>.+)_(?<d>[^_]+)#EXT#@') { return ('{0}@{1}' -f $Matches['l'], $Matches['d']) }
    return $null
}

# ----------------------------------------------------------------------------------------------
# Graph access (retry, paging, host pinning)
# ----------------------------------------------------------------------------------------------
function Get-GraphHostName {
    switch ($Environment) {
        'Global'   { 'graph.microsoft.com' }
        'USGov'    { 'graph.microsoft.us' }
        'USGovDoD' { 'dod-graph.microsoft.us' }
        'China'    { 'microsoftgraph.chinacloudapi.cn' }
    }
}

function Assert-GraphUri {
    param([string]$Uri)
    $u = $null
    if (-not [uri]::TryCreate($Uri, [UriKind]::Absolute, [ref]$u) -or $u.Scheme -ne 'https' -or $u.Host -ne $script:GraphHost) {
        throw "Refusing to call a URI outside https://$($script:GraphHost): '$Uri'"
    }
}

function Get-HttpStatus {
    param($ErrorRecord)
    $ex = $ErrorRecord.Exception
    try { if ($ex.Response -and $ex.Response.StatusCode) { return [int]$ex.Response.StatusCode } } catch { }
    if ($ex.Message -match '\b(4\d\d|5\d\d)\b') { return [int]$Matches[1] }
    return 0
}

function Get-RetryAfterSeconds {
    param($ErrorRecord)
    try {
        $v = $ErrorRecord.Exception.Response.Headers.GetValues('Retry-After') | Select-Object -First 1
        $n = 0
        if ([int]::TryParse([string]$v, [ref]$n) -and $n -gt 0) { return [math]::Min($n, 300) }
    } catch { }
    return 0
}

function Invoke-Graph {
    <# GET with throttling/transient retry. -SoftFail returns $null (and sets $script:LastStatus) instead of throwing. #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers,
        [switch]$SoftFail,
        [string]$What = 'request'
    )
    Assert-GraphUri $Uri
    $attempt = 0
    while ($true) {
        try {
            $p = @{ Method = 'GET'; Uri = $Uri; OutputType = 'PSObject'; ErrorAction = 'Stop' }
            if ($Headers) { $p['Headers'] = $Headers }
            $script:LastStatus = 200
            return (Invoke-MgGraphRequest @p)
        } catch {
            $status = Get-HttpStatus $_
            $script:LastStatus = $status
            $transient = ($status -in 429, 500, 502, 503, 504) -or ($status -eq 0)
            $attempt++
            if ($transient -and $attempt -le $MaxRetries) {
                $wait = Get-RetryAfterSeconds $_
                if ($wait -le 0) { $wait = [math]::Min(60, [math]::Pow(2, $attempt)) + (Get-Random -Minimum 0 -Maximum 3) }
                Write-Log "Transient error $status on $What; retry $attempt/$MaxRetries in ${wait}s" 'WARN'
                Start-Sleep -Seconds $wait
                continue
            }
            if ($SoftFail) {
                if (-not $script:SoftErrors.ContainsKey($What)) { $script:SoftErrors[$What] = @{} }
                $k = [string]$status
                if (-not $script:SoftErrors[$What].ContainsKey($k)) { $script:SoftErrors[$What][$k] = 0 }
                $script:SoftErrors[$What][$k]++
                return $null
            }
            throw
        }
    }
}

function Get-GraphPages {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers,
        [switch]$SoftFail,
        [string]$What = 'collection'
    )
    $items = New-Object 'System.Collections.Generic.List[object]'
    $next = $Uri
    $script:LastPagingComplete = $true
    while ($next) {
        $r = Invoke-Graph -Uri $next -Headers $Headers -SoftFail:$SoftFail -What $What
        if ($null -eq $r) { $script:LastPagingComplete = $false; break }
        foreach ($v in @($r.value)) { if ($null -ne $v) { $items.Add($v) } }
        $next = $r.'@odata.nextLink'
    }
    return , $items
}

# ----------------------------------------------------------------------------------------------
# Identity classification
# ----------------------------------------------------------------------------------------------
function Get-TenantDomain {
    param([string]$ExternalTenantId)
    if ([string]::IsNullOrWhiteSpace($ExternalTenantId)) { return $null }
    if ($script:TenantDomainCache.ContainsKey($ExternalTenantId)) { return $script:TenantDomainCache[$ExternalTenantId] }
    $domain = $null
    if (-not $script:TenantLookupDisabled -and $ExternalTenantId -match '^[0-9a-fA-F\-]{36}$') {
        $uri = "$($script:Base)/v1.0/tenantRelationships/findTenantInformationByTenantId(tenantId='$ExternalTenantId')"
        $r = Invoke-Graph -Uri $uri -SoftFail -What 'tenant lookup'
        if ($r) { $domain = ([string]$r.defaultDomainName).ToLowerInvariant() }
        elseif ($script:LastStatus -eq 403) {
            $script:TenantLookupDisabled = $true
            Write-Log 'CrossTenantInformation.ReadBasic.All not granted: domains of federated users without an e-mail will show as unresolved tenants.' 'WARN'
        }
    }
    $script:TenantDomainCache[$ExternalTenantId] = $domain
    return $domain
}

function Resolve-Party {
    <# Classifies one identity as Internal / External and derives domain + relationship. #>
    param(
        [string]$UserId,
        [string]$PartyTenantId,
        [string]$Name,
        [string]$Email,
        [string]$IdentityType = 'aad',   # aad | anonymous | acs | msa | guest
        [string]$Context = ''            # 'shared' => B2B direct connect semantics
    )
    $isInternal = $false; $isExternal = $false; $rel = $null
    $domain = $null; $domainSource = $null; $upn = $null

    if ($Email) { $Email = $Email.Trim() }
    if ($UserId -and $script:MemberMap.ContainsKey($UserId)) {
        $u = $script:MemberMap[$UserId]
        $isInternal = $true
        if (-not $Name) { $Name = $u.displayName }
        $upn = $u.userPrincipalName
        if (-not $Email) { $Email = $u.mail }
        $domain = Get-EmailDomain $upn; $domainSource = 'Directory'
    }
    elseif ($UserId -and $script:GuestMap.ContainsKey($UserId)) {
        $g = $script:GuestMap[$UserId]
        $isExternal = $true; $rel = 'Guest'
        if (-not $Name) { $Name = $g.displayName }
        $gm = $g.mail; if (-not $gm) { $gm = Get-GuestMailFromUpn $g.userPrincipalName }
        if (-not $Email) { $Email = $gm }
        $upn = $g.userPrincipalName
        $domain = Get-EmailDomain $Email; $domainSource = 'GuestMail'
    }
    elseif ($IdentityType -in 'anonymous', 'acs', 'msa', 'guest') {
        $isExternal = $true
        switch ($IdentityType) { 'anonymous' { $rel = 'Anonymous' } 'acs' { $rel = 'AzureCommunicationServices' } 'msa' { $rel = 'ConsumerAccount' } 'guest' { $rel = 'Guest' } }
    }
    elseif ($PartyTenantId -and $PartyTenantId -ne $script:HomeTenantId) {
        $isExternal = $true
        if ($Context -eq 'shared') { $rel = 'B2BDirectConnect' } else { $rel = 'Federated' }
    }
    elseif ($PartyTenantId -and $PartyTenantId -eq $script:HomeTenantId) {
        $isInternal = $true   # home-tenant identity unknown to the directory snapshot (e.g. deleted/unlicensed)
    }
    elseif ($Email) {
        $ed = Get-EmailDomain $Email
        if ($Email -and $script:GuestByMail.ContainsKey($Email)) { $isExternal = $true; $rel = 'Guest' }
        elseif ($ed -and $script:InternalDomains.Contains($ed)) { $isInternal = $true }
        elseif ($ed) { $isExternal = $true; $rel = 'ExternalEmail' }
    }

    if ($isExternal -and $rel -eq 'Guest' -and -not $IncludeGuests) { $isExternal = $false; $isInternal = $true }   # B2B guests are treated as internal by default

    if (-not $upn) { $upn = $Email }
    if (-not $domain) {
        $domain = Get-EmailDomain $Email
        if ($domain) { $domainSource = 'Email' }
    }
    if ($isExternal -and -not $domain) {
        $td = Get-TenantDomain $PartyTenantId
        if ($td) { $domain = $td; $domainSource = 'TenantLookup' }
        elseif ($PartyTenantId) { $domain = "unresolved-tenant-$PartyTenantId"; $domainSource = 'TenantIdOnly' }
        else { $domain = 'unresolved'; $domainSource = 'None' }
    }
    if (-not $isInternal -and -not $isExternal) { $script:UnclassifiedParties++ }

    [pscustomobject]@{
        Id = $UserId; Name = $Name; Email = $Email; Upn = $upn; TenantId = $PartyTenantId
        IsInternal = $isInternal; IsExternal = $isExternal; Relationship = $rel
        Domain = $domain; DomainSource = $domainSource
    }
}

# ----------------------------------------------------------------------------------------------
# Output row construction
# ----------------------------------------------------------------------------------------------
function Format-InternalList {
    param($Parties)
    $names = @($Parties | Where-Object { $_ -and $_.IsInternal } | ForEach-Object {
            if ($_.Relationship -eq 'Guest' -and $_.Email) { $_.Email } elseif ($_.Upn) { $_.Upn } elseif ($_.Email) { $_.Email } else { $_.Name }
        } | Where-Object { $_ } | Select-Object -Unique)
    if ($names.Count -le 10) { return ($names -join '; ') }
    return (($names | Select-Object -First 10) -join '; ') + "; (+$($names.Count - 10) more)"
}

function Get-PartyKey {
    param($Party)
    if ($Party.Id) { return [string]$Party.Id }
    if ($Party.Email) { return ([string]$Party.Email).ToLowerInvariant() }
    return [string]$Party.Name
}

function ConvertTo-SenderParty {
    param($User, [string]$Context = '')
    $idt = 'aad'
    switch ([string]$User.userIdentityType) {
        'anonymousGuest'                 { $idt = 'anonymous' }
        'azureCommunicationServicesUser' { $idt = 'acs' }
        'personalMicrosoftAccountUser'   { $idt = 'msa' }
    }
    Resolve-Party -UserId $User.id -PartyTenantId $User.tenantId -Name $User.displayName -IdentityType $idt -Context $Context
}

function Add-Interaction {
    <# One output row = one conversation (chat / channel / meeting / call) x one external user. #>
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Kind,
        $First, $Last,
        [string]$ConversationName,
        [string]$ConversationId,
        [string]$InteractionId,
        $Initiator,                 # party or $null (unknown)
        [string]$InitiatorBasis,
        [Parameter(Mandatory)]$External,
        $InternalParties,
        [string]$TeamName,
        [int]$MessagesFromInternal = 0,
        [int]$MessagesFromExternal = 0,
        [int]$Calls = 0,
        [string]$ExternalAddedBy,
        [int]$FilesSharedByInternal = 0,
        [int]$FilesSharedByExternal = 0,
        [bool]$ScreenSharing = $false
    )
    $initType = 'Unknown'; $direction = 'Unknown'
    if ($Initiator) {
        if ($Initiator.IsExternal) { $initType = 'External'; $direction = 'ExternalToInternal' }
        elseif ($Initiator.IsInternal) { $initType = 'Internal'; $direction = 'InternalToExternal' }
    }
    $initName = $null; $initId = $null; $initDomain = $null
    if ($Initiator) {
        $initName = $Initiator.Name
        $initId = if ($Initiator.Upn) { $Initiator.Upn } else { $Initiator.Email }
        $initDomain = $Initiator.Domain
    }
    $row = [ordered]@{
        FirstInteractionUtc    = Format-UtcDate $First
        LastInteractionUtc     = Format-UtcDate $Last
        InteractionType        = $Type
        ConversationKind       = $Kind
        TeamName               = Protect-CsvValue $TeamName
        ConversationName       = Protect-CsvValue $ConversationName
        ConversationId         = Protect-CsvValue $ConversationId
        InitiatedBy            = Protect-CsvValue $initName
        InitiatedByUpnOrEmail  = Protect-CsvValue $initId
        InitiatedByType        = $initType
        InitiatedByDomain      = Protect-CsvValue $initDomain
        InitiatorBasis         = $InitiatorBasis
        Direction              = $direction
        InternalParticipants   = Protect-CsvValue (Format-InternalList $InternalParties)
        ExternalUser           = Protect-CsvValue $External.Name
        ExternalUserEmail      = Protect-CsvValue $(if ($External.Email) { $External.Email } else { $External.Upn })
        ExternalDomain         = Protect-CsvValue $External.Domain
        ExternalDomainSource   = $External.DomainSource
        ExternalTenantId       = Protect-CsvValue $External.TenantId
        ExternalRelationship   = $External.Relationship
        MessageCount           = $MessagesFromInternal + $MessagesFromExternal
        MessagesFromInternal   = $MessagesFromInternal
        MessagesFromExternal   = $MessagesFromExternal
        Calls                  = $Calls
        ExternalAddedBy        = Protect-CsvValue $ExternalAddedBy
        FilesShared            = $FilesSharedByInternal + $FilesSharedByExternal
        FilesSharedByInternal  = $FilesSharedByInternal
        FilesSharedByExternal  = $FilesSharedByExternal
        ScreenSharing          = $ScreenSharing
    }
    $script:Rows.Add([pscustomobject]$row)
}

# ----------------------------------------------------------------------------------------------
# Source: Chats (1:1, group, meeting chats)
# ----------------------------------------------------------------------------------------------
function Get-UserChatsInWindow {
    param([Parameter(Mandatory)][string]$UserId)
    $out = New-Object 'System.Collections.Generic.List[object]'
    foreach ($mode in 'preview', 'basic') {
        if ($mode -eq 'preview') {
            $q = '$expand=members,lastMessagePreview&$orderby=' + [uri]::EscapeDataString('lastMessagePreview/createdDateTime desc') + '&$top=50'
        } else {
            $q = '$expand=members&$top=50'
        }
        $next = "$($script:Base)/v1.0/users/$UserId/chats?$q"
        $failed = $false
        while ($next) {
            $r = Invoke-Graph -Uri $next -SoftFail -What 'user chats'
            if ($null -eq $r) { $failed = $true; break }
            $stop = $false
            foreach ($c in @($r.value)) {
                $ts = $null
                if ($c.lastMessagePreview) { $ts = ConvertTo-UtcDate $c.lastMessagePreview.createdDateTime }
                $hasPreview = ($null -ne $ts)
                if (-not $ts) { $ts = ConvertTo-UtcDate $c.lastUpdatedDateTime }
                if ($ts -and $ts -lt $script:WindowStart) {
                    if ($mode -eq 'preview' -and $hasPreview) { $stop = $true; break }   # sorted desc: nothing newer follows
                    continue
                }
                $out.Add($c)
            }
            if ($stop) { break }
            $next = $r.'@odata.nextLink'
        }
        # Retry in "basic" mode only when the server rejected the query itself (400)
        if (-not $failed -or $script:LastStatus -ne 400) { break }
    }
    return , $out
}

function ConvertTo-ChatParty {
    param($Member, [string]$Context = '')
    $t = [string]$Member.'@odata.type'
    $idt = 'aad'
    if ($t -match 'anonymousGuest') { $idt = 'anonymous' }
    elseif ($t -match 'azureCommunication') { $idt = 'acs' }
    elseif ($t -match 'microsoftAccount') { $idt = 'msa' }
    Resolve-Party -UserId $Member.userId -PartyTenantId $Member.tenantId -Name $Member.displayName -Email $Member.email -IdentityType $idt -Context $Context
}

function Invoke-ChatAnalysis {
    param([Parameter(Mandatory)]$Chat)

    $members = @($Chat.members)
    if ($members.Count -ge 25) {   # $expand=members is capped at 25 by the service
        $full = Get-GraphPages -Uri "$($script:Base)/v1.0/chats/$($Chat.id)/members" -SoftFail -What 'chat members'
        if ($script:LastPagingComplete) { $members = @($full) }
    }
    $parties = New-Object 'System.Collections.Generic.List[object]'
    foreach ($m in $members) { $parties.Add((ConvertTo-ChatParty -Member $m)) }
    $externals = @($parties | Where-Object { $_.IsExternal })
    if ($externals.Count -eq 0) { return }
    $internals = @($parties | Where-Object { $_.IsInternal })

    # per-external accumulators (members now + any external sender seen in the window)
    $ext = @{}
    foreach ($p in $externals) { $ext[(Get-PartyKey $p)] = @{ Party = $p; Msgs = 0; Files = 0; Calls = 0; AddedBy = $null } }
    $intMsgs = 0; $intFiles = 0
    $first = $null; $firstBy = $null; $last = $null

    $msgs = Get-GraphPages -SoftFail -What 'chat messages' -Uri ("$($script:Base)/v1.0/chats/$($Chat.id)/messages?`$top=50&`$orderby=" +
        [uri]::EscapeDataString('lastModifiedDateTime desc') + '&$filter=' + [uri]::EscapeDataString("lastModifiedDateTime gt $($script:WindowStartIso)"))
    if (-not $script:LastPagingComplete) { $script:SourceIncomplete['Chats'] = $true }

    foreach ($msg in $msgs) {
        $created = ConvertTo-UtcDate $msg.createdDateTime
        if (-not $created -or $created -lt $script:WindowStart -or $created -gt $script:WindowEnd) { continue }
        $mtype = [string]$msg.messageType
        $actor = $null; $counted = $false

        if ($mtype -eq 'message') {
            if (-not ($msg.from -and $msg.from.user)) { continue }
            $sender = ConvertTo-SenderParty -User $msg.from.user
            if (-not ($sender.IsInternal -or $sender.IsExternal)) { continue }
            $files = @(@($msg.attachments) | Where-Object { $_ -and [string]$_.contentType -eq 'reference' }).Count
            if ($sender.IsExternal) {
                $k = Get-PartyKey $sender
                if (-not $ext.ContainsKey($k)) { $ext[$k] = @{ Party = $sender; Msgs = 0; Files = 0; Calls = 0; AddedBy = $null } }
                $ext[$k].Msgs++; $ext[$k].Files += $files
            } else { $intMsgs++; $intFiles += $files }
            $actor = $sender; $counted = $true
        }
        elseif ($mtype -eq 'systemEventMessage' -and $msg.eventDetail) {
            $et = [string]$msg.eventDetail.'@odata.type'
            $ini = $null
            if ($msg.eventDetail.initiator -and $msg.eventDetail.initiator.user) {
                $ini = Resolve-Party -UserId $msg.eventDetail.initiator.user.id -PartyTenantId $msg.eventDetail.initiator.user.tenantId -Name $msg.eventDetail.initiator.user.displayName
            }
            if ($et -match 'callEndedEventMessageDetail') {
                foreach ($cp in @($msg.eventDetail.callParticipants)) {
                    if (-not ($cp.participant -and $cp.participant.user)) { continue }
                    $pu = $cp.participant.user
                    $pp = Resolve-Party -UserId $pu.id -PartyTenantId $pu.tenantId -Name $pu.displayName
                    if (-not $pp.IsExternal) { continue }
                    $k = Get-PartyKey $pp
                    if (-not $ext.ContainsKey($k)) { $ext[$k] = @{ Party = $pp; Msgs = 0; Files = 0; Calls = 0; AddedBy = $null } }
                    $ext[$k].Calls++; $counted = $true
                }
                $actor = $ini
            }
            elseif ($et -match 'membersAddedEventMessageDetail') {
                foreach ($am in @($msg.eventDetail.members)) {
                    $ap = Resolve-Party -UserId $am.id -PartyTenantId $am.tenantId -Name $am.displayName
                    if (-not $ap.IsExternal) { continue }
                    $k = Get-PartyKey $ap
                    if (-not $ext.ContainsKey($k)) { $ext[$k] = @{ Party = $ap; Msgs = 0; Files = 0; Calls = 0; AddedBy = $null } }
                    if (-not $ext[$k].AddedBy -and $ini) { $ext[$k].AddedBy = $ini.Name }
                    $counted = $true
                }
                $actor = $ini
            }
        }
        if ($counted) {
            if (-not $first -or $created -lt $first) { $first = $created; $firstBy = $actor }
            if (-not $last -or $created -gt $last) { $last = $created }
        }
    }
    if (-not $first) { return }   # no interaction with an external inside the window
    $script:Counters.ChatsWithExternals++

    $created = ConvertTo-UtcDate $Chat.createdDateTime
    $basis = 'FirstMessageInWindow'
    if ($created -and $created -ge $script:WindowStart) { $basis = 'FirstMessageInChat' }

    foreach ($v in $ext.Values) {
        Add-Interaction -Type 'TeamsChat' -Kind ([string]$Chat.chatType) -First $first -Last $last -ConversationName ([string]$Chat.topic) -ConversationId $Chat.id `
            -InteractionId $Chat.id -Initiator $firstBy -InitiatorBasis $basis -External $v.Party -InternalParties $internals `
            -MessagesFromInternal $intMsgs -MessagesFromExternal $v.Msgs -Calls $v.Calls -ExternalAddedBy $v.AddedBy `
            -FilesSharedByInternal $intFiles -FilesSharedByExternal $v.Files
    }
}

function Invoke-SourceChats {
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $i = 0
    foreach ($u in $script:TargetUsers) {
        $i++
        if ($i % 50 -eq 0) { Write-Log "Chats: processed $i/$($script:TargetUsers.Count) users, $($script:Counters.ChatsWithExternals) external chats so far" }
        $chats = Get-UserChatsInWindow -UserId $u.id
        foreach ($c in $chats) {
            if (-not $seen.Add([string]$c.id)) { continue }
            $script:Counters.ChatsInspected++
            try { Invoke-ChatAnalysis -Chat $c }
            catch { Write-Log "Chat $($c.id) failed: $($_.Exception.Message)" 'WARN'; $script:SourceIncomplete['Chats'] = $true }
        }
    }
}

# ----------------------------------------------------------------------------------------------
# Source: Channels (guests in teams, private + shared channels)
# ----------------------------------------------------------------------------------------------
function Invoke-SourceChannels {
    $teams = Get-GraphPages -What 'teams' -Uri ("$($script:Base)/v1.0/groups?`$filter=" +
        [uri]::EscapeDataString("resourceProvisioningOptions/Any(x:x eq 'Team')") + '&$select=id,displayName&$top=100')
    Write-Log "Channels: $($teams.Count) teams to inspect"
    foreach ($team in $teams) {
        try {
            # Team-level members only matter for external identities when guests are reported as external.
            $teamExternals = @()
            if ($IncludeGuests) {
                $teamMembers = Get-GraphPages -SoftFail -What 'team members' -Uri "$($script:Base)/v1.0/teams/$($team.id)/members"
                foreach ($m in $teamMembers) {
                    $p = ConvertTo-ChatParty -Member $m
                    if ($p.IsExternal) { $teamExternals += $p }
                }
            }
            $channels = Get-GraphPages -SoftFail -What 'channels' -Uri "$($script:Base)/v1.0/teams/$($team.id)/channels"
            foreach ($ch in $channels) {
                $mt = [string]$ch.membershipType
                $ctx = ''; if ($mt -eq 'shared') { $ctx = 'shared' }
                $externals = $teamExternals
                if ($mt -in 'private', 'shared') {
                    $externals = @()
                    $cm = Get-GraphPages -SoftFail -What 'channel members' -Uri "$($script:Base)/v1.0/teams/$($team.id)/channels/$($ch.id)/members"
                    foreach ($m in $cm) {
                        $p = ConvertTo-ChatParty -Member $m -Context $ctx
                        if ($p.IsExternal) { $externals += $p }
                    }
                }
                if ($externals.Count -eq 0) { continue }
                $script:Counters.ChannelsWithExternals++
                $kind = if ($mt) { "$($mt)Channel" } else { 'standardChannel' }

                $ext = @{}
                foreach ($p in $externals) { $ext[(Get-PartyKey $p)] = @{ Party = $p; Msgs = 0; Files = 0 } }
                $intMsgs = 0; $intFiles = 0; $intSenders = @{}
                $first = $null; $firstBy = $null; $last = $null

                $uri = "$($script:Base)/v1.0/teams/$($team.id)/channels/$($ch.id)/messages/delta?`$filter=" +
                    [uri]::EscapeDataString("lastModifiedDateTime gt $($script:WindowStartIso)")
                $msgs = Get-GraphPages -SoftFail -What 'channel messages' -Uri $uri
                if (-not $script:LastPagingComplete) { $script:SourceIncomplete['Channels'] = $true }
                foreach ($msg in $msgs) {
                    if ($msg.'@removed' -or [string]$msg.messageType -ne 'message') { continue }
                    $created = ConvertTo-UtcDate $msg.createdDateTime
                    if (-not $created -or $created -lt $script:WindowStart -or $created -gt $script:WindowEnd) { continue }
                    if (-not ($msg.from -and $msg.from.user)) { continue }
                    $sender = ConvertTo-SenderParty -User $msg.from.user -Context $ctx
                    if (-not ($sender.IsInternal -or $sender.IsExternal)) { continue }
                    $files = @(@($msg.attachments) | Where-Object { $_ -and [string]$_.contentType -eq 'reference' }).Count
                    if ($sender.IsExternal) {
                        $k = Get-PartyKey $sender
                        if (-not $ext.ContainsKey($k)) { $ext[$k] = @{ Party = $sender; Msgs = 0; Files = 0 } }
                        $ext[$k].Msgs++; $ext[$k].Files += $files
                    } else {
                        $intMsgs++; $intFiles += $files
                        $sk = Get-PartyKey $sender; if (-not $intSenders.ContainsKey($sk)) { $intSenders[$sk] = $sender }
                    }
                    if (-not $first -or $created -lt $first) { $first = $created; $firstBy = $sender }
                    if (-not $last -or $created -gt $last) { $last = $created }
                }
                $basis = if ($first) { 'FirstMessageInWindow' } else { 'NoActivityInWindow (membership only)' }
                foreach ($v in $ext.Values) {
                    Add-Interaction -Type 'TeamsChannel' -Kind $kind -First $first -Last $last -ConversationName $ch.displayName -ConversationId $ch.id `
                        -InteractionId $ch.id -Initiator $firstBy -InitiatorBasis $basis -External $v.Party -InternalParties @($intSenders.Values) -TeamName $team.displayName `
                        -MessagesFromInternal $intMsgs -MessagesFromExternal $v.Msgs -FilesSharedByInternal $intFiles -FilesSharedByExternal $v.Files
                }
            }
        }
        catch { Write-Log "Team $($team.id) failed: $($_.Exception.Message)" 'WARN'; $script:SourceIncomplete['Channels'] = $true }
    }
}

# ----------------------------------------------------------------------------------------------
# Source: Meetings (scheduled Teams meetings from calendars)
# ----------------------------------------------------------------------------------------------
function Invoke-SourceMeetings {
    $agg = @{}
    $hdr = @{ 'Prefer' = 'outlook.timezone="UTC"' }
    $select = 'iCalUId,subject,start,organizer,attendees,isOnlineMeeting,onlineMeetingProvider,isCancelled'
    $i = 0
    foreach ($u in $script:TargetUsers) {
        $i++
        if ($i % 50 -eq 0) { Write-Log "Meetings: processed $i/$($script:TargetUsers.Count) mailboxes" }
        $uri = "$($script:Base)/v1.0/users/$($u.id)/calendarView?startDateTime=$($script:WindowStartIso)&endDateTime=$($script:WindowEndIso)&`$select=$select&`$top=100"
        $events = Get-GraphPages -Uri $uri -Headers $hdr -SoftFail -What 'calendar view'
        if (-not $script:LastPagingComplete -and $script:LastStatus -notin 403, 404) { $script:SourceIncomplete['Meetings'] = $true }
        $owner = Resolve-Party -UserId $u.id
        foreach ($ev in $events) {
            if (-not $ev.isOnlineMeeting -or [string]$ev.onlineMeetingProvider -ne 'teamsForBusiness' -or $ev.isCancelled) { continue }
            $start = ConvertTo-UtcDate $ev.start.dateTime
            if (-not $start -or $start -gt $script:WindowEnd) { continue }
            $org = $null
            if ($ev.organizer -and $ev.organizer.emailAddress) {
                $org = Resolve-Party -Name $ev.organizer.emailAddress.name -Email $ev.organizer.emailAddress.address
            }
            $cands = New-Object 'System.Collections.Generic.List[object]'
            foreach ($a in @($ev.attendees)) {
                if ([string]$a.type -eq 'resource' -or -not $a.emailAddress) { continue }
                $cands.Add((Resolve-Party -Name $a.emailAddress.name -Email $a.emailAddress.address))
            }
            if ($org -and $org.IsExternal) { $cands.Add($org) }
            foreach ($e in $cands) {
                if (-not $e.IsExternal) { continue }
                $key = '{0}|{1}|{2}' -f $ev.iCalUId, (Format-UtcDate $start), $e.Email
                if (-not $agg.ContainsKey($key)) {
                    $agg[$key] = @{ Start = $start; Subject = $ev.subject; Id = $ev.iCalUId; Org = $org; Ext = $e; Internals = @{} }
                }
                if ($owner.IsInternal) { $agg[$key].Internals[$owner.Upn] = $owner }
                if ($org -and $org.IsInternal) { $agg[$key].Internals[$org.Upn] = $org }
            }
        }
    }
    foreach ($v in $agg.Values) {
        Add-Interaction -Type 'TeamsMeetingInvite' -Kind 'scheduledMeeting' -First $v.Start -Last $v.Start -InitiatorBasis 'Organizer' -ConversationName $v.Subject -ConversationId $v.Id -InteractionId $v.Id `
            -Initiator $v.Org -External $v.Ext -InternalParties @($v.Internals.Values)
    }
}

# ----------------------------------------------------------------------------------------------
# Source: Calls / meeting attendance (call records, retained 30 days by Microsoft)
# ----------------------------------------------------------------------------------------------
function ConvertTo-CallParty {
    param($Participant)
    if (-not $Participant) { return $null }
    $idn = $Participant.identity
    if (-not $idn) { return $null }
    if ($idn.user) {
        return (Resolve-Party -UserId $idn.user.id -PartyTenantId $idn.user.tenantId -Name $idn.user.displayName)
    }
    if ($idn.guest) { return (Resolve-Party -UserId $idn.guest.id -PartyTenantId $idn.guest.tenantId -Name $idn.guest.displayName -IdentityType 'guest') }
    if ($idn.acsUser) { return (Resolve-Party -UserId $idn.acsUser.id -Name $idn.acsUser.displayName -IdentityType 'acs') }
    return $null   # applications, devices, PSTN phones: not an external Teams domain
}

function Invoke-SourceCalls {
    $from = $script:WindowStart
    if ($DaysBack -gt 30) {
        $from = $script:WindowEnd.AddDays(-30)
        Write-Log 'Call records are retained 30 days by Microsoft: Calls source is limited to the last 30 days.' 'WARN'
    }
    $uri = "$($script:Base)/v1.0/communications/callRecords?`$filter=" + [uri]::EscapeDataString("startDateTime ge $(Format-UtcDate $from)")
    $records = Get-GraphPages -Uri $uri -What 'call records'
    Write-Log "Calls: $($records.Count) call records in window"
    $n = 0
    foreach ($rec in $records) {
        $n++
        if ($n % 200 -eq 0) { Write-Log "Calls: processed $n/$($records.Count)" }
        $full = Invoke-Graph -Uri "$($script:Base)/v1.0/communications/callRecords/$($rec.id)?`$expand=participants_v2" -SoftFail -What 'call record detail'
        if ($null -eq $full) { $script:SourceIncomplete['Calls'] = $true; continue }

        $parts = New-Object 'System.Collections.Generic.List[object]'
        foreach ($p in @($full.participants_v2)) {
            $cp = ConvertTo-CallParty $p
            if ($cp) { $parts.Add($cp) }
        }
        $ext = @($parts | Where-Object { $_.IsExternal })
        if ($ext.Count -eq 0) { continue }
        $int = @($parts | Where-Object { $_.IsInternal })
        $org = ConvertTo-CallParty $full.organizer_v2
        if ($org -and -not ($org.IsInternal -or $org.IsExternal)) { $org = $null }

        $type = 'TeamsCall'; $kind = [string]$full.type
        if ($full.joinWebUrl) { $type = 'TeamsMeetingParticipation'; $kind = 'meeting' }
        $start = ConvertTo-UtcDate $full.startDateTime
        $end = ConvertTo-UtcDate $full.endDateTime; if (-not $end) { $end = $start }
        $mods = @($full.modalities)
        $sharing = ($mods -contains 'screenSharing') -or ($mods -contains 'videoBasedScreenSharing')
        $callCount = 0; if ($type -eq 'TeamsCall') { $callCount = 1 }
        foreach ($e in $ext) {
            Add-Interaction -Type $type -Kind $kind -First $start -Last $end -ConversationName $null -ConversationId $full.id -InteractionId $full.id `
                -Initiator $org -InitiatorBasis 'Organizer/Caller' -External $e -InternalParties $int -Calls $callCount -ScreenSharing $sharing
        }
    }
}

# ----------------------------------------------------------------------------------------------
# Optional: Teams external access policy (MicrosoftTeams module)
# ----------------------------------------------------------------------------------------------
function Get-FederationPolicy {
    try {
        if (-not (Get-Module -ListAvailable -Name MicrosoftTeams)) { throw 'MicrosoftTeams module is not installed.' }
        Import-Module MicrosoftTeams -ErrorAction Stop
        $cmd = Get-Command Connect-MicrosoftTeams
        if ($cmd.Parameters.ContainsKey('Certificate')) {
            Connect-MicrosoftTeams -ApplicationId $ClientId -TenantId $TenantId -Certificate $script:AuthCert | Out-Null
        } else {
            Connect-MicrosoftTeams -ApplicationId $ClientId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint | Out-Null
        }
        $fed = Get-CsTenantFederationConfiguration
        $allowAll = $false; $allowed = @(); $blocked = @()
        $ad = $fed.AllowedDomains
        if ($ad -and $ad.GetType().Name -match 'AllowAllKnownDomains') { $allowAll = $true }
        elseif ($ad -and $ad.AllowedDomain) { $allowed = @($ad.AllowedDomain | ForEach-Object { ([string]$_.Domain).ToLowerInvariant() }) }
        elseif ($ad) { $allowed = @($ad | ForEach-Object { ([string]$_.Domain).ToLowerInvariant() }) }
        if ($fed.BlockedDomains) { $blocked = @($fed.BlockedDomains | ForEach-Object { ([string]$_.Domain).ToLowerInvariant() }) }
        return [pscustomobject]@{ AllowFederatedUsers = [bool]$fed.AllowFederatedUsers; AllowAll = $allowAll; Allowed = $allowed; Blocked = $blocked }
    }
    catch { Write-Log "Federation policy unavailable: $($_.Exception.Message)" 'WARN'; return $null }
    finally { try { Disconnect-MicrosoftTeams -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { } }
}

function Get-DomainPolicyStatus {
    param($Policy, [string]$Domain, [string[]]$Relationships)
    if (-not $Policy) { return 'NotEvaluated' }
    $nonGuest = @($Relationships | Where-Object { $_ -and $_ -ne 'Guest' })
    if ($nonGuest.Count -eq 0) { return 'N/A (guest access, governed by Entra ID)' }
    if (-not $Policy.AllowFederatedUsers) { return 'ExternalAccessDisabled' }
    if ($Policy.Blocked -contains $Domain) { return 'Blocked' }
    if ($Policy.AllowAll) { return 'Allowed (open federation)' }
    if ($Policy.Allowed -contains $Domain) { return 'Allowed (explicit)' }
    return 'NotInAllowList'
}

# ----------------------------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------------------------
function New-DomainSummary {
    param($Rows, $Policy)
    $out = New-Object 'System.Collections.Generic.List[object]'
    foreach ($g in ($Rows | Group-Object ExternalDomain)) {
        $r = @($g.Group)
        $times = @($r | ForEach-Object { $_.FirstInteractionUtc; $_.LastInteractionUtc } | Where-Object { $_ } | Sort-Object)
        $internal = @($r | ForEach-Object {
                if ($_.InitiatedByType -eq 'Internal' -and $_.InitiatedByUpnOrEmail) { $_.InitiatedByUpnOrEmail }
                if ($_.InternalParticipants) { $_.InternalParticipants -split '; ' }
            } | Where-Object { $_ -and $_ -notmatch '^\(\+\d+ more\)$' } | Select-Object -Unique)
        $rels = @($r | ForEach-Object { $_.ExternalRelationship } | Where-Object { $_ } | Select-Object -Unique | Sort-Object)
        $sum = { param($p) [int](($r | Measure-Object -Property $p -Sum).Sum) }
        $out.Add([pscustomobject][ordered]@{
                ExternalDomain          = $g.Name
                PolicyStatus            = Get-DomainPolicyStatus -Policy $Policy -Domain $g.Name -Relationships $rels
                Relationships           = ($rels -join '; ')
                Conversations           = $r.Count
                Chats                   = @($r | Where-Object InteractionType -eq 'TeamsChat').Count
                Channels                = @($r | Where-Object InteractionType -eq 'TeamsChannel').Count
                MeetingInvites          = @($r | Where-Object InteractionType -eq 'TeamsMeetingInvite').Count
                MeetingParticipations   = @($r | Where-Object InteractionType -eq 'TeamsMeetingParticipation').Count
                CallRecords             = @($r | Where-Object InteractionType -eq 'TeamsCall').Count
                InitiatedByInternal     = @($r | Where-Object InitiatedByType -eq 'Internal').Count
                InitiatedByExternal     = @($r | Where-Object InitiatedByType -eq 'External').Count
                Messages                = & $sum 'MessageCount'
                MessagesFromInternal    = & $sum 'MessagesFromInternal'
                MessagesFromExternal    = & $sum 'MessagesFromExternal'
                CallsInChats            = @($r | Where-Object InteractionType -eq 'TeamsChat' | Measure-Object -Property Calls -Sum).Sum
                FilesShared             = & $sum 'FilesShared'
                FilesSharedByInternal   = & $sum 'FilesSharedByInternal'
                FilesSharedByExternal   = & $sum 'FilesSharedByExternal'
                ScreenSharingSessions   = @($r | Where-Object { $_.ScreenSharing -eq $true -or $_.ScreenSharing -eq 'True' }).Count
                UniqueExternalUsers     = @($r | ForEach-Object { if ($_.ExternalUserEmail) { $_.ExternalUserEmail } else { $_.ExternalUser } } | Select-Object -Unique).Count
                UniqueInternalUsers     = $internal.Count
                FirstSeenUtc            = if ($times.Count) { $times[0] } else { $null }
                LastSeenUtc             = if ($times.Count) { $times[-1] } else { $null }
            })
    }
    return @($out | Sort-Object -Property Conversations -Descending)
}

function Protect-OutputDirectory {
    param([string]$Path)
    try {
        if ($env:OS -ne 'Windows_NT') { return }
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "${me}:(OI)(CI)F" | Out-Null
    } catch { Write-Log "Could not tighten ACL on '$Path': $($_.Exception.Message)" 'WARN' }
}

function Get-AuthCertificate {
    $path = "Cert:\$CertificateStore\My\$($CertificateThumbprint.ToUpperInvariant())"
    $cert = Get-Item -LiteralPath $path -ErrorAction Stop
    if (-not $cert.HasPrivateKey) { throw "Certificate $CertificateThumbprint has no accessible private key." }
    $now = Get-Date
    if ($cert.NotAfter -lt $now -or $cert.NotBefore -gt $now) { throw "Certificate $CertificateThumbprint is not within its validity period." }
    if ($cert.NotAfter -lt $now.AddDays(30)) { Write-Log "Certificate expires on $($cert.NotAfter.ToString('yyyy-MM-dd')): rotate soon." 'WARN' }
    return $cert
}

# ----------------------------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------------------------
function Invoke-Main {
    $script:WarningCount = 0
    $script:SoftErrors = @{}
    $script:SourceIncomplete = @{}
    $script:Rows = New-Object 'System.Collections.Generic.List[object]'
    $script:Counters = @{ ChatsInspected = 0; ChatsWithExternals = 0; ChannelsWithExternals = 0 }
    $script:UnclassifiedParties = 0
    $script:TenantDomainCache = @{}
    $script:TenantLookupDisabled = $false
    $script:MemberMap = @{}; $script:GuestMap = @{}; $script:GuestByMail = @{}
    $script:InternalDomains = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $script:GraphHost = Get-GraphHostName
    $script:Base = "https://$($script:GraphHost)"
    $script:WindowEnd = (Get-Date).ToUniversalTime()
    $script:WindowStart = $script:WindowEnd.AddDays(-$DaysBack)
    $script:WindowStartIso = Format-UtcDate $script:WindowStart
    $script:WindowEndIso = Format-UtcDate $script:WindowEnd
    $runId = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $sourceStatus = [ordered]@{}
    $connected = $false

    try {
        # --- output folder ---------------------------------------------------------------------
        if (-not (Test-Path -LiteralPath $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
            Protect-OutputDirectory -Path $OutputPath
        }
        $OutputPath = (Resolve-Path -LiteralPath $OutputPath).Path
        $script:LogFile = Join-Path $OutputPath "TeamsExternalInteractions_$runId.log"
        Write-Log "Teams external interactions collector v$($script:ToolVersion) starting. Window: $($script:WindowStartIso) -> $($script:WindowEndIso); sources: $($Sources -join ',')"

        # --- authentication (certificate, app-only, in-process token cache) --------------------
        $script:AuthCert = Get-AuthCertificate
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -Certificate $script:AuthCert -Environment $Environment -ContextScope Process -NoWelcome -ErrorAction Stop | Out-Null
        $connected = $true
        $ctx = Get-MgContext
        if ($ctx.TenantId -ne $TenantId) { throw "Connected tenant '$($ctx.TenantId)' does not match -TenantId." }

        $needed = @('Organization.Read.All', 'User.Read.All')
        if ($Sources -contains 'Chats')    { $needed += 'Chat.Read.All' }
        if ($Sources -contains 'Channels') { $needed += 'Group.Read.All', 'Channel.ReadBasic.All', 'ChannelMember.Read.All', 'TeamMember.Read.All', 'ChannelMessage.Read.All' }
        if ($Sources -contains 'Meetings') { $needed += 'Calendars.Read' }
        if ($Sources -contains 'Calls')    { $needed += 'CallRecords.Read.All' }
        $granted = @($ctx.Scopes)
        $missing = @()
        if ($granted.Count -gt 0) {
            $missing = @($needed | Where-Object { $granted -notcontains $_ })
            if ($missing.Count) { Write-Log "Application roles not present in the token: $($missing -join ', '). Affected sources may fail." 'WARN' }
        }

        # --- home tenant + directory snapshot ---------------------------------------------------
        $org = Invoke-Graph -Uri "$($script:Base)/v1.0/organization?`$select=id,verifiedDomains" -What 'organization'
        $orgObj = @($org.value) | Select-Object -First 1
        $script:HomeTenantId = [string]$orgObj.id
        if ($script:HomeTenantId -ne $TenantId) { throw "Organization id '$($script:HomeTenantId)' does not match -TenantId." }
        foreach ($d in @($orgObj.verifiedDomains)) { [void]$script:InternalDomains.Add(([string]$d.name).ToLowerInvariant()) }
        Write-Log "Home tenant verified; $($script:InternalDomains.Count) verified domains."

        $users = Get-GraphPages -What 'users' -Uri "$($script:Base)/v1.0/users?`$select=id,displayName,userPrincipalName,mail,userType,accountEnabled&`$top=999"
        foreach ($u in $users) {
            if ([string]$u.userType -eq 'Guest') {
                $script:GuestMap[[string]$u.id] = $u
                $gm = $u.mail; if (-not $gm) { $gm = Get-GuestMailFromUpn $u.userPrincipalName }
                if ($gm) { $script:GuestByMail[([string]$gm).ToLowerInvariant()] = $u.id }
            } else { $script:MemberMap[[string]$u.id] = $u }
        }
        Write-Log "Directory snapshot: $($script:MemberMap.Count) members, $($script:GuestMap.Count) guests."

        $targets = @($script:MemberMap.Values | Where-Object { $IncludeDisabledUsers -or $_.accountEnabled })
        if ($UserPrincipalName) {
            $set = @($UserPrincipalName | ForEach-Object { $_.ToLowerInvariant() })
            $targets = @($targets | Where-Object { $set -contains ([string]$_.userPrincipalName).ToLowerInvariant() })
            if ($targets.Count -eq 0) { throw 'None of the supplied -UserPrincipalName values matched an internal user.' }
        }
        $script:TargetUsers = $targets
        Write-Log "User-based sources will cover $($targets.Count) internal users."

        # --- sources ----------------------------------------------------------------------------
        $map = [ordered]@{ Chats = 'Invoke-SourceChats'; Channels = 'Invoke-SourceChannels'; Meetings = 'Invoke-SourceMeetings'; Calls = 'Invoke-SourceCalls' }
        foreach ($s in $map.Keys) {
            if ($Sources -notcontains $s) { $sourceStatus[$s] = 'Skipped'; continue }
            Write-Log "Source '$s' started."
            $before = $script:Rows.Count
            try {
                & $map[$s]
                $sourceStatus[$s] = if ($script:SourceIncomplete.ContainsKey($s)) { 'CompletedWithErrors' } else { 'Completed' }
            } catch {
                $sourceStatus[$s] = 'Failed'
                Write-Log "Source '$s' failed: $($_.Exception.Message)" 'ERROR'
            }
            Write-Log "Source '$s' finished: status $($sourceStatus[$s]), $($script:Rows.Count - $before) rows."
        }

        # --- optional federation policy ---------------------------------------------------------
        $policy = $null
        if ($IncludeFederationPolicy) { $policy = Get-FederationPolicy }

        # --- outputs ----------------------------------------------------------------------------
        $rows = @($script:Rows | Sort-Object FirstInteractionUtc, ExternalDomain)
        $interCsv = Join-Path $OutputPath "TeamsExternalInteractions_$runId.csv"
        $domCsv = Join-Path $OutputPath "TeamsExternalDomainSummary_$runId.csv"
        $manifest = Join-Path $OutputPath "TeamsExternalInteractions_$runId.manifest.json"

        $nti = @{}; if ($PSVersionTable.PSVersion.Major -lt 6) { $nti['NoTypeInformation'] = $true }
        if ($rows.Count -gt 0) { $rows | Export-Csv -LiteralPath $interCsv -Encoding UTF8 @nti }
        else { 'FirstInteractionUtc,InteractionType' | Set-Content -LiteralPath $interCsv -Encoding UTF8 }
        $summary = @()
        if ($rows.Count -gt 0) { $summary = New-DomainSummary -Rows $rows -Policy $policy }
        if ($summary.Count -gt 0) { $summary | Export-Csv -LiteralPath $domCsv -Encoding UTF8 @nti }
        else { 'ExternalDomain,TotalInteractions' | Set-Content -LiteralPath $domCsv -Encoding UTF8 }

        $softErr = @{}
        foreach ($k in $script:SoftErrors.Keys) { $softErr[$k] = $script:SoftErrors[$k] }
        $meta = [ordered]@{
            toolVersion = $script:ToolVersion; runId = $runId; generatedUtc = (Format-UtcDate (Get-Date).ToUniversalTime())
            tenantId = $TenantId; clientId = $ClientId; environment = $Environment; certificateThumbprint = $CertificateThumbprint.ToUpperInvariant()
            windowStartUtc = $script:WindowStartIso; windowEndUtc = $script:WindowEndIso
            sources = $sourceStatus; scopedToUsers = [bool]$UserPrincipalName; includeGuests = [bool]$IncludeGuests
            counts = [ordered]@{ interactions = $rows.Count; externalDomains = $summary.Count; chatsInspected = $script:Counters.ChatsInspected
                chatsWithExternals = $script:Counters.ChatsWithExternals; channelsWithExternals = $script:Counters.ChannelsWithExternals
                unclassifiedParties = $script:UnclassifiedParties; warnings = $script:WarningCount }
            missingRoles = $missing
            tolerated_http_errors = $softErr
            federationPolicyEvaluated = [bool]$policy
            outputs = @(
                [ordered]@{ file = (Split-Path $interCsv -Leaf); sha256 = (Get-FileHash -LiteralPath $interCsv -Algorithm SHA256).Hash },
                [ordered]@{ file = (Split-Path $domCsv -Leaf); sha256 = (Get-FileHash -LiteralPath $domCsv -Algorithm SHA256).Hash }
            )
        }
        $meta | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifest -Encoding UTF8

        Write-Log "Done. $($rows.Count) interactions across $($summary.Count) external domains."
        Write-Log "Interactions : $interCsv"
        Write-Log "Domain report: $domCsv"
        Write-Log "Manifest     : $manifest"

        $failed = @($sourceStatus.Values | Where-Object { $_ -in 'Failed', 'CompletedWithErrors' })
        if ($failed.Count -gt 0) { return 2 }
        return 0
    }
    catch {
        Write-Log "Fatal: $($_.Exception.Message)" 'ERROR'
        return 1
    }
    finally {
        if ($connected) { try { Disconnect-MgGraph | Out-Null } catch { } }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    exit (Invoke-Main)
}
