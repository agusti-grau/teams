# Teams External Interactions Report

Read-only PowerShell collector that reports **every Microsoft Teams interaction between internal users and
external parties** and rolls it up **per external domain**, to support Security reviews and the management of
Teams external access (allowed/blocked domains).

* Windows Server, Windows PowerShell 5.1 or PowerShell 7
* App-only authentication with a **certificate** (no secrets, no user sign-in)
* Metadata only - **no message bodies and no file names** are written to the output
* **B2B guests are treated as internal by default** (use `-IncludeGuests` to report them as external)

## Output

| File | Content |
|---|---|
| `TeamsExternalInteractions_<runId>.csv` | **One row per conversation x external user** |
| `TeamsExternalDomainSummary_<runId>.csv` | One row per external domain (volumes, sharing, unique users, relationships, policy status) |
| `TeamsExternalInteractions_<runId>.manifest.json` | Parameters, per-source status, counts, SHA-256 of outputs |
| `TeamsExternalInteractions_<runId>.log` | Run log |

### Interactions CSV columns

`FirstInteractionUtc, LastInteractionUtc, InteractionType, ConversationKind, TeamName, ConversationName, ConversationId,
InitiatedBy, InitiatedByUpnOrEmail, InitiatedByType, InitiatedByDomain, InitiatorBasis, Direction, InternalParticipants,
ExternalUser, ExternalUserEmail, ExternalDomain, ExternalDomainSource, ExternalTenantId, ExternalRelationship,
MessageCount, MessagesFromInternal, MessagesFromExternal, Calls, ExternalAddedBy,
FilesShared, FilesSharedByInternal, FilesSharedByExternal, ScreenSharing`

| InteractionType | A "conversation" is... | Source |
|---|---|---|
| `TeamsChat` | a 1:1 / group / meeting chat that includes an external (messages, calls, files, who added the external) | Chats |
| `TeamsChannel` | a private/shared channel (or team channel with `-IncludeGuests`) with an external member; a row exists for membership even without activity in the window | Channels |
| `TeamsMeetingInvite` | a scheduled Teams meeting (calendar) with an external attendee/organiser | Meetings |
| `TeamsMeetingParticipation` | a meeting actually attended by an external (call record); `ScreenSharing` flag | Calls |
| `TeamsCall` | a 1:1 / group call with an external (call record); `ScreenSharing` flag | Calls |

Column semantics:

* **Initiator** = who produced the first interaction inside the window. `InitiatorBasis` says whether that was the
  chat's very first message (`FirstMessageInChat`) or only the first one in the window (`FirstMessageInWindow`);
  meetings/calls use the organiser/caller; channels with no activity show `NoActivityInWindow (membership only)`.
* **Direction**: `InternalToExternal` / `ExternalToInternal`, from the initiator.
* **Counts** (`MessagesFromInternal` is the internal side in total; `MessagesFromExternal` is *this* external's own
  messages; so a group chat with two externals has two rows sharing the internal total).
* **Sharing**: `FilesShared*` counts file/link attachments (`reference` attachments) in chat and channel messages;
  `ScreenSharing` is true when the call record's modalities include screen sharing. SharePoint/OneDrive sharing-link
  creation itself is *not* covered (that lives in the Purview unified audit log).
* `ExternalRelationship`: `Federated` (external access), `B2BDirectConnect` (shared channel), `Anonymous`,
  `AzureCommunicationServices`, `ConsumerAccount`, `ExternalEmail` (calendar address only), `Guest` (only with `-IncludeGuests`).
* `ExternalDomainSource`: `Email`, `GuestMail`, `TenantLookup` (federated users without an e-mail are resolved from
  the tenant ID), `TenantIdOnly` (could not be resolved).

### Domain summary and policy status

With `-IncludeFederationPolicy` each domain gets a `PolicyStatus` from `Get-CsTenantFederationConfiguration`:
`Allowed (open federation)`, `Allowed (explicit)`, `NotInAllowList`, `Blocked`, `ExternalAccessDisabled`, or
`N/A (guest access, governed by Entra ID)`. Typical uses: domains with heavy traffic but not in your allow-list
(policy drift / candidates to allow), allow-listed domains with zero traffic (candidates to remove), domains with
file/screen sharing from external initiators.

## Limits you should know about

* **Call records are only retained 30 days by Microsoft** - the `Calls` source cannot look further back. Run the
  script on a schedule (e.g. weekly) and archive the CSVs for longer history.
* Chat/channel messages are only returned while they exist (retention policies/deletions apply).
* `TeamsMeetingInvite` is *scheduled* meetings from calendars; `TeamsMeetingParticipation` is *actual* attendance.
  Ad-hoc meetings appear only in the latter.
* Federated users sometimes carry no e-mail; their domain is then resolved from the tenant's default domain,
  which can be an `*.onmicrosoft.com` name rather than the e-mail domain used in your allow-list.
* Teams **protected APIs**: reading chat/channel messages with application permissions may require Microsoft
  approval for the app: <https://learn.microsoft.com/graph/teams-protected-apis>. The script deliberately avoids the
  metered `getAllMessages` APIs.
* **Scale (~4,000 users)**: chats and calendars are enumerated per user (about 8,000 list calls plus one call per
  external chat/meeting/call record). Expect roughly 1-3 hours, dominated by throttling (HTTP 429 is handled with
  back-off). Run it off-hours from a scheduled task, do a pilot first with `-UserPrincipalName`, and use
  `-Sources` to split the work across runs if needed. Progress is logged every 50 users.

## Setup

### 1. Certificate

Create (or use your PKI) a certificate with a private key in `LocalMachine\My` on the server, exportable = No.

```powershell
$cert = New-SelfSignedCertificate -Subject 'CN=TeamsExternalInteractionsReport' -CertStoreLocation Cert:\LocalMachine\My `
        -KeyExportPolicy NonExportable -KeySpec Signature -KeyLength 3072 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(1)
Export-Certificate -Cert $cert -FilePath .\TeamsExternalInteractionsReport.cer   # public part only
$cert.Thumbprint
```

Grant the account that runs the script read access to the private key (certlm.msc > All Tasks > Manage Private Keys).

### 2. App registration (single tenant)

Entra admin center > App registrations > New registration. Upload the `.cer` under *Certificates & secrets*.
Add **Application** permissions (Microsoft Graph) and grant admin consent. Grant only what your `-Sources` need:

| Permission | Needed for |
|---|---|
| `Organization.Read.All`, `User.Read.All` | always (tenant id, verified domains, user/guest directory) |
| `Chat.Read.All` | Chats |
| `Group.Read.All`, `Channel.ReadBasic.All`, `ChannelMember.Read.All`, `ChannelMessage.Read.All` (+ `TeamMember.Read.All` only with `-IncludeGuests`) | Channels |
| `Calendars.Read` | Meetings |
| `CallRecords.Read.All` | Calls |
| `CrossTenantInformation.ReadBasic.All` | resolving the domain of federated users with no e-mail (recommended) |

These are high-privilege, read-everything permissions. Mitigate:

* `Calendars.Read`: restrict the app to specific mailboxes with **RBAC for Applications in Exchange Online**
  (or an Application Access Policy). Mailboxes the app cannot read are logged and skipped.
* Add a **Conditional Access** workload-identity policy limiting the app to the server's egress IP.
* Use a dedicated app, one certificate per server, rotate at least yearly (script warns < 30 days to expiry).
* Alert on sign-ins and permission changes of the app (Entra audit/sign-in logs).

Optional `-IncludeFederationPolicy`: install the `MicrosoftTeams` module (`Install-Module MicrosoftTeams -RequiredVersion <pinned>`)
and give the app's service principal the **Teams Administrator** (or a custom Teams read-only) Entra role.

### 3. Install the Graph module (pin the version you have reviewed)

```powershell
Install-Module Microsoft.Graph.Authentication -RequiredVersion 2.25.0 -Scope AllUsers -Repository PSGallery
```

Only `Microsoft.Graph.Authentication` is needed (the script calls Graph REST directly - small supply-chain surface).

### 4. Run

```powershell
.\Get-TeamsExternalInteractions.ps1 `
    -TenantId <tenant-guid> -ClientId <app-guid> -CertificateThumbprint <thumbprint> `
    -DaysBack 30 -IncludeFederationPolicy
```

Pilot first: `-DaysBack 7 -Sources Chats -UserPrincipalName alice@contoso.com`.
Scheduled task: run as a dedicated service account (or gMSA) with *Log on as a batch job*, action
`powershell.exe -NoProfile -ExecutionPolicy AllSigned -File C:\Scripts\Get-TeamsExternalInteractions.ps1 ...`;
sign the script with your code-signing certificate for `AllSigned`.

Exit codes: `0` success, `1` fatal, `2` finished but some source failed / was incomplete (see manifest and log).

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-TenantId` `-ClientId` `-CertificateThumbprint` | required | App-only identity |
| `-CertificateStore` | `LocalMachine` | or `CurrentUser` |
| `-Environment` | `Global` | `USGov`, `USGovDoD`, `China` |
| `-DaysBack` | `30` | 1-365 |
| `-Sources` | all | `Chats`, `Channels`, `Meetings`, `Calls` |
| `-UserPrincipalName` | all users | Scope chats/meetings to specific users |
| `-IncludeGuests` | off | Report B2B guests as external (default: guests are internal) |
| `-IncludeDisabledUsers` | off | Include disabled accounts |
| `-IncludeFederationPolicy` | off | Add Teams external-access policy status per domain |
| `-OutputPath` | `.\output` | Created with restricted ACL (SYSTEM, Administrators, current user) |
| `-MaxRetries` | `6` | Throttling/transient retries |

## Security and privacy model

* **Certificate auth only**, token cache `ContextScope Process`; no secrets in script, config or logs.
* Connected tenant and `organization.id` must equal `-TenantId`, otherwise the run aborts.
* All requests are `GET`; the script never writes to the tenant. Paging URLs are validated to stay on the Graph host.
* Input is validated (GUID/thumbprint/UPN patterns); no `Invoke-Expression`, no downloads, no dynamic code.
* Values coming from external tenants (display names, subjects) are sanitised against CSV formula injection.
* The reports are personal data (employees' and externals' names/e-mails/communication metadata): store them in a
  restricted location, define retention, and make sure the processing is covered by your works-council/DPIA
  requirements. `.gitignore` blocks reports and key material from being committed.
* The manifest contains SHA-256 hashes of the outputs for tamper evidence.

## Testing

`tests/Invoke-MockRun.ps1` runs the collector against an in-memory mock of Graph (no tenant needed), once with
default settings and once with `-IncludeGuests`:

```powershell
pwsh -File tests/Invoke-MockRun.ps1
```

## Troubleshooting

| Symptom | Cause |
|---|---|
| `403` on chats/messages | Missing `Chat.Read.All` consent, or protected-API approval pending |
| Many `404`/`403` in `tolerated_http_errors` for user chats/calendars | Unlicensed users / mailboxes outside the RBAC scope (expected) |
| Domains shown as `unresolved-tenant-<guid>` | `CrossTenantInformation.ReadBasic.All` not granted or tenant not resolvable |
| `Application roles not present in the token` | Consent not granted for that permission |

## Status

The collector is covered by an offline mock test only. It has **not yet been validated against a live tenant**:
run a pilot (`-UserPrincipalName`, short `-DaysBack`) and review the output before relying on it.

## License

[MIT](LICENSE). The report output contains personal data; handling it lawfully is the operator's responsibility.
