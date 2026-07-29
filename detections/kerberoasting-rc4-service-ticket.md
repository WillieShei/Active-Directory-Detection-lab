# Detection: Kerberoasting via RC4 Service Ticket Request

**MITRE ATT&CK:** [T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
**Data source:** Windows Security Event Log (EventCode 4769), forwarded from a domain controller
**Platform:** Splunk Enterprise 10.4.2
**Status:** Validated against a live in-lab attack

## What the attack does

Any authenticated domain user can request a Kerberos service ticket (TGS) for any account that has a Service Principal Name (SPN) registered. The domain controller issues that ticket encrypted with the target service account's password hash. This is normal Kerberos behaviour, not a flaw.

The abuse: an attacker requests tickets for one or more service accounts, extracts them from memory, and cracks them offline against a wordlist. Because the cracking happens off the DC, on hardware the attacker controls, the theft itself generates no further activity on the network. Service accounts are attractive targets because their passwords are often set once and rarely rotated.

The single artifact the DC records is a 4769 event for each ticket request.

## Detection logic

Two signals separate a Kerberoast from normal ticket traffic:

1. **Encryption downgrade.** Modern Active Directory issues service tickets with AES (encryption type `0x12`). Kerberoasting tools deliberately request RC4 (`0x17`) because RC4 tickets are faster to crack. In an environment where AES is the norm, an RC4 request for a user service account is anomalous.
2. **Volume and target.** A single account requesting tickets for many distinct services in a short window is behaviourally suspect, regardless of encryption type.

This detection keys on the encryption downgrade and groups by requesting account to surface the volumetric pattern.

### SPL

```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$"
| stats count min(_time) as firstTime max(_time) as lastTime values(Service_Name) as services by Account_Name, Client_Address
| convert ctime(firstTime) ctime(lastTime)
| where count > 0
```

**Clause by clause:**

- `EventCode=4769` — Kerberos service ticket requests only.
- `Ticket_Encryption_Type=0x17` — RC4, the downgrade tell.
- `Service_Name!="*$"` — excludes machine accounts, whose names end in `$` and which legitimately request tickets constantly. This scopes the detection to user service accounts, where Kerberoasting lives.
- `stats ... by Account_Name, Client_Address` — collapses many requests from one source into a single row, exposing the volumetric signature. `values(Service_Name)` lists every service the account roasted.
- `convert ctime(...)` — renders the first/last timestamps human-readable.

## Baseline

Before testing, the environment's 4769 traffic was captured to establish what "normal" looks like:

```spl
index=wineventlog EventCode=4769
| stats count by Service_Name, Ticket_Encryption_Type
| sort -count
```

Result: **every** service ticket used encryption type `0x12` (AES256). No RC4 present. This clean baseline is what makes the RC4 signal reliable here; in a production environment with legacy systems still negotiating RC4, the detection would need additional tuning (for example, allow-listing known RC4-dependent services, or leaning more heavily on the volumetric signal).

## Validation

The detection was tested against a live attack in the lab rather than assumed to work.

**Setup — a deliberately vulnerable target account was created on the DC:**

```powershell
New-ADUser -Name "svc-sql" -SamAccountName "svc-sql" -UserPrincipalName "svc-sql@corp.local" -AccountPassword (ConvertTo-SecureString "<password>" -AsPlainText -Force) -Enabled $true
setspn -A MSSQLSvc/db01.corp.local:1433 svc-sql
```

**Attack — a service ticket was requested using a built-in .NET class, no third-party tooling:**

```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/db01.corp.local:1433"
```

That any domain user can do this with a native class, no attack framework required, is itself worth noting: the barrier to Kerberoasting is low.

**Result — the DC logged a 4769 that the detection matched:**

| Field | Value |
|-------|-------|
| EventCode | 4769 |
| Service Name | svc-sql |
| Ticket Encryption Type | 0x17 (RC4) |
| Account Name | Administrator@CORP.LOCAL |
| Client Address | ::1 |

The RC4 encryption type against an all-AES baseline made this unambiguous.

### Note on `Client Address: ::1`

The client address logged as `::1`, IPv6 loopback, because the test was executed on the DC itself, the only Windows host in this single-endpoint lab. In a real Kerberoast the request originates from the attacker's workstation, and this field would carry that host's address, making it a primary pivot for locating the source of the activity. The loopback value here is a lab artifact, not a property of the technique.

## Operationalization

The detection runs as a scheduled saved search in the `lab_detections` app:

```ini
[Kerberoasting - RC4 Service Ticket Request]
search = index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" \
| stats count min(_time) as firstTime max(_time) as lastTime values(Service_Name) as services by Account_Name, Client_Address \
| convert ctime(firstTime) ctime(lastTime) \
| where count > 0
dispatch.earliest_time = -60m
dispatch.latest_time = now
enableSched = 1
cron_schedule = */5 * * * *
alert_type = number of events
alert_comparator = greater than
alert_threshold = 0
```

**Design tradeoff — search window.** The lab runs a 60-minute lookback so that manually generated test events stay catchable across the gap between running an attack and the next scheduled fire. A production deployment would run a tighter window aligned to the schedule interval (for example `-15m` on a 5-minute cron, giving overlap without a coverage gap), to reduce duplicate alerting on the same event across successive runs. The wide window is a deliberate lab-testing choice, documented rather than hidden.

## Limitations and future work

- **Single tells can be evaded.** An attacker who requests AES tickets instead of RC4 defeats the encryption-type clause. The volumetric signal (one account, many services, short window) is the more robust detection and is the natural next iteration: alert on `distinct_count(Service_Name)` per account over time rather than on encryption type alone.
- **RC4 in production.** Environments with legacy dependencies may see benign RC4, requiring allow-listing before this detection is low-noise.
- **No correlation yet.** A stronger version would correlate the 4769 with subsequent authentication from the roasted account, catching the point where a cracked credential is actually used.

## Lessons from building it

- The detection logic was proven interactively in the search bar before being promoted to a saved search. Config was never trusted until the SPL was known to match real data.
- When the scheduled alert did not fire, the Splunk scheduler log (`index=_internal sourcetype=scheduler`) showed the search running successfully with `result_count=0` — the problem was a time-window gap, not broken logic. Reading the scheduler log rather than guessing is the fastest way to triage a detection that isn't firing.
