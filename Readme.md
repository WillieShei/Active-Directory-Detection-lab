# Active Directory Detection Lab (Splunk)

A home lab for building and validating security detections in Splunk against a live Active Directory environment. Every detection here is tested by running the actual attack technique and confirming the detection fires, rather than copied from a rule set and assumed to work.

## Environment

| Component | Detail |
|-----------|--------|
| SIEM | Splunk Enterprise 10.4.2 on Ubuntu Server, running as a dedicated service account |
| Endpoint | Windows Server domain controller (`DC01`, domain `corp.local`) |
| Log shipping | Splunk Universal Forwarder → indexer on port 9997 |
| Endpoint telemetry | Sysmon 15.21 with the [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) config; PowerShell script block logging enabled |
| Virtualization | VirtualBox, isolated internal network for domain traffic plus a host-only network for management |

### Data pipeline

Windows Security, System, and PowerShell Operational logs flow to the `wineventlog` index; Sysmon flows to `sysmon`. Ingest is filtered at the forwarder with event-code whitelists rather than shipping every event, keeping the environment under the free-tier license limit while retaining the events that matter for detection. Field parsing is handled by the Splunk Add-on for Microsoft Windows and the Splunk Add-on for Sysmon, with custom search-time extractions where the add-ons leave gaps (for example, `ScriptBlockText` out of 4104 events).

## Detection content

All detections, field extractions, and saved searches live in a self-contained Splunk app (`lab_detections/`) so the work is version-controlled, survives Splunk upgrades, and is cleanly separated from vendor content.

| Detection | Technique | Data source | Status |
|-----------|-----------|-------------|--------|
| [Kerberoasting — RC4 Service Ticket Request](detections/kerberoasting-rc4-service-ticket.md) | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | 4769 | Validated |

*(more to follow — LSASS credential access on Sysmon EID 10 is next)*

## Approach

The point of this lab is the engineering discipline, not the volume of rules:

- **Baseline before detecting.** Each detection starts by characterizing normal traffic, so the anomaly it keys on is understood rather than assumed.
- **Validate against live attacks.** A detection is not "done" until the technique has been executed in the lab and the detection has been seen to fire on it.
- **Document tradeoffs honestly.** Where a lab choice differs from what production would do (search-window width, single-endpoint artifacts like loopback client addresses), it is written down and explained, not hidden.
- **Debug with the platform's own telemetry.** When something doesn't fire, the answer is in Splunk's internal logs (`index=_internal`), not in guesswork.

## License note

Built on the Splunk Enterprise free tier. Scheduled alerting is available on the trial and is disabled when the trial converts to Splunk Free, so scheduled-search behaviour is captured while it is available.

