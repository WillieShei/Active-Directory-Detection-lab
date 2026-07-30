# Detection: LSASS Credential Access from an Unexpected Source

**MITRE ATT&CK:** [T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
**Data source:** Sysmon Event ID 10 (ProcessAccess)
**Platform:** Splunk Enterprise 10.4.2, Sysmon 15.21 with the sysmon-modular config
**Status:** Validated against a live attack, with the primary defensive control both enforced and bypassed

## What the attack does

LSASS (`lsass.exe`) is the Windows process that holds credential material in memory: password hashes, Kerberos tickets, sometimes cleartext. Credential dumping means opening a handle to LSASS, reading its memory, then extracting credentials from the captured data offline. It's a common post-exploitation step because the credentials it yields enable lateral movement.

This validation uses a living-off-the-land variant: `rundll32.exe` invoking the `MiniDump` export of the built-in `comsvcs.dll`. No external tooling, no dropped binary, just signed Windows components used against their intent. That's why the technique is worth detecting: there's no malicious file to catch, only a behavior.

## Where the detection actually lives

This one comes down to *where* the filtering happens: in the SIEM query, or in what the sensor chooses to record. Here, most of the work is already done before Splunk ever sees the event, and that changed how I wrote the rule.

The sysmon-modular config doesn't log every handle opened to LSASS. Its Event ID 10 rule group is an include filter keyed on `CallTrace`:

```xml
<!-- Event ID 10 == ProcessAccess - Includes -->
<RuleGroup groupRelation="or">
  <ProcessAccess onmatch="include">
    <CallTrace name="technique_id=T1003,..." condition="contains">dbghelp.dll</CallTrace>
    <CallTrace name="technique_id=T1003,..." condition="contains">dbgcore.dll</CallTrace>
```

Sysmon only records an LSASS access when the call stack routes through `dbghelp.dll` or `dbgcore.dll`, the debugging libraries that memory-dumping code loads. Instead of logging every benign handle, it records only accesses that look like a dump in progress. By the time an event reaches Splunk, the hard filtering is already done.

## Baseline

Before writing any detection logic, I looked at what LSASS access normally looks like:

```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| stats count by SourceImage, GrantedAccess
| sort -count
```

| SourceImage | GrantedAccess | count |
|-------------|---------------|-------|
| `C:\Windows\Sysmon64.exe` | `0x1fffff` | 650 |
| `C:\Windows\system32\csrss.exe` | `0x1fffff` | 1 |
| `C:\Windows\system32\wininit.exe` | `0x1fffff` | 1 |

Two things stood out. Only three processes touch LSASS in a way that matches the CallTrace filter, and all three are signed Windows binaries, so the known-good list is short and clean. And every one of them requests `0x1fffff` (PROCESS_ALL_ACCESS, the widest rights available, which includes memory read). That second point rules out access-rights as a signal: the legitimate baseline already sits at the highest access level that exists. The only thing left to key on is the source.

## Detection logic

Since the telemetry layer already isolated dump-like accesses, the SIEM rule just needs to answer one question: was the accessor one of the three known-good processes, or something else?

```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| rex field=SourceImage "(?<src>[^\\\\]+)$"
| search NOT src IN ("Sysmon64.exe","csrss.exe","wininit.exe")
| stats count min(_time) as firstTime max(_time) as lastTime values(GrantedAccess) as access values(CallTrace) as calltrace by SourceImage, src
| convert ctime(firstTime) ctime(lastTime)
| where count > 0
```

`EventCode=10 TargetImage="*lsass.exe"` pulls handles opened to LSASS, already CallTrace-filtered by Sysmon. The `rex` line strips the full path down to just the executable name so the exclusion list stays readable. `NOT src IN (...)` drops the three known-good baseline accessors, so anything left is an unexpected process touching LSASS. Carrying `values(CallTrace)` into the result means a triggered alert comes with the call stack attached, so you can see why it fired without going back to raw logs.

## Validation, both sides of the control

The point wasn't just to confirm the detection fires. It was to run the technique against a real defensive control, once with that control active and once with it gone.

### With Microsoft Defender enabled

Defender's real-time protection was on, the default state, when I ran:

```powershell
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass-pid> C:\Windows\Temp\lsass.dmp full
```

Result: `Access is denied`, even from an elevated prompt. Defender's LSASS protection blocked the handle before the dump could start. No dump file was written, and because the access never fully opened, no Event ID 10 was generated either. Worth noting on its own: the DC's default posture already defeats this specific technique.

### With protection removed

To test the case a real environment has to plan for (the control absent, misconfigured, or evaded), I disabled real-time monitoring on the isolated lab DC, ran the dump to completion, then restored protection immediately:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true    # temporary, isolated lab only
# ... run the MiniDump (now completes) ...
Set-MpPreference -DisableRealtimeMonitoring $false   # restored immediately
Remove-Item C:\Windows\Temp\lsass.dmp -Force         # dump contains credential material; deleted
```

The dump completed this time, and Sysmon logged the event the detection is built to catch:

| Field | Value |
|-------|-------|
| SourceImage | `C:\Windows\system32\rundll32.exe` |
| TargetImage | `C:\Windows\system32\lsass.exe` |
| GrantedAccess | `0x1fffff` |
| CallTrace | `... dbgcore.dll+a47a | ... comsvcs.dll+2715a | rundll32.exe+4266 ...` |

Read the `CallTrace` from the bottom up: `rundll32.exe` calls into `comsvcs.dll`, which calls into `dbgcore.dll` (the library that does the actual dump), ending in a full-access handle to `lsass.exe`. `dbgcore.dll` showing up is what satisfied Sysmon's include filter in the first place. The rule then fired because `rundll32.exe` isn't in the baseline.

## One attempt that didn't generate an event

Earlier, I tried Task Manager's "Create dump file" option on `lsass.exe`. The dump file was created, but no matching Event ID 10 showed up. Task Manager's dump path doesn't route through `dbghelp.dll`/`dbgcore.dll` the way the include filter requires, so Sysmon never recorded it. This is a good reminder that the CallTrace filter targets specific dump *techniques*, not the act of dumping in general, and a detection is only as good as the telemetry backing it.

## Limitations

- **The exclusion is filename-based**, which is weak. An attacker who renames their tool to `Sysmon64.exe` would slip past the same exclusion. A production version should match on the full signed path and ideally verify the signature.
- **CallTrace can be evaded.** Dumping techniques that skip `dbghelp`/`dbgcore` (direct syscalls, custom minidump code) never trip the Sysmon include filter, so they never reach this rule. Closing that gap means adding telemetry from somewhere else, like kernel callbacks or EDR.
- **Defender already stops the tested variant.** In this environment `comsvcs` is caught upstream. This detection matters more for environments where that control is weaker or absent, or for techniques Defender doesn't cover.

## What I took away from building it

Recognizing that Sysmon had already done the CallTrace filtering turned what could've been a complex access-mask rule into a simple source-exclusion one. Knowing where the filtering already happens saves you from rebuilding it in SPL.

The baseline mattered more than I expected going in. Seeing that every legitimate accessor uses `0x1fffff` ruled out an access-rights detection before I wrote one line of SPL.

And testing both sides of Defender gave a more honest picture than a single "it fires" screenshot would have: one control working as intended, the same technique caught by telemetry once that control is gone.
