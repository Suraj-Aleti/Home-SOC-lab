# Home SOC Lab — Detection Engineering Write-Up

**Stack:** Kali Linux (attacker) · Metasploitable2 (victim) · Splunk Enterprise (SIEM) · Suricata (NIDS)
**Techniques covered:** Brute Force (T1110) · Port Scanning (T1046) · Exploitation of a Known Vulnerable Service (T1190)
**Status:** Active / ongoing — new techniques added as the lab grows.

---

## Objective / Scope

Built a personal Security Operations Center (SOC) lab to gain hands-on experience with attack simulation and detection engineering, complementing coursework and certification study with practical, demonstrable work.

**Goal:** simulate real attacker techniques mapped to MITRE ATT&CK, ingest logs into a SIEM, and write detection queries that catch the activity — then document the full loop from attack → log → detection.

## Architecture

| Component | Role | Details |
|---|---|---|
| Kali Linux | Attacker + NIDS | VirtualBox VM, runs attacks against the victim; also runs Suricata as a lightweight network IDS on its own interface |
| Metasploitable2 | Victim | Deliberately vulnerable Ubuntu 8.04 VM, VirtualBox |
| Splunk Enterprise (Free tier) | SIEM | Installed on host machine, receives forwarded logs from both VMs |

**Network:** Both VMs on a VirtualBox **Host-only Adapter** (isolated from the internet, host and VMs can reach each other). Chosen over Internal Network since it auto-assigns IPs via DHCP. Kali additionally has a second, NAT-attached adapter used solely for package installation (e.g. `apt install suricata`) — Metasploitable2 never received a NAT adapter, preserving its full isolation.

**Log pipeline (Metasploitable2):** `syslog` (via `sysklogd`) forwards events over UDP to the host machine's Host-only IP, where Splunk listens on port 514.

**Log pipeline (Kali):** Kali runs `rsyslog` (modern syslog daemon) configured to forward to the same Splunk UDP:514 listener. Suricata's alert output (`/var/log/suricata/fast.log`) is tailed and piped into `logger -t suricata`, tagging each alert so it rides the existing syslog forwarding pipe into Splunk alongside Kali's other system logs.

**Notable setup issue resolved (Metasploitable2):** Metasploitable2's ancient `sysklogd` did not correctly parse the `@host:port` syslog forwarding syntax — the `:514` port suffix caused silent forwarding failure. Fixed by using the bare `@host` syntax (defaults to port 514). Confirmed the fix using `tcpdump` on the victim VM to verify outbound UDP packets before/after the config change.

**Notable setup issue resolved (Kali):** Kali initially had no `rsyslog` installed at all (minimal image). After installing it and editing the config, the running `rsyslogd` process had not reloaded the new config — a full `systemctl restart` (rather than assuming the prior restart had applied it) was required before forwarding actually began. Verified with `tcpdump` on the Host-only interface before and after.

**Field extraction:** Configured a custom Splunk field extraction (`src_ip`) against `sourcetype=syslog` so source IPs are automatically parsed from raw event text, rather than requiring an inline `rex` in every search.

---

## Attack Simulated #1 — Brute Force (MITRE ATT&CK T1110)

**What was done:** Repeated SSH login attempts from Kali against Metasploitable2 using intentionally incorrect passwords, followed by a successful login.

```
ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa msfadmin@<victim-ip>
```

**Log source:** `syslog` (sshd auth events forwarded from Metasploitable2)

**Detection query (failed attempts by source, thresholded):**
```spl
index=main sourcetype=syslog "Failed password"
| stats count by src_ip
| where count > 3
```

**Follow-through query (failures → eventual success, same source):**
```spl
index=main sourcetype=syslog ("Failed password" OR "Accepted password")
| table _time, src_ip, _raw
```
Sorted by time, this shows the narrative: multiple failures followed by a successful login from the same source IP — mapping to **T1110 (Brute Force)** followed by **T1078 (Valid Accounts)**.

<img width="2880" height="1516" alt="image" src="https://github.com/user-attachments/assets/4478f6d6-8baa-4947-80a5-600389efc464" />


**Result:** Detection successfully flagged the brute-force pattern once failure count exceeded the threshold.

---

## Attack Simulated #2 — Port Scan (MITRE ATT&CK T1046)

**What was done:** Ran an nmap service/version-detection scan from Kali against Metasploitable2:

```
nmap -sV 192.168.56.101
```

`-sV` extends a standard port scan (which only sends TCP SYN packets to determine open/closed state) by actively connecting to each open port and sending protocol-specific probe data, then matching the response against a signature database to identify the service and version running. This is why the scan additionally returned entries like `vsftpd 2.3.4`, `Postfix smtpd`, and `Apache httpd 2.2.8`, rather than just bare port/service-name guesses.

**Scan results:** 21 open ports identified across FTP, SSH, Telnet, SMTP, DNS, HTTP, RPC, Samba, NFS, MySQL, PostgreSQL, VNC, IRC, and others — several with known-vulnerable versions (e.g. `vsftpd 2.3.4`, `distccd`, `UnrealIRCd`).

**Log source:** `syslog` (forwarded from Metasploitable2)

**Result:** No unified "port scan detected" event appeared anywhere in Splunk. Instead, the scan produced **fragmented, service-specific noise** scattered across unrelated log sources:
- `postfix/anvil` connection statistics (max cache size, connection count/rate)
- `kernel` NFS version warnings (`unknown version ... for prog 100003, nfsd`)
- Apache JK connector (`jsvc.exec`) warnings and errors (`Closing ajp connection`, `BAD packet signature`)

None of these entries contained the scanning source IP, and none were tagged or correlated as scan activity — each service simply logged its own confusion about the probe traffic it received, with no way to connect the dots between them without manually correlating timestamps across sources.

**Finding:** Port scan activity produced no unified detection signal on this host. Without network-layer visibility (e.g., a NIDS or firewall connection logging), a port scan is effectively invisible as a discrete event — it only surfaces as disconnected background noise across whichever services happen to react to the probes, which would be extremely difficult to correlate at any meaningful scale. This is a real, common detection gap: application/syslog-level logging alone is insufficient to catch reconnaissance activity; it requires purpose-built network-layer monitoring.


---

### Closing the gap — adding Suricata (Network IDS)

The finding above (no unified detection for scan activity) motivated adding a lightweight **Suricata** NIDS instance on Kali, monitoring its own outbound interface (`eth0`), to catch reconnaissance traffic at the network layer rather than relying on incidental application logging.

**Setup:**
```
sudo apt install suricata -y
sudo suricata-update
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```

**Forwarding Suricata alerts into the same Splunk pipeline:** Suricata's `fast.log` alert output is tailed and piped into `logger`, tagging entries as `suricata` so they ride the existing syslog → Splunk forwarding path:
```
sudo tail -f /var/log/suricata/fast.log | logger -t suricata
```

**Re-running the same scan** (`nmap -sV 192.168.56.101`) with Suricata active produced a clean, correctly-attributed alert using the Emerging Threats ruleset:

```
[**] [1:2024364:5] ET SCAN Possible Nmap User-Agent Observed [**]
[Classification: Web Application Attack] [Priority: 1]
{TCP} 192.168.56.102:49444 -> 192.168.56.101:80
```

This single signature-based alert correctly identifies the source (`192.168.56.102`, Kali), destination and port (`192.168.56.101:80`), and the technique (nmap's HTTP User-Agent string observed during service-version probing) — a stark contrast to the fragmented, uncorrelated syslog noise from the same scan documented above.

**Detection query (Splunk):**
```spl
index=main "suricata" "ET SCAN"
```

**Before / after finding:** Application-level syslog alone could not surface the port scan as a discrete event. Adding network-layer monitoring (Suricata) closed that gap, producing a single, correctly-attributed, signature-matched alert for the same activity — demonstrating why SOC environments layer network-based detection (NIDS) alongside host/application log aggregation rather than relying on either alone.

<img width="2874" height="1510" alt="image" src="https://github.com/user-attachments/assets/5ffdbc07-4ae6-4af1-b636-ccd6e391c594" />

---

## Attack Simulated #3 — Exploitation of a Known Vulnerable Service (MITRE ATT&CK T1190)

**What was done:** The nmap scan (Attack #2) identified `vsftpd 2.3.4` running on Metasploitable2 — a version with a publicly known, intentionally-planted backdoor. Used Metasploit to exploit it directly from Kali:

```
msfconsole
search vsftpd
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 192.168.56.101
set LHOST 192.168.56.102
run
```

**Result:** Full root shell obtained with zero authentication — the backdoor activates when a username containing `:)` is sent to the FTP service, which opens a listener on TCP port 6200 that Metasploit then connects to automatically. Confirmed with `getuid` → `root`.

**Initial finding — no detection at all:** Checked both `syslog` (Metasploitable2/Kali) and the existing stock Suricata ruleset — **nothing related to the exploit appeared anywhere.** Unlike the port scan (which at least produced incidental noise), this exploit left **zero trace** in any existing log source: vsftpd does not log the malicious connection any differently than a normal one, and the stock Suricata ruleset had no signature for this specific, well-known backdoor. This is a more serious gap than Attack #2 — a scan is reconnaissance, but this is a full compromise, and it was completely invisible.

**Closing the gap — writing a custom Suricata detection:** Wrote two custom rules targeting the two network-visible stages of this exploit (the trigger string and the resulting backdoor shell connection), added to `/var/lib/suricata/rules/local.rules` (Suricata's actual default rule path — note: NOT `/etc/suricata/rules/`, which is a separate directory that isn't loaded by default; had to add `local.rules` explicitly under `rule-files:` in `suricata.yaml` and copy the rule file to the correct path):

```
alert tcp any any -> 192.168.56.101 21 (msg:"CUSTOM vsftpd Backdoor Trigger (smiley) Observed"; content:"|3a 29|"; sid:1000001; rev:1;)
alert tcp any any -> 192.168.56.101 6200 (msg:"CUSTOM vsftpd Backdoor Shell Connection on Port 6200"; sid:1000002; rev:1;)
```

**Re-ran the exploit** with the custom rules loaded. Both fired correctly:

```
[**] [1:1000001:1] CUSTOM vsftpd Backdoor Trigger (smiley) Observed [**]
{TCP} 192.168.56.102:43391 -> 192.168.56.101:21

[**] [1:1000002:1] CUSTOM vsftpd Backdoor Shell Connection on Port 6200 [**]
{TCP} 192.168.56.102:34375 -> 192.168.56.101:6200
```

**Detection query (Splunk):**
```spl
index=main "suricata" "CUSTOM"
```

**Finding:** A fully successful, zero-authentication root compromise produced no signal whatsoever in host logging or stock NIDS rules. Closing this gap required writing custom, exploit-specific network signatures — general-purpose rulesets and default application logging are not sufficient against known backdoors unless a signature specifically exists for them. This is a realistic illustration of why detection engineering requires proactively researching and authoring rules for known threats relevant to an environment, rather than assuming default tooling covers everything.

<img width="2880" height="1518" alt="image" src="https://github.com/user-attachments/assets/1d711ea0-6e38-491a-9ae1-2dc72a563809" />

---

## Findings / Limitations

- SSH auth logs never contain plaintext passwords, by design — brute-force detection therefore relies on **behavioral thresholds** (failure counts per source over time), not credential inspection.
- Metasploitable2 has no firewall/connection logging enabled by default, so port scan activity produced only scattered, uncorrelated application-level noise (see Attack #2) rather than a discrete, detectable event — a real gap that required network-layer monitoring (e.g. a NIDS like Suricata) to close.
- A successful root-level exploit (Attack #3) produced zero trace in any default log source or stock NIDS ruleset — detection required authoring custom, exploit-specific signatures, underscoring that default tooling does not automatically cover known threats without deliberate signature research.

## What I'd Improve

- Upgrade Suricata forwarding from `fast.log` (plain text) to `eve.json` (structured JSON alerts) for richer, more queryable fields in Splunk.
- Convert the brute-force detection query into a scheduled Splunk alert (Save As → Alert) rather than a manual search.
- Tune the failure-count threshold to reduce false positives in a shared-IP environment.
- Expand log sources beyond syslog (e.g. auditd, application logs) for broader technique coverage.
- Add a second victim host or web-app target (DVWA) to cover web-based attack techniques.

---

*Lab built using VirtualBox, Kali Linux, Metasploitable2, and Splunk Enterprise (Free tier). All activity conducted against self-hosted, isolated VMs — no external systems targeted.*
