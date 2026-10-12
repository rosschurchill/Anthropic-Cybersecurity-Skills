---
name: detecting-remote-service-session-hijacking
description: 'Detects remote service session hijacking (MITRE T1563) - RDP takeover via tscon.exe /dest:rdp-tcp# (often run as SYSTEM, needing no credentials) and 4778/4779 reconnect-from-new-source handoffs, and SSH hijacking via reuse of another user''s SSH agent socket (SSH_AUTH_SOCK) or multiplexed ControlMaster channel - by correlating session reconnect/disconnect events, tscon process creation, and lateral activity that occurs with NO matching new authentication event. Use when hunting lateral movement that rides an existing RDP or SSH session rather than a fresh logon. Keywords: RDP hijacking, tscon, Event ID 4778 4779, SSH agent socket, SSH_AUTH_SOCK, session hijack, T1563. Do not use for broad lateral-movement hunting or new-session remote access with stolen credentials - use detecting-lateral-movement-in-network.'
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- threat-detection
- session-hijacking
- lateral-movement
- rdp
- ssh
- tscon
- windows-events
- t1563
- auditd
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-03
- DE.AE-02
- PR.AA-05
- RS.MI-01
mitre_attack:
- T1563
- T1563.001
- T1563.002
- T1021.001
- T1021.004
---

# Detecting Remote Service Session Hijacking

## When to Use

Use this skill to detect **takeover of a pre-existing remote session** (RDP or
SSH) for lateral movement (ATT&CK T1563) — distinct from opening a *new* session
with valid accounts. For RDP, catch `tscon.exe` session reassignment (often as
SYSTEM, needing no credentials) and reconnect-from-new-source handoffs. For SSH,
catch reuse of another user's SSH agent socket / multiplexed session where
activity continues with no corresponding new authentication event. Reach for it
when:

- Lateral movement appears without a matching fresh logon.
- `tscon.exe` with `/dest:rdp-tcp#` runs, especially at SYSTEM.
- A process touches another user's SSH agent socket.

For broad lateral-movement hunting or new-session access with stolen creds, use
`detecting-lateral-movement-in-network`.

## Prerequisites

- **Windows RDP**: Security Event ID **4778** (reconnect) / **4779** (disconnect)
  with source IP; **4624** type 10 (RemoteInteractive) and **4648**; process
  creation 4688 / Sysmon 1 for `tscon.exe`, `query session`/`qwinsta`;
  TerminalServices-LocalSessionManager/RemoteConnectionManager operational logs;
  System **7045** (service create) for the persistence variant.
- **Linux/macOS SSH**: `auditd` SYSCALL for `open`/`connect` on `$SSH_AUTH_SOCK`
  and `/tmp/ssh-*` agent sockets, EXECVE for `ssh`/`scp`/`sftp`, and
  `auth.log`/`secure` sshd session open/close; process ancestry of shells under
  sshd.
- A way to tie **session activity to authentication events** (the core
  correlation).

## Workflow

1. **RDP tscon redirect.** Alert on `tscon.exe` with ` /dest:rdp-tcp#`,
   especially when the process runs at SYSTEM integrity — this reassigns another
   user's session with no credentials.
2. **RDP reconnect handoff (hunt).** A **4778** (reconnect) for an account
   immediately following a **4779** (disconnect) for the *same account from a
   different source IP*, with **no fresh 4624 logon** — the hijack handoff.
   Corroborate with `rdpclip.exe`/`tstheme.exe` spawning under an unexpected
   session.
3. **RDP persistence variant.** Alert on `sc.exe`/7045 creating a service whose
   binary path contains `tscon.exe`.
4. **SSH agent-socket abuse.** Alert when a process owned by user A accesses user
   B's `$SSH_AUTH_SOCK`/`/tmp/ssh-*`; correlate with outbound ssh from the host
   that has **no matching new sshd auth event**.
5. **SSH multiplex reuse.** Flag new commands over an existing ControlMaster
   channel from an unexpected process/user.
6. **Apply the core invariant and respond.** Across both: *session activity
   continues or a lateral connection occurs without a corresponding new
   authentication event.*

## Key Concepts

- **Hijack vs new logon:** the defining difference is the **absence of a new
  auth event** for activity that should require one — that is what separates
  T1563 from T1021.
- **tscon needs no password:** run as SYSTEM, `tscon <id> /dest:rdp-tcp#` attaches
  a disconnected session to the attacker with no credentials — a classic,
  high-signal command.
- **4778/4779 alone are benign:** normal reconnects fire them; the detection
  requires the **source-IP-change + no-new-auth** correlation to avoid noise.
- **SSH agent sockets are shared credentials in memory:** reusing another user's
  socket inherits their authenticated access without re-authenticating.

## Tools & Systems

Windows Security / TerminalServices event logs, Sysmon, SigmaHQ (tscon redirect
rule), Splunk, MITRE CAR-2013-07-002, `auditd`, osquery, PAM session recorders
(CyberArk, Teleport).

## Detection Queries

### Sigma -- RDP hijack via tscon redirect

```yaml
title: RDP Session Hijack via tscon
status: stable
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\tscon.exe'
    CommandLine|contains: ' /dest:rdp-tcp#'
  condition: selection
falsepositives:
  - Rare legitimate admin session shadowing
level: high
```

### Splunk -- reconnect handoff from a new source with no new logon

The join must be `type=left`. The headline case this query is named for is a
reconnect with **no** matching Logon_Type=10 authentication, which is the
`isnull(authTime)` branch below -- and a default (inner) join returns only rows
that matched the subsearch, so it would silently discard exactly that case.

```spl
`wineventlog_security` EventCode IN (4778,4779)
| transaction Account_Name maxspan=5m
| search EventCode=4779 EventCode=4778
| eval srcChanged=if(mvcount(mvdedup(Source_Network_Address))>1,1,0)
| where srcChanged=1
| join type=left Account_Name Computer [ search `wineventlog_security` EventCode=4624 Logon_Type=10 | eval authTime=_time ]
| where isnull(authTime) OR (_time - authTime) > 300
| table _time, Computer, Account_Name, Source_Network_Address
```

### Linux -- auditd for cross-user SSH agent-socket access

```
-a always,exit -F arch=b64 -S connect -F dir=/tmp -k ssh_agent_abuse
-w /run/user -p r -k ssh_agent_abuse
# alert when the accessing uid != the socket owner uid, with no new sshd auth
```

## Common Scenarios

- **SYSTEM tscon:** attacker with SYSTEM runs `tscon 2 /dest:rdp-tcp#1` to seize
  an admin's disconnected session — Sigma rule fires.
- **Reconnect from attacker IP:** 4779 then 4778 for the same account from a new
  IP, no 4624 — handoff hunt fires.
- **SSH agent reuse:** a compromised service account uses a logged-in admin's
  `SSH_AUTH_SOCK` to ssh onward with no new auth.
- **False positive:** an admin legitimately reconnecting from a second
  workstation — resolved by requiring the no-new-auth condition.

## Output Format

```
SESSION HIJACK DETECTION
  Host:            <computer>
  Verdict:         <confirmed | suspected | admin-reconnect>
  Service:         <RDP | SSH>
  Method:          <tscon /dest | reconnect handoff | SSH agent-socket reuse | ControlMaster reuse>
  Evidence:        <tscon@SYSTEM | 4779->4778 new src, no 4624 | cross-uid socket access, no sshd auth>
  Hijacked acct:   <account> ; attacker src: <ip>
  ATT&CK:          T1563(.001/.002)[, T1021.001, T1021.004]
  Actions taken:   <session terminated | host isolated | account sessions reset | origin hunted>
```

## Response

- **RDP:** disable where unneeded; restrict interactive/SYSTEM access; enforce
  disconnect timeout + reauth; use Restricted Admin mode and a PAM/jump host for
  privileged sessions (NIST CSF PR.AA-05).
- **SSH:** disable agent forwarding on hosts that don't need it; use short-lived
  certificates; restrict socket permissions.
- **On detection:** force-logoff/terminate the session, isolate the host, reset
  affected account sessions, and hunt the entry session's origin.
