# Detecting Remote Service Session Hijacking — research notes

- **Proposed slug:** detecting-remote-service-session-hijacking
- **ATT&CK:** T1563 Remote Service Session Hijacking (tactic: lateral-movement) — sub-techniques T1563.001 (SSH Hijacking), T1563.002 (RDP Hijacking); related: T1021.001 (RDP), T1021.004 (SSH)
- **Status:** research (not yet a skill)

## Defensive goal
Detect takeover of a *pre-existing* remote session (RDP or SSH) for lateral movement — distinct from opening a new session with valid accounts. For RDP, catch `tscon.exe` session reassignment (often as SYSTEM, needing no credentials) and reconnect-from-new-source patterns. For SSH, catch reuse of another user's SSH agent socket / multiplexed session where activity continues with no corresponding new authentication event.

## Data sources / telemetry
- **Windows RDP:** Security Event ID 4778 (session reconnect) and 4779 (session disconnect) with source IP/hostname; 4624 (type 10 / RemoteInteractive logon) and 4648 (explicit cred logon); process creation 4688 / Sysmon 1 for `tscon.exe`, `qwinsta`/`query session`, `mstsc`; Sysmon 3/22; System Event ID 7045 (service create — persistence variant `sc create ... tscon`); TerminalServices-LocalSessionManager/RemoteConnectionManager operational logs.
- **Linux/macOS SSH:** auditd SYSCALL records for `open`/`connect` on `$SSH_AUTH_SOCK` and `/tmp/ssh-*` (agent sockets) and `~/.ssh/cm-*`/ControlMaster sockets (verify path coverage); auditd EXECVE for `ssh`/`scp`/`sftp`; `/var/log/auth.log` / `secure` (sshd session open/close); process ancestry of shells spawned under sshd.
- MITRE detection strategies: DET0588 / analytic AN1620 (RDP) → Security 4624/4648, Sysmon 1, Sysmon 3/22, System 7045; DET0256 (SSH) → auditd socket access + EXECVE, session activity with no new login. (verify IDs on live attack.mitre.org.)

## Detection logic / approach
- **RDP – tscon redirect (SigmaHQ `proc_creation_win_tscon_rdp_redirect`, id f72aa3e8-…):**
  ```
  selection: CommandLine|contains: ' /dest:rdp-tcp#'
  condition: selection      # also: tscon.exe running at SYSTEM / integrity S-1-16-16384
  ```
- **RDP – reconnect handoff (hunt):** a 4778 (reconnect) for an account immediately following a 4779 (disconnect) for the *same account from a different source IP*, with no corresponding fresh 4624 logon — the hijack handoff. Correlate with `rdpclip.exe`/`tstheme.exe` spawning under an unexpected session.
- **RDP – persistence variant (Splunk):** `sc.exe`/7045 creating a service whose binary path contains `tscon.exe`.
- **SSH – agent-socket abuse:** auditd alert when a process owned by user A accesses user B's `$SSH_AUTH_SOCK`/`/tmp/ssh-*` socket; correlate with outbound ssh from the host that has **no matching new sshd auth event** (session continuity without authentication).
- **SSH – multiplexed reuse:** flag new commands flowing over an existing ControlMaster channel from an unexpected process/user (verify ControlMaster path detection feasibility).
- Core invariant across both: *session activity continues or a lateral connection occurs without a corresponding new authentication event.*

## Response / mitigation
- RDP: disable where unneeded; restrict interactive/SYSTEM access; enforce "disconnect" timeout and reauth; Restricted Admin mode; monitor privileged session via a PAM/jump host. SSH: disable agent forwarding on hosts that don't need it; use short-lived certs; restrict socket permissions. On detection: force-logoff/terminate the session, isolate host, reset affected account sessions, hunt for the entry session's origin.

## Real tools
Windows Security/TerminalServices event logs, Sysmon, SigmaHQ (tscon redirect rule), Splunk (research.splunk.com Tscon service-create), MITRE CAR-2013-07-002 (RDP connection), auditd, osquery, PAM session recorders (CyberArk, Teleport). (verify rule IDs.)

## Draft frontmatter mappings
- mitre_attack: [T1563, T1563.001, T1563.002, T1021.001, T1021.004]
- nist_csf: [DE.CM-01, DE.CM-03, DE.AE-02, PR.AA-05, RS.MI-01]
- d3fend (optional): D3-UA (User Behavior Analysis), D3-PSA (Process Spawn Analysis), D3-RNA — verify current D3FEND IDs
- suggested subdomain: threat-hunting
- nearest existing sibling (for the negative trigger): detecting-lateral-movement-in-network

## Draft description (<=1024 chars)
Detects remote service session hijacking — RDP takeover via tscon.exe /dest:rdp-tcp# (often as SYSTEM) and 4778/4779 reconnect-from-new-source handoffs, and SSH hijacking via reuse of another user's SSH agent socket — by correlating session reconnect/disconnect events, tscon process creation, and lateral activity that occurs with NO matching new authentication event. Use when hunting for lateral movement that rides an existing RDP or SSH session rather than a fresh logon. Keywords: RDP hijacking, tscon, 4778, 4779, SSH agent socket, SSH_AUTH_SOCK, session hijack, T1563. Do not use for detecting new-session remote access with stolen creds (T1021) or broad lateral-movement hunting - use detecting-lateral-movement-in-network.

## Key references
- https://attack.mitre.org/techniques/T1563/ , /001/ , /002/
- https://attack.mitre.org/detectionstrategies/DET0588 and /DET0256 (verify)
- https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_tscon_rdp_redirect/
- https://research.splunk.com/endpoint/c13b3d74-6b63-4db5-a841-4206f0370077/
- https://car.mitre.org/analytics/CAR-2013-07-002

## Open questions / scope boundaries
- 4778/4779 alone = normal reconnect; the skill must insist on the source-IP-change + no-new-auth correlation to control false positives. Legitimate admin maintenance is the main FP source.
- Confirm whether ControlMaster socket paths can be reliably audited on common distros. Must NOT teach how to perform tscon/SSH hijacking. Decide if the persistence-via-service variant lives here or in a persistence skill.
