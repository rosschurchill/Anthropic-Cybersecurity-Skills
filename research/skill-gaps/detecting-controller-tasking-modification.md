# Detecting Controller Tasking Modification — research notes

- **Proposed slug:** detecting-controller-tasking-modification
- **ATT&CK (ICS):** T0821 Modify Controller Tasking (tactic: execution) — closely related:
  T0889 Modify Program, T0843 Program Download, T0834 Native API. Historical: Stuxnet, PLC-Blaster
- **Status:** research (not yet a skill)

## Defensive goal
Detect an adversary changing how and when a controller executes its programs — altering task
scheduling, priority, triggers, or cycle/scan parameters so attacker code runs more frequently or
ahead of legitimate logic. Stuxnet and PLC-Blaster both abused controller task structures to get
their code executed. The skill catches changes to task parameters (not just the program content),
which is a distinct and often overlooked tampering surface.

## Data sources / telemetry
- **Asset application / engineering-software logs (primary):** MITRE's DET0741 leans on application
  log content (DC0038) — watch vendor engineering tools and controller logs for records that task
  parameters (schedule, priority, trigger, cycle time, OB/task association in Siemens; periodic vs
  event task config in Rockwell) changed. Engineering and asset-management tools typically retain
  the expected controller program and a change record to diff against.
- **Device alarms (DC0108):** some controllers raise an alarm when task parameters change; not all
  devices emit these — coverage is device-dependent.
- **Passive ICS network sensor:** because Program Download (T0843) is a common delivery path for a
  tasking change, download/online-edit operations on S7comm, CIP, Modbus/UMAS are corroborating
  signals — a download followed by changed task behavior is the chain. **Verify per-vendor task
  configuration service codes against captures.**
- **Engineering workstation (Sysmon/EDR):** programming-software launch and project-file writes on
  the host that issued the tasking change.
- **Historian / process data:** changed scan/cycle behavior can shift update rates and timing of
  process values — subtle but observable as timing anomalies.

## Detection logic / approach
MITRE detection strategy **DET0741** (single analytic AN1874): monitor asset application logs for
indications that task parameters changed, and device alarms where emitted; monitor program downloads
since they may enable the technique; use engineering/asset-management baselines of the expected
program to identify modified tasking.

Primary analytic — task-config baseline diff:
```
on schedule and on observed download/edit:
  current_tasks = read_task_config(controller)   # task list, priority, trigger, cycle time
  if current_tasks != golden_master_tasks[controller] and no approved change ticket:
     ALERT "controller tasking changed" (controller, task, old->new priority/trigger)
```
Log analytic (Splunk/Sentinel/ArcSight — OpenText ships ICS ATT&CK content incl. a Modify Controller
Tasking rule; FortiSIEM ships PH_RULE_ICS_Modify_Controller_Tasking): alert on engineering-software
events indicating task priority/schedule/trigger edits, joined to EWS session and change-feed;
fire when unauthorized.

Corroboration (Zeek/ICSNPP): a program-download/online-edit event on `icsnpp-s7comm`/`cip.log` from
a non-EWS host within the window of the tasking-config change raises confidence.

## Response / mitigation
Baseline task configuration alongside program logic and diff on a schedule (M0947 Audit). Restrict
who/what can issue tasking changes — software/device authentication (M0813), authorization
enforcement (M0800), engineering-source allowlisting and key-switch enforcement (M0801). Gate behind
change control. On confirmed unauthorized change: isolate the controller, capture current task
config and logic for forensics, restore the approved configuration.

## Real tools
Dragos Platform, Nozomi Guardian/Vantage, Claroty CTD, Microsoft Defender for IoT; Zeek + CISA
ICSNPP; FortiSIEM (PH_RULE_ICS_Modify_Controller_Tasking); OpenText ArcSight ESM ICS ATT&CK content;
vendor engineering software (TIA Portal task/OB config, Studio 5000 task properties, Control Expert);
Wireshark ICS dissectors.

## Draft frontmatter mappings
- mitre_attack: [T0821, T0889, T0843]
- nist_csf: [DE.CM-01, DE.CM-09, DE.AE-02, DE.AE-03, PR.PS-01, ID.AM-02]
- suggested subdomain: ot-ics-security
- nearest existing sibling (for the negative trigger): detecting-plc-logic-modification

## Draft description (<=1024 chars)
Detects unauthorized changes to PLC/controller task execution — task scheduling, priority, triggers,
and scan/cycle parameters an adversary alters so their code runs more often or ahead of legitimate
logic (the Stuxnet/PLC-Blaster task-abuse pattern). Combines engineering-software and controller
application-log monitoring, task-config golden-master baselining, device alarms, and program-download
corroboration (ATT&CK ICS T0821). Use when triaging unexplained controller timing/scan changes, task
priority or trigger edits, or building controller-configuration baselining. Keywords: modify
controller tasking, task priority, scan cycle, OB task, periodic task, Stuxnet, PLC-Blaster,
FortiSIEM ICS, T0821. Do not use for detecting changes to the controller program logic content
itself - use detecting-plc-logic-modification.

## Key references
- MITRE ATT&CK T0821 + DET0741: https://attack.mitre.org/techniques/T0821/ , https://attack.mitre.org/detectionstrategies/DET0741
- FortiSIEM ICS rule: https://help.fortinet.com/fsiem/Public_Resource_Access/7_1_1/rules/PH_RULE_ICS_Modify_Controller_Tasking.htm
- OpenText ArcSight ESM ICS ATT&CK content: https://marketplace.opentext.com/cybersecurity/content/arcsight-esm-ics-mitre-attack-monitoring
- CISA ICSNPP: https://github.com/cisagov/ICSNPP

## Open questions / scope boundaries
- Author must map the vendor-specific task model (Siemens OB/task priorities, Rockwell periodic vs
  event tasks) and how to read task config safely per platform.
- Boundary vs T0889 (program content) and T0843 (the download) — this skill is the *tasking/schedule*
  change. Must NOT include offensive task-manipulation procedures.
- Verify any network service codes for task-config writes against captures before shipping rules.
