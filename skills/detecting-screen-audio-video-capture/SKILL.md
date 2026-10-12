---
name: detecting-screen-audio-video-capture
description: 'Detects covert screen, microphone, and camera capture used for collection (MITRE T1113/T1123/T1125) - a process invoking OS capture APIs or utilities (CopyFromScreen, screencapture, scrot/maim/ffmpeg/arecord, AVFoundation/CoreAudio) then writing image/audio/video files to temp or hidden folders - by correlating API/tool use with media-file writes and filtering legitimate recorders. Uses Sysmon Event ID 1/7/10/11, PowerShell Script Block Logging (4104), macOS TCC/Unified Logs, and Linux auditd. Use when hunting spyware/RAT screenshotting, eavesdropping, or webcam recording on endpoints. Keywords: screen capture, audio capture, video capture, CopyFromScreen, screencapture, scrot, ffmpeg, arecord, webcam, microphone, T1113, T1123, T1125. Do not use for clipboard theft - use detecting-clipboard-data-theft.'
domain: cybersecurity
subdomain: endpoint-security
tags:
- endpoint-security
- threat-detection
- collection
- screen-capture
- audio-capture
- video-capture
- spyware
- sysmon
- t1113
- surveillance
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-03
- DE.AE-02
- DE.AE-03
- RS.MI-01
mitre_attack:
- T1113
- T1123
- T1125
---

# Detecting Screen, Audio and Video Capture

## When to Use

Use this skill to detect an implant or operator **covertly recording the
victim's screen, microphone, or camera** to collect sensitive information —
on-screen data, conversations, surroundings (ATT&CK T1113 Screen Capture, T1123
Audio Capture, T1125 Video Capture). The detection focuses on what a defender
observes on the endpoint: a process touching OS capture APIs/utilities, followed
by image/audio/video files written to temp or hidden directories, from a parent
with no legitimate reason to record. Reach for it when:

- Hunting spyware/RAT screenshotting, eavesdropping, or webcam recording.
- A non-conferencing process gains camera/mic access or writes media to temp.

The APIs are benign in daily use, so this lives on **allowlisting legitimate
recorders + correlation**. For clipboard theft use
`detecting-clipboard-data-theft`.

## Prerequisites

- **Windows screen**: Sysmon Event ID 1 (process) and 7 (module load — GDI);
  PowerShell Script Block Logging (4104) for `System.Drawing`/`CopyFromScreen`;
  Sysmon 11 for `.bmp`/`.png`/`.jpg` in `%TEMP%`/hidden dirs.
- **Windows audio**: Sysmon 7 (`winmm.dll`, `avrt.dll`) + 10, correlated with 11
  writing `.wav`/`.mp3`.
- **macOS**: Unified Log / exec of `screencapture`; TCC microphone/camera access
  events; `fs_usage` media writes; AVFoundation/CoreAudio/CoreGraphics use.
- **Linux**: `auditd`/Sysmon-for-Linux execve for `scrot`/`maim`/`gnome-screenshot`/
  `spectacle`/`flameshot`/`import`/`recordmydesktop`/`ffmpeg`/`arecord`, and access
  to `/dev/video*` / `/dev/snd/*`.
- An **allowlist of legitimate recorders** (Zoom/Teams/Webex/OBS/Snagit/Greenshot)
  and the OS screenshot-hotkey daemon.

## Workflow

1. **Allowlist legitimate recorders** and the OS screenshot daemon so routine
   recording doesn't alarm.
2. **API/tool + file-write correlation (core).** Alert when a non-allowlisted
   process (a) loads/invokes a capture API or utility, then (b) writes a media
   file to a temp/hidden dir within a short window — **especially on an interval**
   (polling capture).
3. **Windows PowerShell screenshot.** Alert on 4104 script blocks containing
   `CopyFromScreen`, `System.Drawing.Bitmap`, `Graphics.FromImage`.
4. **macOS.** Flag `screencapture` exec from a non-interactive/suspicious parent
   (not a Terminal/Finder user action), or any process gaining TCC
   microphone/camera access that is not on the conferencing allowlist.
5. **Linux.** Match capture-binary execve (excluding `--help`/`--version`) then
   correlate with media-file creation; tune out interactive desktop sessions.
6. **Weight confidence** — interval/periodic captures and headless/service parents
   are higher confidence — then **respond** (see *Response*).

## Key Concepts

- **Benign APIs, malicious context:** `CopyFromScreen`/`screencapture`/`ffmpeg`
  are everyday tools; the signal is a non-allowlisted or headless parent writing
  media to temp, not the API itself.
- **Interval capture is a tell:** spyware often screenshots on a timer; periodic
  media writes from one process are higher confidence than a one-off.
- **Script-block logging is mandatory on Windows:** in-memory `CopyFromScreen`
  leaves no binary — 4104 is the only place it shows.
- **macOS TCC is the camera/mic gate:** a non-conferencing app obtaining TCC
  camera/mic access is a strong eavesdropping signal.

## Tools & Systems

Sysmon, Windows PowerShell Script Block Logging, Elastic Security (Linux
screenshot/audio rules), Splunk, `auditd`/Sysmon-for-Linux, macOS Unified Logs +
TCC + `fs_usage`, Sigma.

## Detection Queries

### Sigma -- PowerShell screen capture (Windows, needs 4104)

```yaml
title: PowerShell Screen Capture (CopyFromScreen)
status: experimental
logsource:
  product: windows
  category: ps_script
detection:
  selection:
    ScriptBlockText|contains:
      - 'CopyFromScreen'
      - 'System.Drawing.Bitmap'
      - 'Graphics.FromImage'
  condition: selection
falsepositives:
  - Legitimate screenshot automation (allowlist)
level: high
```

### Splunk -- capture tool then media file in temp (correlation)

```spl
`sysmon` EventCode=1 (Image="*scrot" OR Image="*maim" OR Image="*ffmpeg" OR Image="*arecord"
    OR Image="*\\screencapture" OR CommandLine="*CopyFromScreen*")
| search NOT [ | inputlookup approved_recorders | fields Image ]
| eval toolTime=_time
| join Computer [ search `sysmon` EventCode=11
    (TargetFilename="*\\Temp\\*" OR TargetFilename="*/tmp/*")
    (TargetFilename="*.png" OR TargetFilename="*.bmp" OR TargetFilename="*.wav" OR TargetFilename="*.mp4") ]
| where _time>=toolTime AND (_time-toolTime) < 60
| table _time, Computer, Image, CommandLine, TargetFilename
```

### macOS -- non-conferencing process gets TCC camera/mic (concept)

```
# Unified Log / ESF: TCC access grant to camera/microphone by a process
# not on the conferencing allowlist (Zoom/Teams/Webex/FaceTime)
log stream --predicate 'subsystem == "com.apple.TCC" AND eventMessage CONTAINS "kTCCServiceMicrophone"'
```

## Common Scenarios

- **Interval screenshots:** a RAT screenshots every 30s to `%TEMP%\s\*.png` —
  tool + periodic temp writes fire.
- **Mic eavesdrop:** a non-conferencing process records via `arecord`/CoreAudio to
  a hidden `.wav`.
- **Webcam capture:** `ffmpeg -f v4l2 -i /dev/video0` from a headless parent.
- **False positive:** Zoom/OBS recording a legitimate meeting — allowlisted.

## Output Format

```
CAPTURE DETECTION
  Host/user:       <host> / <user>
  Verdict:         <confirmed | suspected | approved-recorder>
  Type:            <screen T1113 | audio T1123 | video T1125>
  Mechanism:       <CopyFromScreen | screencapture | scrot/ffmpeg/arecord | TCC cam/mic | /dev/video|snd>
  Media written:   <path> in <temp/hidden>, interval <periodic?>
  Parent:          <parent process> (allowlisted: <n>)
  ATT&CK:          T1113 / T1123 / T1125
  Actions taken:   <host isolated | process killed | media preserved | TCC/device access revoked>
```

## Response

- **Isolate the host**, kill the capturing process, and preserve the written
  media files and process lineage as evidence.
- **Harden:** application control over scripting hosts; macOS TCC policy via MDM to
  deny camera/mic to unmanaged apps; Linux restrict `/dev/video*`/`/dev/snd` and
  audit capture binaries; enable **PowerShell Script Block Logging fleet-wide**
  (the only way to see in-memory `CopyFromScreen`).
- Review which accounts/apps legitimately need capture and deny the rest.
