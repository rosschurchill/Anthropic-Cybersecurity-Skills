# Detecting Screen, Audio and Video Capture — research notes

- **Proposed slug:** detecting-screen-audio-video-capture
- **ATT&CK:** T1113 Screen Capture, T1123 Audio Capture, T1125 Video Capture (tactic: collection) — umbrella skill mapping all three Collection peripheral-capture techniques
- **Status:** research (not yet a skill)

## Defensive goal
Detect an implant or operator covertly recording the victim's screen, microphone, or camera to collect sensitive information (on-screen data, conversations, surroundings). The skill focuses on what a *defender observes* on the endpoint — a process touching the OS capture APIs or capture utilities, followed by image/audio/video files written to temp or hidden directories, from a parent that has no legitimate reason to record. It must suppress the large population of legitimate recorders (Zoom, Teams, OBS used deliberately) via allowlisting and correlation, since the APIs themselves are benign.

## Data sources / telemetry
- **Windows screen (T1113):** Sysmon Event ID 1 (process creation) and Event ID 7 (image/module load) — unusual processes calling `CopyFromScreen` / loading GDI; PowerShell Script Block Logging (Event ID 4104) catches `System.Drawing` / `CopyFromScreen` one-liners; Sysmon Event ID 11 (file create) for `.bmp`/`.png`/`.jpg` written to `%TEMP%` or hidden folders. Native tool `xwd` (X11) does not apply to Windows.
- **Windows audio (T1123):** Sysmon Event ID 7 (load of `winmm.dll`, `avrt.dll`) and Event ID 10 (process access) correlated with Event ID 11 writing `.wav`/`.mp3`.
- **macOS:** Unified Logs / process exec of built-in `screencapture`; TCC (Transparency, Consent and Control) microphone/camera access events; `fs_usage` file I/O for AIFF/WAV/MP3 or image writes; AVFoundation / CoreAudio / CoreGraphics API use from unexpected parents.
- **Linux:** auditd execve / Sysmon-for-Linux for capture binaries — `scrot`, `maim`, `gnome-screenshot`, `spectacle`, `flameshot`, `import` (ImageMagick), `recordmydesktop`, `ffmpeg`, `arecord` (ALSA), access to `/dev/video*` and `/dev/snd/*`, PulseAudio.
- MITRE detection strategies: **DET0346** (Screen Capture, Win/macOS — `CopyFromScreen`/`screencapture`, Sysmon EID 1+7, image extensions, tunable parent process + interval window), **DET0221** (Audio Capture, Win/Linux/macOS — AN0620 Linux ALSA/`arecord`, AN0621 macOS AVFoundation/CoreAudio+TCC). A Video Capture (T1125) strategy ID was not confirmed — **verify against v19.2**.

## Detection logic / approach
- **API/tool + file-write correlation (core DET0346/DET0221 logic):** alert when a non-allowlisted process (a) loads/invokes a capture API or utility, then (b) writes a media file (image/audio/video) to temp/hidden dirs within a short window, especially on an interval (polling capture).
- **Windows screenshot via PowerShell (Sigma, needs Script Block Logging):**
  ```
  selection: EventID: 4104
    ScriptBlockText|contains:
      - 'CopyFromScreen'
      - 'System.Drawing.Bitmap'
      - 'Graphics.FromImage'
  condition: selection
  ```
- **Linux screenshot/recorder (Elastic-style EQL over process start):** match `process.name` in (`gnome-screenshot`,`scrot`,`maim`,`flameshot`,`spectacle`,`import`,`recordmydesktop`,`obs`,`ffmpeg`,`arecord`) excluding `--help`/`--version`, then correlate with file creation. Tune out interactive desktop sessions.
- **macOS:** flag `screencapture` exec from a non-interactive / suspicious parent (not Terminal/Finder user action), or any process gaining TCC microphone/camera access that is not on the conferencing allowlist.
- **FP reduction:** allowlist Zoom/Teams/Webex/OBS/Snagit/Greenshot and the OS screenshot hotkey daemon; require the suspicious-parent or temp-directory signal; weight interval/periodic captures and headless/service parents as higher confidence.

## Response / mitigation
- Containment: isolate host, kill the capturing process, preserve the written media files and process lineage as evidence. Harden: application control (WDAC/AppLocker) over scripting hosts; macOS TCC policy via MDM to deny camera/mic to unmanaged apps; Linux restrict `/dev/video*`/`/dev/snd` and audit capture binaries; enable PowerShell Script Block Logging fleet-wide (it is the only way to see in-memory `CopyFromScreen`). Review which accounts/apps legitimately need capture and deny the rest.

## Real tools
Sysmon, Windows PowerShell Script Block Logging, Elastic Security (Linux screenshot/audio rules), Splunk (Braodo-stealer screenshot-in-temp analytic), auditd / Sysmon-for-Linux, macOS Unified Logs + TCC + `fs_usage`, Sigma. Native capture utilities observed: `screencapture` (macOS), `scrot`/`maim`/`gnome-screenshot`/`ffmpeg`/`arecord` (Linux), `CopyFromScreen` (.NET/Windows). (no invented endpoints.)

## Draft frontmatter mappings
- mitre_attack: [T1113, T1123, T1125]
- nist_csf: [DE.CM-01, DE.CM-03, DE.AE-02, DE.AE-03, RS.MI-01]
- d3fend (optional): D3-PA (Process Analysis), D3-FCA (File Creation Analysis) — verify current D3FEND IDs
- suggested subdomain: endpoint-security
- nearest existing sibling (for the negative trigger): detecting-clipboard-data-theft

## Draft description (<=1024 chars)
Detects covert screen, microphone, and camera capture used for collection — a process invoking OS capture APIs/utilities (CopyFromScreen, screencapture, scrot/maim/ffmpeg/arecord, AVFoundation/CoreAudio) then writing image/audio/video files to temp or hidden folders — by correlating API/tool use with media-file writes and filtering legitimate recorders. Uses Sysmon EID 1/7/10/11, PowerShell Script Block Logging (4104), macOS TCC/Unified Logs, and Linux auditd. Use when hunting for or alerting on spyware/RAT screenshotting, eavesdropping, or webcam recording. Keywords: screen capture, audio capture, video capture, CopyFromScreen, screencapture, keylogger spyware, webcam, microphone, T1113, T1123, T1125. Do not use for clipboard theft - use detecting-clipboard-data-theft; for reversing a RAT's capture module use analyzing a malware-analysis skill.

## Key references
- https://attack.mitre.org/techniques/T1113/ , /T1123/ , /T1125/
- https://attack.mitre.org/detectionstrategies/DET0346 (Screen Capture) and DET0221 (Audio Capture) — verify against v19.2
- https://research.splunk.com/endpoint/00524d1f-a032-46f5-9108-e7d9f01bfb3c/ (Braodo screenshot-in-temp)
- https://www.elastic.co/guide/en/security/current/linux-video-recording-or-screenshot-activity-detected.html and .../linux-audio-recording-activity-detected.html

## Open questions / scope boundaries
- Confirm whether T1125 (Video Capture) has its own v19.2 detection strategy ID, or whether it rides DET0346/DET0221 — **verify**. Author must pick the allowlist of legitimate recorders per environment and set the interval-capture window.
- Strictly defensive: observe capture artefacts only; no capture tooling. This umbrella owns endpoint peripheral capture; it must NOT cover clipboard theft, generic keylogging, or reverse-engineering a sample's capture code (hand those to the clipboard and malware-analysis siblings).
