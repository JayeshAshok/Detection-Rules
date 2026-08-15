# DET202 — Suspicious Windows Command Shell (cmd.exe) Execution

## Overview

This branch implements detection logic for **MITRE ATT&CK Analytic AN0578**, focused on identifying potentially malicious use of the Windows Command Shell (`cmd.exe`).

Rather than treating every command shell execution as malicious, this detection focuses on identifying command shell activity that exhibits characteristics commonly observed during attacker operations, including discovery, execution, privilege escalation, lateral movement, and post-exploitation activity.

The detection is divided into five behavioral components:

1. Suspicious CMD Execution
2. CMD Discovery Activity
3. CMD Lateral Movement Activity
4. CMD Spawning Suspicious Child Processes
5. Batch File Execution from Suspicious Locations

## Detection Philosophy

The primary detection is **Suspicious CMD Execution**.

The remaining detections are intended to act as supporting evidence that increases confidence that the command shell activity is malicious.

Supporting detections should not be considered high-confidence indicators on their own because many administrative and operational activities can legitimately generate similar behavior.

Instead, the detection is designed to identify a suspicious command shell invocation and then determine whether additional attacker-like behaviors occur as part of the same activity chain.

## Behavioral Components

### 1. Suspicious CMD Execution

Detects command shell execution that appears unusual or potentially malicious.

Examples include:

- CMD launched from unusual parent processes
- Interactive shell abuse
- Suspicious command-line switches
- Command chaining
- Scripted execution patterns

Example process chains:

```text
winword.exe -> cmd.exe
mshta.exe -> cmd.exe
wscript.exe -> cmd.exe
regsvr32.exe -> cmd.exe
```

Example command patterns:

```text
cmd.exe /c whoami
cmd.exe /c systeminfo
cmd.exe /c net user
cmd.exe /k ipconfig
cmd.exe /c hostname && whoami
```

This is the primary detection component.

---

### 2. CMD Discovery Activity

Detects commands commonly used by attackers to gather information about a host, user accounts, network configuration, or Active Directory environment.

Examples include:

```text
whoami
hostname
systeminfo
ipconfig
arp
route print
net user
net localgroup
nltest
quser
```

These commands are frequently executed shortly after gaining access to a system in order to understand the environment and identify potential opportunities for further movement.

---

### 3. CMD Lateral Movement Activity

Detects commands commonly associated with remote execution, remote administration, and movement between systems.

Examples include:

```text
psexec
wmic
schtasks
sc.exe
net use
at.exe
```

These commands may indicate an attempt to execute code on remote systems, create remote services, or establish access to additional hosts.

---

### 4. CMD Spawning Suspicious Child Processes

Detects command shell activity that launches binaries frequently abused by attackers.

Examples include:

```text
powershell.exe
rundll32.exe
regsvr32.exe
mshta.exe
certutil.exe
wscript.exe
cscript.exe
bitsadmin.exe
```

These binaries are commonly used to execute payloads, download content, proxy execution, bypass application controls, or establish persistence.

---

### 5. Batch File Execution from Suspicious Locations

Detects execution of batch scripts from locations commonly abused by attackers.

Examples include:

```text
%TEMP%
C:\Users\Public\
C:\Temp\
Removable media
```

Attackers frequently store temporary tooling and scripts in user-writable directories to avoid requiring administrative privileges and to reduce visibility.

## Intended Behavior

The detection is intended to identify a suspicious command shell execution and then determine whether additional attacker-like activity occurs as part of the same activity sequence.

Example:

```text
winword.exe
    │
    ▼
cmd.exe /c whoami
    │
    ├── systeminfo
    ├── ipconfig
    └── net user
```

This activity is more suspicious than a standalone execution of `cmd.exe`.

Another example:

```text
cmd.exe
    │
    ▼
powershell.exe
    │
    ▼
Network Activity
```

This sequence provides stronger evidence of malicious activity than any individual event by itself.

## Detection Architecture

```text
Suspicious CMD Execution
            │
            ▼
     Supporting Activity
            │
            ├── Discovery Commands
            ├── Lateral Movement Commands
            ├── Suspicious Child Processes
            └── Suspicious Batch Execution
            │
            ▼
 Increased Detection Confidence
```

## Sigma Rules

This branch contains the following Sigma rules:

```text
AN0578/
│
├── suspicious_cmd_execution.yml
├── cmd_discovery_activity.yml
├── cmd_lateral_movement_activity.yml
├── cmd_suspicious_child_process.yml
└── batch_file_suspicious_location.yml
```

Together, these rules provide coverage for common attacker abuse of the Windows Command Shell while minimizing false positives from legitimate administrative activity.