# DET0455 — Suspicious PowerShell Execution

## Overview

This branch implements detection logic for **MITRE ATT&CK Detection Strategy DET0455**, focused on detecting potentially malicious use of PowerShell.

The detection is divided into three behavioral components:

1. **Suspicious PowerShell Execution**
2. **PowerShell Initiating Network Connection**
3. **PowerShell Spawning a Child Process**

The three components are intended to be correlated into a **single Sentinel detection** rather than generating separate alerts for each behavior.

## Detection Logic

The primary condition for triggering the detection is:

```text
Suspicious PowerShell Execution
```

When this behavior is detected, the rule should generate an alert.

The severity of the alert should then be increased when additional suspicious activity occurs **after the initial Suspicious PowerShell Execution**.

### Severity Logic

| Detected Behavior                                                          | Severity |
| -------------------------------------------------------------------------- | -------- |
| Suspicious PowerShell Execution                                            | Medium   |
| Suspicious PowerShell Execution + PowerShell Initiating Network Connection | High     |
| Suspicious PowerShell Execution + PowerShell Spawning a Child Process      | High     |
| Suspicious PowerShell Execution + Network Connection + Child Process       | Critical |

The network connection and child-process detections **should not independently trigger high-confidence alerts**. They are supporting signals used to increase the confidence and severity of an existing suspicious PowerShell detection.

## Behavioral Flow

```text
                 Suspicious PowerShell Execution
                              │
                              ▼
                         Alert Created
                         Severity: Medium
                              │
                    ┌─────────┴─────────┐
                    │                   │
                    ▼                   ▼
       PowerShell Initiating     PowerShell Spawning
       Network Connection         a Child Process
                    │                   │
                    └─────────┬─────────┘
                              │
                              ▼
                       Increase Severity
```

If both behaviors occur:

```text
Suspicious PowerShell Execution
             │
             ├── Network Connection
             │
             └── Child Process
                    │
                    ▼
             Critical Severity
```
