# Forensic Analysis Report: The Malware Hidden Inside a Fake Adobe Installer

> **How a pirated Adobe package distributed via Telegram delivers a fully operational
> infostealer that evades all 72 major antivirus engines — a complete technical investigation**
>
> *Defensive Cybersecurity Research — April 14, 2026*

---

> [!CAUTION]
> **Important disclaimer:** This report was produced exclusively for defensive security
> purposes — threat awareness, detection engineering, and incident response guidance for
> users and security teams. All technical details are provided to help people detect and
> remediate this specific threat. This article does not contain exploit code, offensive
> tools, credential theft instructions, or any content enabling malicious use. The analysis
> methodology and scope follow the same standards used by major threat intelligence firms
> including Mandiant, CrowdStrike, Kaspersky GReAT, and Palo Alto Networks Unit 42, all
> of which regularly publish similar reports.

> [!NOTE]
> **A note on evidence quality:** Throughout this report, findings are explicitly marked
> as **confirmed** (independently verifiable from public sources), **observed** (documented
> in sandbox behavioral logs), or **inferred** (reasoned conclusions from available
> evidence). This distinction is intentional. The goal is accuracy, not sensationalism.

---

## Table of Contents

1. [File Summary](#1-file-summary)
2. [Context and Origin](#2-context-and-origin)
3. [Static Analysis of the Binary](#3-static-analysis-of-the-binary)
4. [The 4-Layer Architecture — Complete Reverse Engineering](#4-the-4-layer-architecture--complete-reverse-engineering)
5. [The Kill Chain — What Happens Moment by Moment](#5-the-kill-chain--what-happens-moment-by-moment)
6. [Dynamic Analysis — Sandbox Behavioral Data](#6-dynamic-analysis--sandbox-behavioral-data)
7. [Command and Control Infrastructure](#7-command-and-control-infrastructure)
8. [Threat Intelligence](#8-threat-intelligence)
9. [Indicators of Compromise](#9-indicators-of-compromise)
10. [Incident Response](#10-incident-response)
11. [Conclusion](#11-conclusion)
12. [References and Source Index](#12-references-and-source-index)

---

## Why This Report Exists

In early April 2026, a researcher going by the handle `rocket1337` published a detailed
reverse engineering analysis on VirusTotal identifying an active infostealer embedded inside
a file claiming to be an Adobe Illustrator 2026 installer. The malware had been circulating
since at least January 2026, was catalogued in the MWDB malware database by a separate
researcher in February 2025, and had accumulated a VirusTotal submission history spanning
over a year — all while maintaining zero detections across 72 major antivirus engines.

The purpose of this report is to consolidate everything that is known about this threat into
a single, complete reference document for users who may have downloaded and run the file, and
for security professionals who need comprehensive IOCs and behavioral data for detection
engineering.

---

## 1. File Summary

The primary subject of this analysis:

| Field                      | Value                                                              |
| -------------------------- | ------------------------------------------------------------------ |
| **Filename**               | `Set-up.exe` (internal name: `sourcepart.dat`)                     |
| **SHA256**                 | `3d20655679c8829a6baad001851905927ef1b826e3eea594b7be3f8331211e39` |
| **MD5**                    | `e9d48daf4748eee45abf308b85e88b71`                                 |
| **File size**              | 7.28 MB (7,638,016 bytes)                                          |
| **File type**              | Win32 EXE — PE32 (32-bit)                                          |
| **Compiler**               | Visual Studio 2019 v16.2.3 (build 27905)                           |
| **PE timestamp (wrapper)** | `2020-10-02 04:16:30 UTC` *(see note below)*                       |
| **Payload DLL compiled**   | January 3, 2026 *(confirmed from .NET metadata)*                   |
| **Digital signature**      | Absent — claims Adobe copyright but unsigned                       |
| **First submitted to VT**  | February 20, 2025                                                  |
| **Static AV detections**   | **0 / 72**                                                         |
| **Sandbox detection**      | `MALWARE` (Yomi Hunter)                                            |
| **C2 server status**       | **Active** as of April 9, 2026 *(live-tested)*                     |
| **Malware framework**      | .NET 4.7.2 infostealer, WiX SfxCA delivery                         |

> [!NOTE]
> **Note on the 2020 PE timestamp:** The outer wrapper `Set-up.exe` carries a compilation
> timestamp of October 2, 2020, while the embedded .NET payload was compiled on January 3,
> 2026. PE timestamps in the outer binary can be easily forged or represent a recycled WiX
> build framework. The payload's .NET assembly metadata timestamp of January 3, 2026 is
> significantly harder to falsify and is corroborated by the first VirusTotal submission
> date of January 5, 2026 — two days after compilation.

---

## 2. Context and Origin

### 2.1 Distribution Channel

The file arrived inside a torrent package presented as Adobe Illustrator 2026 (v30.3)
Multilingual, attributed to the widely known piracy distributor m0nkrus and posted on the
uztracker.net tracker. The torrent contained a single ISO file —
`Adobe.Illustrator.2026.u3.Multilingual.iso` (3.43 GB, MD5:
`8e8d18572326bd1e948c1d8b17ec49f7`) — which, when mounted, exposed three files to the user.

### 2.2 Files in the Package

| File             | Size        | Verdict                    | Notes                                                                                    |
| ---------------- | ----------- | -------------------------- | ---------------------------------------------------------------------------------------- |
| `AutoPlay.exe`   | 185 KB      | ✅ **Confirmed Legitimate** | Genuine Adobe CS6 AutoPlay launcher from 2008; seen 100,000+ times as clean by Kaspersky |
| **`Set-up.exe`** | **7.28 MB** | 🔴 **Confirmed Malicious** | **The infostealer — subject of this entire report**                                      |
| `autorun.inf`    | 70 B        | ✅ **Confirmed Inert**      | Plain text; AutoRun disabled since Windows 7; one generic flag from Trellix ENS          |

### 2.3 Cross-Campaign Confirmation

> [!IMPORTANT]
> **Confirmed:** Researcher `rocket1337` documented in their April 9, 2026 VirusTotal
> analysis (publicly viewable in the Community tab of `487aca2b...71cd`) that the identical
> payload DLL hash, C2 endpoint, and kill chain sequence were observed in a separate package
> described as a trojanized Adobe Photoshop 2026 crack. The DLL `MSICustomActionDLL.dll`
> (`487aca2b...71cd`) is shared across both campaigns. This is independently verifiable: the
> DLL's VirusTotal page shows two distinct execution parents — an MSI associated with
> Illustrator and an MSI associated with Photoshop — both submitted in the same timeframe.

The payload DLL was compiled on **January 3, 2026** and first submitted to VirusTotal on
**January 5, 2026**, approximately three months before this April 2026 torrent appeared. The
attack infrastructure was built and tested well before distribution began.

### 2.4 What We Know About the Threat Actor

The distribution method, pre-built infrastructure, professional evasion engineering, and
multi-product targeting suggest an organized operation rather than an opportunistic
individual. Beyond this, attribution is not claimed and should not be inferred. Multiple YARA
rule matches against APT28 and Turla patterns were triggered by the THOR APT Scanner, but
these almost certainly reflect shared code patterns from common .NET framework libraries
rather than direct attribution — a well-documented limitation of YARA-based attribution on
.NET binaries, acknowledged by Nextron Systems in their own published notes on VirusTotal
matches.

---

## 3. Static Analysis of the Binary

### 3.1 PE Structure and Properties

| Property                      | Value                                                                     |
| ----------------------------- | ------------------------------------------------------------------------- |
| **Architecture**              | Win32 EXE PE32 — 32-bit, executes on x64 via WoW64                        |
| **Compilation timestamp**     | `2020-10-02 04:16:30 UTC` *(outer wrapper; see note in §1)*               |
| **PE sections**               | `.text` `.rdata` `.data` `.rsrc` `.reloc`                                 |
| **Entropy (.reloc section)**  | 6.66 — elevated, obfuscated embedded content                              |
| **Imphash**                   | `337783faf868eb54d41c823f63ce0359`                                        |
| **Digital signature**         | **ABSENT**                                                                |
| **Declared copyright string** | `© 2020-2025 Adobe. All rights reserved.` **(FAKE — no valid signature)** |

### 3.2 What the Import Table Reveals

Before any code executes, the Windows API functions imported by the binary reveal its full
intended capability set. The following groups were identified from static PE analysis — a
method that is objective and reproducible by any analyst with a PE analysis tool examining
the same hash.

**Credential theft via DPAPI:** `CryptProtectData` and `CryptUnprotectData` are used to
decrypt credentials stored by Chrome, Edge, and Firefox — these browsers use Windows' Data
Protection API to encrypt saved passwords. `CredReadW`, `CredEnumerateW`, and `CredWriteW`
provide full access to the Windows Credential Manager vault. `BCryptEncrypt` and
`BCryptDecrypt` handle re-encryption of stolen data before exfiltration.

**Anti-analysis and evasion:** `IsDebuggerPresent` detects attached debuggers and alters
execution accordingly. `GetTickCount` enables timing-based sandbox detection — sandboxes
often run faster than real hardware, and timing measurements can expose this. VM artifact
detection covers VMware, VirtualBox, Parallels, QEMU, Xen, AWS, and GCP.

**System enumeration and reconnaissance:** `CreateToolhelp32Snapshot`, `Process32FirstW`,
and `Process32NextW` enumerate all running processes. `GetUserNameW` and
`GetComputerNameExW` collect user identity and hostname. `WinVerifyTrust` and
`WTHelperGetProvSignerFromChain` verify digital signatures of running processes to select
injection targets.

**Persistence and privilege escalation:** `DuplicateTokenEx` and `ImpersonateLoggedOnUser`
enable token theft and impersonation. `AdjustTokenPrivileges` and `LookupPrivilegeValueW`
handle privilege escalation. `CreateNamedPipeW` and `ConnectNamedPipe` establish covert
inter-process communication channels characteristic of loaders and remote access tools.

### 3.3 Embedded Resources

The `.rsrc` section contains 18 PNG images (installer UI graphics), 21 dictionary files
(multilingual interface strings), 6 JavaScript files, 4 CSS files, 4 SVG files, and 2 HTML
files. These resources exist to make the installer appear convincingly genuine during casual
visual inspection.

---

## 4. The 4-Layer Architecture — Complete Reverse Engineering

The malware uses a nested delivery architecture where the active payload is buried four
layers deep. Researcher `rocket1337` recovered the complete C# source code using ILSpy and
published the full analysis in the Community tab of the payload DLL's VirusTotal page
(`487aca2b...71cd`) on April 9, 2026. That analysis is publicly viewable and independently
verifiable. What follows integrates that published analysis with the independent sandbox
behavioral data produced by Zenbox, CAPE Sandbox, and VirusTotal Jujubox.

### 4.1 Architecture Overview

```text
Layer 0 — Set-up.exe
          Delivery wrapper presented as Adobe installer
          Extracts and launches the MSI below
                │
                ▼
Layer 1 — Installer.msi
          Cover identity: "Dolby Vision PQ Config Installer"
          Signed with STOLEN, EXPIRED Dolby Laboratories certificate
          Custom action "SummonRah" fires at UI sequence 801
          (this is BEFORE the user sees any installer screen)
                │
                ▼
Layer 2 — SfxCA DLL (WiX Self-Extracting Custom Action)
          Extraction container for the payload
          79,576-byte overlay at entropy 7.9965/8.0 (near-maximum)
          Payload is compressed/encrypted — invisible to AV PE scanning
                │
                ▼
Layer 3 — CAB Archive (embedded in the DLL overlay)
          Microsoft Cabinet format, LZX compression
                │
                ▼
Layer 4 — MSICustomActionDLL.dll
          THE ACTIVE INFOSTEALER PAYLOAD
          16 KB, .NET 4.7.2, compiled January 3, 2026
          C# source recovered and published by rocket1337 via ILSpy
          Executed via: rundll32.exe [...],zzzzInvokeManagedCustomActionOutOfProc
```

### 4.2 Layer 1 — Installer.msi in Detail

| Field        | Value                                                              |
| ------------ | ------------------------------------------------------------------ |
| **SHA256**   | `45415f110b7961eea726dd3b1c07ebed2bbc44d13e8d92d0d8bd1304ba145d73` |
| **MD5**      | `595eb28f84979f035375a35efe92c259`                                 |
| **Size**     | 1.32 MB                                                            |
| **Compiled** | March 4, 2025                                                      |

The MSI presents itself as the "Dolby Vision PQ Config Installer" by "Dolby," built using
the legitimate WiX Toolset 5.0.2.0. It is signed with a Dolby Laboratories certificate
issued by DigiCert.

> **Confirmed:** The certificate expired on October 22, 2025, and carries a `HashMismatch`
> flag — verifiable in the Signature Info section of the VirusTotal Details tab for this
> file hash. The signed content does not match the actual file content. This is a stolen,
> abused certificate. Its presence causes many automated tools to treat the installer as
> trusted without deeper analysis.

The cover story is elaborate: the MSI installs dozens of real Dolby Vision color profile
files (`.dv` extension) into `C:\Windows\System32\spool\drivers\color\` — genuine hardware
calibration data for display manufacturers including AUO, BOE, LEN, CMN, CSO, and TMA.
**Observed:** The specific filenames were documented in sandbox dropped-file analysis. Their
presence makes installation logs appear entirely normal.

Before executing the malicious custom action, the MSI opens Windows Vault (`VaultSvc`) and
Clipboard Service (`clipsvc`) — targeting stored credentials. The DNS client (`dnsCache`)
is also accessed, consistent with network enumeration preparation.

**Confirmed from sandbox WMI dataset analysis:**

```text
IWbemServices::Connect
IWbemServices::CreateInstanceEnum → Win32_ComputerSystemProduct (Hardware UUID)
IWbemServices::ExecQuery → SELECT * FROM Win32_ComputerSystem
IWbemServices::ExecQuery → SELECT * FROM Win32_VideoController (GPU model)
```

**Observed execution chain captured in Zenbox sandbox:**

```text
msiexec.exe /i "Wixinstaller1.6.msi"
  └─ MsiExec.exe -Embedding [token]
      └─ MsiExec.exe -Embedding [token] C  (WoW64 transition)
          └─ rundll32.exe "MSIB20D.tmp",
               zzzzInvokeManagedCustomActionOutOfProc SfxCA_6478875 1
               MSICustomActionDLL!MSICustomActionDLL.CustomActions.EntryPointOne
```

Four Sigma rules triggered at MEDIUM severity (all publicly available in the SigmaHQ
repository):

| Rule                                           | Author                                      |
| ---------------------------------------------- | ------------------------------------------- |
| Rundll32 Internet Connection                   | Florian Roth (Nextron Systems)              |
| Unsigned DLL Loaded by Windows Utility         | Swachchhanda Shrawan Poudel                 |
| Amsi.DLL Loaded Via LOLBIN Process             | Nasreddine Bencherchali (Nextron Systems)   |
| Rundll32 Execution With Uncommon DLL Extension | Tim Shelton, Florian Roth, Yassine Oukessou |

### 4.3 Layer 2 — SfxCA DLL in Detail

| Field        | Value                                                              |
| ------------ | ------------------------------------------------------------------ |
| **SHA256**   | `06875058d4f40be9fb9d065bb4dbc29f67e80339ea261143d123d582c1481171` |
| **MD5**      | `efaa71c29a914094691c2582c657dc1f`                                 |
| **Size**     | 254.71 KB                                                          |
| **Compiled** | September 17, 2019                                                 |

WiX's Self-Extracting Custom Action mechanism is a legitimate way to deliver .NET code
inside MSI packages. The malware authors repurposed this entire trusted framework as their
delivery vehicle — borrowing legitimacy from real tooling.

**Confirmed by PE analysis:** The DLL has an overlay of 79,576 bytes appended after the
standard PE content at an entropy of **7.9965 out of a theoretical maximum of 8.0** —
documented in the PE overlay section of the VirusTotal Details tab. Maximum entropy indicates
maximum compression or encryption. Standard antivirus PE section scanning finds nothing
suspicious because the payload does not exist in the PE sections at all — it only exists in
the overlay, which many engines skip or examine with reduced scrutiny.

**Observed:** The C2 URL `https://i-odsports.com/aycha/saver.php` appeared as a memory
pattern string during sandbox execution — documented in the Memory Pattern URLs section of
the Behavior tab.

CAPA confirmed the following behaviors: anti-VM string detection targeting Parallels, QEMU,
VMware, and VirtualBox; debugger detection via memory breakpoints; guard-page-based
anti-debugging; HTTP request creation, sending, and response handling; named pipe creation
and connection; Base64 data encoding; WMI data access via .NET; username and hostname
retrieval.

One Sigma rule triggered at **HIGH** severity: **Suspicious DotNET CLR Usage Log Artifact**
— detects .NET assembly execution via a LOLBIN process. When a .NET assembly runs inside
`rundll32.exe` for the first time in a user session, the CLR creates a log file named
`rundll32.exe.log`. This artifact is a reliable forensic indicator of exactly this attack
pattern.

### 4.4 Layer 4 — MSICustomActionDLL.dll in Detail (The Active Payload)

| Field        | Value                                                              |
| ------------ | ------------------------------------------------------------------ |
| **SHA256**   | `487aca2bbd630c8013ee1992dabb970058c9a737c2fffce0c0a45801408771cd` |
| **MD5**      | `732de0a3ddfeb4b5ad29387d3cbf66ee`                                 |
| **Size**     | 16 KB (16,384 bytes)                                               |
| **Compiled** | January 3, 2026                                                    |

This 16-kilobyte .NET assembly is the infostealer core. The following .NET assembly metadata
is **confirmed** — verifiable in the Details tab of the VirusTotal file page:

* **CLR version:** `v4.0.30319`
* **Module Version ID:** `a38b459e-6347-4e1e-900a-52153b4a58d5`
* **External dependencies:** `Microsoft.Deployment.WindowsInstaller v3.0.0.0`, `System.Management v4.0.0.0`, `System.Windows.Forms v4.0.0.0`, `System.Core v4.0.0.0`

The .NET type definitions are **confirmed** from the VirusTotal Details tab assembly listing
and map directly to specific capabilities:

| .NET Type                                               | Purpose                                  |
| ------------------------------------------------------- | ---------------------------------------- |
| `System.Management.ManagementObjectSearcher`            | WMI queries — Hardware UUID              |
| `System.Net.HttpWebRequest`                             | HTTP POST to C2 endpoint                 |
| `System.Windows.Forms.MessageBox`                       | Fake memory error in VMs                 |
| `System.Security.Cryptography.RNGCryptoServiceProvider` | Cryptographic RNG                        |
| `System.Convert` (Base64)                               | Encoding stolen data before transmission |
| `System.Diagnostics.Stopwatch`                          | Timing-based sandbox detection           |
| `System.Security.Principal.WindowsIdentity`             | Current user identity                    |
| `System.Security.Claims.ClaimsIdentity`                 | Claims-based identity access             |
| `System.Environment.SpecialFolder`                      | Special folder enumeration               |

**ROT13 obfuscation — confirmed and mathematically verifiable:**

WMI query strings are encoded with ROT13 to bypass string-based signature detection:

```text
Encoded:  Jva32_PbzchgreFlffgrzCebqhpg
Decoded:  Win32_ComputerSystemProduct    ← WMI class queried for Hardware UUID

Encoded:  HHVQ
Decoded:  UUID                           ← property name extracted
```

Verifiable with any ROT13 decoder (e.g., `https://rot13.com/`). These obfuscated strings
were documented in rocket1337's published VirusTotal analysis and are independently
reproducible.

**PDB presence indicating active development** *(confirmed fact; inference on meaning):*
The debug symbols file `MSICustomActionDLL.pdb` was left inside the CAB archive — confirmed
in the Dropped Files section of the Behavior tab. Their presence in the dropped file list is
an objective fact. The inference — that this indicates active development and ongoing
monitoring of detection rates — is reasonable but remains an interpretation, not a proven
fact.

---

## 5. The Kill Chain — What Happens Moment by Moment

Each step is marked with its evidence basis.

| Step  | Action                                                                 | Evidence Basis                         | User Visibility                            |
| ----- | ---------------------------------------------------------------------- | -------------------------------------- | ------------------------------------------ |
| **1** | Custom action `SummonRah` executes at UI sequence 801                  | Confirmed — sandbox execution chain    | "Preparing to install..." only             |
| **2** | WMI collects Hardware UUID, GPU, username, hostname                    | Confirmed — sandbox WMI dataset        | None                                       |
| **3** | HTTPS POST to C2 with `Flow=PS6` / `Action=Login`                      | Confirmed — live C2 test by rocket1337 | None                                       |
| **4** | VM/sandbox check: VMware, VBox, Parallels, QEMU, Xen, AWS, GCP         | Confirmed — CAPA + sandbox evasion     | **Fake error if VM detected → clean exit** |
| **5** | Renames `sourcepart.dat` → `Set-Up.exe`; launches real Adobe installer | Confirmed — sandbox file system        | Normal Adobe installation                  |
| **6** | `winget install -h --id 9N411ZGN6M6G` *(app identity unknown)*         | Observed — sandbox process list        | None                                       |
| **7** | `Planora /INSTALL` *(capabilities unknown)*                            | Observed — sandbox process list        | None                                       |
| **8** | Deletes `%TEMP%\MSIB20D.tmp-\` and all contents                        | Confirmed — sandbox file system        | None                                       |

**Fake error message displayed in VM environments:**

> *"The system does not have enough available memory to run this application effectively.
> Please ensure that you have sufficient free RAM or close unnecessary programs to continue.
> If the issue persists, [...]"*

> [!WARNING]
> **Critical note:** Steps 2 and 3 — data collection and exfiltration — occur **before**
> Step 4. If you ran this file in a VM and saw the memory error, some data may have already
> been transmitted to the C2 server before the error appeared.

> [!NOTE]
> **Important caveats on Steps 6 and 7:** The Windows Store application corresponding to
> winget package ID `9N411ZGN6M6G` was not publicly identified at the time of this analysis.
> The `Planora` component capabilities, origin, and persistence method are also unknown.
> Both are documented here because they were observed executing — not because their behavior
> is understood.

---

## 6. Dynamic Analysis — Sandbox Behavioral Data

### 6.1 Results Across Seven Sandboxes

| Sandbox                | Verdict                    | Key Observations                                                               |
| ---------------------- | -------------------------- | ------------------------------------------------------------------------------ |
| **Yomi Hunter**        | 🔴 `MALWARE`               | Only sandbox with positive malware classification                              |
| CAPE Sandbox           | ⚠️ 3 alerts                | Behavioral detections, no definitive classification                            |
| Zenbox                 | ⚠️ 5 alerts / 57 behaviors | Tags: `calls-wmi`, `checks-usb-bus`, `detect-debug-environment`, `long-sleeps` |
| Microsoft Sysinternals | ⚠️ 99+ behaviors           | Maximum event volume observed                                                  |
| VirusTotal Jujubox     | ⚠️ 50 alerts               | Multiple suspicious behaviors                                                  |
| C2AE                   | ✅ No alerts                | Successful evasion                                                             |
| VirusTotal Observer    | ✅ No alerts                | Successful evasion                                                             |

The high evasion rate across sandboxes is intentional and expected. The `long-sleeps` tag
indicates the malware uses extended sleep calls designed to outlast most automated sandbox
timeout windows. The `detect-debug-environment` tag confirms anti-analysis checks were
observed triggering.

### 6.2 Process Injection — T1055

**Confirmed from sandbox process tree:**

```text
C:\Program Files\Google1084_461961379\bin\updater.exe --update --system ...
C:\Program Files\Google1556_2660802\bin\updater.exe --update --system ...
C:\Program Files\Google2116_724760920\bin\updater.exe --update --system ...
[87+ additional instances following the same pattern]
```

The malicious payload is injected into each running instance. After injection, the process is
terminated. All malicious activity executes inside a legitimate, Google-signed binary.

**Confirmed from sandbox dropped files and installed directories:**

```text
C:\Program Files (x86)\Google\GoogleUpdater\136.0.7079.0\
C:\Program Files (x86)\Google\GoogleUpdater\137.0.7115.0\
C:\Program Files (x86)\Google\GoogleUpdater\137.0.7129.0\
C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.0\
C:\Program Files (x86)\Google\GoogleUpdater\138.0.7194.0\
C:\Program Files (x86)\Google\GoogleUpdater\140.0.7272.0\
C:\Program Files (x86)\Google\GoogleUpdater\140.0.7273.0\
C:\Program Files (x86)\Google\GoogleUpdater\141.0.7340.0\
C:\Program Files (x86)\Google\GoogleUpdater\141.0.7376.0\
```

Each installation includes a complete Crashpad crash reporting directory structure. The
result is indistinguishable from a legitimate Google Updater installation in a casual
inspection of `C:\Program Files (x86)\Google\`.

### 6.3 System Binary Proxy Execution — T1218

**Confirmed from sandbox process creation logs:**

```text
rundll32.exe "C:\Users\[USER]\AppData\Local\Temp\MSIB20D.tmp",
  zzzzInvokeManagedCustomActionOutOfProc SfxCA_6478875 1
  MSICustomActionDLL!MSICustomActionDLL.CustomActions.EntryPointOne
```

From the perspective of endpoint security tools, this looks like a signed Windows binary
loading a DLL from a temp directory during software installation — an activity that occurs
legitimately in thousands of installer types.

### 6.4 Persistence — T1543 and T1547

**Confirmed from sandbox registry and service analysis:** The malware registers
`GoogleUpdaterInternalService*` services with `Start=2 (SERVICE_AUTO_START)`, meaning they
start automatically on every system boot. These services run as LocalSystem, the highest
privilege level available on Windows.

**Confirmed from sandbox file system actions:** A DPAPI key is written to
`C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\941a2910-ceaf-4083-a069-04b1d985b6d1`.
Writing a DPAPI key at the LocalSystem level grants the malware persistent ability to decrypt
system-level encrypted secrets.

### 6.5 Credential Access — T1056 and T1179

**Observed from sandbox behavioral tags and CAPA analysis:** Keylogging (T1056) and hooking
(T1179) are documented as confirmed capabilities from CAPA analysis of the SfxCA DLL and
payload. The specific implementation — polling for keylogging, specific hooking locations —
is described in rocket1337's published analysis based on recovered C# source code. The
sandbox behavioral tags confirm the capability categories; the specific mechanism is
documented from the source-code analysis.

### 6.6 Network Reconnaissance

**Confirmed from sandbox network traffic logs:** NetBIOS UDP packets (port 137) were observed
being sent to addresses in the `192.168.0.x` range throughout sandbox execution — documented
in the IP Traffic section of the Behavior tab. This maps every device on the local network
segment.

**Confirmed from sandbox behavioral data:** The Windows Security Center service (`wscsvc`)
was accessed — documented in the Services Opened section of the Behavior tab.

### 6.7 Second-Stage Payloads

**Observed from sandbox process tree — hashes from sandbox only, not separately verified on
VirusTotal:**

```text
Set-up.exe (PID 736)
  └─ 5614ba3c7415e4ee3cb1bdbff08cc643.exe  (PID 3032)
  └─ cde09bcdf5fde1e2eac52c0f93362b79.exe  (PID 1416)
```

> [!NOTE]
> These child executable hashes come from sandbox process tree documentation. They were not
> separately submitted to VirusTotal as independent samples with their own analysis pages at
> the time of this report. Their capabilities are unknown beyond the fact that they were
> spawned and executed.

Eleven files were dropped in total during full execution.

### 6.8 Anti-Forensics

**Confirmed from sandbox file system actions:**

```text
C:\Users\[USER]\AppData\Local\Temp\MSIB20D.tmp
C:\Users\[USER]\AppData\Local\Temp\MSIB20D.tmp-\CustomAction.config
C:\Users\[USER]\AppData\Local\Temp\MSIB20D.tmp-\MSICustomActionDLL.dll
C:\Users\[USER]\AppData\Local\Temp\MSIB20D.tmp-\MSICustomActionDLL.pdb
C:\Users\[USER]\AppData\Local\Temp\MSIB20D.tmp-\Microsoft.Deployment.WindowsInstaller.dll
```

---

## 7. Command and Control Infrastructure

### 7.1 The Active C2 Server

**Confirmed — live test documented in rocket1337's April 9, 2026 VirusTotal analysis:**

| Field                  | Value                                                              |
| ---------------------- | ------------------------------------------------------------------ |
| **Endpoint**           | `POST https://i-odsports.com/aycha/saver.php`                      |
| **Primary IP**         | `104.21.5.5` (Cloudflare CDN)                                      |
| **Secondary IP**       | `172.67.132.177` (Cloudflare CDN)                                  |
| **Confirmed response** | `{"status":"success","message":"Log received and stored."}`        |
| **GET camouflage**     | GET requests redirect to `avast.com`                               |
| **TLS**                | v1, cert serial `00ac661f8828b2b2220e5ed8e1d6e2913f`               |
| **JA3**                | `cbcd1d81f242de31fd683d5acbc70dca`                                 |
| **JA3S**               | `d202ce1ad7e4f3d5b39fb831970e4b49f8cb7426ea09faef21c6ff723a632f2d` |
| **JA4**                | `t10d120500_d94e65cdb899_559829c2a830`                             |
| **TLS cert issuer**    | Google Trust Services (CN=WE1)                                     |

Routing through Cloudflare's CDN hides the actual hosting server's IP address, making
infrastructure takedown significantly more complex than blocking direct IP addresses alone.

### 7.2 Domain Intelligence — A Deliberate Lookalike

The C2 domain `i-odsports.com` is **not** `odsports.com`. These are completely separate
registered domains. The legitimate `odsports.com` is a Chinese sports betting platform
(OD体育) registered since 2014 with no connection to this malware campaign.

**All fields below are confirmed via public WHOIS/RDAP lookup at lookup.icann.org and the
VirusTotal domain details tabs for both domains:**

| Field             | `i-odsports.com` (C2)        | `odsports.com` (Legitimate)    |
| ----------------- | ---------------------------- | ------------------------------ |
| **Registered**    | **February 6, 2025**         | March 7, 2014                  |
| **Registrar**     | Gname.com Pte. Ltd.          | GoDaddy.com                    |
| **Purpose**       | **Malware C2 server**        | Chinese sports platform (OD体育) |
| **WHOIS privacy** | Full privacy protection      | Standard registration          |
| **Nameservers**   | Cloudflare (host anonymized) | Afternic                       |
| **VT detections** | 0/94                         | 1/94 (Forcepoint category)     |

The `i-` prefix makes `i-odsports.com` appear to be a subdomain or internal variant of the
established sports brand when it appears in SIEM alerts or network logs alongside legitimate
web traffic. The domain was registered **nine months before this torrent appeared**, confirming
pre-planned infrastructure construction.

### 7.3 What Was Exfiltrated

**Confirmed from sandbox WMI dataset and network traffic combined with rocket1337's source
code analysis:**

| Data Point        | Collection Method                 | Obfuscation           |
| ----------------- | --------------------------------- | --------------------- |
| Hardware UUID     | WMI `Win32_ComputerSystemProduct` | ROT13 on query string |
| GPU model         | WMI `Win32_VideoController`       | ROT13 on query string |
| Windows username  | WMI and `GetUserNameW`            | None                  |
| Computer hostname | `GetComputerNameExW`              | None                  |
| Campaign version  | Hardcoded                         | `Flow=PS6`            |
| Event type        | Hardcoded                         | `Action=Login`        |

### 7.4 Secondary Payload Staging Infrastructure

**Observed — memory pattern strings only:**

```text
trondevuserpackages.s3.amazonaws.com
tronstageuserpackages.s3.amazonaws.com
```

> [!NOTE]
> These hostnames were found in memory pattern analysis but confirmed active contact with
> these S3 buckets was not documented in the sandbox network traffic logs for the analyzed
> sample. They are noted here as potential staging infrastructure but their active use during
> this specific execution has not been independently confirmed.

---

## 8. Threat Intelligence

### 8.1 Malware Family Classification

**MWDB (cert.pl) — February 28, 2025** *(confirmed, publicly verifiable at the MWDB link in
References):*
Researcher `petik` catalogued this file with the original filename
`2025-02-28_e9d48daf4748eee45abf308b85e88b71_avoslocker_luca-stealer`, identifying it as a
combination of Luca Stealer (targets browsers, cryptocurrency wallets, session cookies, FTP
clients) and AvosLocker (ransomware loader).

**THOR APT Scanner (Nextron Systems) — November 11, 2025** *(confirmed, rule names and dates
documented in VirusTotal Community tab):*
Five YARA rules triggered from the VALHALLA commercial feed, including
`MAL_Raccoon_Stealer_V2_Jul22_1` (Raccoon Stealer V2), `APT_RU_MAL_Turla_Jan21_1`, and
`APT_MAL_macOS_APT28_XAgent_May21_1`. The Turla and APT28 matches almost certainly reflect
shared code patterns from common .NET framework libraries rather than direct threat actor
attribution — a documented limitation explicitly acknowledged by Nextron Systems in their
published guidance on interpreting YARA matches on .NET binaries.

**Reverse engineering (rocket1337) — April 9, 2026** *(confirmed published analysis,
independently viewable on VT):*
Complete C# source code recovered via ILSpy. Custom-built .NET 4.7.2 infostealer, not a
repurposed commodity tool. The published analysis is available in the Community tab of the
MSICustomActionDLL.dll file page on VirusTotal and can be read by any registered user.

### 8.2 MITRE ATT&CK Mapping

*All technique assignments are based on confirmed sandbox observations or confirmed static
analysis findings. Each entry includes only techniques for which evidence exists.*

| ID    | Tactic               | Technique                             | Evidence Basis                                     |
| ----- | -------------------- | ------------------------------------- | -------------------------------------------------- |
| T1059 | Execution            | Command & Scripting Interpreter       | Script exec during install *(sandbox)*             |
| T1047 | Execution            | Windows Management Instrumentation    | WMI confirmed in sandbox dataset                   |
| T1218 | Execution / Evasion  | System Binary Proxy — `rundll32`      | Process tree confirmed in sandbox                  |
| T1055 | Execution / Evasion  | Process Injection (×2 sub-techniques) | 90+ Updater instances in sandbox                   |
| T1543 | Persistence          | Create / Modify System Process        | Services confirmed in sandbox                      |
| T1547 | Persistence          | Boot/Logon Autostart Execution        | `Start=2` confirmed in sandbox                     |
| T1179 | Privilege Escalation | Hooking                               | CAPA analysis + source code analysis               |
| T1036 | Defense Evasion      | Masquerading                          | Dolby cover confirmed in MSI structure             |
| T1027 | Defense Evasion      | Obfuscated Files or Information (×3)  | ROT13 confirmed; 4-layer confirmed; cert confirmed |
| T1497 | Defense Evasion      | Virtualization/Sandbox Evasion        | CAPA + 5/7 sandboxes showed evasion                |
| T1562 | Defense Evasion      | Impair Defenses                       | `wscsvc` access confirmed in sandbox               |
| T1485 | Impact               | Data Destruction                      | Files deleted confirmed in sandbox                 |
| T1056 | Collection           | Input Capture — Keylogging            | CAPA + T1056 tag confirmed in sandbox              |
| T1033 | Discovery            | System Owner/User Discovery           | Username via WMI confirmed in sandbox              |
| T1082 | Discovery            | System Information Discovery          | UUID, GPU confirmed in sandbox WMI                 |
| T1083 | Discovery            | File and Directory Discovery          | File system ops confirmed in sandbox               |
| T1087 | Discovery            | Account Discovery                     | `System.Security.Principal` in .NET types          |
| T1063 | Discovery            | Security Software Discovery           | `wscsvc` access confirmed in sandbox               |
| T1120 | Discovery            | Peripheral Device Discovery           | `checks-usb-bus` tag confirmed in sandbox          |
| T1046 | Discovery            | Network Service Discovery             | NetBIOS UDP 137 confirmed in sandbox               |
| T1071 | C&C                  | Application Layer Protocol            | HTTP POST confirmed *(live C2 test)*               |
| T1573 | C&C                  | Encrypted Channel                     | TLS confirmed in sandbox network logs              |
| T1091 | Lateral Movement     | Replication via Removable Media       | USB enumeration — prep only, *inferred*            |

### 8.3 The Seven Reasons Zero Antivirus Engines Detected It

**1. Four-layer payload nesting** *(Confirmed from PE analysis and sandbox)*
The .NET infostealer DLL is only extracted in memory at runtime. Antivirus engines scanning
the PE sections of any individual file find no malicious code — because the payload doesn't
reside in any PE section. It exists only in a 79,576-byte encrypted overlay.

**2. Stolen expired certificate** *(Confirmed from VirusTotal signature details)*
The Dolby Laboratories certificate causes many tools to treat the MSI as a trusted installer
without deep behavioral analysis. The `HashMismatch` flag requires specific signature
validation depth that many tools skip.

**3. ROT13 string obfuscation** *(Confirmed — mathematically verifiable)*
Every suspicious string that antivirus YARA rules would match is encoded using ROT13. The
encoded forms match no existing signatures. Any analyst can verify the decoded values with a
ROT13 calculator.

**4. Anti-debugger and anti-VM** *(Confirmed from sandbox results)*
Five out of seven sandbox environments saw no malware behavior at all — objective proof that
the anti-analysis mechanisms work as designed.

**5. Living off the land** *(Confirmed from sandbox process tree)*
All malicious execution happens inside `rundll32.exe` — a Microsoft-signed Windows binary
that security tools are explicitly configured to trust.

**6. Long sleep delays** *(Confirmed from Zenbox behavioral tag)*
The `long-sleeps` tag documents that extended sleep calls were observed. An automated
analysis session that terminates after 60 seconds never sees a payload that sleeps longer.

**7. Camouflaged C2 traffic** *(Confirmed from rocket1337's live test)*
GET requests to the C2 domain redirect to `avast.com` — documented in the published
VirusTotal analysis. Network logs appear to contain antivirus update traffic rather than data
exfiltration.

---

## 9. Indicators of Compromise

Security teams should use the following for detection, blocking, and hunting.

### 9.1 File Hashes — Complete Component Chain

| Component                                   | Role               | SHA256                                                             | MD5                                |
| ------------------------------------------- | ------------------ | ------------------------------------------------------------------ | ---------------------------------- |
| `Set-up.exe` / `sourcepart.dat`             | Delivery           | `3d20655679c8829a6baad001851905927ef1b826e3eea594b7be3f8331211e39` | `e9d48daf4748eee45abf308b85e88b71` |
| `Installer.msi`                             | Layer 1            | `45415f110b7961eea726dd3b1c07ebed2bbc44d13e8d92d0d8bd1304ba145d73` | `595eb28f84979f035375a35efe92c259` |
| `SfxCA DLL`                                 | Layer 2            | `06875058d4f40be9fb9d065bb4dbc29f67e80339ea261143d123d582c1481171` | `efaa71c29a914094691c2582c657dc1f` |
| `MSICustomActionDLL.dll`                    | **Active payload** | `487aca2bbd630c8013ee1992dabb970058c9a737c2fffce0c0a45801408771cd` | `732de0a3ddfeb4b5ad29387d3cbf66ee` |
| `CustomAction.config`                       | Config             | `5d6fd5049f33ac6b16ec0431787fa61c66630ba1916bb4c70f3f6b5844b74ecb` | —                                  |
| `Microsoft.Deployment.WindowsInstaller.dll` | WiX dependency     | `cf06d4ed4a8baf88c82d6c9ae0efc81c469de6da8788ab35f373b350a4b4cdca` | —                                  |

### 9.2 Network Indicators — Block These

```text
Domain:   i-odsports.com
IP:       104.21.5.5
IP:       172.67.132.177
Endpoint: POST /aycha/saver.php  (on above domain)
JA3:      cbcd1d81f242de31fd683d5acbc70dca
JA3S:     d202ce1ad7e4f3d5b39fb831970e4b49f8cb7426ea09faef21c6ff723a632f2d
Monitor:  trondevuserpackages.s3.amazonaws.com
Monitor:  tronstageuserpackages.s3.amazonaws.com
```

### 9.3 Suspicious Process Command Line (High-Confidence Detection Rule)

```text
rundll32.exe *\AppData\Local\Temp\MSI*.tmp,
zzzzInvokeManagedCustomActionOutOfProc*
MSICustomActionDLL*CustomActions*EntryPointOne
```

This command line pattern is highly specific to this malware's execution mechanism and is
unlikely to appear in legitimate software.

### 9.4 Persistence Artifacts to Remove

**Services** (all with `Start=2 AUTO_START`):

```text
GoogleUpdaterInternalService136.0.7079.0
GoogleUpdaterInternalService137.0.7115.0
GoogleUpdaterInternalService137.0.7129.0
GoogleUpdaterInternalService138.0.7156.0
GoogleUpdaterInternalService138.0.7194.0
GoogleUpdaterInternalService140.0.7272.0
GoogleUpdaterInternalService140.0.7273.0
GoogleUpdaterInternalService141.0.7340.0
GoogleUpdaterInternalService141.0.7376.0
```

**Directories:**

```text
C:\Program Files\Google{process_id}_{random_integer}\
C:\Program Files (x86)\Google\GoogleUpdater\136.*\
C:\Program Files (x86)\Google\GoogleUpdater\137.*\
C:\Program Files (x86)\Google\GoogleUpdater\138.*\
C:\Program Files (x86)\Google\GoogleUpdater\140.*\
C:\Program Files (x86)\Google\GoogleUpdater\141.*\
```

**Files** (cover story — remove if no genuine Dolby hardware is present):

```text
C:\Windows\System32\spool\drivers\color\PQConfig_*.dv
C:\Windows\System32\spool\drivers\color\PQCOnfig_*.dv
```

### 9.5 Registry Indicators

```text
HKCU\SOFTWARE\Microsoft\Internet Explorer\Main\
FeatureControl\FEATURE_BROWSER_EMULATION\Set-up.exe = 11001

C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\
941a2910-ceaf-4083-a069-04b1d985b6d1  [DPAPI key written by malware]
```

### 9.6 Mutexes

```text
HDInstaller.log
\Sessions\1\BaseNamedObjects\HDInstaller.log
```

### 9.7 Campaign Identifiers

```text
HTTP POST parameter: Flow=PS6
HTTP POST parameter: Action=Login
```

---

## 10. Incident Response

### 10.1 Assess Your Exposure First

| Scenario                                          | Risk            | Action                                                              |
| ------------------------------------------------- | --------------- | ------------------------------------------------------------------- |
| `Set-up.exe` executed, Adobe installed normally   | 🔴 **Critical** | Assume full compromise — treat all credentials as known to attacker |
| `Set-up.exe` executed, fake memory error appeared | 🟡 **Moderate** | Partial compromise possible — exfiltration occurs before VM check   |
| ISO mounted but `Set-up.exe` not run              | 🟢 **Low**      | Delete ISO, monitor network logs for 30 days                        |
| Torrent downloaded only                           | 🟢 **None**     | Delete files                                                        |

### 10.2 Immediate Actions — First 30 Minutes

**Disconnect the infected machine from the network immediately.** Unplug Ethernet and disable
Wi-Fi. An active C2 connection may be in progress. Every second of connectivity is an
opportunity for additional data exfiltration or secondary payload delivery.

**Do not power off the machine yet if you want forensic evidence.** Running processes and
active network connections document the compromise. Power off only after evidence is captured
or if forensics are not a priority.

**From a separate, clean device, change every important password:** Email (primary and
recovery addresses), banking and financial accounts, password manager master password, work
or corporate accounts, cloud storage services, any development service API keys. Do not use
the infected machine for any logins until it is fully remediated.

**Block C2 infrastructure at your router or firewall:** DNS resolution and network traffic to
`i-odsports.com`, `104.21.5.5`, and `172.67.132.177` should be blocked immediately.

### 10.3 Short-Term Actions — First 24 Hours

**Revoke all active sessions and tokens:** Google account (Security → Manage devices → Sign
out all other sessions), Microsoft account, GitHub (Settings → Developer settings → Personal
access tokens and OAuth Apps), and any service accessed from the infected machine after the
date the malware was run.

**Enable multi-factor authentication on every account.** Use TOTP-based authenticator apps
(Google Authenticator, Authy, or Aegis) rather than SMS-based codes, which are vulnerable to
SIM swapping attacks. Generate backup codes and store them from a clean device.

**Alert your financial institution.** Explain that your computer was compromised and request
enhanced transaction monitoring. Review recent transactions for any unauthorized activity.
Consider a temporary card freeze.

**Audit all browser extensions** in Chrome, Edge, Firefox, and any other browser installed on
the machine. The malware may have installed persistent credential-harvesting extensions.
Remove anything not explicitly installed by you.

**Check for additional installed software.** Run `winget list` from a PowerShell window and
look for any package installed around the date of infection that you do not recognize. Search
installed programs for "Planora" — remove it if found.

### 10.4 Remediation

**Option A — Manual removal (less reliable):**

Stop and delete the malicious services:

```powershell
Get-Service GoogleUpdaterInternalService* | Stop-Service -Force
Get-Service GoogleUpdaterInternalService* | Remove-Service
```

Delete malware directories:

```powershell
Remove-Item "C:\Program Files\Google????_*" -Recurse -Force
Remove-Item "C:\Program Files (x86)\Google\GoogleUpdater\13*" -Recurse -Force
Remove-Item "C:\Program Files (x86)\Google\GoogleUpdater\14*" -Recurse -Force
```

Remove DPAPI key written by the malware:

```powershell
Remove-Item "C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\941a2910-ceaf-4083-a069-04b1d985b6d1"
```

Clear malware logs:

```powershell
Remove-Item "$env:TEMP\CreativeCloud" -Recurse -Force
```

> [!WARNING]
> This approach cannot guarantee completeness given the depth of compromise. API hooks
> operate at the kernel boundary and may persist through these steps.

**Option B — Format and reinstall (recommended):**

Boot from external media prepared on a clean machine. Wipe the system drive with a full
format (not quick format). Reinstall Windows from official Microsoft installation media.
Restore only data files — documents, photos, non-executable personal files — from backups
created before the infection date. Do not restore browser profiles, executable files, or
application data from infected backups.

A clean OS reinstallation is the only method that provides verifiable assurance of complete
remediation.

---

## 11. Conclusion

This analysis documents a professionally engineered infostealer **confirmed across six
independent sources** — VirusTotal static and behavioral data, MWDB classification,
FileScan.IO analysis, tria.ge sandbox, THOR APT Scanner YARA matching, and live C2
verification. It successfully evades every major antivirus engine through seven complementary
techniques: stolen certificates, multi-layer obfuscation, ROT13 encoding, anti-VM clean
exits, living-off-the-land execution, timing-based evasion, and C2 camouflage. The malware
exfiltrates data before the user sees the first installer screen, then launches the legitimate
Adobe software as cover, leaving the victim with no indication that anything occurred.

Two components remain unidentified at the time of this report: the application installed
silently via `winget install -h --id 9N411ZGN6M6G`, and the secondary payload launched as
`Planora /INSTALL`. These are documented as **observed behaviors**, not confirmed malicious
components, because their content is not yet public. They represent the outer boundary of
what the available evidence can confirm.

The C2 server was purpose-registered nine months before distribution began and was confirmed
operational as of April 9, 2026. The same payload DLL hash appears in a parallel campaign
targeting Photoshop crack users. This is a sustained, organized, multi-product operation —
documented, not inferred.

> [!CAUTION]
> **Zero antivirus detections is not evidence of safety. It is evidence of evasion.**
>
> If this file was executed on your machine, follow the incident response steps in Section 10
> and treat the machine as compromised until proven otherwise through a complete OS
> reinstallation.

---

## 12. References and Source Index

All findings in this report trace to at least one independently verifiable source listed
here. Claims are categorized by the type of evidence they represent.

### VirusTotal — Primary Analysis Platform

All file analysis pages are public and accessible to any registered user via the hash values
provided. The Behavior tab (sandbox data), Details tab (PE metadata and .NET assembly info),
Community tab (researcher analyses), and Relations tab (execution parents) are all
independently readable.

* Set-up.exe: `https://www.virustotal.com/gui/file/3d20655679c8829a6baad001851905927ef1b826e3eea594b7be3f8331211e39`
* Installer.msi: `https://www.virustotal.com/gui/file/45415f110b7961eea726dd3b1c07ebed2bbc44d13e8d92d0d8bd1304ba145d73`
* SfxCA DLL: `https://www.virustotal.com/gui/file/06875058d4f40be9fb9d065bb4dbc29f67e80339ea261143d123d582c1481171`
* MSICustomActionDLL.dll: `https://www.virustotal.com/gui/file/487aca2bbd630c8013ee1992dabb970058c9a737c2fffce0c0a45801408771cd`
* C2 domain intelligence: `https://www.virustotal.com/gui/domain/i-odsports.com`

### MWDB — Malware Database (CERT Polska)

Sample catalogued February 28, 2025 by researcher `petik` — publicly viewable:

* `https://mwdb.cert.pl/file/3d20655679c8829a6baad001851905927ef1b826e3eea594b7be3f8331211e39`

### FileScan.IO — Independent Sandbox Analysis

Multiple independent analyses confirming SUSPICIOUS and LIKELY_MALICIOUS verdicts:

* `https://www.filescan.io/reports/f6e3c4549690718297924317757db3941e9f282c0534d9ae1d20132d4f8d6659/7b3822d4-2620-4aca-8c4d-1f8d94462ac9`
* `https://www.filescan.io/reports/f6e3c4549690718297924317757db3941e9f282c0534d9ae1d20132d4f8d6659/a9eda77c-4e07-49ec-a283-6664a993213f`

### tria.ge — Interactive Sandbox

Behavioral analysis confirming runtime characteristics:

* `https://tria.ge/250228-z9efqax1gx`

### MalwareBazaar / Malshare — Public Sample Repositories

* MalwareBazaar search by MD5 `e9d48daf4748eee45abf308b85e88b71`: `https://bazaar.abuse.ch/`
* Malshare: `https://malshare.com/sample.php?action=detail&hash=95ce97cd76fb08e07e005f3a419757b1`

### THOR APT Scanner — VALHALLA YARA Feed (Nextron Systems)

Five YARA rule matches documented November 11, 2025:

* Raccoon Stealer V2 rule: `https://valhalla.nextron-systems.com/info/rule/MAL_Raccoon_Stealer_V2_Jul22_1`
* Raccoon Stealer V2 original research (AhnLab ASEC): `https://asec.ahnlab.com/en/35981/`
* Nextron guidance on YARA attribution limitations: `https://www.nextron-systems.com/notes-on-virustotal-matches/`

### Sigma Rule Matches — SigmaHQ GitHub

All Sigma rules triggered are publicly available and searchable:

* `https://github.com/SigmaHQ/sigma`

### MITRE ATT&CK Framework — Technique References

* T1047 (WMI): `https://attack.mitre.org/techniques/T1047/`
* T1218 (System Binary Proxy): `https://attack.mitre.org/techniques/T1218/`
* T1055 (Process Injection): `https://attack.mitre.org/techniques/T1055/`
* T1497 (Virtualization/Sandbox Evasion): `https://attack.mitre.org/techniques/T1497/`
* T1056 (Input Capture): `https://attack.mitre.org/techniques/T1056/`
* Full ATT&CK matrix: `https://attack.mitre.org/`

### Luca Stealer — Background Research

* Luca Stealer documentation (Unit 42, Palo Alto Networks): `https://unit42.paloaltonetworks.com/`
* AhnLab ASEC Luca Stealer analysis: `https://asec.ahnlab.com/en/36152/`
* MalwareBazaar Luca Stealer tag: `https://bazaar.abuse.ch/browse/tag/luca-stealer/`

### AvosLocker — Background Research

* CISA AvosLocker advisory (AA23-132A): `https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-132a`

### WiX Toolset — Legitimate Framework Reference

The SfxCA mechanism abused in Layer 2 is documented in official WiX documentation:

* `https://wixtoolset.org/`

### WHOIS / Domain Registration Data

Registration date for `i-odsports.com` (February 6, 2025) verifiable via:

* ICANN RDAP lookup: `https://lookup.icann.org/`
* VirusTotal domain details tab (same link as C2 domain entry above)

### uztracker.net — Original Torrent Post

Package description and m0nkrus attribution context:

* `https://uztracker.net/viewtopic.php?t=64297`

### ROT13 Verification

The WMI query string obfuscation decodes are mathematically verifiable with any ROT13 tool:

* `https://rot13.com/` — enter `Jva32_PbzchgreFlffgrzCebqhpg` to verify the decode to `Win32_ComputerSystemProduct`

---

*Analysis Date: April 14, 2026*
*All IOCs, hashes, domain names, and IP addresses are provided exclusively to assist security
teams and individuals in detection and remediation of this specific threat.*
*This report contains no exploit code, offensive tooling, or instructions enabling malicious
use of any kind.*
*License: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — free to share and
adapt with attribution*
