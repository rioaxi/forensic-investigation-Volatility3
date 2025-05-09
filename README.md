# 🕵️ Forensic Investigation using Volatility 3

This project documents a forensic memory analysis conducted using [Volatility 3](https://github.com/volatilityfoundation/volatility3). The memory dump originates from a Windows 7 x64 system infected with **Amadey malware**, a known info-stealer and loader. The investigation covers command-line artifacts, process trees, file paths, and network connections to trace the malware's behavior and persistence mechanisms.

---

## 🛠️ Tools Used

- 🧠 **Volatility 3** (v2.5.0)
- 🖥️ Memory Image: `Windows 7 x64-Snapshot4.vmem`
- 🐧 Host OS: Ubuntu 20.04
- 🔍 Filters: `grep`, `cmdline`, `filescan`, `pstree`, `netscan`

---

## 🎯 Investigation Objectives

- Identify the malicious process and its origin
- Extract indicators of compromise (IOCs)
- Analyze lateral activity and external communications
- Identify persistence mechanisms and cleanup targets

---

## 🔍 Key Findings

### 1️⃣ What is the name of the parent process that triggered this malicious behavior?

- **Answer:** `lssass.exe` (⚠️ not the legitimate `lsass.exe`)
- **Command Used:**
  ```bash
  ./vol.py -f ... windows.cmdline
  ```
- **Explanation:** 
  The `cmdline` plugin output revealed a suspicious process with PID 2748 and the name `lssass.exe`. This is a known masquerading technique — the extra "s" in the name makes it look like the legitimate `lsass.exe`, a critical Windows process.
  
  **Red flags observed:**
  - The legitimate `lsass.exe` runs from `C:\Windows\System32\lsass.exe` (PID 508).
  - The suspicious one runs from `C:\Users\0XSH3R~1\AppData\Local\Temp\925e7e99c5\lssass.exe` — the Temp directory is commonly abused by malware.
  - This naming is clearly an attempt to blend in with real system processes while avoiding user suspicion.

---

### 2️⃣ Where is this process housed on the workstation?

- **Answer:**  
  `C:\Users\0XSH3R~1\AppData\Local\Temp\925e7e99c5\lssass.exe`
- **Found via:** `windows.cmdline`

---

### 3️⃣ Can you identify the Command and Control (C2C) server IP that the process interacts with?

- **Answer:** `41.75.84.12`
- **Command Used:**
  ```bash
  ./vol.py -f ... windows.netscan
  ```
- **Details:**
  ```
  PID 2748 (lssass.exe) → 41.75.84.12:80
  ```
- **Explanation:**
  The `windows.netscan` plugin showed active and closed network connections. Two specific entries indicated that the malicious `lssass.exe` process (PID 2748) attempted to connect to external IP address `41.75.84.12` on port 80 — typical for HTTP-based communication.
  
  These closed connections suggest:
  - The malware likely attempted to fetch additional payloads or exfiltrate data.
  - Communication occurred over standard HTTP to avoid detection.
  - The server IP is likely part of Amadey's Command and Control infrastructure.
  
  Identifying and blocking this IP can help mitigate further spread or reinfection.

---

### 4️⃣ How many distinct files is the malware trying to bring onto the compromised workstation?

- **Answer:** 2
  - `clip64.dll`
  - `storePwd.exe`
- **Command Used:**
  ```bash
  ./vol.py -f ... windows.filescan | grep -i 'AppData' | grep -Ei "\.exe|\.dll"
  ```

---

### 5️⃣ What is the full path of the file downloaded and used by the malware?

- **Answer:**  
  `C:\Users\0xSh3rl0ck\AppData\Roaming\116711e5a2ab05\clip64.dll`
- **Found via:** `windows.filescan`

---

### 6️⃣ Which child process is initiated by the malware to execute these files?

- **Answer:** `rundll32.exe`
- **Command Used:**
  ```bash
  ./vol.py -f ... windows.pstree
  ```
- **Process Tree:**
  ```
  2748 lssass.exe
   └── 3064 rundll32.exe
  ```

---

### 7️⃣ Where else might the malware be ensuring its consistent presence (persistence)?

- **Answer:**  
  `C:\Windows\System32\Tasks\lssass.exe`
- **Command Used:**
  ```bash
  ./vol.py -f ... windows.filescan | grep -i 'lssass.exe'
  ```
- **Explanation:**
  In addition to running from the user's Temp folder, the malware binary was also found under the `System32\Tasks` directory, indicating the creation of a malicious Scheduled Task.
  
  This is a common persistence technique:
  - Malware adds itself to the Windows Task Scheduler to re-execute at login or scheduled times.
  - This ensures that even after a reboot, the payload is reloaded.
  - Using a name like `lssass.exe` makes the task blend in with legitimate system activities.

  Analysts and responders should examine Task Scheduler for unauthorized entries and remove or disable them as part of cleanup.

---

## 🧪 Indicators of Compromise (IOCs)

| Type              | Value                                                             |
|-------------------|-------------------------------------------------------------------|
| Process Name      | `lssass.exe` (fake)                                               |
| File Path         | `C:\Users\0XSH3R~1\AppData\Local\Temp\925e7e99c5\lssass.exe`       |
| Dropped DLL       | `C:\Users\0xSh3rl0ck\AppData\Roaming\116711e5a2ab05\clip64.dll`   |
| Dropped EXE       | `C:\Users\0xSh3rl0ck\AppData\Local\Temp\storePwd.exe`             |
| Persistence Path  | `C:\Windows\System32\Tasks\lssass.exe`                            |
| C2 IP Address     | `41.75.84.12`                                                     |

---

## 🧹 Recommendations for Remediation

- Immediately isolate affected system from the network
- Kill the process tree of `lssass.exe` and `rundll32.exe`
- Remove dropped files from Temp and Roaming directories
- Delete the malicious Scheduled Task under `System32\Tasks`
- Block IP `41.75.84.12` at perimeter firewall
- Perform full credential reset and lateral movement assessment

---

## 📚 References

- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
- [Amadey Malware Analysis - ANY.RUN](https://any.run/malware-trends/amadey)
- [MITRE ATT&CK - Scheduled Task/Job (T1053)](https://attack.mitre.org/techniques/T1053/)
- [MITRE ATT&CK - Masquerading (T1036)](https://attack.mitre.org/techniques/T1036/)

---
