# File-Integrity-Checker

*COMPANY*: CODTECH IT SOLUTION

*NAME*: SUKHDEEP SINGH

*INTERN ID*: CT04DK913

*DOMAIN*: CYBER SECURITY & ETHICAL HACKER

*DURATION*: 4 WEEKS

*MENTOR*:NEELA SANTOSH

DESCRIPTION

**1. Introduction**

In the current digital environment, where data manipulation and cyber-attacks are increasingly common, the integrity of critical files is of utmost importance. This project aims to build a **File Integrity Checker** using **Python** with a **Graphical User Interface (GUI)** to make it accessible and user-friendly. The tool monitors files and directories, generates cryptographic hash values (SHA-256), and checks these values over time to detect any unauthorized changes or corruption. The project serves both security purposes and practical data management needs.

**2. Objective**

The main objective of this project is to develop a Python application with an interactive GUI that:
- Allows users to select files or directories via a user-friendly interface.
- Computes and stores the SHA-256 hash of each selected file.
- Compares current hash values with stored originals during periodic or on-demand scans.
- Notifies the user of any discrepancies through alerts or logs within the GUI.

**3. Technology Stack**

- **Programming Language**: Python 3.x  
- **GUI Framework**: Tkinter (Python’s standard GUI toolkit)  
- **Hashing Algorithm**: SHA-256 (via Python's `hashlib` module)  
- **Storage Format**: JSON for storing original hash values and logs  
- **File Handling**: `os`, `pathlib`, and `json` for interacting with the file system

**4. System Workflow**

The system operates in two primary modes:

**a. Setup Mode (Initial Hashing):**  
Through the GUI, the user selects files or directories to monitor. The system computes SHA-256 hashes for each file and stores them securely in a JSON file as a reference for future comparisons.

**b. Verification Mode (Integrity Check):**  
When the user initiates a file integrity check through the GUI, the system recalculates the hash of each file and compares it with the previously stored value. If a mismatch is detected, it signifies that the file has been modified, and the application notifies the user via the interface and logs the change.

**5. Features**

- **User-Friendly GUI**: Built with Tkinter, offering file/directory selection dialogs, status indicators, and a log viewer.
- **Secure Hashing**: SHA-256 ensures tamper-proof and unique fingerprinting of files.
- **Recursive Monitoring**: Option to include all files within selected folders and subfolders.
- **Real-Time Alerts**: Immediate visual notifications when a file's integrity is compromised.
- **Log Management**: Viewable logs directly within the GUI showing file changes, timestamps, and status.
- **Cross-Platform Support**: Compatible with Windows, Linux, and macOS as long as Python is installed.

**6. Use Cases**

- Monitoring configuration files and documents for tampering.
- Verifying the integrity of backups or software packages.
- Detecting malware or ransomware activity that alters file content.
- Compliance and auditing in enterprise environments.

**7. Limitations and Future Enhancements**

While the current implementation is functional and effective for local file integrity checks, it has certain limitations:
- No real-time file system monitoring (i.e., no event-based tracking).
- Notifications are limited to GUI alerts; integration with email or system notifications could be added.
- JSON storage is simple but could be replaced with a more secure, encrypted database.
- Does not currently support version control or automatic recovery of altered files.

Future enhancements may include:
- Real-time monitoring using watchdog or OS hooks.
- Integration with cloud storage or remote monitoring.
- GUI improvements for better usability and aesthetics.
- Addition of exportable PDF reports for auditing purposes.

**8. Conclusion**

The File Integrity Checker developed using Python with a Tkinter-based GUI is a practical and user-friendly solution for monitoring file changes and ensuring data integrity. By combining the power of cryptographic hashing with an accessible interface, this project addresses a vital need in cybersecurity and file management. It also demonstrates key concepts in Python programming, GUI development, and security principles, making it a valuable academic and practical endeavor.
