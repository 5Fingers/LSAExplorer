![version](https://img.shields.io/badge/version-1.0-blue)
![python versions](https://img.shields.io/badge/.NET->=4.7.2-blue)
[![Windows](https://img.shields.io/badge/os-windows-yellow)](https://github.com/scito/extract_otp_secrets/releases/latest)
# LSAExplorer

LSAExplorer is a C# .NET tool designed to interact with the Windows Local Security Authority (LSA), manipulate privileges, impersonate tokens, and access sensitive registry secrets. It provides detailed insights into LSA secrets and allows for privilege elevation for advanced operations.

---

## Features

- **LSA Secret Management**: Access and retrieve sensitive LSA secrets and their timestamps from the registry.
- **Privilege Elevation**: Elevate the current process to SYSTEM-level privileges using token manipulation (optional in restricted environments).
- **Token Impersonation**: Open and duplicate tokens to impersonate logged-on users.
- **Registry Secret Access**: Interact with and retrieve registry keys under `HKLM\SECURITY\Policy\Secrets`.
- **Winlogon Process Query**: Automatically locate the `winlogon` process ID for SYSTEM impersonation.

---

## Requirements

- **Operating System**: Windows 10/11 (x64 recommended).
- **Framework**: .NET Framework 4.7.2 or higher.

---

## Usage

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/LSAExplorer.git
   cd LSAExplorer
   ```

2. Open the solution in **Visual Studio**.

3. Build the project for your target platform (x64/x86).

4. Run the compiled executable with Administrator privileges.

5. Launch the executable with elevated privileges:
   ```bash
   LSAExplorer.exe
   ```

6. The tool will:
   - Attempt to open and query registry keys under `HKLM\SECURITY\Policy\Secrets`.
   - Elevate privileges to SYSTEM if required (optional).
   - Read and display LSA secrets, including current and old values along with timestamps.

7. Logs and output will be displayed in the console.

---

## Disclaimer

This tool is intended for **Ethical and Educational Use Only!**<br> Use it only in environments where you have explicit permission to perform security operations.<br> The author are not liable for any misuse or damages caused by this tool.

---

## License

LSAExplorer is released under the [MIT License](LICENSE).
