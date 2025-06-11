# Windows BAM Parser

A comprehensive Windows **BAM (Background Activity Moderator)** registry parser for digital forensics and system analysis. This tool extracts and analyzes application execution timestamps from the Windows registry to help with forensic investigations, system monitoring, and security analysis.

## 🔍 What is BAM?

**Background Activity Moderator (BAM)** is a Windows service introduced in Windows 10 that tracks when applications were last executed on the system. It stores this information in the Windows registry and is valuable for:

- **Digital Forensics**: Determine what programs were executed and when
- **Incident Response**: Track malware execution and user activity
- **System Monitoring**: Analyze application usage patterns
- **Timeline Reconstruction**: Build chronological views of system activity

## ✨ Features

- **Multi-Version Support**: Works with Windows 10 (1709+) and Windows 11
- **Interactive Interface**: User-friendly menu system with multiple display options
- **Flexible Output**: Choose from 10, 20, 30, 50, 100, or all recent programs
- **Custom Numbers**: Specify any number of recent programs to display
- **JSON Export**: Export results to structured JSON files for further analysis
- **Comprehensive Logging**: Detailed logging with timestamps and error handling
- **User Account Analysis**: Tracks activity across different user accounts (SIDs)
- **Timestamp Conversion**: Converts Windows FILETIME to readable dates
- **Error Handling**: Robust error handling and graceful exit options

## 🛠️ Requirements

### Dependencies
```python
pip install pywin32
```

### System Requirements
- **Operating System**: Windows 10 (build 16299+) or Windows 11
- **Python**: 3.6 or higher
- **Privileges**: Administrator privileges required for registry access
- **Architecture**: Works on both x86 and x64 systems

### Supported Windows Builds
| Windows Version | Build Numbers | Registry Path |
|----------------|---------------|---------------|
| Windows 10 1709 | 16299 | `bam\UserSettings` |
| Windows 10 1803 | 17134 | `bam\UserSettings` |
| Windows 10 1809+ | 17763+ | `bam\State\UserSettings` |
| Windows 11 All | 22000+ | `bam\State\UserSettings` |

## 🚀 Installation

1. **Clone or Download** the script
2. **Install Dependencies**:
   ```bash
   pip install pywin32
   ```
3. **Run as Administrator** (required for registry access)

## 📖 Usage

### Basic Usage
```bash
python bam_parser.py
```

### Interactive Menu
When you run the script, you'll see this menu:

```
============================================================
Windows BAM (Background Activity Moderator) Parser
============================================================
Detected Windows Build: 19045

Choose how many recent programs to display:
1. Top 10 (default)
2. Top 20
3. Top 30
4. Top 50
5. Top 100
6. All programs
7. Custom number
8. Exit

Enter your choice (1-8) or press Enter for default:
```

### Menu Options

| Option | Description | Example |
|--------|-------------|---------|
| **1** | Show top 10 recent programs | Default choice |
| **2** | Show top 20 recent programs | Quick overview |
| **3** | Show top 30 recent programs | Detailed view |
| **4** | Show top 50 recent programs | Extended analysis |
| **5** | Show top 100 recent programs | Comprehensive view |
| **6** | Show ALL programs | Complete forensic analysis |
| **7** | Custom number (1-1000) | Specify exact count |
| **8** | Exit program | Clean exit |

### Exit Options
- **Option 8**: Exit from main menu
- **Ctrl+C**: Emergency exit at any time
- **"exit"**: Type at export prompt to quit

## 📊 Output Examples

### Console Output
```
============================================================
BAM Registry Analysis Summary
============================================================
Windows Build: 19045
Total SIDs processed: 4
Total executables found: 131

Top 10 Most Recent Executables:
------------------------------------------------------------
 1. 2025-06-11 09:17:10 - brave.exe
    Full path: \Device\HarddiskVolume3\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe
    SID: S-1-5-21-1499236265-2510578363-2032424015-1001

 2. 2025-06-11 09:17:09 - cmd.exe
    Full path: \Device\HarddiskVolume3\Windows\System32\cmd.exe
    SID: S-1-5-21-1499236265-2510578363-2032424015-1001
```

### JSON Export Structure
```json
{
  "metadata": {
    "export_timestamp": "2025-06-11T09:17:11.697000",
    "windows_build": "19045",
    "total_entries": 4,
    "total_executables": 131
  },
  "bam_entries": [
    {
      "sid": "S-1-5-21-1499236265-2510578363-2032424015-1001",
      "executable_count": 123,
      "executables": [
        {
          "path": "\\Device\\HarddiskVolume3\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
          "timestamp": "2025-06-11 09:17:10",
          "raw_timestamp": 133625470304567890,
          "data_size": 24,
          "additional_data": "..."
        }
      ]
    }
  ]
}
```

## 🔐 Understanding SIDs (Security Identifiers)

| SID Pattern | Account Type | Description |
|-------------|--------------|-------------|
| `S-1-5-18` | SYSTEM | Windows system processes |
| `S-1-5-19` | LOCAL SERVICE | Local service account |
| `S-1-5-20` | NETWORK SERVICE | Network service account |
| `S-1-5-21-...-500` | Administrator | Built-in administrator |
| `S-1-5-21-...-1000+` | User Account | Regular user accounts |
| `S-1-5-90-0-1` | Window Manager | Desktop Window Manager |

## 🗂️ File Structure

```
bam_parser.py              # Main script
bam_export_YYYYMMDD_HHMMSS.json  # JSON export files
bam_parser_YYYYMMDD_HHMMSS.log   # Log files
README.md                  # This documentation
```

## 🔧 Advanced Usage

### Programmatic Usage
```python
from bam_parser import BamParser

# Initialize parser
parser = BamParser(log_level=logging.DEBUG)

# Get parsed data
bam_data = parser.parse()

# Export to JSON
output_file = parser.export_to_json("custom_export.json")

# Print summary with custom count
parser.print_summary(top_count=50)
```

### Custom Logging
```python
import logging

# Set custom log level
parser = BamParser(log_level=logging.DEBUG)  # Verbose logging
parser = BamParser(log_level=logging.ERROR)  # Errors only
```

## 🛡️ Security Considerations

### Required Privileges
- **Administrator rights** are required to access the BAM registry keys
- The script accesses `HKEY_LOCAL_MACHINE` registry hive
- Some antivirus software may flag registry access tools

### Privacy Notes
- BAM data contains user activity information
- Exported JSON files contain sensitive system information
- Use responsibly and in compliance with applicable laws and policies

## 🐛 Troubleshooting

### Common Issues

#### "Access Denied" Error
```
Solution: Run as Administrator
Right-click Command Prompt → "Run as administrator"
```

#### "Version not supported" Error
```
Solution: Check Windows version
Supported: Windows 10 (1709+) and Windows 11
```

#### "Failed to access registry" Error
```
Solution: Verify BAM service is running
1. Run: services.msc
2. Find "Background Activity Moderator"
3. Ensure it's running
```

#### Empty Results
```
Possible causes:
- BAM service disabled
- Fresh Windows installation
- Registry corruption
```

### Debug Mode
```bash
# Enable debug logging for troubleshooting
python bam_parser.py
# Check the generated .log file for detailed information
```

## 📋 Changelog

### Version 2.0 (Current)
- ✅ Interactive menu system
- ✅ Multiple display options (10, 20, 30, 50, 100, all)
- ✅ Custom number input
- ✅ Exit options at multiple points
- ✅ Enhanced error handling
- ✅ Comprehensive logging
- ✅ JSON export with metadata
- ✅ Windows 11 support
- ✅ Type hints and documentation

### Version 1.0 (Original)
- ✅ Basic BAM parsing
- ✅ Windows 10 support
- ✅ Simple output format

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test on different Windows versions
5. Submit a pull request

## 📝 License

This project is released under the MIT License. See LICENSE file for details.
> Inspired from [BamParser by Ektoplasma](https://github.com/Ektoplasma/BamParser)

## ⚠️ Disclaimer

This tool is for educational and legitimate forensic purposes only. Users are responsible for complying with all applicable laws and regulations. The authors are not responsible for any misuse of this tool.

## 📞 Support

For questions, issues, or feature requests:
- Create an issue on the project repository
- Check the troubleshooting section above
- Review the log files for detailed error information

## 🔗 References

- [Microsoft Documentation - BAM](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/configure-block-at-first-sight-windows-defender-antivirus)
- [Windows Registry Forensics](https://www.forensicswiki.org/wiki/Windows_Registry)
- [SANS Digital Forensics](https://www.sans.org/white-papers/)

---

**Made with ❤️ for the digital forensics community**
