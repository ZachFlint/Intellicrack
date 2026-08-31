# Adobe Injector - Intellicrack Integration

## Overview

Adobe Injector is a fully integrated licensing bypass tool for Adobe products, rebranded and integrated into Intellicrack from the GenP project.

## Location

**Production Runtime:** `C:\Intellicrack\tools\AdobeInjector\`

This directory contains the production-ready executable and its dependencies.

## Files

### Required Runtime Files (3)
```
AdobeInjector.exe    - Main executable (2.3 MB)
config.ini           - Runtime configuration (12 KB)
wintrust.dll         - Required dependency for Adobe patching (374 KB)
```

**IMPORTANT:** All 3 files must remain together in the same directory for the tool to function.

## Integration

Adobe Injector is integrated into Intellicrack via:
- **Location:** Tools Tab → Adobe Injector sub-tab
- **Integration Module:** `src/intellicrack/core/adobe_injector_integration.py`
- **UI Tab:** `src/intellicrack/ui/tabs/adobe_injector_tab.py`

## Features

### Core Capabilities
- **Adobe Product Patching:** Bypasses licensing checks in Adobe Creative Cloud applications
- **Registry Manipulation:** Manages Adobe licensing registry keys
- **DLL Injection:** Patches Adobe protection DLLs
- **Silent Mode:** Automated patching without user interaction

### Integration Methods
1. **Embedded Window:** Native Win32 API window embedding
2. **Subprocess Control:** Background process with output capture
3. **Terminal Integration:** Execute via embedded terminal
4. **AutoIt3X COM:** Advanced control via COM interface

## Usage

### Via Intellicrack GUI
1. Launch Intellicrack: `python -m intellicrack.ui.main_app`
2. Navigate to **Tools** → **Adobe Injector**
3. Click **"Launch Adobe Injector"**
4. Use embedded interface for patching

### Standalone
```bash
cd C:\Intellicrack\tools\AdobeInjector
AdobeInjector.exe
```

## Configuration

### config.ini
Runtime configuration for Adobe Injector operations. Modify to change default behavior.

### Runtime Options
- `/scan` - Scan for Adobe products
- `/patch` - Apply patches
- `/silent` - Run without GUI

## Branding

- **Product Name:** Adobe Injector v1.0.0
- **Copyright:** Intellicrack 2025
- **Icon:** Intellicrack.ico (embedded)
- **Footer Label:** "Intellicrack"

## Source Code

Original source and build tools are located in:
```
C:\Intellicrack\GenP\Rebranded\
├── AdobeInjector.au3       - AutoIt3 source code
├── build.bat               - Compilation script
├── config.ini              - Build configuration
└── Intellicrack.ico       - Application icon
```

To rebuild:
```bash
cd C:\Intellicrack\GenP\Rebranded
build.bat
```

## Technical Details

### Binary Format
- **Type:** Windows PE32+ executable
- **Architecture:** x64
- **Compiler:** AutoIt3 (Aut2Exe)
- **Compression:** UPX
- **Language:** AutoIt3 script compiled to native

### Dependencies
- Windows API (user32.dll, kernel32.dll, advapi32.dll)
- Custom wintrust.dll (patched for signature bypass)
- .NET Framework (for Adobe registry access)

### Protection Bypass Techniques
1. **Signature Verification Bypass:** Modified wintrust.dll
2. **Registry Key Manipulation:** Direct registry writes
3. **DLL Injection:** Runtime hooking of Adobe protection
4. **Trial Reset:** Cleanup of Adobe activation data

## Security Note

This tool is designed for **defensive security research** purposes:
- Testing robustness of software licensing systems
- Identifying weaknesses in protection mechanisms
- Helping developers strengthen their licensing implementations

Use only in controlled environments for authorized security assessment.

## Maintenance

### Updating Adobe Injector
1. Modify `C:\Intellicrack\GenP\Rebranded\AdobeInjector.au3`
2. Run `build.bat` to compile
3. Copy new `AdobeInjector.exe` to `C:\Intellicrack\tools\AdobeInjector\`
4. Test integration in Intellicrack UI

### Backup Original
Keep a backup of the working executable before updates:
```bash
copy AdobeInjector.exe AdobeInjector.exe.backup
```

## Troubleshooting

### "Adobe Injector not found"
- Verify all 3 files exist in `tools/AdobeInjector/`
- Check file permissions
- Ensure path is correct in integration code

### "Failed to embed window"
- Run Intellicrack as Administrator
- Check if antivirus is blocking
- Verify Win32 API permissions

### "Patching failed"
- Ensure wintrust.dll is present
- Check config.ini settings
- Run in Administrator mode
- Verify Adobe product is installed

## Version History

**v1.0.0** (2025-01-04)
- Initial Intellicrack integration
- Complete rebranding from GenP
- Removed external links and community references
- Updated to Intellicrack branding
- Production-ready release
