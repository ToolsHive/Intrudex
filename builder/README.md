# Intrudex Builders

This directory contains build scripts for creating standalone executables of both the Intrudex Client and Server components.

## 🏗️ Directory Structure

```
builder/
├── Client/
│   ├── Intrudex-Client-Builder.py    # GUI builder for client
│   ├── version.txt                   # Version information
│   └── Intrudex.jpg                  # Icon file
├── Server/
│   ├── version.txt                   # Version information
│   └── Intrudex.jpg                  # Icon file
├── Client-builder.ps1                # PowerShell build script for client
└── Server-builder.ps1                # PowerShell build script for server
```

## 🚀 Quick Start

### Client Builder

```powershell
# Run the GUI builder
.\Client-builder.ps1

# Or with options
.\Client-builder.ps1 -UseUPX -Icon "custom.ico"
```

### Server Builder

```powershell
# Basic build
.\Server-builder.ps1

# Build with UPX compression
.\Server-builder.ps1 -UseUPX
```

## ⚙️ Build Options

| Option | Description | Default |
|--------|-------------|---------|
| `-Script` | Python script to compile | `run.py` (Server) / `Intrudex-Client-Builder.py` (Client) |
| `-Icon` | Icon for executable | `Intrudex.jpg` |
| `-Name` | Output executable name | `Intrudex_Server`/`Intrudex_Client_Builder` |
| `-UseUPX` | Enable UPX compression | `false` |
| `-Help` | Show help message | N/A |

## 📚 Detailed Builder Documentation

### Client Builder Arguments
```powershell
.\Client-builder.ps1 [arguments]

Arguments:
  -Script        Path to Python script         Default: Intrudex-Client-Builder.py
  -Icon          Path to icon file            Default: Intrudex.jpg
  -Name          Output executable name        Default: Intrudex_Client_Builder
  -VersionFile   Version information file     Default: version.txt
  -UseUPX        Enable UPX compression       Default: $false
  -Help          Show help message
```

### Server Builder Arguments
```powershell
.\Server-builder.ps1 [arguments]

Arguments:
  -Script        Path to Python script         Default: run.py
  -Icon          Path to icon file            Default: Intrudex.jpg
  -Name          Output executable name        Default: Intrudex_Server
  -VersionFile   Version information file     Default: version.txt
  -UPXDir        Path to UPX directory        Default: C:\path\to\upx
  -UseUPX        Enable UPX compression       Default: $true
  -Help          Show help message
```

## 🔨 Advanced Features

### Client Builder
- GUI-based build configuration
- Real-time build progress visualization
- Build log export functionality
- Custom build directory selection
- Multiple build configurations (Debug/Release)
- Thread count customization
- Automatic dependency scanning
- Error detection and reporting
- Build artifacts cleanup
- Desktop shortcut creation
- Settings persistence
- Administrator privilege handling

### Server Builder
- Automatic folder scanning
- Dependency bundling
- Resource compilation
- Version information embedding
- UPX compression optimization
- Build progress visualization
- Error logging and reporting
- Clean build support
- Build artifact management
- Executable verification
- Performance optimization
- Size reduction features

## 💻 Example Usage

### Client Builder Examples
```powershell
# Basic GUI build
.\Client-builder.ps1

# Custom icon and name
.\Client-builder.ps1 -Icon "custom.ico" -Name "MyClient"

# Debug build with UPX
.\Client-builder.ps1 -UseUPX -Script "debug.py"
```

### Server Builder Examples
```powershell
# Basic server build
.\Server-builder.ps1

# Production build with custom UPX
.\Server-builder.ps1 -UseUPX -UPXDir "C:\Tools\UPX"

# Custom name and version
.\Server-builder.ps1 -Name "CustomServer" -VersionFile "prod_version.txt"
```

## 🔧 Requirements

- Python 3.8 or higher
- PyInstaller (`pip install pyinstaller`)
- UPX (optional, for compression)
- Administrator privileges

## 🛠️ Client Builder Features

- Modern GUI interface
- Real-time build output
- UPX compression support
- Build configuration options
- Progress tracking
- Custom build paths

## 📦 Server Builder Features

- Automatic dependency detection
- Version information embedding
- Clean build option
- Build artifacts cleanup
- Detailed build logging
- Error handling

## 🔍 Troubleshooting

1. **UPX Compression Failed**
   - Ensure UPX is installed and in PATH
   - Try building without UPX using `-UseUPX:$false`

2. **Missing Dependencies**
   ```powershell
   # Install required packages
   pip install -r requirements.txt
   ```

3. **Permission Issues**
   - Run PowerShell as Administrator
   - Check file permissions in build directory

## 📝 Notes

- Builds are created in `dist/` directory
- Final executable is copied to script root
- Build artifacts are automatically cleaned
- Logs are saved in working directory

1. Follow PowerShell best practices
2. Test builds before committing
3. Update documentation as needed

## 📄 License

Part of the Intrudex project. See main project license.
