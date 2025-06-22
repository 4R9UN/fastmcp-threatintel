# FastMCP ThreatIntel Installation Script for Windows
# Supports: Windows 10/11, PowerShell 5.1+

param(
    [switch]$Force,
    [string]$InstallPath = "$env:USERPROFILE\fastmcp-threatintel",
    [switch]$NoDesktopShortcut,
    [switch]$Quiet
)

# Enable strict mode
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Configuration
$RepoUrl = "https://github.com/4R9UN/fastmcp-threatintel.git"
$PythonMinVersion = [Version]"3.10.0"

# Colors for output
$Colors = @{
    Info    = "Cyan"
    Success = "Green"
    Warning = "Yellow"
    Error   = "Red"
}

function Write-Status {
    param([string]$Message, [string]$Type = "Info")
    if (-not $Quiet) {
        $prefix = switch ($Type) {
            "Info"    { "[INFO]" }
            "Success" { "[SUCCESS]" }
            "Warning" { "[WARNING]" }
            "Error"   { "[ERROR]" }
        }
        Write-Host "$prefix $Message" -ForegroundColor $Colors[$Type]
    }
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Python {
    try {
        $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
        if (-not $pythonCmd) {
            $pythonCmd = Get-Command python3 -ErrorAction SilentlyContinue
        }
        
        if ($pythonCmd) {
            $versionOutput = & $pythonCmd.Source --version 2>$null
            if ($versionOutput -match "Python (\d+\.\d+\.\d+)") {
                $version = [Version]$matches[1]
                if ($version -ge $PythonMinVersion) {
                    Write-Status "Python $version found" "Success"
                    return $pythonCmd.Source
                } else {
                    Write-Status "Python $version found, but Python $PythonMinVersion+ is required" "Error"
                    return $null
                }
            }
        }
        
        Write-Status "Python not found or version check failed" "Error"
        return $null
    } catch {
        Write-Status "Error checking Python: $($_.Exception.Message)" "Error"
        return $null
    }
}

function Install-Python {
    Write-Status "Python not found. Installing Python..." "Info"
    
    try {
        # Check if winget is available
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Write-Status "Installing Python using winget..." "Info"
            winget install Python.Python.3.12 --silent
        } else {
            # Fallback to manual download
            Write-Status "Downloading Python installer..." "Info"
            $pythonUrl = "https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe"
            $installerPath = "$env:TEMP\python-installer.exe"
            
            Invoke-WebRequest -Uri $pythonUrl -OutFile $installerPath
            
            Write-Status "Installing Python..." "Info"
            Start-Process -FilePath $installerPath -ArgumentList "/quiet", "InstallAllUsers=0", "PrependPath=1" -Wait
            
            Remove-Item $installerPath -Force
        }
        
        # Refresh PATH
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
        
        Write-Status "Python installation completed" "Success"
        return Test-Python
    } catch {
        Write-Status "Failed to install Python: $($_.Exception.Message)" "Error"
        return $null
    }
}

function Install-Git {
    if (Get-Command git -ErrorAction SilentlyContinue) {
        Write-Status "Git already installed" "Success"
        return $true
    }
    
    Write-Status "Installing Git..." "Info"
    
    try {
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            winget install Git.Git --silent
        } elseif (Get-Command choco -ErrorAction SilentlyContinue) {
            choco install git -y
        } else {
            Write-Status "Please install Git manually from https://git-scm.com/download/win" "Error"
            return $false
        }
        
        # Refresh PATH
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
        
        Write-Status "Git installation completed" "Success"
        return $true
    } catch {
        Write-Status "Failed to install Git: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Install-UV {
    if (Get-Command uv -ErrorAction SilentlyContinue) {
        Write-Status "UV package manager already installed" "Success"
        return $true
    }
    
    Write-Status "Installing UV package manager..." "Info"
    
    try {
        # Install UV using the official installer
        Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression
        
        # Add UV to PATH for current session
        $uvPath = "$env:USERPROFILE\.cargo\bin"
        if (Test-Path $uvPath) {
            $env:PATH = "$uvPath;$env:PATH"
        }
        
        if (Get-Command uv -ErrorAction SilentlyContinue) {
            Write-Status "UV package manager installed successfully" "Success"
            return $true
        } else {
            Write-Status "UV installation completed but command not found. Please restart PowerShell." "Warning"
            return $false
        }
    } catch {
        Write-Status "Failed to install UV: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Clone-Repository {
    Write-Status "Cloning repository to $InstallPath..." "Info"
    
    if (Test-Path $InstallPath) {
        if ($Force) {
            Write-Status "Removing existing directory..." "Warning"
            Remove-Item $InstallPath -Recurse -Force
        } else {
            Write-Status "Directory $InstallPath already exists. Use -Force to overwrite." "Error"
            return $false
        }
    }
    
    try {
        git clone $RepoUrl $InstallPath
        Set-Location $InstallPath
        Write-Status "Repository cloned successfully" "Success"
        return $true
    } catch {
        Write-Status "Failed to clone repository: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Install-Dependencies {
    Write-Status "Installing dependencies..." "Info"
    
    try {
        Set-Location $InstallPath
        uv sync
        
        Write-Status "Dependencies installed successfully" "Success"
        return $true
    } catch {
        Write-Status "Failed to install dependencies: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Setup-Environment {
    Write-Status "Setting up environment..." "Info"
    
    $envFile = Join-Path $InstallPath ".env"
    
    if (-not (Test-Path $envFile)) {
        Write-Status "Creating .env file..." "Info"
        
        $envContent = @"
# FastMCP ThreatIntel Configuration
# Add your API keys here

# Required APIs
VIRUSTOTAL_API_KEY=
OTX_API_KEY=

# Optional APIs
ABUSEIPDB_API_KEY=
IPINFO_API_KEY=

# Performance Settings
CACHE_TTL=3600
MAX_RETRIES=3
REQUEST_TIMEOUT=30
"@
        
        Set-Content -Path $envFile -Value $envContent -Encoding UTF8
        Write-Status ".env file created" "Success"
        Write-Status "Please edit .env file and add your API keys" "Warning"
    }
}

function Create-Shortcuts {
    Write-Status "Creating shortcuts..." "Info"
    
    try {
        # Create PowerShell profile alias
        $profilePath = $PROFILE.CurrentUserAllHosts
        $profileDir = Split-Path $profilePath -Parent
        
        if (-not (Test-Path $profileDir)) {
            New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
        }
        
        $aliasContent = @"

# FastMCP ThreatIntel
function threatintel {
    Set-Location '$InstallPath'
    uv run threatintel @args
}
"@
        
        if (Test-Path $profilePath) {
            Add-Content -Path $profilePath -Value $aliasContent
        } else {
            Set-Content -Path $profilePath -Value $aliasContent
        }
        
        Write-Status "PowerShell alias 'threatintel' created" "Success"
        
        # Create desktop shortcut
        if (-not $NoDesktopShortcut) {
            $WshShell = New-Object -comObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\FastMCP ThreatIntel.lnk")
            $Shortcut.TargetPath = "powershell.exe"
            $Shortcut.Arguments = "-NoExit -Command `"Set-Location '$InstallPath'; uv run threatintel interactive`""
            $Shortcut.WorkingDirectory = $InstallPath
            $Shortcut.Description = "FastMCP ThreatIntel - AI-Powered Threat Intelligence"
            $Shortcut.Save()
            
            Write-Status "Desktop shortcut created" "Success"
        }
        
        # Create Start Menu shortcut
        $startMenuPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\FastMCP ThreatIntel.lnk"
        $Shortcut = $WshShell.CreateShortcut($startMenuPath)
        $Shortcut.TargetPath = "powershell.exe"
        $Shortcut.Arguments = "-NoExit -Command `"Set-Location '$InstallPath'; uv run threatintel interactive`""
        $Shortcut.WorkingDirectory = $InstallPath
        $Shortcut.Description = "FastMCP ThreatIntel - AI-Powered Threat Intelligence"
        $Shortcut.Save()
        
        Write-Status "Start Menu shortcut created" "Success"
        
    } catch {
        Write-Status "Warning: Failed to create some shortcuts: $($_.Exception.Message)" "Warning"
    }
}

function Test-Installation {
    Write-Status "Running basic tests..." "Info"
    
    try {
        Set-Location $InstallPath
        $output = uv run threatintel --version 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Status "Basic functionality test passed" "Success"
            return $true
        } else {
            Write-Status "Basic functionality test failed, but installation completed" "Warning"
            return $false
        }
    } catch {
        Write-Status "Basic functionality test failed: $($_.Exception.Message)" "Warning"
        return $false
    }
}

function Show-Completion {
    Write-Status "Installation completed successfully!" "Success"
    
    if (-not $Quiet) {
        Write-Host ""
        Write-Host "🎉 FastMCP ThreatIntel is now installed!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Next steps:" -ForegroundColor Yellow
        Write-Host "1. Edit the configuration file: $InstallPath\.env"
        Write-Host "2. Add your API keys (VirusTotal and OTX are required)"
        Write-Host "3. Run the setup wizard: Set-Location '$InstallPath'; uv run threatintel setup"
        Write-Host "4. Start analyzing: uv run threatintel interactive"
        Write-Host ""
        Write-Host "For more information, visit: https://github.com/4R9UN/fastmcp-threatintel"
        Write-Host ""
        Write-Host "💡 Tip: Restart PowerShell or run '. `$PROFILE' to use the 'threatintel' command" -ForegroundColor Cyan
    }
}

# Main installation function
function Main {
    if (-not $Quiet) {
        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Blue
        Write-Host "║                FastMCP ThreatIntel Installer                 ║" -ForegroundColor Blue
        Write-Host "║          AI-Powered Threat Intelligence Analysis             ║" -ForegroundColor Blue
        Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Blue
        Write-Host ""
    }
    
    Write-Status "Starting installation..." "Info"
    
    # Check system requirements
    Write-Status "Checking system requirements..." "Info"
    
    $pythonPath = Test-Python
    if (-not $pythonPath) {
        $pythonPath = Install-Python
        if (-not $pythonPath) {
            Write-Status "Failed to install Python. Please install Python 3.10+ manually." "Error"
            exit 1
        }
    }
    
    # Install dependencies
    if (-not (Install-Git)) {
        Write-Status "Git installation failed. Please install Git manually." "Error"
        exit 1
    }
    
    if (-not (Install-UV)) {
        Write-Status "UV installation failed. Please restart PowerShell and try again." "Error"
        exit 1
    }
    
    # Install the application
    if (-not (Clone-Repository)) {
        exit 1
    }
    
    if (-not (Install-Dependencies)) {
        exit 1
    }
    
    Setup-Environment
    Create-Shortcuts
    Test-Installation
    
    Show-Completion
}

# Handle Ctrl+C
try {
    Main
} catch {
    Write-Status "Installation interrupted: $($_.Exception.Message)" "Error"
    exit 1
}