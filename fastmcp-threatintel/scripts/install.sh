#!/bin/bash
# FastMCP ThreatIntel Installation Script for Unix-like systems
# Supports: Linux, macOS, WSL

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO_URL="https://github.com/4R9UN/fastmcp-threatintel.git"
INSTALL_DIR="$HOME/fastmcp-threatintel"
PYTHON_MIN_VERSION="3.10"

# Functions
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_python() {
    if command -v python3 &> /dev/null; then
        python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        if python3 -c "import sys; exit(0 if sys.version_info >= (3, 10) else 1)"; then
            print_success "Python $python_version found"
            return 0
        else
            print_error "Python $python_version found, but Python $PYTHON_MIN_VERSION+ is required"
            return 1
        fi
    else
        print_error "Python 3 not found"
        return 1
    fi
}

install_uv() {
    if command -v uv &> /dev/null; then
        print_success "UV package manager already installed"
    else
        print_status "Installing UV package manager..."
        curl -LsSf https://astral.sh/uv/install.sh | sh
        export PATH="$HOME/.cargo/bin:$PATH"
        
        if command -v uv &> /dev/null; then
            print_success "UV package manager installed successfully"
        else
            print_error "Failed to install UV package manager"
            exit 1
        fi
    fi
}

install_git() {
    if command -v git &> /dev/null; then
        print_success "Git already installed"
    else
        print_status "Installing Git..."
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            if command -v apt-get &> /dev/null; then
                sudo apt-get update && sudo apt-get install -y git
            elif command -v yum &> /dev/null; then
                sudo yum install -y git
            elif command -v pacman &> /dev/null; then
                sudo pacman -S --noconfirm git
            else
                print_error "Unable to install Git automatically. Please install Git manually."
                exit 1
            fi
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            if command -v brew &> /dev/null; then
                brew install git
            else
                print_error "Please install Git manually or install Homebrew first."
                exit 1
            fi
        else
            print_error "Unable to install Git automatically. Please install Git manually."
            exit 1
        fi
    fi
}

clone_repository() {
    print_status "Cloning repository to $INSTALL_DIR..."
    
    if [ -d "$INSTALL_DIR" ]; then
        print_warning "Directory $INSTALL_DIR already exists"
        read -p "Do you want to remove it and continue? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "$INSTALL_DIR"
        else
            print_error "Installation cancelled"
            exit 1
        fi
    fi
    
    git clone "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    print_success "Repository cloned successfully"
}

install_dependencies() {
    print_status "Installing dependencies..."
    cd "$INSTALL_DIR"
    
    # Install dependencies with UV
    uv sync
    
    if [ $? -eq 0 ]; then
        print_success "Dependencies installed successfully"
    else
        print_error "Failed to install dependencies"
        exit 1
    fi
}

setup_environment() {
    print_status "Setting up environment..."
    cd "$INSTALL_DIR"
    
    # Create .env file if it doesn't exist
    if [ ! -f ".env" ]; then
        print_status "Creating .env file..."
        cat > .env << 'EOF'
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
EOF
        print_success ".env file created"
        print_warning "Please edit .env file and add your API keys"
    fi
}

create_shortcuts() {
    print_status "Creating shortcuts..."
    
    # Create shell alias
    shell_profile=""
    if [ -f "$HOME/.bashrc" ]; then
        shell_profile="$HOME/.bashrc"
    elif [ -f "$HOME/.zshrc" ]; then
        shell_profile="$HOME/.zshrc"
    elif [ -f "$HOME/.profile" ]; then
        shell_profile="$HOME/.profile"
    fi
    
    if [ -n "$shell_profile" ]; then
        echo "" >> "$shell_profile"
        echo "# FastMCP ThreatIntel" >> "$shell_profile"
        echo "alias threatintel='cd $INSTALL_DIR && uv run threatintel'" >> "$shell_profile"
        print_success "Shell alias 'threatintel' created in $shell_profile"
    fi
    
    # Create desktop shortcut for Linux
    if [[ "$OSTYPE" == "linux-gnu"* ]] && [ -d "$HOME/Desktop" ]; then
        cat > "$HOME/Desktop/FastMCP-ThreatIntel.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=FastMCP ThreatIntel
Comment=AI-Powered Threat Intelligence Analysis
Exec=gnome-terminal -- bash -c "cd $INSTALL_DIR && uv run threatintel interactive; bash"
Icon=$INSTALL_DIR/assets/icon.png
Terminal=true
Categories=Security;Development;
EOF
        chmod +x "$HOME/Desktop/FastMCP-ThreatIntel.desktop"
        print_success "Desktop shortcut created"
    fi
}

run_tests() {
    print_status "Running basic tests..."
    cd "$INSTALL_DIR"
    
    # Test basic functionality
    if uv run threatintel --version &> /dev/null; then
        print_success "Basic functionality test passed"
    else
        print_warning "Basic functionality test failed, but installation completed"
    fi
}

print_completion() {
    print_success "Installation completed successfully!"
    echo
    echo -e "${GREEN}🎉 FastMCP ThreatIntel is now installed!${NC}"
    echo
    echo "Next steps:"
    echo "1. Edit the configuration file: $INSTALL_DIR/.env"
    echo "2. Add your API keys (VirusTotal and OTX are required)"
    echo "3. Run the setup wizard: cd $INSTALL_DIR && uv run threatintel setup"
    echo "4. Start analyzing: uv run threatintel interactive"
    echo
    echo "For more information, visit: https://github.com/4R9UN/fastmcp-threatintel"
    echo
    if [ -n "$shell_profile" ]; then
        echo "💡 Tip: Restart your terminal or run 'source $shell_profile' to use the 'threatintel' alias"
    fi
}

# Main installation process
main() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                FastMCP ThreatIntel Installer                 ║"
    echo "║          AI-Powered Threat Intelligence Analysis             ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo
    
    print_status "Starting installation..."
    
    # Check system requirements
    print_status "Checking system requirements..."
    
    if ! check_python; then
        print_error "Python $PYTHON_MIN_VERSION+ is required. Please install it first."
        exit 1
    fi
    
    # Install dependencies
    install_git
    install_uv
    
    # Install the application
    clone_repository
    install_dependencies
    setup_environment
    create_shortcuts
    run_tests
    
    print_completion
}

# Handle interruption
trap 'echo -e "\n${RED}Installation interrupted${NC}"; exit 1' INT

# Run main function
main "$@"