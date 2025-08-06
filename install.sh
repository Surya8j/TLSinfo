#!/bin/bash

set -e

# TLS Info Installation Script
# Usage: curl -sSL https://install.tlsinfo.dev | bash

# Configuration
REPO="yourusername/tlsinfo"
BINARY_NAME="tlsinfo"
INSTALL_DIR="/usr/local/bin"
TEMP_DIR=$(mktemp -d)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Detect OS and architecture
detect_os() {
    case "$(uname -s)" in
        Linux*)     OS="linux" ;;
        Darwin*)    OS="darwin" ;;
        MINGW*)     OS="windows" ;;
        FreeBSD*)   OS="freebsd" ;;
        *)          log_error "Unsupported operating system: $(uname -s)"; exit 1 ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   ARCH="amd64" ;;
        arm64|aarch64)  ARCH="arm64" ;;
        armv7l)         ARCH="arm" ;;
        *)              log_error "Unsupported architecture: $(uname -m)"; exit 1 ;;
    esac
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    if ! command_exists curl && ! command_exists wget; then
        missing_deps+=("curl or wget")
    fi
    
    if ! command_exists tar && [ "$OS" != "windows" ]; then
        missing_deps+=("tar")
    fi
    
    if ! command_exists unzip && [ "$OS" = "windows" ]; then
        missing_deps+=("unzip")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_error "Please install the missing dependencies and try again."
        exit 1
    fi
}

# Download file using curl or wget
download_file() {
    local url=$1
    local output=$2
    
    if command_exists curl; then
        curl -sSL "$url" -o "$output"
    elif command_exists wget; then
        wget -q "$url" -O "$output"
    else
        log_error "Neither curl nor wget is available"
        exit 1
    fi
}

# Get latest release version from GitHub API
get_latest_version() {
    local api_url="https://api.github.com/repos/${REPO}/releases/latest"
    local version
    
    if command_exists curl; then
        version=$(curl -sSL "$api_url" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    elif command_exists wget; then
        version=$(wget -qO- "$api_url" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    else
        log_error "Cannot fetch latest version"
        exit 1
    fi
    
    if [ -z "$version" ]; then
        log_error "Failed to get latest version from GitHub API"
        exit 1
    fi
    
    echo "$version"
}

# Check if running as root for system installation
check_permissions() {
    if [ "$INSTALL_DIR" = "/usr/local/bin" ] && [ "$(id -u)" -ne 0 ]; then
        log_warning "Installing to $INSTALL_DIR requires root privileges"
        log_info "You can:"
        log_info "1. Run with sudo: curl -sSL https://install.tlsinfo.dev | sudo bash"
        log_info "2. Install to user directory: curl -sSL https://install.tlsinfo.dev | INSTALL_DIR=\$HOME/.local/bin bash"
        exit 1
    fi
}

# Create install directory if it doesn't exist
create_install_dir() {
    if [ ! -d "$INSTALL_DIR" ]; then
        log_info "Creating install directory: $INSTALL_DIR"
        mkdir -p "$INSTALL_DIR"
        
        # Add to PATH if installing to user directory
        if [[ "$INSTALL_DIR" == *"$HOME"* ]]; then
            local shell_rc=""
            case "$SHELL" in
                */bash) shell_rc="$HOME/.bashrc" ;;
                */zsh)  shell_rc="$HOME/.zshrc" ;;
                */fish) shell_rc="$HOME/.config/fish/config.fish" ;;
            esac
            
            if [ -n "$shell_rc" ] && [ -f "$shell_rc" ]; then
                if ! grep -q "$INSTALL_DIR" "$shell_rc"; then
                    echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$shell_rc"
                    log_info "Added $INSTALL_DIR to PATH in $shell_rc"
                    log_warning "Please restart your shell or run: source $shell_rc"
                fi
            fi
        fi
    fi
}

# Main installation function
install_tlsinfo() {
    log_info "Starting TLS Info installation..."
    
    # Detect system
    detect_os
    detect_arch
    
    log_info "Detected OS: $OS"
    log_info "Detected Architecture: $ARCH"
    
    # Check dependencies and permissions
    check_dependencies
    check_permissions
    
    # Get latest version
    log_info "Fetching latest release information..."
    VERSION=$(get_latest_version)
    log_info "Latest version: $VERSION"
    
    # Construct download URL
    SUFFIX="${OS}-${ARCH}"
    if [ "$OS" = "windows" ]; then
        ARCHIVE_EXT="zip"
        BINARY_EXT=".exe"
    else
        ARCHIVE_EXT="tar.gz"
        BINARY_EXT=""
    fi
    
    ARCHIVE_NAME="${BINARY_NAME}-${VERSION}-${SUFFIX}.${ARCHIVE_EXT}"
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE_NAME}"
    
    log_info "Download URL: $DOWNLOAD_URL"
    
    # Download the archive
    log_info "Downloading $ARCHIVE_NAME..."
    cd "$TEMP_DIR"
    download_file "$DOWNLOAD_URL" "$ARCHIVE_NAME"
    
    # Extract the archive
    log_info "Extracting archive..."
    if [ "$OS" = "windows" ]; then
        unzip -q "$ARCHIVE_NAME"
    else
        tar -xzf "$ARCHIVE_NAME"
    fi
    
    # Find the binary
    BINARY_PATH="${BINARY_NAME}-${SUFFIX}${BINARY_EXT}"
    if [ ! -f "$BINARY_PATH" ]; then
        log_error "Binary not found in archive: $BINARY_PATH"
        exit 1
    fi
    
    # Make binary executable (Unix systems)
    if [ "$OS" != "windows" ]; then
        chmod +x "$BINARY_PATH"
    fi
    
    # Create install directory
    create_install_dir
    
    # Install the binary
    log_info "Installing $BINARY_NAME to $INSTALL_DIR..."
    mv "$BINARY_PATH" "$INSTALL_DIR/$BINARY_NAME$BINARY_EXT"
    
    # Verify installation
    if [ -x "$INSTALL_DIR/$BINARY_NAME$BINARY_EXT" ]; then
        log_success "TLS Info installed successfully!"
        log_info "Location: $INSTALL_DIR/$BINARY_NAME$BINARY_EXT"
        
        # Test the installation
        if command_exists "$BINARY_NAME" || [ -x "$INSTALL_DIR/$BINARY_NAME$BINARY_EXT" ]; then
            log_info "Testing installation..."
            if "$INSTALL_DIR/$BINARY_NAME$BINARY_EXT" --help >/dev/null 2>&1; then
                log_success "Installation test passed!"
            else
                log_warning "Installation test failed, but binary was installed"
            fi
        else
            log_warning "Binary installed but not in PATH. You may need to:"
            log_warning "1. Restart your shell"
            log_warning "2. Add $INSTALL_DIR to your PATH"
            log_warning "3. Use the full path: $INSTALL_DIR/$BINARY_NAME$BINARY_EXT"
        fi
        
        # Show usage examples
        echo ""
        log_info "Quick start:"
        echo "  $BINARY_NAME example.com"
        echo "  $BINARY_NAME github.com --pq-only"
        echo "  $BINARY_NAME --help"
        echo ""
        
    else
        log_error "Installation failed"
        exit 1
    fi
}

# Cleanup function
cleanup() {
    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
}

# Set trap for cleanup
trap cleanup EXIT

# Handle command line options
while [[ $# -gt 0 ]]; do
    case $1 in
        --install-dir=*)
            INSTALL_DIR="${1#*=}"
            shift
            ;;
        --version=*)
            VERSION="${1#*=}"
            shift
            ;;
        --help|-h)
            cat << EOF
TLS Info Installation Script

Usage: $0 [options]

Options:
    --install-dir=DIR    Installation directory (default: /usr/local/bin)
    --version=VERSION    Specific version to install (default: latest)
    --help, -h           Show this help message

Environment Variables:
    INSTALL_DIR          Installation directory
    TLSINFO_VERSION      Version to install

Examples:
    # Install latest version to /usr/local/bin (requires sudo)
    curl -sSL https://install.tlsinfo.dev | sudo bash
    
    # Install to user directory
    curl -sSL https://install.tlsinfo.dev | INSTALL_DIR=\$HOME/.local/bin bash
    
    # Install specific version
    curl -sSL https://install.tlsinfo.dev | bash -s -- --version=v1.0.0

EOF
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Override with environment variables if set
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${TLSINFO_VERSION:-$VERSION}"

# Check if tlsinfo is already installed
if command_exists "$BINARY_NAME"; then
    CURRENT_VERSION=$($BINARY_NAME --version 2>/dev/null | grep -o 'v[0-9]\+\.[0-9]\+\.[0-9]\+' || echo "unknown")
    if [ "$CURRENT_VERSION" != "unknown" ] && [ -z "$VERSION" ]; then
        LATEST_VERSION=$(get_latest_version)
        if [ "$CURRENT_VERSION" = "$LATEST_VERSION" ]; then
            log_info "TLS Info $CURRENT_VERSION is already installed and up to date"
            exit 0
        else
            log_info "Upgrading TLS Info from $CURRENT_VERSION to $LATEST_VERSION"
        fi
    fi
fi

# Run installation
install_tlsinfo
        