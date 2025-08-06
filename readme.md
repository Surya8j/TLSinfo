# TLS Info

```
████████╗██╗     ███████╗    ██╗███╗   ██╗███████╗ ██████╗ 
╚══██╔══╝██║     ██╔════╝    ██║████╗  ██║██╔════╝██╔═══██╗
   ██║   ██║     ███████╗    ██║██╔██╗ ██║█████╗  ██║   ██║
   ██║   ██║     ╚════██║    ██║██║╚██╗██║██╔══╝  ██║   ██║
   ██║   ███████╗███████║    ██║██║ ╚████║██║     ╚██████╔╝
   ╚═╝   ╚══════╝╚══════╝    ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ 
```

A command-line tool to analyze TLS encryption algorithms and post-quantum cryptographic security for websites.

## Features

- 🔒 **TLS Analysis**: Display TLS versions, cipher suites, key exchange, and authentication methods
- 🛡️ **Post-Quantum Security**: Analyze quantum resistance of cryptographic algorithms
- 📊 **Multiple Sites**: Check multiple websites simultaneously
- 🎯 **Focused Views**: TLS-only or post-quantum-only analysis modes
- 📁 **Batch Processing**: Read sites from file
- 🌈 **Colorized Output**: Beautiful, easy-to-read terminal output
- ⚡ **Fast**: Concurrent processing with configurable timeouts

## Installation

### Using Go (Recommended)

```bash
go install github.com/Surya8j/tlsinfo@latest
```

### Pre-built Binaries

Download the latest release from [GitHub Releases](https://github.com/Surya8j/tlsinfo/releases):

```bash
# Linux/macOS
curl -sSL https://install.tlsinfo.dev | bash

# Or download manually
wget https://github.com/Surya8j/tlsinfo/releases/latest/download/tlsinfo-linux-amd64.tar.gz
tar -xzf tlsinfo-linux-amd64.tar.gz
sudo mv tlsinfo /usr/local/bin/
```

### Package Managers

```bash
# Homebrew (macOS/Linux)
brew install tlsinfo

# Arch Linux (AUR)
yay -S tlsinfo
```

## Usage

### Basic Usage

```bash
# Single website
tlsinfo example.com

# Multiple websites  
tlsinfo github.com google.com cloudflare.com

# With custom port
tlsinfo example.com:8443
```

### Advanced Options

```bash
# Verbose output with detailed certificate info
tlsinfo github.com --verbose

# Show only supported TLS versions
tlsinfo github.com --tls-versions

# Post-quantum security analysis only
tlsinfo github.com --pq-only

# Read sites from file
tlsinfo --file sites.txt

# Custom timeout
tlsinfo github.com --timeout 30

# Disable colors
tlsinfo github.com --no-color
```

### File Format

Create a `sites.txt` file with one domain per line:

```
github.com
google.com
cloudflare.com
example.com:8443
# This is a comment
stackoverflow.com
```

## Sample Output

### Standard Analysis

```bash
$ tlsinfo github.com

🔒 TLS Information for github.com:443
═══════════════════════════════════════

Supported TLS Versions: TLS 1.2, TLS 1.3
Active Connection: TLS 1.3
Cipher Suite: TLS_AES_128_GCM_SHA256

Key Encryption:
  Key Exchange:     X25519 (ECDHE)
  Authentication:   RSA-PSS 2048-bit
  Certificate:      RSA 2048-bit + SHA256

Data Encryption:
  Symmetric Cipher: AES-128-GCM
  Hash Function:    SHA256
  Mode:            GCM (Authenticated)

Post-Quantum Security:
  Key Exchange:     ❌ Vulnerable (ECC based)
  Authentication:   ❌ Vulnerable (Classical signatures)
  Data Encryption:  ✅ Partial (64-bit quantum security)
  Overall:          ❌ NOT SECURE

Connection: ✅ Secure (Classical threats)
            ⚠️  Vulnerable to quantum attacks
```

### Post-Quantum Analysis

```bash
$ tlsinfo github.com --pq-only

🛡️  Post-Quantum Security Analysis for github.com:443
═══════════════════════════════════════════════════════

Current Algorithms:
  Key Exchange:     X25519 (ECDHE)
  Authentication:   RSA-PSS 2048-bit
  Data Encryption:  AES-128-GCM
  Hash Function:    SHA256

Quantum Vulnerability:
  ❌ Key Exchange:     Vulnerable to Shor's algorithm
  ❌ Authentication:   Vulnerable to Shor's algorithm
  ✅ Data Encryption:  Grover's algorithm reduces security to ~64-bit
  ✅ Hash Function:    ~128-bit quantum security (sufficient)

Threat Assessment:
  Risk Level:          🔴 HIGH
  Estimated Timeline:  Quantum threat by ~2030-2040
  Migration Status:    ❌ Not post-quantum ready

Recommendations:
  • Migrate to Kyber/ML-KEM for key exchange
  • Adopt Dilithium/ML-DSA for authentication
  • Upgrade to AES-256 for long-term security
  • Plan for hybrid classical+post-quantum transition
```

### Multiple Sites

```bash
$ tlsinfo github.com google.com badsite.invalid

🔒 TLS Information for github.com:443
═══════════════════════════════════════
Supported TLS Versions: TLS 1.2, TLS 1.3
Active Connection: TLS 1.3
Connection: ✅ Secure

🔒 TLS Information for google.com:443
═══════════════════════════════════════
Supported TLS Versions: TLS 1.2, TLS 1.3
Active Connection: TLS 1.3
Connection: ✅ Secure

❌ badsite.invalid:443
   Error: no such host

────────────────────────────────────────
Summary: 2 successful, 1 failed
```

## Understanding Post-Quantum Security

This tool analyzes the quantum resistance of cryptographic algorithms currently in use:

### ✅ Quantum-Safe Algorithms
- **Key Exchange**: Kyber, ML-KEM, SIKE, BIKE
- **Authentication**: Dilithium, ML-DSA, Falcon, SPHINCS+
- **Encryption**: AES-256, ChaCha20-Poly1305
- **Hash**: SHA-256, SHA-384, SHA-512, BLAKE2

### ❌ Quantum-Vulnerable Algorithms  
- **Key Exchange**: RSA, ECDHE, X25519 (vulnerable to Shor's algorithm)
- **Authentication**: RSA, ECDSA (vulnerable to Shor's algorithm)
- **Encryption**: AES-128 (reduced to ~64-bit security by Grover's algorithm)

### Timeline
Most experts estimate that cryptographically relevant quantum computers capable of breaking current encryption will emerge between 2030-2040.

## Command-Line Options

```
Usage:
  tlsinfo [flags] <domain> [domain2] [domain3]...

Flags:
  -h, --help         Show help message
  -v, --verbose      Show detailed certificate and TLS information
  -t, --tls-versions Show only supported TLS versions  
  -p, --pq-only      Show only post-quantum security analysis
  -f, --file string  Read sites from file (one per line)
      --timeout int  Connection timeout in seconds (default 10)
      --parallel     Check sites concurrently (default true)
      --no-color     Disable colored output

Examples:
  tlsinfo example.com
  tlsinfo github.com google.com
  tlsinfo --file sites.txt
  tlsinfo cloudflare.com --pq-only
```

## Building from Source

### Prerequisites
- Go 1.21 or later
- Git

### Build Instructions

```bash
# Clone the repository
git clone https://github.com/Surya8j/tlsinfo.git
cd tlsinfo

# Install dependencies
go mod tidy

# Build
go build -o tlsinfo

# Run
./tlsinfo github.com
```

### Cross-compilation

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o tlsinfo-linux-amd64

# macOS
GOOS=darwin GOARCH=amd64 go build -o tlsinfo-darwin-amd64

# Windows
GOOS=windows GOARCH=amd64 go build -o tlsinfo-windows-amd64.exe
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`go test ./...`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## Security

This tool performs network connections to analyze TLS configurations. It:

- ✅ Uses standard Go TLS libraries
- ✅ Validates certificates by default
- ✅ Does not store or transmit sensitive data
- ✅ Only analyzes publicly available TLS handshake information
- ❌ Does not perform any intrusive testing

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Go TLS Package](https://pkg.go.dev/crypto/tls)
- [Cobra CLI Framework](https://github.com/spf13/cobra)
- [Fatih Color](https://github.com/fatih/color)

## Support

- 📖 [Documentation](https://github.com/Surya8j/tlsinfo/wiki)
- 🐛 [Report Issues](https://github.com/Surya8j/tlsinfo/issues)
- 💬 [Discussions](https://github.com/Surya8j/tlsinfo/discussions)
- 📧 [Email](mailto:support@tlsinfo.dev)

## Roadmap

- [ ] Support for QUIC/HTTP3 analysis
- [ ] Integration with certificate transparency logs
- [ ] Export results to JSON/CSV/PDF
- [ ] Docker container
- [ ] Web interface
- [ ] Continuous monitoring mode
- [ ] Integration with CI/CD pipelines

---

**⚠️ Disclaimer**: This tool is for educational and security analysis purposes. The post-quantum security assessment is based on current understanding of quantum computing threats and may change as the field evolves.
