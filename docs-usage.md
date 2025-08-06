# TLS Info Usage Guide

This comprehensive guide covers all features and use cases of the TLS Info tool.

## Table of Contents

- [Basic Usage](#basic-usage)
- [Command Line Options](#command-line-options)
- [Output Modes](#output-modes)
- [Batch Processing](#batch-processing)
- [Understanding Output](#understanding-output)
- [Post-Quantum Analysis](#post-quantum-analysis)
- [Troubleshooting](#troubleshooting)
- [Advanced Examples](#advanced-examples)

## Basic Usage

### Single Website Analysis

```bash
# Analyze a single website
tlsinfo example.com

# Specify custom port
tlsinfo example.com:8443

# Include protocol (automatically stripped)
tlsinfo https://example.com
```

### Multiple Websites

```bash
# Check multiple sites at once
tlsinfo github.com google.com cloudflare.com

# Mix domains and ports
tlsinfo github.com example.com:8443 cloudflare.com:443
```

## Command Line Options

### Core Options

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--help` | `-h` | Show help message | - |
| `--verbose` | `-v` | Detailed certificate info | false |
| `--tls-versions` | `-t` | Show only TLS versions | false |
| `--pq-only` | `-p` | Post-quantum analysis only | false |
| `--file` | `-f` | Read sites from file | - |
| `--timeout` | - | Connection timeout (seconds) | 10 |
| `--parallel` | - | Concurrent processing | true |
| `--no-color` | - | Disable colored output | false |

### Examples with Options

```bash
# Verbose analysis with certificate details
tlsinfo github.com --verbose

# Quick TLS version check
tlsinfo github.com --tls-versions

# Focus on quantum security
tlsinfo github.com --pq-only

# Custom timeout for slow connections
tlsinfo example.com --timeout 30

# Disable colors for scripting
tlsinfo github.com --no-color
```

## Output Modes

### 1. Standard Mode (Default)

Shows comprehensive TLS information including:
- Supported TLS versions
- Active connection details  
- Key encryption methods
- Data encryption algorithms
- Brief post-quantum analysis
- Connection security status

```bash
tlsinfo github.com
```

### 2. Verbose Mode

Adds detailed certificate information:
- Certificate chain details
- Validity periods
- Issuer information
- Extended algorithm details

```bash
tlsinfo github.com --verbose
```

### 3. TLS Versions Only

Shows supported TLS/SSL versions in a clean format:

```bash
tlsinfo github.com --tls-versions
```

Output:
```
🔒 TLS Versions for github.com:443
═══════════════════════════════════════
✅ TLS 1.3 (Preferred)
✅ TLS 1.2 
❌ TLS 1.1 
❌ TLS 1.0 
❌ SSL 3.0
```

### 4. Post-Quantum Only

Focuses exclusively on quantum security analysis:

```bash
tlsinfo github.com --pq-only
```

## Batch Processing

### File Input

Create a file with domains (one per line):

```bash
# sites.txt
github.com
google.com
cloudflare.com:443
example.com:8443
# Comments are supported
stackoverflow.com
```

```bash
# Process all sites in file
tlsinfo --file sites.txt

# Combine file and command line arguments
tlsinfo github.com --file sites.txt
```

### File Format

- One domain per line
- Comments start with `#`
- Empty lines are ignored
- Ports can be specified with `:`
- Protocols are automatically stripped

```text
# Production servers
api.example.com:443
app.example.com:8443

# CDN endpoints  
cdn1.example.com
cdn2.example.com

# Third-party services
github.com
google.com
```

## Understanding Output

### Connection Status Icons

| Icon | Meaning |
|------|---------|
| ✅ | Secure/Supported |
| ❌ | Insecure/Not Supported |
| ⚠️ | Warning/Partial |
| 🔒 | TLS Information |
| 🛡️ | Post-Quantum Analysis |

### TLS Versions

| Version | Security Status | Notes |
|---------|----------------|-------|
| TLS 1.3 | ✅ Secure | Latest, most secure |
| TLS 1.2 | ✅ Secure | Widely supported |
| TLS 1.1 | ⚠️ Deprecated | Should be disabled |
| TLS 1.0 | ❌ Insecure | Legacy, vulnerable |
| SSL 3.0 | ❌ Insecure | Severely compromised |

### Cipher Suite Components

A cipher suite like `TLS_AES_128_GCM_SHA256` breaks down as:
- **TLS**: Protocol version family
- **AES_128**: Symmetric encryption (AES with 128-bit key)
- **GCM**: Mode of operation (Galois/Counter Mode)
- **SHA256**: Hash function for integrity

## Post-Quantum Analysis

### Threat Levels

| Level | Icon | Description |
|-------|------|-------------|
| LOW | 🟢 | Quantum-safe algorithms |
| MEDIUM | 🟡 | Partially vulnerable |
| HIGH | 🔴 | Highly vulnerable to quantum attacks |

### Algorithm Categories

#### Key Exchange
- **Vulnerable**: RSA, ECDHE, X25519
- **Quantum-Safe**: Kyber, ML-KEM, SIKE

#### Authentication  
- **Vulnerable**: RSA, ECDSA
- **Quantum-Safe**: Dilithium, ML-DSA, Falcon

#### Data Encryption
- **Vulnerable**: AES-128 (reduced security)
- **Quantum-Safe**: AES-256, ChaCha20-Poly1305

#### Hash Functions
- **Quantum-Safe**: SHA-256, SHA-384, SHA-512

### Understanding Recommendations

Common recommendations and their meanings:

| Recommendation | Explanation |
|----------------|-------------|
| "Migrate to Kyber/ML-KEM" | Replace current key exchange with post-quantum alternative |
| "Adopt Dilithium/ML-DSA" | Use quantum-safe digital signatures |
| "Upgrade to AES-256" | Increase symmetric key size for quantum resistance |
| "Plan hybrid transition" | Use both classical and post-quantum algorithms |

## Troubleshooting

### Common Issues

#### Connection Timeouts
```bash
# Increase timeout for slow connections
tlsinfo slow-site.com --timeout 60
```

#### Permission Denied (Port Access)
```bash
# Use default HTTPS port instead of custom port
tlsinfo example.com  # instead of example.com:443
```

#### Site Not Found
```bash
# Check domain spelling
tlsinfo github.com  # not githib.com

# Remove protocol prefix
tlsinfo example.com  # not https://example.com
```

#### No Color Output
```bash
# Force color output
export FORCE_COLOR=1
tlsinfo github.com

# Or disable explicitly
tlsinfo github.com --no-color
```

### Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| "no such host" | Domain doesn't exist | Check domain spelling |
| "connection refused" | Port closed/filtered | Verify port is open |
| "timeout" | Slow connection | Increase --timeout value |
| "certificate verify failed" | Invalid certificate | Site has certificate issues |

## Advanced Examples

### Security Audit Script

```bash
#!/bin/bash
# audit-sites.sh
echo "# TLS Security Audit Report - $(date)"
echo "## Post-Quantum Readiness"
tlsinfo --file production-sites.txt --pq-only --no-color

echo "## TLS Version Support"  
tlsinfo --file production-sites.txt --tls-versions --no-color
```

### Monitoring Script

```bash
#!/bin/bash
# monitor-tls.sh
for site in api.example.com app.example.com; do
    echo "Checking $site..."
    if ! tlsinfo "$site" --no-color | grep -q "✅ Secure"; then
        echo "WARNING: $site may have TLS issues!"
        # Send alert notification here
    fi
done
```

### JSON Output (for integration)

While tlsinfo doesn't natively output JSON, you can parse results:

```bash
# Extract key information
tlsinfo github.com --no-color | grep -E "(TLS Version|Cipher Suite|Connection)"
```

### CI/CD Integration

```yaml
# .github/workflows/security-check.yml
- name: Check TLS Security
  run: |
    tlsinfo production-api.example.com --pq-only
    if [ $? -ne 0 ]; then
      echo "TLS security check failed"
      exit 1
    fi
```

### Performance Testing

```bash
# Time multiple sites
time tlsinfo github.com google.com cloudflare.com

# Sequential vs parallel processing
tlsinfo site1.com site2.com site3.com --parallel=false
```

## Integration Examples

### With Shell Scripts

```bash
#!/bin/bash
SITES=("github.com" "google.com" "cloudflare.com")

for site in "${SITES[@]}"; do
    echo "=== Checking $site ==="
    tlsinfo "$site" --pq-only
    echo ""
done
```

### With Monitoring Tools

```bash
# Nagios/Icinga check
if tlsinfo "$1" --no-color | grep -q "❌.*HIGH"; then
    echo "CRITICAL - Site uses quantum-vulnerable encryption"
    exit 2
fi
```

### With Reporting

```bash
# Generate CSV report
echo "Site,TLS_Version,Quantum_Safe,Risk_Level" > tls-report.csv
for site in $(cat sites.txt); do
    result=$(tlsinfo "$site" --pq-only --no-color)
    # Parse and append to CSV
done
```

This completes the comprehensive usage guide for TLS Info!