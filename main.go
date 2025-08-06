package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	verbose      bool
	tlsVersions  bool
	pqOnly       bool
	filename     string
	timeout      int
	parallel     bool
	noColor      bool
)

// TLSInfo holds TLS connection information
type TLSInfo struct {
	Host            string
	Port            string
	TLSVersion      uint16
	CipherSuite     uint16
	ServerCerts     []*x509.Certificate
	PeerCertChain   []*x509.Certificate
	SupportedTLS    []uint16
	ConnectionState *tls.ConnectionState
	Error           error
}

// PostQuantumAnalysis holds PQ security analysis
type PostQuantumAnalysis struct {
	KeyExchange      PQStatus
	Authentication   PQStatus
	DataEncryption   PQStatus
	HashFunction     PQStatus
	OverallSecurity  string
	ThreatLevel      string
	Recommendations  []string
}

type PQStatus struct {
	Algorithm     string
	IsQuantumSafe bool
	Vulnerability string
	Notes         string
}

// Color definitions
var (
	green  = color.New(color.FgGreen)
	red    = color.New(color.FgRed)
	yellow = color.New(color.FgYellow)
	cyan   = color.New(color.FgCyan)
	white  = color.New(color.FgWhite, color.Bold)
	blue   = color.New(color.FgBlue)
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "tlsinfo [flags] <domain> [domain2] [domain3]...",
		Short: "Display encryption algorithms and post-quantum security analysis",
		Long: `████████╗██╗     ███████╗    ██╗███╗   ██╗███████╗ ██████╗ 
╚══██╔══╝██║     ██╔════╝    ██║████╗  ██║██╔════╝██╔═══██╗
   ██║   ██║     ███████╗    ██║██╔██╗ ██║█████╗  ██║   ██║
   ██║   ██║     ╚════██║    ██║██║╚██╗██║██╔══╝  ██║   ██║
   ██║   ███████╗███████║    ██║██║ ╚████║██║     ╚██████╔╝
   ╚═╝   ╚══════╝╚══════╝    ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ 

Display encryption algorithms and post-quantum security analysis for websites.`,
		Example: `  tlsinfo example.com
  tlsinfo github.com google.com
  tlsinfo --file sites.txt
  tlsinfo cloudflare.com --pq-only`,
		Args: cobra.MinimumNArgs(0),
		Run:  runTLSInfo,
	}

	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show detailed certificate and TLS information")
	rootCmd.Flags().BoolVarP(&tlsVersions, "tls-versions", "t", false, "Show only supported TLS versions")
	rootCmd.Flags().BoolVarP(&pqOnly, "pq-only", "p", false, "Show only post-quantum security analysis")
	rootCmd.Flags().StringVarP(&filename, "file", "f", "", "Read sites from file (one per line)")
	rootCmd.Flags().IntVar(&timeout, "timeout", 10, "Connection timeout in seconds")
	rootCmd.Flags().BoolVar(&parallel, "parallel", true, "Check sites concurrently")
	rootCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable colored output")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runTLSInfo(cmd *cobra.Command, args []string) {
	if noColor {
		color.NoColor = true
	}

	var sites []string

	// Collect sites from arguments
	sites = append(sites, args...)

	// Read sites from file if specified
	if filename != "" {
		fileSites, err := readSitesFromFile(filename)
		if err != nil {
			red.Printf("❌ Error reading file %s: %v\n", filename, err)
			os.Exit(1)
		}
		sites = append(sites, fileSites...)
	}

	if len(sites) == 0 {
		red.Println("❌ Error: No sites provided")
		cmd.Help()
		os.Exit(1)
	}

	// Process sites
	results := make([]TLSInfo, len(sites))
	
	for i, site := range sites {
		host, port := parseHostPort(site)
		results[i] = getTLSInfo(host, port)
	}

	// Display results
	displayResults(results)
}

func parseHostPort(site string) (string, string) {
	// Remove protocol if present
	site = strings.TrimPrefix(site, "https://")
	site = strings.TrimPrefix(site, "http://")
	
	// Check if port is specified
	if strings.Contains(site, ":") {
		parts := strings.Split(site, ":")
		return parts[0], parts[1]
	}
	
	return site, "443"
}

func readSitesFromFile(filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	
	lines := strings.Split(string(data), "\n")
	var sites []string
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			sites = append(sites, line)
		}
	}
	
	return sites, nil
}

func getTLSInfo(host, port string) TLSInfo {
	info := TLSInfo{
		Host: host,
		Port: port,
	}

	// Set timeout
	dialer := &net.Dialer{
		Timeout: time.Duration(timeout) * time.Second,
	}

	// Get supported TLS versions
	info.SupportedTLS = getSupportedTLSVersions(host, port, dialer)

	// Connect with highest TLS version
	config := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: false,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), config)
	if err != nil {
		info.Error = err
		return info
	}
	defer conn.Close()

	state := conn.ConnectionState()
	info.ConnectionState = &state
	info.TLSVersion = state.Version
	info.CipherSuite = state.CipherSuite
	info.ServerCerts = state.PeerCertificates

	return info
}

func getSupportedTLSVersions(host, port string, dialer *net.Dialer) []uint16 {
	versions := []uint16{
		tls.VersionTLS13,
		tls.VersionTLS12,
		tls.VersionTLS11,
		tls.VersionTLS10,
	}

	var supported []uint16

	for _, version := range versions {
		config := &tls.Config{
			ServerName:         host,
			MinVersion:         version,
			MaxVersion:         version,
			InsecureSkipVerify: false,
		}

		conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), config)
		if err == nil {
			supported = append(supported, version)
			conn.Close()
		}
	}

	return supported
}

func displayResults(results []TLSInfo) {
	successful := 0
	failed := 0

	for _, result := range results {
		if result.Error != nil {
			failed++
			displayError(result)
		} else {
			successful++
			if pqOnly {
				displayPQAnalysis(result)
			} else if tlsVersions {
				displayTLSVersions(result)
			} else {
				displayFullInfo(result)
			}
		}
		
		if len(results) > 1 {
			fmt.Println()
		}
	}

	// Summary for multiple sites
	if len(results) > 1 {
		fmt.Println(strings.Repeat("─", 40))
		fmt.Printf("Summary: %s successful, %s failed\n", 
			green.Sprint(successful), 
			red.Sprint(failed))
	}
}

func displayError(info TLSInfo) {
	red.Printf("❌ %s:%s\n", info.Host, info.Port)
	fmt.Printf("   Error: %v\n", info.Error)
}

func displayFullInfo(info TLSInfo) {
	fmt.Printf("🔒 TLS Information for %s:%s\n", info.Host, info.Port)
	fmt.Println(strings.Repeat("═", 39))
	
	// Supported versions
	if len(info.SupportedTLS) > 0 {
		fmt.Printf("Supported TLS Versions: %s\n", formatSupportedVersions(info.SupportedTLS))
	}
	
	fmt.Printf("Active Connection: %s\n", getTLSVersionName(info.TLSVersion))
	fmt.Printf("Cipher Suite: %s\n", getCipherSuiteName(info.CipherSuite))
	fmt.Println()

	// Key Encryption
	white.Println("Key Encryption:")
	keyExchange, auth := analyzeCipherSuite(info.CipherSuite)
	fmt.Printf("  Key Exchange:     %s\n", keyExchange)
	fmt.Printf("  Authentication:   %s\n", auth)
	if len(info.ServerCerts) > 0 {
		fmt.Printf("  Certificate:      %s\n", getCertificateInfo(info.ServerCerts[0]))
	}
	fmt.Println()

	// Data Encryption  
	white.Println("Data Encryption:")
	symmetric, hash, mode := getDataEncryptionInfo(info.CipherSuite)
	fmt.Printf("  Symmetric Cipher: %s\n", symmetric)
	fmt.Printf("  Hash Function:    %s\n", hash)
	fmt.Printf("  Mode:            %s\n", mode)
	fmt.Println()

	// Post-Quantum Analysis (brief)
	if !pqOnly {
		displayBriefPQAnalysis(info)
	}

	// Connection status
	green.Print("Connection: ✅ Secure")
	pqAnalysis := analyzePostQuantum(info)
	if pqAnalysis.ThreatLevel == "HIGH" {
		yellow.Print(" (Classical threats)")
		fmt.Print("\n            ")
		yellow.Print("⚠️  Vulnerable to quantum attacks")
	}
	fmt.Println()
}

func displayBriefPQAnalysis(info TLSInfo) {
	pqAnalysis := analyzePostQuantum(info)
	white.Println("Post-Quantum Security:")
	
	status := "❌"
	if pqAnalysis.KeyExchange.IsQuantumSafe {
		status = "✅"
	}
	fmt.Printf("  Key Exchange:     %s %s\n", status, getShortPQStatus(pqAnalysis.KeyExchange))
	
	status = "❌"
	if pqAnalysis.Authentication.IsQuantumSafe {
		status = "✅"
	}
	fmt.Printf("  Authentication:   %s %s\n", status, getShortPQStatus(pqAnalysis.Authentication))
	
	status = "❌"
	if pqAnalysis.DataEncryption.IsQuantumSafe {
		status = "✅"
	}
	fmt.Printf("  Data Encryption:  %s %s\n", status, getShortPQStatus(pqAnalysis.DataEncryption))
	
	overallStatus := "❌"
	if pqAnalysis.OverallSecurity == "SECURE" {
		overallStatus = "✅"
	}
	fmt.Printf("  Overall:          %s %s\n", overallStatus, pqAnalysis.OverallSecurity)
	fmt.Println()
}

func displayPQAnalysis(info TLSInfo) {
	fmt.Printf("🛡️  Post-Quantum Security Analysis for %s:%s\n", info.Host, info.Port)
	fmt.Println(strings.Repeat("═", 55))
	
	pqAnalysis := analyzePostQuantum(info)
	
	white.Println("Current Algorithms:")
	keyExchange, auth := analyzeCipherSuite(info.CipherSuite)
	symmetric, hash, _ := getDataEncryptionInfo(info.CipherSuite)
	fmt.Printf("  Key Exchange:     %s\n", keyExchange)
	fmt.Printf("  Authentication:   %s\n", auth)
	fmt.Printf("  Data Encryption:  %s\n", symmetric)
	fmt.Printf("  Hash Function:    %s\n", hash)
	fmt.Println()

	white.Println("Quantum Vulnerability:")
	printPQStatus("Key Exchange", pqAnalysis.KeyExchange)
	printPQStatus("Authentication", pqAnalysis.Authentication)
	printPQStatus("Data Encryption", pqAnalysis.DataEncryption)
	printPQStatus("Hash Function", pqAnalysis.HashFunction)
	fmt.Println()

	white.Println("Threat Assessment:")
	threatColor := red
	if pqAnalysis.ThreatLevel == "LOW" {
		threatColor = green
	} else if pqAnalysis.ThreatLevel == "MEDIUM" {
		threatColor = yellow
	}
	
	fmt.Printf("  Risk Level:          %s %s\n", getThreatEmoji(pqAnalysis.ThreatLevel), threatColor.Sprint(pqAnalysis.ThreatLevel))
	if pqAnalysis.ThreatLevel != "LOW" {
		fmt.Println("  Estimated Timeline:  Quantum threat by ~2030-2040")
	}
	
	migrationStatus := "❌ Not post-quantum ready"
	if pqAnalysis.OverallSecurity == "SECURE" {
		migrationStatus = "✅ Post-quantum ready"
	}
	fmt.Printf("  Migration Status:    %s\n", migrationStatus)
	
	if len(pqAnalysis.Recommendations) > 0 {
		fmt.Println()
		white.Println("Recommendations:")
		for _, rec := range pqAnalysis.Recommendations {
			fmt.Printf("  • %s\n", rec)
		}
	}
}

func displayTLSVersions(info TLSInfo) {
	fmt.Printf("🔒 TLS Versions for %s:%s\n", info.Host, info.Port)
	fmt.Println(strings.Repeat("═", 39))
	
	allVersions := []uint16{
		tls.VersionTLS13,
		tls.VersionTLS12,
		tls.VersionTLS11,
		tls.VersionTLS10,
		0x0300, // SSL 3.0
	}
	
	for i, version := range allVersions {
		supported := contains(info.SupportedTLS, version)
		status := "❌"
		if supported {
			status = "✅"
		}
		
		versionName := getTLSVersionName(version)
		extra := ""
		if supported && version == info.TLSVersion {
			extra = " (Preferred)"
		}
		
		fmt.Printf("%s %s%s\n", status, versionName, extra)
		
		// Add spacing for readability
		if i == 1 { // After TLS 1.2
			fmt.Println()
		}
	}
}

// Helper functions for TLS analysis
func formatSupportedVersions(versions []uint16) string {
	var names []string
	for _, version := range versions {
		names = append(names, getTLSVersionName(version))
	}
	return strings.Join(names, ", ")
}

func getTLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case 0x0300:
		return "SSL 3.0"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

func getCipherSuiteName(suite uint16) string {
	switch suite {
	case tls.TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case tls.TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:
		return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
		return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", suite)
	}
}

func analyzeCipherSuite(suite uint16) (keyExchange, auth string) {
	switch suite {
	// TLS 1.3 suites
	case tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256:
		return "X25519 (ECDHE)", "RSA-PSS/ECDSA"
	
	// TLS 1.2 ECDHE suites
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "ECDHE (P-256)", "RSA"
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:
		return "ECDHE (P-256)", "RSA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "ECDHE (P-256)", "ECDSA P-256"
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
		return "ECDHE (P-256)", "ECDSA P-256"
	default:
		return "Unknown", "Unknown"
	}
}

func getDataEncryptionInfo(suite uint16) (symmetric, hash, mode string) {
	switch suite {
	case tls.TLS_AES_128_GCM_SHA256:
		return "AES-128-GCM", "SHA256", "GCM (Authenticated)"
	case tls.TLS_AES_256_GCM_SHA384:
		return "AES-256-GCM", "SHA384", "GCM (Authenticated)"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "ChaCha20-Poly1305", "SHA256", "AEAD (Authenticated)"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "AES-128-GCM", "SHA256", "GCM (Authenticated)"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "AES-256-GCM", "SHA384", "GCM (Authenticated)"
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
		return "ChaCha20-Poly1305", "SHA256", "AEAD (Authenticated)"
	default:
		return "Unknown", "Unknown", "Unknown"
	}
}

func getCertificateInfo(cert *x509.Certificate) string {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		if rsaPub, ok := cert.PublicKey.(interface{ Size() int }); ok {
			keySize := rsaPub.Size() * 8
			return fmt.Sprintf("RSA %d-bit + %s", keySize, cert.SignatureAlgorithm.String())
		}
		return fmt.Sprintf("RSA + %s", cert.SignatureAlgorithm.String())
	case x509.ECDSA:
		return fmt.Sprintf("ECDSA + %s", cert.SignatureAlgorithm.String())
	default:
		return cert.PublicKeyAlgorithm.String()
	}
}

func analyzePostQuantum(info TLSInfo) PostQuantumAnalysis {
	analysis := PostQuantumAnalysis{}
	
	keyExchange, auth := analyzeCipherSuite(info.CipherSuite)
	symmetric, hash, _ := getDataEncryptionInfo(info.CipherSuite)
	
	// Analyze key exchange
	analysis.KeyExchange = PQStatus{
		Algorithm: keyExchange,
		IsQuantumSafe: isKeyExchangeQuantumSafe(keyExchange),
		Vulnerability: getKeyExchangeVulnerability(keyExchange),
		Notes: "ECC and RSA vulnerable to Shor's algorithm",
	}
	
	// Analyze authentication
	analysis.Authentication = PQStatus{
		Algorithm: auth,
		IsQuantumSafe: isAuthQuantumSafe(auth),
		Vulnerability: getAuthVulnerability(auth),
		Notes: "Classical signatures vulnerable to Shor's algorithm",
	}
	
	// Analyze data encryption
	analysis.DataEncryption = PQStatus{
		Algorithm: symmetric,
		IsQuantumSafe: isSymmetricQuantumSafe(symmetric),
		Vulnerability: getSymmetricVulnerability(symmetric),
		Notes: "AES-128 provides ~64-bit quantum security",
	}
	
	// Analyze hash function
	analysis.HashFunction = PQStatus{
		Algorithm: hash,
		IsQuantumSafe: isHashQuantumSafe(hash),
		Vulnerability: getHashVulnerability(hash),
		Notes: "Hash functions generally quantum-resistant",
	}
	
	// Overall assessment
	if !analysis.KeyExchange.IsQuantumSafe || !analysis.Authentication.IsQuantumSafe {
		analysis.ThreatLevel = "HIGH"
		analysis.OverallSecurity = "NOT SECURE"
	} else if !analysis.DataEncryption.IsQuantumSafe {
		analysis.ThreatLevel = "MEDIUM"
		analysis.OverallSecurity = "PARTIALLY SECURE"
	} else {
		analysis.ThreatLevel = "LOW"
		analysis.OverallSecurity = "SECURE"
	}
	
	// Generate recommendations
	analysis.Recommendations = generatePQRecommendations(analysis)
	
	return analysis
}

func isKeyExchangeQuantumSafe(keyExchange string) bool {
	// Post-quantum safe algorithms
	quantumSafe := []string{
		"Kyber512", "Kyber768", "Kyber1024",
		"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
		"SIKE", "BIKE", "HQC",
	}
	
	for _, safe := range quantumSafe {
		if strings.Contains(keyExchange, safe) {
			return true
		}
	}
	
	return false
}

func isAuthQuantumSafe(auth string) bool {
	quantumSafe := []string{
		"Dilithium2", "Dilithium3", "Dilithium5",
		"ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
		"Falcon-512", "Falcon-1024",
		"SPHINCS+",
	}
	
	for _, safe := range quantumSafe {
		if strings.Contains(auth, safe) {
			return true
		}
	}
	
	return false
}

func isSymmetricQuantumSafe(symmetric string) bool {
	// AES-256 is considered quantum-safe (128-bit quantum security)
	// AES-128 provides ~64-bit quantum security (borderline)
	return strings.Contains(symmetric, "AES-256") || 
		   strings.Contains(symmetric, "ChaCha20")
}

func isHashQuantumSafe(hash string) bool {
	// Most cryptographic hash functions are quantum-resistant
	// SHA-256 provides ~128-bit quantum security
	// SHA-384/SHA-512 provide higher security
	return strings.Contains(hash, "SHA") || 
		   strings.Contains(hash, "BLAKE") ||
		   strings.Contains(hash, "SHA3")
}

func getKeyExchangeVulnerability(keyExchange string) string {
	if strings.Contains(keyExchange, "RSA") {
		return "Vulnerable to Shor's algorithm"
	}
	if strings.Contains(keyExchange, "ECDHE") || strings.Contains(keyExchange, "X25519") {
		return "Vulnerable to Shor's algorithm"
	}
	return "Quantum-resistant"
}

func getAuthVulnerability(auth string) string {
	if strings.Contains(auth, "RSA") || strings.Contains(auth, "ECDSA") {
		return "Vulnerable to Shor's algorithm"
	}
	return "Quantum-resistant"
}

func getSymmetricVulnerability(symmetric string) string {
	if strings.Contains(symmetric, "AES-128") {
		return "Grover's algorithm reduces security to ~64-bit"
	}
	if strings.Contains(symmetric, "AES-256") || strings.Contains(symmetric, "ChaCha20") {
		return "Quantum-resistant (>128-bit quantum security)"
	}
	return "Unknown quantum security level"
}

func getHashVulnerability(hash string) string {
	if strings.Contains(hash, "SHA256") {
		return "~128-bit quantum security (sufficient)"
	}
	if strings.Contains(hash, "SHA384") || strings.Contains(hash, "SHA512") {
		return "High quantum security (>128-bit)"
	}
	return "Quantum-resistant"
}

func generatePQRecommendations(analysis PostQuantumAnalysis) []string {
	var recommendations []string
	
	if !analysis.KeyExchange.IsQuantumSafe {
		recommendations = append(recommendations, "Migrate to Kyber/ML-KEM for key exchange")
	}
	
	if !analysis.Authentication.IsQuantumSafe {
		recommendations = append(recommendations, "Adopt Dilithium/ML-DSA for authentication")
	}
	
	if strings.Contains(analysis.DataEncryption.Algorithm, "AES-128") {
		recommendations = append(recommendations, "Upgrade to AES-256 for long-term security")
	}
	
	if analysis.ThreatLevel == "HIGH" {
		recommendations = append(recommendations, "Plan for hybrid classical+post-quantum transition")
		recommendations = append(recommendations, "Monitor NIST PQC standardization updates")
	}
	
	return recommendations
}

func printPQStatus(component string, status PQStatus) {
	icon := "❌"
	if status.IsQuantumSafe {
		icon = "✅"
	}
	fmt.Printf("  %s %-15s %s\n", icon, component+":", status.Vulnerability)
}

func getShortPQStatus(status PQStatus) string {
	if status.IsQuantumSafe {
		return "Quantum-safe"
	}
	if strings.Contains(status.Algorithm, "RSA") || strings.Contains(status.Algorithm, "ECDSA") {
		return "Vulnerable (Classical signatures)"
	}
	if strings.Contains(status.Algorithm, "ECDHE") || strings.Contains(status.Algorithm, "X25519") {
		return "Vulnerable (ECC based)"
	}
	if strings.Contains(status.Algorithm, "AES-128") {
		return "Partial (64-bit quantum security)"
	}
	return "Unknown"
}

func getThreatEmoji(level string) string {
	switch level {
	case "LOW":
		return "🟢"
	case "MEDIUM":
		return "🟡"
	case "HIGH":
		return "🔴"
	default:
		return "⚪"
	}
}

func contains(slice []uint16, item uint16) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}