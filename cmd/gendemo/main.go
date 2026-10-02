// generate_demo creates sample pcap files for the TRACE demo.
package main

import (
	"fmt"
	"os"

	"github.com/SIH-2026/trace/internal/testutil"
)

func main() {
	os.MkdirAll("demo", 0o755)

	// IKEv2 AES-256-GCM capture
	gcm := testutil.BuildIKEv2GCMCapture()
	if err := os.WriteFile("demo/ikev2-gcm256.pcap", gcm, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Created demo/ikev2-gcm256.pcap (%d bytes)\n", len(gcm))

	// IKEv2 AES-256-CBC capture
	cbc := testutil.BuildIKEv2CBCCapture()
	if err := os.WriteFile("demo/ikev2-cbc256.pcap", cbc, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Created demo/ikev2-cbc256.pcap (%d bytes)\n", len(cbc))

	// Non-IPsec capture (negative test)
	tcp := testutil.BuildNonIPsecCapture()
	if err := os.WriteFile("demo/non-ipsec-tcp.pcap", tcp, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Created demo/non-ipsec-tcp.pcap (%d bytes)\n", len(tcp))
}
