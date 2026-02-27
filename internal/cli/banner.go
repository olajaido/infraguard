package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/yourorg/infraguard/internal/colour"
)

// version is set via ldflags during build: -X github.com/yourorg/infraguard/internal/cli.version=1.0.0
var version = "dev"

const banner = `
  _        __                                     _
 (_)_ __  / _|_ __ __ _  __ _ _   _  __ _ _ __ __| |
 | | '_ \| |_| '__/ _' |/ _' | | | |/ _' | '__/ _' |
 | | | | |  _| | | (_| | (_| | |_| | (_| | | | (_| |
 |_|_| |_|_| |_|  \__,_|\__, |\__,_|\__,_|_|  \__,_|
                        |___/
`

const subtitle = "AWS Infrastructure Auditing CLI"

// PrintBanner prints the infraguard banner, version, and scan context to w.
// The banner is only printed when colour output is enabled (suppressed in JSON mode
// and piped output). accountID and regions provide context about the scan.
func PrintBanner(w io.Writer, accountID string, regions []string) {
	if !colour.IsEnabled() {
		return // Don't print banner in JSON mode or piped output
	}

	// Print banner in cyan
	fmt.Fprint(w, colour.Cyan(banner))
	fmt.Fprintf(w, "  %s\n", colour.Cyan(subtitle))
	fmt.Fprintf(w, "  %s\n\n", colour.White(fmt.Sprintf("Version: %s", version)))

	// Print scan context
	fmt.Fprintf(w, "  %s %s\n", colour.Bold("Account:"), colour.White(accountID))
	fmt.Fprintf(w, "  %s %s\n\n", colour.Bold("Regions:"), colour.White(strings.Join(regions, ", ")))
}
