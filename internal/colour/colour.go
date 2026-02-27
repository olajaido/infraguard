// Package colour provides ANSI colour codes for terminal output.
// Colours are automatically disabled for non-TTY output, when NO_COLOR is set,
// or when explicitly disabled (e.g., for JSON output mode).
package colour

import (
	"fmt"
	"os"
)

var enabled = true

func init() {
	// Auto-disable if NO_COLOR env var is set
	if os.Getenv("NO_COLOR") != "" {
		enabled = false
		return
	}

	// Auto-disable if stdout is not a TTY
	if fileInfo, err := os.Stdout.Stat(); err == nil {
		if (fileInfo.Mode() & os.ModeCharDevice) == 0 {
			enabled = false
		}
	}
}

// Disable turns off colour output globally.
// This should be called when JSON output is requested.
func Disable() {
	enabled = false
}

// Enable turns on colour output globally.
func Enable() {
	enabled = true
}

// IsEnabled returns true if colour output is currently enabled.
func IsEnabled() bool {
	return enabled
}

// ANSI colour codes
const (
	reset      = "\033[0m"
	bold       = "\033[1m"
	red        = "\033[31m"
	green      = "\033[32m"
	yellow     = "\033[33m"
	blue       = "\033[34m"
	cyan       = "\033[36m"
	white      = "\033[37m"
	brightRed  = "\033[91m"
	orange     = "\033[38;5;208m" // 256-color orange
)

// Bold returns the string in bold.
func Bold(s string) string {
	if !enabled {
		return s
	}
	return bold + s + reset
}

// Red returns the string in red.
func Red(s string) string {
	if !enabled {
		return s
	}
	return red + s + reset
}

// BoldRed returns the string in bold red.
func BoldRed(s string) string {
	if !enabled {
		return s
	}
	return bold + brightRed + s + reset
}

// Orange returns the string in orange.
func Orange(s string) string {
	if !enabled {
		return s
	}
	return orange + s + reset
}

// Yellow returns the string in yellow.
func Yellow(s string) string {
	if !enabled {
		return s
	}
	return yellow + s + reset
}

// Cyan returns the string in cyan.
func Cyan(s string) string {
	if !enabled {
		return s
	}
	return cyan + s + reset
}

// Blue returns the string in blue.
func Blue(s string) string {
	if !enabled {
		return s
	}
	return blue + s + reset
}

// Green returns the string in green.
func Green(s string) string {
	if !enabled {
		return s
	}
	return green + s + reset
}

// White returns the string in white.
func White(s string) string {
	if !enabled {
		return s
	}
	return white + s + reset
}

// Sprintf is a convenience function that applies colour after formatting.
// Usage: colour.Sprintf(colour.Bold, "Count: %d", 42)
func Sprintf(colourFunc func(string) string, format string, args ...interface{}) string {
	return colourFunc(fmt.Sprintf(format, args...))
}
