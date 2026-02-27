// Package reporter provides output formatters for infraguard findings.
package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/yourorg/infraguard/internal/colour"
	"github.com/yourorg/infraguard/internal/engine"
)

// Reporter formats and writes a RunResult to an output stream.
type Reporter interface {
	// Report writes the findings and any run errors to w.
	Report(w io.Writer, result *engine.RunResult) error
}

// TextReporter writes human-readable, terminal-friendly output.
type TextReporter struct{}

// NewTextReporter returns a TextReporter.
func NewTextReporter() *TextReporter { return &TextReporter{} }

// Report implements Reporter for human-readable terminal output.
func (r *TextReporter) Report(w io.Writer, result *engine.RunResult) error {
	if len(result.Findings) == 0 && len(result.Errors) == 0 {
		_, err := fmt.Fprintln(w, colour.Green("✓ No findings."))
		return err
	}

	// Map severity to colour function
	sevColour := map[engine.Severity]func(string) string{
		engine.SeverityCritical: colour.BoldRed,
		engine.SeverityHigh:     colour.Orange,
		engine.SeverityMedium:   colour.Yellow,
		engine.SeverityLow:      colour.Cyan,
		engine.SeverityInfo:     colour.Blue,
	}

	// Group findings by severity for readability.
	order := []engine.Severity{
		engine.SeverityCritical,
		engine.SeverityHigh,
		engine.SeverityMedium,
		engine.SeverityLow,
		engine.SeverityInfo,
	}

	byseverity := make(map[engine.Severity][]engine.Finding)
	for _, f := range result.Findings {
		byseverity[f.Severity] = append(byseverity[f.Severity], f)
	}

	for _, sev := range order {
		findings, ok := byseverity[sev]
		if !ok {
			continue
		}

		// Print coloured severity header
		colourFn := sevColour[sev]
		fmt.Fprintf(w, "\n%s %d finding(s)\n", colourFn(fmt.Sprintf("[%s]", sev)), len(findings))
		fmt.Fprintln(w, colour.White(strings.Repeat("─", 60)))

		for _, f := range findings {
			// Field labels in bold, severity badge in colour
			fmt.Fprintf(w, "  %s       [%s] %s\n", colour.Bold("Check:"), colourFn(string(f.Severity)), f.CheckName)
			fmt.Fprintf(w, "  %s    %s\n", colour.Bold("Resource:"), f.ResourceID)
			fmt.Fprintf(w, "  %s      %s\n", colour.Bold("Region:"), f.Region)
			if len(f.RelatedResources) > 0 {
				fmt.Fprintf(w, "  %s     %s\n", colour.Bold("Related:"), strings.Join(f.RelatedResources, ", "))
			}
			fmt.Fprintf(w, "  %s     %s\n", colour.Bold("Message:"), f.Message)
			fmt.Fprintf(w, "  %s %s\n", colour.Bold("Remediation:"), f.Remediation)
			fmt.Fprintf(w, "  %s  %s\n\n", colour.Bold("Discovered:"), f.DiscoveredAt.Format(time.RFC3339))
		}
	}

	// Print errors in red
	for key, err := range result.Errors {
		fmt.Fprintf(w, "%s %s: %v\n", colour.Red("[ERROR]"), key, err)
	}

	return nil
}

// JSONReporter writes structured JSON output suitable for machine consumption
// and CI pipeline integration.
type JSONReporter struct{}

// NewJSONReporter returns a JSONReporter.
func NewJSONReporter() *JSONReporter { return &JSONReporter{} }

// jsonOutput is the top-level envelope written by JSONReporter.
type jsonOutput struct {
	Findings []engine.Finding  `json:"findings"`
	Errors   map[string]string `json:"errors,omitempty"`
	Summary  map[string]int    `json:"summary"`
}

// Report implements Reporter for structured JSON output.
func (r *JSONReporter) Report(w io.Writer, result *engine.RunResult) error {
	summary := make(map[string]int)
	for _, f := range result.Findings {
		summary[string(f.Severity)]++
	}

	errStrings := make(map[string]string, len(result.Errors))
	for k, v := range result.Errors {
		errStrings[k] = v.Error()
	}

	out := jsonOutput{
		Findings: result.Findings,
		Errors:   errStrings,
		Summary:  summary,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("reporter: failed to encode JSON output: %w", err)
	}
	return nil
}
