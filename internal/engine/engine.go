package engine

import (
	"context"
	"fmt"
	"sync"
)

// Engine holds the registry of checks and runs them against target regions.
type Engine struct {
	checks []Check
}

// NewEngine returns an empty Engine. Register checks with Register before
// calling Run.
func NewEngine() *Engine {
	return &Engine{}
}

// Register adds one or more checks to the engine. Duplicate check names are
// not validated here; they will produce duplicate findings. Callers are
// responsible for ensuring uniqueness, typically via init() registration in
// each check package.
func (e *Engine) Register(checks ...Check) {
	e.checks = append(e.checks, checks...)
}

// CheckCount returns the number of checks currently registered.
func (e *Engine) CheckCount() int {
	return len(e.checks)
}

// RunResult is the aggregated output of a single engine run.
type RunResult struct {
	// Findings is the complete, unordered list of findings across all checks
	// and all regions.
	Findings []Finding

	// Errors maps "<check-name>/<region>" to the error returned by that check.
	// A non-empty Errors map does not prevent other checks from running.
	Errors map[string]error
}

// Run executes all registered checks concurrently across the provided regions.
// Each (check, region) pair is run as a separate goroutine. The context may be
// used to cancel the entire run.
//
// Run always returns a RunResult, even if some checks fail; partial results are
// valid. An error is returned only if the run cannot start at all (e.g. no
// regions provided).
func (e *Engine) Run(ctx context.Context, cfg CheckConfig, regions []string) (*RunResult, error) {
	if len(regions) == 0 {
		return nil, fmt.Errorf("engine: no target regions provided")
	}
	if len(e.checks) == 0 {
		return &RunResult{Errors: map[string]error{}}, nil
	}

	type result struct {
		findings []Finding
		err      error
		key      string // "<check-name>/<region>"
	}

	resultCh := make(chan result, len(e.checks)*len(regions))

	var wg sync.WaitGroup

	for _, region := range regions {
		for _, check := range e.checks {
			wg.Add(1)

			// Capture loop variables for the goroutine.
			region := region
			check := check

			go func() {
				defer wg.Done()

				// Build a per-region config by copying and overriding the region.
				regionCfg := cfg
				regionCfg.Region = region
				regionCfg.AWSConfig.Region = region

				// Log check start
				fmt.Fprintf(cfg.LogWriter, "  → Running check: %s [%s]\n", check.Name(), region)

				findings, err := check.Run(ctx, regionCfg)

				// Log check completion
				if err != nil {
					fmt.Fprintf(cfg.LogWriter, "  ✗ Failed: %s [%s] - %v\n", check.Name(), region, err)
				} else {
					fmt.Fprintf(cfg.LogWriter, "  ✓ Completed: %s [%s] - %d findings\n", check.Name(), region, len(findings))
				}

				resultCh <- result{
					findings: findings,
					err:      err,
					key:      check.Name() + "/" + region,
				}
			}()
		}
	}

	// Close the channel once all goroutines have written their results.
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	out := &RunResult{
		Errors: make(map[string]error),
	}

	completed := 0
	total := len(e.checks) * len(regions)

	for r := range resultCh {
		completed++
		if r.err != nil {
			out.Errors[r.key] = r.err
		} else {
			out.Findings = append(out.Findings, r.findings...)
		}
	}

	// Print completion summary
	if cfg.LogWriter != nil {
		fmt.Fprintf(cfg.LogWriter, "\n✓ Scan complete: %d/%d checks finished, %d findings, %d errors\n\n",
			completed, total, len(out.Findings), len(out.Errors))
	}

	return out, nil
}
