// Package chaos implements the --chaos sweep: inject latency on the path
// to the OCSP responder via `tc netem` and record the soft-fail rate at
// each delay level. This reproduces the CYB 260 OCSP soft-fail experiment
// as a repeatable feature rather than a one-off lab run.
//
// Requires NET_ADMIN and the iproute2 package (see the probe Dockerfile).
package chaos

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

const defaultIface = "eth0"

// DefaultDelaysMS is deliberately dense near 2s: the original research
// found the soft-fail transition is sharp but jittery in the 1960-2000ms
// band rather than a clean step.
var DefaultDelaysMS = []int{0, 100, 500, 1000, 1500, 1700, 1900, 1950, 1960, 1970, 1980, 1990, 2000}

// Sweep runs trials at each delay level in delaysMS, calling runTrial for
// each of trials repetitions, and returns the soft-fail rate per level.
// It ALWAYS removes the netem qdisc on return (including on ctx
// cancellation / SIGINT/SIGTERM) — a leaked qdisc silently poisons every
// later measurement.
func Sweep(ctx context.Context, iface string, delaysMS []int, trials int, runTrial func(ctx context.Context, delayMS int) (softFailed bool, err error)) (map[int]float64, error) {
	if iface == "" {
		iface = defaultIface
	}

	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	defer func() {
		if err := clearQdisc(iface); err != nil {
			log.Printf("chaos: WARNING: failed to clear qdisc on %s during cleanup: %v", iface, err)
		}
	}()

	results := make(map[int]float64, len(delaysMS))

	for _, delay := range delaysMS {
		select {
		case <-sigCtx.Done():
			return results, sigCtx.Err()
		default:
		}

		if err := setDelay(iface, delay); err != nil {
			return results, fmt.Errorf("chaos: setting delay=%dms on %s: %w", delay, iface, err)
		}

		softFails := 0
		for i := 0; i < trials; i++ {
			select {
			case <-sigCtx.Done():
				return results, sigCtx.Err()
			default:
			}
			failed, err := runTrial(sigCtx, delay)
			if err != nil {
				log.Printf("chaos: trial error at delay=%dms: %v", delay, err)
				continue
			}
			if failed {
				softFails++
			}
		}
		rate := float64(softFails) / float64(trials)
		results[delay] = rate
		log.Printf("chaos: delay=%dms softfail_rate=%.2f (%d/%d)", delay, rate, softFails, trials)
	}

	return results, nil
}

func setDelay(iface string, delayMS int) error {
	// Idempotent: `replace` works whether or not a netem qdisc already
	// exists on this interface.
	cmd := exec.Command("tc", "qdisc", "replace", "dev", iface, "root", "netem",
		"delay", strconv.Itoa(delayMS)+"ms")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func clearQdisc(iface string) error {
	cmd := exec.Command("tc", "qdisc", "del", "dev", iface, "root")
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		// "no qdisc" / "Cannot delete" style errors are expected when
		// there's nothing to clear (e.g. Sweep was never called, or a
		// previous run already cleaned up) — treat as success.
		if strings.Contains(msg, "Error: Cannot delete qdisc with handle of zero") ||
			strings.Contains(msg, "RTNETLINK answers: No such file or directory") {
			return nil
		}
		return fmt.Errorf("%w: %s", err, msg)
	}
	return nil
}

// WriteCSV writes the sweep results as a CSV to path, sorted by delay.
func WriteCSV(path string, delaysMS []int, results map[int]float64) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString("delay_ms,softfail_rate\n"); err != nil {
		return err
	}
	for _, d := range delaysMS {
		rate, ok := results[d]
		if !ok {
			continue
		}
		if _, err := fmt.Fprintf(f, "%d,%.4f\n", d, rate); err != nil {
			return err
		}
	}
	return nil
}
