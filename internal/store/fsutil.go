package store

import (
	"fmt"
	"os"
)

// ensureDir creates dir and its parents with owner-only permissions. The database holds key
// material, so the directory must not be world readable even before the file exists.
func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}

	return nil
}
