package geolocation

import (
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

// ensureMMDB only accepts an operator-provisioned local database. Inherited
// hosted GeoLite downloads are not a trusted GoreeCloud update channel.
func ensureMMDB(logger *log.Logger, dataDir string) (string, error) {
	if dataDir == "" {
		return "", fmt.Errorf("geolocation database directory is not configured")
	}
	files, err := filepath.Glob(filepath.Join(dataDir, mmdbGlob))
	if err != nil {
		return "", fmt.Errorf("scan local geolocation databases: %w", err)
	}
	if len(files) == 0 {
		return "", fmt.Errorf("local geolocation database is required in %s; automatic downloads are disabled", dataDir)
	}
	mmdbPath := files[len(files)-1]
	if _, err := os.Stat(mmdbPath); err != nil {
		return "", fmt.Errorf("read local geolocation database: %w", err)
	}
	logger.Debugf("using existing geolocation database: %s", mmdbPath)
	return mmdbPath, nil
}
