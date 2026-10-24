package geolocation

import (
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"sync"

	"github.com/oschwald/maxminddb-golang"
	log "github.com/sirupsen/logrus"
)

type Geolocation interface {
	Lookup(ip net.IP) (*Record, error)
	GetAllCountries() ([]Country, error)
	GetCitiesByCountry(countryISOCode string) ([]City, error)
	Stop() error
}

type geolocationImpl struct {
	mmdbPath   string
	mux        sync.RWMutex
	db         *maxminddb.Reader
	locationDB *SqliteStore
	stopCh     chan struct{}
}

type Record struct {
	City struct {
		GeonameID uint `maxminddb:"geoname_id"`
		Names     struct {
			En string `maxminddb:"en"`
		} `maxminddb:"names"`
	} `maxminddb:"city"`
	Continent struct {
		GeonameID uint   `maxminddb:"geoname_id"`
		Code      string `maxminddb:"code"`
	} `maxminddb:"continent"`
	Country struct {
		GeonameID uint   `maxminddb:"geoname_id"`
		ISOCode   string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		ISOCode string `maxminddb:"iso_code"`
		Names   struct {
			En string `maxminddb:"en"`
		} `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
}

type City struct {
	GeoNameID int `gorm:"column:geoname_id"`
	CityName  string
}

type Country struct {
	CountryISOCode string `gorm:"column:country_iso_code"`
	CountryName    string
}

const (
	mmdbPattern       = "GeoLite2-City_*.mmdb"
	geonamesdbPattern = "geonames_*.db"
)

// NewGeolocation uses only locally provisioned data. The legacy autoUpdate
// parameter is retained for caller compatibility but never permits downloads.
func NewGeolocation(ctx context.Context, dataDir string, _ bool) (Geolocation, error) {
	mmdbGlobPattern := filepath.Join(dataDir, mmdbPattern)
	mmdbFile, err := getDatabaseFilename(ctx, mmdbGlobPattern)
	if err != nil {
		return nil, fmt.Errorf("failed to get database filename: %v", err)
	}

	geonamesDbGlobPattern := filepath.Join(dataDir, geonamesdbPattern)
	geonamesDbFile, err := getDatabaseFilename(ctx, geonamesDbGlobPattern)
	if err != nil {
		return nil, fmt.Errorf("failed to get database filename: %v", err)
	}

	if err := loadGeolocationDatabases(ctx, dataDir, mmdbFile, geonamesDbFile); err != nil {
		return nil, fmt.Errorf("failed to load MaxMind databases: %v", err)
	}

	mmdbPath := path.Join(dataDir, mmdbFile)
	db, err := openDB(mmdbPath)
	if err != nil {
		return nil, err
	}

	locationDB, err := NewSqliteStore(ctx, dataDir, geonamesDbFile)
	if err != nil {
		return nil, err
	}

	geo := &geolocationImpl{
		mmdbPath:   mmdbPath,
		mux:        sync.RWMutex{},
		db:         db,
		locationDB: locationDB,
		stopCh:     make(chan struct{}),
	}

	return geo, nil
}

func openDB(mmdbPath string) (*maxminddb.Reader, error) {
	_, err := os.Stat(mmdbPath)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%v does not exist", mmdbPath)
	} else if err != nil {
		return nil, err
	}

	db, err := maxminddb.Open(mmdbPath)
	if err != nil {
		return nil, fmt.Errorf("%v could not be opened: %w", mmdbPath, err)
	}

	return db, nil
}

func (gl *geolocationImpl) Lookup(ip net.IP) (*Record, error) {
	gl.mux.RLock()
	defer gl.mux.RUnlock()

	if gl.db == nil {
		return nil, fmt.Errorf("geolocation database is not available")
	}

	var record Record
	err := gl.db.Lookup(ip, &record)
	if err != nil {
		return nil, err
	}

	return &record, nil
}

// GetAllCountries retrieves a list of all countries.
func (gl *geolocationImpl) GetAllCountries() ([]Country, error) {
	allCountries, err := gl.locationDB.GetAllCountries()
	if err != nil {
		return nil, err
	}

	countries := make([]Country, 0)
	for _, country := range allCountries {
		if country.CountryName != "" {
			countries = append(countries, country)
		}
	}
	return countries, nil
}

// GetCitiesByCountry retrieves a list of cities in a specific country based on the country's ISO code.
func (gl *geolocationImpl) GetCitiesByCountry(countryISOCode string) ([]City, error) {
	allCities, err := gl.locationDB.GetCitiesByCountry(countryISOCode)
	if err != nil {
		return nil, err
	}

	cities := make([]City, 0)
	for _, city := range allCities {
		if city.CityName != "" {
			cities = append(cities, city)
		}
	}
	return cities, nil
}

func (gl *geolocationImpl) Stop() error {
	close(gl.stopCh)

	gl.mux.Lock()
	db := gl.db
	gl.db = nil
	gl.mux.Unlock()

	if db != nil {
		if err := db.Close(); err != nil {
			return err
		}
	}
	if gl.locationDB != nil {
		if err := gl.locationDB.close(); err != nil {
			return err
		}
	}
	return nil
}

func fileExists(filePath string) (bool, error) {
	_, err := os.Stat(filePath)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, fmt.Errorf("%v does not exist", filePath)
	}
	return false, err
}

func getExistingDatabases(pattern string) []string {
	files, _ := filepath.Glob(pattern)
	return files
}

func getDatabaseFilename(ctx context.Context, filenamePattern string) (string, error) {
	files := getExistingDatabases(filenamePattern)
	if len(files) == 0 {
		return "", fmt.Errorf("local geolocation database matching %s is required; automatic downloads are disabled", filepath.Base(filenamePattern))
	}
	filename := filepath.Base(files[len(files)-1])
	log.WithContext(ctx).Debugf("Using existing geolocation database, %s", filename)
	return filename, nil
}

func cleanupOldDatabases(ctx context.Context, pattern string, currentFile string) error {
	files := getExistingDatabases(pattern)

	for _, db := range files {
		if filepath.Base(db) == currentFile {
			continue
		}
		log.WithContext(ctx).Debugf("Removing old database: %s", db)
		err := os.Remove(db)
		if err != nil {
			return err
		}
	}
	return nil
}

func cleanupMaxMindDatabases(ctx context.Context, dataDir string, mmdbFile string, geonamesdbFile string) error {
	for _, file := range []string{mmdbFile, geonamesdbFile} {
		switch file {
		case mmdbFile:
			pattern := filepath.Join(dataDir, mmdbPattern)
			if err := cleanupOldDatabases(ctx, pattern, file); err != nil {
				return err
			}
		case geonamesdbFile:
			pattern := filepath.Join(dataDir, geonamesdbPattern)
			if err := cleanupOldDatabases(ctx, pattern, file); err != nil {
				return err
			}
		}
	}
	return nil
}

type Mock struct{}

func (g *Mock) Lookup(ip net.IP) (*Record, error) {
	return &Record{}, nil
}

func (g *Mock) GetAllCountries() ([]Country, error) {
	return []Country{}, nil
}

func (g *Mock) GetCitiesByCountry(countryISOCode string) ([]City, error) {
	return []City{}, nil
}

func (g *Mock) Stop() error {
	return nil
}
