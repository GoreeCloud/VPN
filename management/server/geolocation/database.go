package geolocation

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const geonamesCsvFields = 14

// loadGeolocationDatabases requires both locally provisioned databases. The
// inherited hosted download path is intentionally unavailable: a missing file
// is a configuration error, not permission to contact an external provider.
func loadGeolocationDatabases(_ context.Context, dataDir string, mmdbFile string, geonamesdbFile string) error {
	for _, file := range []string{mmdbFile, geonamesdbFile} {
		if _, err := os.Stat(path.Join(dataDir, file)); err != nil {
			return fmt.Errorf("local geolocation database %s unavailable (automatic downloads disabled): %w", file, err)
		}
	}
	return nil
}

// importCsvToSqlite imports a CSV file into a SQLite database.
func importCsvToSqlite(dataDir string, csvFile string, geonamesdbFile string) error {
	geonames, err := loadGeonamesCsv(csvFile)
	if err != nil {
		return err
	}

	db, err := gorm.Open(sqlite.Open(path.Join(dataDir, geonamesdbFile)), &gorm.Config{
		Logger:          logger.Default.LogMode(logger.Silent),
		CreateBatchSize: 1000,
	})
	if err != nil {
		return err
	}
	defer func() {
		sql, err := db.DB()
		if err != nil {
			return
		}
		sql.Close()
	}()

	if err := db.AutoMigrate(&GeoNames{}); err != nil {
		return err
	}

	return db.Create(geonames).Error
}

func loadGeonamesCsv(filepath string) ([]GeoNames, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader := csv.NewReader(f)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	var geoNames []GeoNames
	for index, record := range records {
		if index == 0 {
			continue
		}
		if len(record) < geonamesCsvFields {
			return nil, fmt.Errorf("geonames csv record %d has %d fields, want at least %d", index, len(record), geonamesCsvFields)
		}

		geoNameID, err := strconv.Atoi(record[0])
		if err != nil {
			return nil, err
		}

		geoName := GeoNames{
			GeoNameID:           geoNameID,
			LocaleCode:          record[1],
			ContinentCode:       record[2],
			ContinentName:       record[3],
			CountryIsoCode:      record[4],
			CountryName:         record[5],
			Subdivision1IsoCode: record[6],
			Subdivision1Name:    record[7],
			Subdivision2IsoCode: record[8],
			Subdivision2Name:    record[9],
			CityName:            record[10],
			MetroCode:           record[11],
			TimeZone:            record[12],
			IsInEuropeanUnion:   record[13],
		}
		geoNames = append(geoNames, geoName)
	}

	return geoNames, nil
}

// copyFile performs a file copy operation from the source file to the destination.
func copyFile(src string, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}

	return nil
}
