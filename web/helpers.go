package web

import (
	"crypto/rand"
	"github.com/oschwald/geoip2-golang"
	log "github.com/sirupsen/logrus"
	"net"

	"github.com/librespeed/speedtest/config"
)

var (
	geoip2db *geoip2.Reader
)

func getRandomData(length int) []byte {
	data := make([]byte, length)
	if _, err := rand.Read(data); err != nil {
		log.Fatalf("Failed to generate random data: %s", err)
	}
	return data
}

func getIPInfo(addr string) *geoip2.City {
	if geoip2db == nil {
		return nil
	}
	ip := net.ParseIP(addr)
	cityInfo, err := geoip2db.City(ip)
	if err != nil {
		cityInfo = nil
	}
	return cityInfo
}

func InitGeoIP2Database(conf *config.Config) {
	// Open GeoIP2 database
	var err error
	if geoip2db, err = geoip2.Open(conf.GeoIPFile); err != nil {
		log.Errorf("Failed to open GeoIP 2 Database: %e", err)
		geoip2db = nil
	}
}
