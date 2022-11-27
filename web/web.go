package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/render"
	"github.com/pires/go-proxyproto"
	log "github.com/sirupsen/logrus"

	"github.com/librespeed/speedtest/config"
	"github.com/librespeed/speedtest/results"
)

const (
	// chunk size is 1 mib
	chunkSize = 1048576
)

//go:embed assets
var defaultAssets embed.FS

var (
	// generate random data for download test on start to minimize runtime overhead
	randomData = getRandomData(chunkSize)
)

func ListenAndServe(conf *config.Config) error {
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.GetHead)

	cs := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS", "HEAD"},
		AllowedHeaders: []string{"*"},
	})

	r.Use(cs.Handler)
	r.Use(middleware.NoCache)
	r.Use(middleware.Recoverer)

	var assetFS http.FileSystem
	if fi, err := os.Stat(conf.AssetsPath); os.IsNotExist(err) || !fi.IsDir() {
		log.Warnf("Configured asset path %s does not exist or is not a directory, using default assets", conf.AssetsPath)
		sub, err := fs.Sub(defaultAssets, "assets")
		if err != nil {
			log.Fatalf("Failed when processing default assets: %s", err)
		}
		assetFS = http.FS(sub)
	} else {
		assetFS = justFilesFilesystem{fs: http.Dir(conf.AssetsPath), readDirBatchSize: 2}
	}

	r.Get(conf.BaseURL+"/*", pages(assetFS, conf.BaseURL))
	r.HandleFunc(conf.BaseURL+"/empty", empty)
	r.HandleFunc(conf.BaseURL+"/backend/empty", empty)
	r.Get(conf.BaseURL+"/garbage", garbage)
	r.Get(conf.BaseURL+"/backend/garbage", garbage)
	r.Get(conf.BaseURL+"/getIP", getIP)
	r.Get(conf.BaseURL+"/backend/getIP", getIP)
	r.Get(conf.BaseURL+"/results", results.DrawPNG)
	r.Get(conf.BaseURL+"/results/", results.DrawPNG)
	r.Get(conf.BaseURL+"/backend/results", results.DrawPNG)
	r.Get(conf.BaseURL+"/backend/results/", results.DrawPNG)
	r.Post(conf.BaseURL+"/results/telemetry", results.Record)
	r.Post(conf.BaseURL+"/backend/results/telemetry", results.Record)
	r.HandleFunc(conf.BaseURL+"/stats", results.Stats)
	r.HandleFunc(conf.BaseURL+"/backend/stats", results.Stats)

	// PHP frontend default values compatibility
	r.HandleFunc(conf.BaseURL+"/empty.php", empty)
	r.HandleFunc(conf.BaseURL+"/backend/empty.php", empty)
	r.Get(conf.BaseURL+"/garbage.php", garbage)
	r.Get(conf.BaseURL+"/backend/garbage.php", garbage)
	r.Get(conf.BaseURL+"/getIP.php", getIP)
	r.Get(conf.BaseURL+"/backend/getIP.php", getIP)
	r.Post(conf.BaseURL+"/results/telemetry.php", results.Record)
	r.Post(conf.BaseURL+"/backend/results/telemetry.php", results.Record)
	r.HandleFunc(conf.BaseURL+"/stats.php", results.Stats)
	r.HandleFunc(conf.BaseURL+"/backend/stats.php", results.Stats)

	go listenProxyProtocol(conf, r)

	return startListener(conf, r)
}

func listenProxyProtocol(conf *config.Config, r *chi.Mux) {
	if conf.ProxyProtocolPort != "0" {
		addr := net.JoinHostPort(conf.BindAddress, conf.ProxyProtocolPort)
		l, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("Cannot listen on proxy protocol port %s: %s", conf.ProxyProtocolPort, err)
		}

		pl := &proxyproto.Listener{Listener: l}
		defer pl.Close()

		log.Infof("Starting proxy protocol listener on %s", addr)
		log.Fatal(http.Serve(pl, r))
	}
}

func pages(fs http.FileSystem, BaseURL string) http.HandlerFunc {
	var removeBaseURL *regexp.Regexp
	if BaseURL != "" {
		removeBaseURL = regexp.MustCompile("^" + BaseURL + "/")
	}
	fn := func(w http.ResponseWriter, r *http.Request) {
		if BaseURL != "" {
			r.URL.Path = removeBaseURL.ReplaceAllString(r.URL.Path, "/")
		}
		if r.RequestURI == "/" {
			r.RequestURI = "/index.html"
		}

		http.FileServer(fs).ServeHTTP(w, r)
	}

	return fn
}

func empty(w http.ResponseWriter, r *http.Request) {
	_, err := io.Copy(ioutil.Discard, r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()

	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
}

func garbage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Description", "File Transfer")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=random.dat")
	w.Header().Set("Content-Transfer-Encoding", "binary")

	// chunk size set to 4 by default
	chunks := 4

	ckSize := r.FormValue("ckSize")
	if ckSize != "" {
		i, err := strconv.ParseInt(ckSize, 10, 64)
		if err != nil {
			log.Errorf("Invalid chunk size: %s", ckSize)
			log.Warnf("Will use default value %d", chunks)
		} else {
			// limit max chunk size to 1024
			if i > 1024 {
				chunks = 1024
			} else {
				chunks = int(i)
			}
		}
	}

	for i := 0; i < chunks; i++ {
		if _, err := w.Write(randomData); err != nil {
			log.Errorf("Error writing back to client at chunk number %d: %s", i, err)
			break
		}
	}
}

func getIP(w http.ResponseWriter, r *http.Request) {
	var ret results.Result

	clientIP := r.Header.Get("CF-Connecting-IP")
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	clientIP = strings.ReplaceAll(clientIP, "::ffff:", "")

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		clientIP = ip
	}

	isSpecialIP := true
	switch {
	case clientIP == "::1":
		ret.ProcessedString = clientIP + " - 本机 IPv6 访问"
	case strings.HasPrefix(clientIP, "fe80:"):
		ret.ProcessedString = clientIP + " - 链路本地 IPv6 访问"
	case strings.HasPrefix(clientIP, "127."):
		ret.ProcessedString = clientIP + " - 本机 IPv4 访问"
	case strings.HasPrefix(clientIP, "10."):
		ret.ProcessedString = clientIP + " - 内网 IPv4 访问"
	case regexp.MustCompile(`^172\.(1[6-9]|2\d|3[01])\.`).MatchString(clientIP):
		ret.ProcessedString = clientIP + " - 内网 IPv4 访问"
	case strings.HasPrefix(clientIP, "192.168"):
		ret.ProcessedString = clientIP + " - 内网 IPv4 访问"
	case strings.HasPrefix(clientIP, "169.254"):
		ret.ProcessedString = clientIP + " - 链路本地 IPv4 访问"
	case regexp.MustCompile(`^100\.([6-9][0-9]|1[0-2][0-7])\.`).MatchString(clientIP):
		ret.ProcessedString = clientIP + " - CGNAT IPv4 访问"
	default:
		isSpecialIP = false
	}

	if isSpecialIP {
		b, _ := json.Marshal(&ret)
		if _, err := w.Write(b); err != nil {
			log.Errorf("Error writing to client: %s", err)
		}
		return
	}

	getISPInfo := r.FormValue("isp") == "true"

	if getISPInfo {
		cityInfo := getIPInfo(clientIP)
		if cityInfo != nil {
			ret.RawISPInfo = results.IPInfoResponse{
				IP:       clientIP,
				City:     cityInfo.City.Names["zh-CN"],
				Country:  cityInfo.Country.Names["zh-CN"],
				Postal:   cityInfo.Postal.Code,
				Timezone: cityInfo.Location.TimeZone,
				Readme:   "Data from MaxMind GeoIP2",
			}
		}

		ret.ProcessedString = fmt.Sprintf("%s - %s, %s", clientIP, ret.RawISPInfo.City, ret.RawISPInfo.Country)
	}

	render.JSON(w, r, ret)
}
