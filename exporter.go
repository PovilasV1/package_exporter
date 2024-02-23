package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	namespace = "package_exporter"
)

type aptOriginArchKey struct {
	origin string
	arch   string
}

func (k aptOriginArchKey) getOriginArch() (string, string) {
	return k.origin, k.arch
}

var (
	listenAddress = flag.String("web.listen-address", ":9888", "Address to listen on for web interface.")
	metricPath    = flag.String("web.metrics-path", "/metrics", "Path under which to expose metrics.")
)

type yumCollector struct {
	packagesPending  *prometheus.Desc
	packagesObsolete *prometheus.Desc
	rebootRequired   *prometheus.Desc
}

type aptCollector struct {
	packagesPending    *prometheus.Desc
	packagesAutoremove *prometheus.Desc
	rebootRequired     *prometheus.Desc
}

func newYumCollector() *yumCollector {
	return &yumCollector{
		packagesPending: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "yum_packages_pending"),
			"Number of packages pending for update by YUM",
			[]string{"origin"}, nil,
		),
		packagesObsolete: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "yum_packages_obsolete"),
			"Number of obsolete packages",
			[]string{"origin"}, nil,
		),
		rebootRequired: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "yum_reboot_required"),
			"Reboot required",
			nil, nil,
		),
	}
}

func newAptCollector() *aptCollector {
	return &aptCollector{
		packagesPending: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "apt_packages_pending"),
			"Number of packages pending for update by APT",
			[]string{"origin", "arch"}, nil,
		),
		packagesAutoremove: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "apt_autoremove_pending"),
			"Number of pending autoremove packages by APT",
			nil, nil,
		),
		rebootRequired: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "apt_reboot_required"),
			"Reboot required",
			nil, nil,
		),
	}
}

func (collector *yumCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- collector.packagesPending
	ch <- collector.packagesObsolete
	ch <- collector.rebootRequired
}

func (collector *aptCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- collector.packagesPending
	ch <- collector.packagesAutoremove
	ch <- collector.rebootRequired
}

func (collector *yumCollector) Collect(ch chan<- prometheus.Metric) {
	packagesPerOrigin, err := getYumPendingPackages()
	if err != nil {
		log.Println("Error collecting YUM metrics:", err)
		return
	}
	obsoletesPerOrigin, err := getYumObsoletePackages()
	if err != nil {
		log.Println("Error collecting YUM metrics:", err)
		return
	}
	rebootRequired, err := getYumRebootRequired()
	if err != nil {
		log.Println("Error collecting YUM metrics:", err)
		return
	}
	for origin, packages := range packagesPerOrigin {
		var pending_packages int
		pending_packages = len(packages)
		ch <- prometheus.MustNewConstMetric(collector.packagesPending, prometheus.GaugeValue, float64(pending_packages), origin)
	}
	for origin, packages := range obsoletesPerOrigin {
		var obsolete_packages int
		obsolete_packages = len(packages)
		ch <- prometheus.MustNewConstMetric(collector.packagesObsolete, prometheus.GaugeValue, float64(obsolete_packages), origin)
	}
	ch <- prometheus.MustNewConstMetric(collector.rebootRequired, prometheus.GaugeValue, float64(rebootRequired))
}

func (collector *aptCollector) Collect(ch chan<- prometheus.Metric) {
	packagesPerOrigin, err := getAptPendingPackages()
	if err != nil {
		log.Println("Error collecting APT metrics:", err)
		return
	}
	packagesAutoremove, err := getAptAutoremovePackages()
	if err != nil {
		log.Println("Error collecting APT metrics:", err)
		return
	}
	rebootRequired, err := getAptRebootRequired()
	if err != nil {
		log.Println("Error collecting APT metrics:", err)
		return
	}
	for originarch, packages := range packagesPerOrigin {
		var pending_packages int
		pending_packages = len(packages)
		origin, arch := originarch.getOriginArch()
		ch <- prometheus.MustNewConstMetric(collector.packagesPending, prometheus.GaugeValue, float64(pending_packages), origin, arch)
	}
	ch <- prometheus.MustNewConstMetric(collector.packagesAutoremove, prometheus.GaugeValue, float64(packagesAutoremove))
	ch <- prometheus.MustNewConstMetric(collector.rebootRequired, prometheus.GaugeValue, float64(rebootRequired))
}

func getYumPendingPackages() (map[string][]string, error) {
	cmd := exec.Command("/usr/bin/yum", "check-update", "--quiet")
	output, err := cmd.Output()
	if err != nil {
		if err.Error() != "exit status 100" {
			return nil, err
		}
	}

	if len(output) > 0 {
		lines := strings.Split(string(output), "\n")
		packagesPerOrigin := make(map[string][]string)

		for _, line := range lines {
			if strings.Contains(line, ".") {
				parts := strings.Fields(line)
				packageName := parts[0]
				origin := parts[2]
				packagesPerOrigin[origin] = append(packagesPerOrigin[origin], packageName)
			}
		}
		return packagesPerOrigin, nil
	} else {
		return nil, nil
	}
}

func getAptPendingPackages() (map[aptOriginArchKey][]string, error) {
	cmd := exec.Command("/usr/bin/apt-get", "--just-print", "dist-upgrade")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	if len(output) > 0 {
		lines := strings.Split(string(output), "\n")
		packagesPerOrigin := make(map[aptOriginArchKey][]string)
		instRegex := regexp.MustCompile(`^Inst`)
		re := regexp.MustCompile(`\(([^)]+)\)`)
		packageRegex := regexp.MustCompile(`\s([\S\s]+?)\s`)

		for _, line := range lines {
			if instRegex.MatchString(line) {
				packageName := packageRegex.FindStringSubmatch(line)[1]
				match := re.FindStringSubmatch(line)
				origins := strings.Split(match[1], " ")[1:]
				originString := strings.Join(origins[:len(origins)-1], " ")
				origin := strings.ReplaceAll(originString, ", ", ",")
				arch := strings.Trim(origins[len(origins)-1], "[]")
				key := aptOriginArchKey{origin, arch}
				packagesPerOrigin[key] = append(packagesPerOrigin[key], packageName)
			}
		}
		return packagesPerOrigin, nil
	} else {
		return nil, nil
	}
}

func getYumObsoletePackages() (map[string][]string, error) {
	cmd := exec.Command("/usr/bin/yum", "list", "obsoletes", "--quiet")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	if len(output) > 0 {
		lines := strings.Split(string(output), "\n")
		packagesPerOrigin := make(map[string][]string)

		for _, line := range lines {
			if strings.Contains(line, ".") {
				if !strings.HasPrefix(line, "    ") {
					parts := strings.Fields(line)
					packageName := parts[0]
					origin := parts[2]
					packagesPerOrigin[origin] = append(packagesPerOrigin[origin], packageName)
				}
			}
		}
		return packagesPerOrigin, nil
	} else {
		return nil, nil
	}
}

func getAptAutoremovePackages() (int, error) {
	cmd := exec.Command("/usr/bin/apt-get", "--just-print", "autoremove")
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	if len(output) < 0 {
		count := 0
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Remv") {
				count++
			}
		}
		return count, nil
	} else {
		return 0, nil
	}
}

func getYumRebootRequired() (int, error) {
	cmd := exec.Command("/bin/needs-restarting", "-r")
	cmd.Run()
	var exitCode int
	exitCode = cmd.ProcessState.ExitCode()
	if exitCode == 0 {
		return 0, nil
	} else {
		return 1, nil
	}
}

func getAptRebootRequired() (int, error) {
	if _, err := os.Stat("/run/reboot-required"); err == nil {
		return 1, nil
	} else {
		return 0, nil
	}
}

func getPackageManager() (string, error) {
	// Try apt-get first
	cmd := exec.Command("apt-get", "--version")
	output, err := cmd.CombinedOutput()
	if err == nil {
		return "apt", nil
	}

	// Try yum next
	cmd = exec.Command("yum", "--version")
	output, err = cmd.CombinedOutput()
	if err == nil {
		return "yum", nil
	}

	// If neither apt-get nor yum were found, return an error
	return "", fmt.Errorf("neither apt nor yum package manager found: %s", string(output))
}

func main() {
	packageManager, err := getPackageManager()
	if err != nil {
		log.Println("Error:", err)
		return
	}
	if packageManager == "yum" {
		collector := newYumCollector()
		prometheus.MustRegister(collector)
	} else {
		collector := newAptCollector()
		prometheus.MustRegister(collector)
	}
	log.Fatal(serverMetrics(*listenAddress, *metricPath))
}

func serverMetrics(listenAddress, metricsPath string) error {
	http.Handle(metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`
            <html>
            <head><title>Package Metrics</title></head>
            <body>
						<h1>Package Exporter</h1>
            <p><a href='` + metricsPath + `'>Metrics</a></p>
            </body>
            </html>
        `))
	})
	return http.ListenAndServe(listenAddress, nil)
}
