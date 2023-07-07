package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type ScanConfig struct {
	ScanCountPerIP   int
	ServerName       []string
	HTTPVerifyHosts  []string
	HandshakeTimeout time.Duration
	ScanMinRTT       time.Duration
	ScanMaxRTT       time.Duration
	RecordLimit      int
	InputFile        string
	OutputFile       string
	OutputSeparator  string
	Level            int
}

type GScanner struct {
	ScanWorker     int
	VerifyPing     bool
	ScanMinPingRTT time.Duration
	ScanMaxPingRTT time.Duration
	DisablePause   bool
	EnableBackup   bool
	BackupDir      string

	ScanRecords `json:"-"`

	ScanMode string
	PING     ScanConfig
	QUIC     ScanConfig
	TLS      ScanConfig
	SNI      ScanConfig
}

func init() {
	rand.Seed(time.Now().UnixNano())

	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func (gs *GScanner) loadConfig(cfgFile string) error {
	exe, err := os.Executable()
	if err != nil {
		return errors.New("could not get executable path")
	}
	execFolder := filepath.Dir(exe)

	if strings.HasPrefix(cfgFile, "./") {
		cfgFile = filepath.Join(execFolder, cfgFile)
	}

	config := gs
	if err := readJsonConfig(cfgFile, config); err != nil {
		return fmt.Errorf("could not read config file: %v", err)
	}

	if config.EnableBackup {
		if strings.HasPrefix(config.BackupDir, "./") {
			config.BackupDir = filepath.Join(execFolder, config.BackupDir)
		}
		err := os.MkdirAll(config.BackupDir, 0o644)
		if err != nil {
			return fmt.Errorf("could not create backup dir: %v", err)
		}
	}

	config.ScanMode = strings.ToLower(config.ScanMode)
	if config.ScanMode == "ping" {
		config.VerifyPing = false
	}

	config.ScanMinPingRTT *= time.Millisecond
	config.ScanMaxPingRTT *= time.Millisecond

	scanConfigs := []*ScanConfig{&config.QUIC, &config.TLS, &config.SNI, &config.PING}
	for _, scanConfig := range scanConfigs {
		if strings.HasPrefix(scanConfig.InputFile, "./") {
			scanConfig.InputFile = filepath.Join(execFolder, scanConfig.InputFile)
		} else {
			scanConfig.InputFile, _ = filepath.Abs(scanConfig.InputFile)
		}
		if strings.HasPrefix(scanConfig.OutputFile, "./") {
			scanConfig.OutputFile = filepath.Join(execFolder, scanConfig.OutputFile)
		} else {
			scanConfig.OutputFile, _ = filepath.Abs(scanConfig.OutputFile)
		}
		if !pathExist(scanConfig.InputFile) {
			os.Create(scanConfig.InputFile)
		}

		scanConfig.ScanMinRTT *= time.Millisecond
		scanConfig.ScanMaxRTT *= time.Millisecond
		scanConfig.HandshakeTimeout *= time.Millisecond
	}
	return nil
}

func main() {
	var cfgfile string
	flag.StringVar(&cfgfile, "Config File", "./config.json", "Config file, json format")
	flag.Parse()

	scanner := new(GScanner)

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("panic:", r)
		}
		fmt.Println()
		if scanner.DisablePause {
			return
		}
		if runtime.GOOS == "windows" {
			cmd := exec.Command("cmd", "/C", "pause")
			cmd.Stdout = os.Stdout
			cmd.Stdin = os.Stdin
			// 改为 start, 程序可以正常退出, 这样一些程序监视工具可以正常测到程序结束了
			cmd.Start()
		} else {
			fmt.Println("Press [Enter] to exit...")
			fmt.Scanln()
		}
	}()
	err := scanner.loadConfig(cfgfile)
	if err != nil {
		log.Println(err)
		return
	}

	scanMode := scanner.ScanMode
	cfg, _ := scanner.getScanConfig(scanMode)

	iprangeFile := cfg.InputFile
	if !pathExist(iprangeFile) {
		log.Panicf("IP Range file not exist: %s", iprangeFile)
	}

	log.Printf("Start loading IP Range file: %s", iprangeFile)
	ipqueue, err := parseIPRangeFile(iprangeFile)
	if err != nil {
		log.Panicln(err)
	}

	log.Printf("Start scanning available IP")
	startTime := time.Now()
	scanner.StartScan(ipqueue)

	records := scanner.Records()

	log.Printf("Scanned %d IP in %s, found %d records",
		scanner.ScanCount(), time.Since(startTime), len(records))

	if len(records) == 0 {
		return
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].RTT < records[j].RTT
	})
	a := make([]string, len(records))
	for i, r := range records {
		a[i] = r.IP
	}
	b := new(bytes.Buffer)
	if cfg.OutputSeparator == "gop" {
		out := strings.Join(a, `", "`)
		b.WriteString(`"`)
		b.WriteString(out)
		b.WriteString(`",`)
	} else {
		out := strings.Join(a, cfg.OutputSeparator)
		b.WriteString(out)
	}

	if err := os.WriteFile(cfg.OutputFile, b.Bytes(), 0o644); err != nil {
		log.Printf("Failed to write output file:%s for reason: %v", cfg.OutputFile, err)
	} else {
		log.Printf("All results written to %s", cfg.OutputFile)
	}

	if scanner.EnableBackup {
		filename := fmt.Sprintf("%s_%s_lv%d.txt", scanMode, time.Now().Format("20060102_150405"), cfg.Level)

		bakfilename := filepath.Join(scanner.BackupDir, filename)
		if err := os.WriteFile(bakfilename, b.Bytes(), 0o644); err != nil {
			log.Printf("Failed to write output file:%s for reason: %v\n", bakfilename, err)
		} else {
			log.Printf("All results written to %s\n", bakfilename)
		}
	}
}

func (gcfg *GScanner) getScanConfig(scanMode string) (*ScanConfig, testIPFunc) {
	switch scanMode {
	case "quic":
		return &gcfg.QUIC, testQuic
	case "tls":
		return &gcfg.TLS, testTls
	case "sni":
		return &gcfg.SNI, testSni
	case "ping":
		return &gcfg.PING, testPing
	// case "socks5":
	// testIPFunc = testSocks5
	default:
		log.Panicln("Unknown scan mode:", scanMode)
	}
	return nil, nil
}
