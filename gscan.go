package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
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

type GScanConfig struct {
	ScanWorker     int
	VerifyPing     bool
	ScanMinPingRTT time.Duration
	ScanMaxPingRTT time.Duration
	DisablePause   bool
	EnableBackup   bool
	BackupDir      string

	ScanMode string
	Ping     ScanConfig
	Quic     ScanConfig
	Tls      ScanConfig
	Sni      ScanConfig
}

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func initConfig(cfgFile, execFolder string) *GScanConfig {
	if strings.HasPrefix(cfgFile, "./") {
		cfgFile = filepath.Join(execFolder, cfgFile)
	}

	config := new(GScanConfig)
	if err := readJsonConfig(cfgFile, config); err != nil {
		log.Panicln(err)
	}

	if config.EnableBackup {
		if strings.HasPrefix(config.BackupDir, "./") {
			config.BackupDir = filepath.Join(execFolder, config.BackupDir)
		}
		if _, err := os.Stat(config.BackupDir); os.IsNotExist(err) {
			if err := os.MkdirAll(config.BackupDir, 0o755); err != nil {
				log.Println(err)
			}
		}
	}

	config.ScanMode = strings.ToLower(config.ScanMode)
	if config.ScanMode == "ping" {
		config.VerifyPing = false
	}

	config.ScanMinPingRTT *= time.Millisecond
	config.ScanMaxPingRTT *= time.Millisecond

	scanConfigs := []*ScanConfig{&config.Quic, &config.Tls, &config.Sni, &config.Ping}
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
		if _, err := os.Stat(scanConfig.InputFile); os.IsNotExist(err) {
			os.Create(scanConfig.InputFile)
		}

		scanConfig.ScanMinRTT *= time.Millisecond
		scanConfig.ScanMaxRTT *= time.Millisecond
		scanConfig.HandshakeTimeout *= time.Millisecond
	}
	return config
}

func main() {
	var disablePause bool
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("panic:", r)
		}
		fmt.Println()
		if !disablePause {
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
		}
	}()

	var cfgfile string
	flag.StringVar(&cfgfile, "Config File", "./config.json", "Config file, json format")
	flag.Parse()

	execFolder := "./"
	if e, err := os.Executable(); err != nil {
		log.Panicln(err)
	} else {
		execFolder = filepath.Dir(e)
	}
	// execFolder = "./"

	gcfg := initConfig(cfgfile, execFolder)
	disablePause = gcfg.DisablePause

	var cfg *ScanConfig
	scanMode := gcfg.ScanMode
	switch scanMode {
	case "quic":
		cfg = &gcfg.Quic
		testIPFunc = testQuic
	case "tls":
		cfg = &gcfg.Tls
		testIPFunc = testTls
	case "sni":
		cfg = &gcfg.Sni
		testIPFunc = testSni
	case "ping":
		cfg = &gcfg.Ping
		testIPFunc = testPing
	case "socks5":
		// testIPFunc = testSocks5
	default:
	}

	iprangeFile := cfg.InputFile
	if _, err := os.Stat(iprangeFile); os.IsNotExist(err) {
		log.Panicln(err)
	}

	log.Printf("Start loading IP Range file: %s\n", iprangeFile)
	ipqueue, err := parseIPRangeFile(iprangeFile)
	if err != nil {
		log.Panicln(err)
	}

	log.Printf("Start scanning available IP\n")
	startTime := time.Now()
	srs := StartScan(gcfg, cfg, ipqueue)
	log.Printf("Scanned %d IP in %s, found %d records\n", srs.ScanCount(), time.Since(startTime).String(), len(srs.records))

	records := srs.records
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
		b.WriteString(`"` + out + `",`)
	} else {
		out := strings.Join(a, cfg.OutputSeparator)
		b.WriteString(out)
	}

	if err := os.WriteFile(cfg.OutputFile, b.Bytes(), 0o644); err != nil {
		log.Printf("Failed to write output file:%s for reason:%v\n", cfg.OutputFile, err)
	} else {
		log.Printf("All results written to %s\n", cfg.OutputFile)
	}
	if gcfg.EnableBackup {
		filename := fmt.Sprintf("%s_%s_lv%d.txt", scanMode, time.Now().Format("20060102_150405"), cfg.Level)
		bakfilename := filepath.Join(gcfg.BackupDir, filename)
		if err := os.WriteFile(bakfilename, b.Bytes(), 0o644); err != nil {
			log.Printf("Failed to write output file:%s for reason:%v\n", bakfilename, err)
		} else {
			log.Printf("All results written to %s\n", bakfilename)
		}
	}
}
