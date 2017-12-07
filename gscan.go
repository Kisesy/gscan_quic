package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
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

type PingConfig struct {
	ScanMinPingRTT time.Duration
	ScanMaxPingRTT time.Duration
}

type ScanConfig struct {
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
	ScanCountPerIP int
	EnableBackup   bool
	BackupDir      string

	Operation string
	Ping      PingConfig
	Quic      ScanConfig
	Tls       ScanConfig
	Sni       ScanConfig
}

var execFolder = "./"

func init() {
	rand.Seed(time.Now().Unix())

	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func initFiles(cfg *GScanConfig) {
	if cfg.EnableBackup {
		if strings.HasPrefix(cfg.BackupDir, "./") {
			cfg.BackupDir = filepath.Join(execFolder, cfg.BackupDir)
		}
		if _, err := os.Stat(cfg.BackupDir); os.IsNotExist(err) {
			if err := os.MkdirAll(cfg.BackupDir, 0644); err != nil {
				log.Println(err)
			}
		}
	}
	cfgs := []*ScanConfig{&cfg.Quic, &cfg.Tls, &cfg.Sni}
	for _, c := range cfgs {
		if strings.HasPrefix(c.InputFile, "./") {
			c.InputFile = filepath.Join(execFolder, c.InputFile)
		} else {
			c.InputFile, _ = filepath.Abs(c.InputFile)
		}
		if strings.HasPrefix(c.OutputFile, "./") {
			c.OutputFile = filepath.Join(execFolder, c.OutputFile)
		} else {
			c.OutputFile, _ = filepath.Abs(c.OutputFile)
		}
		if _, err := os.Stat(c.InputFile); os.IsNotExist(err) {
			os.OpenFile(c.InputFile, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
		}
	}
}
func main() {
	defer func() {
		if r := recover(); r != nil {
			panic(fmt.Sprintf("panic: %s\n", r))
		}
		fmt.Println()
		if runtime.GOOS == "windows" {
			cmd := exec.Command("cmd", "/C", "pause")
			cmd.Stdout = os.Stdout
			cmd.Stdin = os.Stdin
			cmd.Run()
		} else {
			fmt.Println("Press [Enter] to exit...")
			fmt.Scanln()
		}
	}()

	var cfgfile string
	flag.StringVar(&cfgfile, "Config File", "./config.json", "Config file, json format")
	flag.Parse()

	if e, err := os.Executable(); err != nil {
		log.Panicln(err)
	} else {
		execFolder = filepath.Dir(e)
	}
	// execFolder = "./"

	if strings.HasPrefix(cfgfile, "./") {
		cfgfile = filepath.Join(execFolder, cfgfile)
	}

	var Config *GScanConfig
	err := readJsonConfig(cfgfile, &Config)
	if err != nil {
		log.Panicln(err)
	}

	initFiles(Config)

	var cfg *ScanConfig
	operation := strings.ToLower(Config.Operation)
	switch operation {
	case "quic":
		cfg = &Config.Quic
		testIPFunc = testQuic
	case "tls":
		cfg = &Config.Tls
		testIPFunc = testTls
	case "sni":
		cfg = &Config.Sni
		testIPFunc = testSni
	case "socks5":
		// testIPFunc = testSocks5
	default:
	}

	iprangeFile := cfg.InputFile
	if _, err := os.Stat(iprangeFile); os.IsNotExist(err) {
		log.Panicln(err)
	}

	Config.Ping.ScanMinPingRTT = Config.Ping.ScanMinPingRTT * time.Millisecond
	Config.Ping.ScanMaxPingRTT = Config.Ping.ScanMaxPingRTT * time.Millisecond

	options := &ScanOptions{Config: Config}

	log.Printf("Start loading IP Range file: %s\n", iprangeFile)
	ipqueue, err := parseIPRangeFile(iprangeFile)
	if err != nil {
		log.Panicln(err)
	}

	log.Printf("Start scanning available IP\n")
	startTime := time.Now()
	count := Scan(options, cfg, ipqueue)
	log.Printf("Scanned %d IP in %s, found %d records\n", count, time.Since(startTime).String(), len(options.records))

	if records := options.records; len(records) > 0 {
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

		if err := ioutil.WriteFile(cfg.OutputFile, b.Bytes(), 0644); err != nil {
			log.Printf("Failed to write output file:%s for reason:%v\n", cfg.OutputFile, err)
		} else {
			log.Printf("All results writed to %s\n", cfg.OutputFile)
		}
		if Config.EnableBackup {
			filename := operation + "_" + time.Now().Format("20060102_150405") + ".txt"
			bakfilename := filepath.Join(Config.BackupDir, filename)
			if err := ioutil.WriteFile(bakfilename, b.Bytes(), 0644); err != nil {
				log.Printf("Failed to write output file:%s for reason:%v\n", bakfilename, err)
			} else {
				log.Printf("All results writed to %s\n", bakfilename)
			}
		}
	}
}
