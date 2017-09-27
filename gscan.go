package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mikioh/ipaddr"
)

type ScanGoogleIPConfig struct {
	HTTPVerifyHosts    []string
	SSLCertVerifyHosts []string
	RecordLimit        int
	OutputFile         string
	OutputSeparator    string
}

type ScanGoogleHostsConfig struct {
	InputHosts      string
	OutputHosts     string
	HTTPVerifyHosts []string
}

type GScanConfig struct {
	VerifyPing     bool
	ScanMinPingRTT time.Duration
	ScanMaxPingRTT time.Duration
	ScanMinSSLRTT  time.Duration
	ScanMaxSSLRTT  time.Duration
	ScanWorker     int
	ScanCountPerIP int

	Operation       string
	scanIP          bool
	ScanGoogleIP    ScanGoogleIPConfig
	ScanGoogleHosts ScanGoogleHostsConfig
}

func main() {
	iprange_file := flag.String("iprange", "./iprange.conf", "IP Range file")
	conf_file := flag.String("conf", "./gscan.conf", "Config file, json format")
	flag.Parse()
	conf_content, err := ioutil.ReadFile(*conf_file)
	if nil != err {
		fmt.Printf("%v\n", err)
		return
	}
	var cfg GScanConfig
	err = json.Unmarshal(conf_content, &cfg)
	if nil != err {
		fmt.Printf("%v\n", err)
		return
	}
	tlsCfg.ServerName = cfg.ScanGoogleIP.HTTPVerifyHosts[0]

	cfg.scanIP = strings.EqualFold(cfg.Operation, "ScanGoogleIP")
	cfg.ScanMaxSSLRTT = cfg.ScanMaxSSLRTT * time.Millisecond
	cfg.ScanMinSSLRTT = cfg.ScanMinSSLRTT * time.Millisecond
	cfg.ScanMaxPingRTT = cfg.ScanMaxPingRTT * time.Millisecond
	cfg.ScanMinPingRTT = cfg.ScanMinPingRTT * time.Millisecond

	var outputfile_path string
	if cfg.scanIP {
		outputfile_path, _ = filepath.Abs(cfg.ScanGoogleIP.OutputFile)
	} else {
		outputfile_path, _ = filepath.Abs(cfg.ScanGoogleHosts.OutputHosts)
	}
	outputfile, err := os.OpenFile(outputfile_path, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
	if nil != err {
		fmt.Printf("%v\n", err)
		return
	}
	defer func() {
		err = outputfile.Close()
		if nil != err {
			log.Printf("Failed to close output file:%s for reason:%v\n", outputfile_path, err)
		} else {
			log.Printf("All results writed to %s\n", outputfile_path)
		}
	}()

	options := ScanOptions{
		Config: &cfg,
	}

	if !cfg.scanIP {
		options.inputHosts, err = parseHostsFile(cfg.ScanGoogleHosts.InputHosts)
		if nil != err {
			fmt.Printf("%v\n", err)
			return
		}
	}
	log.Printf("Start loading IP Range file:%s\n", *iprange_file)
	ipranges, err := parseIPRangeFile(*iprange_file)

	if nil != err {
		fmt.Printf("%v\n", err)
		return
	}

	log.Printf("Start scanning available IP\n")

	start_time := time.Now()
	worker_count := cfg.ScanWorker

	var wg sync.WaitGroup
	wg.Add(worker_count)

	wait := make(chan os.Signal, 1)
	signal.Notify(wait, os.Interrupt, os.Kill)

	eval_count := 0
	go func() {
		ch := make(chan string, 20)
		for i := 0; i < worker_count; i++ {
			go testip_worker(ch, &options, &wg)
		}
		for iprange := range ipranges {
			c := ipaddr.NewCursor([]ipaddr.Prefix{iprange})
			for ip := c.First(); ip != nil; ip = c.Next() {
				ch <- ip.IP.String()
				eval_count++

				if cfg.scanIP {
					if options.RecordSize() >= cfg.ScanGoogleIP.RecordLimit {
						goto _end
					}
				} else {
					if len(options.inputHosts) == 0 {
						goto _end
					}
				}
			}
		}

	_end:
		close(ch)
		wg.Wait()
		close(wait)
	}()

	<-wait

	log.Printf("Scanned %d IP in %fs, found %d records\n", eval_count, time.Since(start_time).Seconds(), len(options.records))

	if records := options.records; len(records) > 0 {
		sort.Slice(records, func(i, j int) bool {
			return records[i].SSLRTT < records[j].SSLRTT
		})
		if cfg.scanIP {
			ss := make([]string, len(records))
			b := new(bytes.Buffer)
			for i, rec := range records {
				if i%7 == 0 {
					b.WriteString("\n")
				}
				// b.WriteString(fmt.Sprintf("%-18s", `"`+rec.IP+`",`))
				b.WriteString(`"` + rec.IP + `",`)
				ss[i] = rec.IP
			}
			_, err = outputfile.WriteString(strings.Join(ss, cfg.ScanGoogleIP.OutputSeparator))
			if nil != err {
				log.Printf("Failed to write output file:%s for reason:%v\n", outputfile_path, err)
			}
			b.WriteString("\n")
			// ioutil.WriteFile("google_ip2.txt", []byte(`"`+strings.Join(ss, `","`)+`",`), 0666)
			ioutil.WriteFile(fmt.Sprintf("google_ip_%s.txt", time.Now().Format("20060102_15.04.05")), b.Bytes(), 0666)
		} else {
			outputfile.WriteString(fmt.Sprintf("###############Update %s###############\n", time.Now().Format("2006-01-02 15:04:05")))
			outputfile.WriteString("###############GScan Hosts Begin#################\n")
			domains_set := make(map[string]int)
			for _, rec := range options.records {
				for _, domain := range rec.MatchHosts {
					if _, exists := domains_set[domain]; !exists {
						outputfile.WriteString(fmt.Sprintf("%s\t%s\n", rec.IP, domain))
						domains_set[domain] = 1
					}
				}
			}
			outputfile.WriteString("###############GScan Hosts End##################\n")
			outputfile.WriteString("\n")
			outputfile.WriteString("#No available IP found,inherit from input\n")
			for _, h := range options.inputHosts {
				outputfile.WriteString(fmt.Sprintf("%s\t%s\n", h.IP, h.Host))
			}
		}

	}
}
