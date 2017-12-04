package main

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

type ScanRecord struct {
	IP      string
	PingRTT time.Duration
	SSLRTT  time.Duration

	httpVerifyTimeout time.Duration
}

type ScanOptions struct {
	Config *GScanConfig

	recordMutex sync.Mutex
	records     []*ScanRecord

	scanCounter int32
}

func (options *ScanOptions) AddRecord(rec *ScanRecord) {
	options.recordMutex.Lock()
	if nil == options.records {
		options.records = make([]*ScanRecord, 0)
	}
	options.records = append(options.records, rec)
	options.recordMutex.Unlock()
	log.Printf("Found a record: IP=%s, SSLRTT=%s\n", rec.IP, rec.SSLRTT.String())
}

func (options *ScanOptions) IncScanCounter() {
	atomic.AddInt32(&(options.scanCounter), 1)
	if options.scanCounter%1000 == 0 {
		log.Printf("Scanned %d IPs, Found %d records\n", options.scanCounter, options.RecordSize())
	}
}

func (options *ScanOptions) RecordSize() int {
	options.recordMutex.Lock()
	defer options.recordMutex.Unlock()
	return len(options.records)
}

var testIPFunc func(ip string, config *GScanConfig, record *ScanRecord) bool

func testip(ip string, config *GScanConfig) *ScanRecord {
	record := new(ScanRecord)
	record.IP = ip
	for i := 0; i < config.ScanCountPerIP; i++ {
		if !testIPFunc(ip, config, record) {
			return nil
		}
	}
	record.PingRTT = record.PingRTT / time.Duration(config.ScanCountPerIP)
	record.SSLRTT = record.SSLRTT / time.Duration(config.ScanCountPerIP)
	return record
}

func testip_worker(ctx context.Context, ch chan string, options *ScanOptions, wg *sync.WaitGroup) {
	defer wg.Done()
	for ip := range ch {
		var pingRTT time.Duration
		if options.Config.VerifyPing {
			start := time.Now()
			pingRTT = (options.Config.Ping.ScanMinPingRTT + options.Config.Ping.ScanMaxPingRTT) / 2
			if options.Config.VerifyPing {
				err := Ping(ip, options.Config.Ping.ScanMaxPingRTT)
				if err != nil {
					continue
				}
				end := time.Now()
				if err == nil {
					if options.Config.Ping.ScanMinPingRTT > 0 && end.Sub(start) < options.Config.Ping.ScanMinPingRTT {
						continue
					}
					pingRTT = end.Sub(start)

				}
			}
		}

		record := testip(ip, options.Config)
		if record != nil {
			record.PingRTT = record.PingRTT + pingRTT
			select {
			case <-ctx.Done():
				return
			default:
				options.AddRecord(record)
			}
		}
		options.IncScanCounter()
	}
}
