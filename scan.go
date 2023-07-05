package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"time"
)

type ScanRecord struct {
	IP  string
	RTT time.Duration
}

type ScanRecords struct {
	recordMutex sync.Mutex
	records     []*ScanRecord
	scanCounter int32
}

func (srs *ScanRecords) AddRecord(rec *ScanRecord) {
	srs.recordMutex.Lock()
	srs.records = append(srs.records, rec)
	srs.recordMutex.Unlock()
	log.Printf("Found a record: IP=%s, RTT=%s\n", rec.IP, rec.RTT.String())
}

func (srs *ScanRecords) IncScanCounter() {
	scanCount := atomic.AddInt32(&srs.scanCounter, 1)
	if scanCount%1000 == 0 {
		log.Printf("Scanned %d IPs, Found %d records\n", scanCount, srs.RecordSize())
	}
}

func (srs *ScanRecords) RecordSize() int {
	srs.recordMutex.Lock()
	defer srs.recordMutex.Unlock()
	return len(srs.records)
}

func (srs *ScanRecords) ScanCount() int32 {
	return atomic.LoadInt32(&srs.scanCounter)
}

var testIPFunc func(ctx context.Context, ip string, config *ScanConfig, record *ScanRecord) bool

func testip(ctx context.Context, ip string, config *ScanConfig) *ScanRecord {
	record := new(ScanRecord)
	for i := 0; i < config.ScanCountPerIP; i++ {
		if !testIPFunc(ctx, ip, config, record) {
			return nil
		}
	}
	record.IP = ip
	record.RTT = record.RTT / time.Duration(config.ScanCountPerIP)
	return record
}

func testIPWorker(ctx context.Context, ipQueue chan string, gcfg *GScanConfig, cfg *ScanConfig, srs *ScanRecords) {
	for ip := range ipQueue {
		srs.IncScanCounter()

		if gcfg.VerifyPing {
			start := time.Now()

			pingErr := Ping(ip, gcfg.ScanMaxPingRTT)
			if pingErr != nil || time.Since(start) < gcfg.ScanMinPingRTT {
				continue
			}
		}

		select {
		case <-ctx.Done():
			return
		default:
			r := testip(ctx, ip, cfg)
			if r != nil {
				srs.AddRecord(r) // 这里放到前面，扫描时可能会多出一些记录, 但是不影响
				if srs.RecordSize() >= cfg.RecordLimit {
					return
				}
			}
		}

	}
}

func StartScan(gcfg *GScanConfig, cfg *ScanConfig, ipQueue chan string) *ScanRecords {
	var wg sync.WaitGroup
	var srs ScanRecords

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	wg.Add(gcfg.ScanWorker)
	for i := 0; i < gcfg.ScanWorker; i++ {
		go func() {
			defer wg.Done()
			testIPWorker(ctx, ipQueue, gcfg, cfg, &srs)
		}()
	}
	wg.Wait()
	return &srs
}
