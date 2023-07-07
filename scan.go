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

func (srs *ScanRecords) Records() []*ScanRecord {
	srs.recordMutex.Lock()
	defer srs.recordMutex.Unlock()
	return srs.records
}

type testIPFunc func(ctx context.Context, ip string, config *ScanConfig, record *ScanRecord) bool

func testip(ctx context.Context, testFunc testIPFunc, ip string, config *ScanConfig) *ScanRecord {
	record := new(ScanRecord)
	for i := 0; i < config.ScanCountPerIP; i++ {
		if !testFunc(ctx, ip, config, record) {
			return nil
		}
	}
	record.IP = ip
	record.RTT = record.RTT / time.Duration(config.ScanCountPerIP)
	return record
}

func (gs *GScanner) testIPWorker(ctx context.Context, ipQueue chan string) {
	cfg, testFunc := gs.getScanConfig(gs.ScanMode)

	for ip := range ipQueue {
		// log.Printf("Start testing IP: %s", ip)

		if gs.VerifyPing {
			start := time.Now()

			pingErr := Ping(ip, gs.ScanMaxPingRTT)
			if pingErr != nil || time.Since(start) < gs.ScanMinPingRTT {
				continue
			}
		}

		select {
		case <-ctx.Done():
			return
		default:
			r := testip(ctx, testFunc, ip, cfg)
			if r != nil {
				gs.AddRecord(r) // 这里放到前面，扫描时可能会多出一些记录, 但是不影响
				if gs.RecordSize() >= cfg.RecordLimit {
					return
				}
			}
			gs.IncScanCounter() // 扫描完后才增加计数
		}

	}
}

func (gs *GScanner) StartScan(ipQueue chan string) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	n := gs.ScanWorker
	ops(n, n, func(i, thread int) {
		gs.testIPWorker(ctx, ipQueue)
	})
}
