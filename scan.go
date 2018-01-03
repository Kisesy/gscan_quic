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
	recordMutex sync.RWMutex
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
	scanCount := atomic.AddInt32(&(srs.scanCounter), 1)
	if scanCount%1000 == 0 {
		log.Printf("Scanned %d IPs, Found %d records\n", scanCount, srs.RecordSize())
	}
}

func (srs *ScanRecords) RecordSize() int {
	srs.recordMutex.RLock()
	defer srs.recordMutex.RUnlock()
	return len(srs.records)
}

func (srs *ScanRecords) ScanCount() int32 {
	return atomic.LoadInt32(&(srs.scanCounter))
}

var testIPFunc func(ip string, config *ScanConfig, record *ScanRecord) bool

func testip_worker(ctx context.Context, ch chan string, gcfg *GScanConfig, cfg *ScanConfig, srs *ScanRecords, wg *sync.WaitGroup) {
	defer wg.Done()

_s:
	for ip := range ch {
		srs.IncScanCounter()

		if gcfg.VerifyPing {
			start := time.Now()
			if err := Ping(ip, gcfg.Ping.ScanMaxPingRTT); err != nil {
				continue
			}
			if time.Since(start) < gcfg.Ping.ScanMinPingRTT {
				continue
			}
		}

		record := new(ScanRecord)
		record.IP = ip
		for i := 0; i < gcfg.ScanCountPerIP; i++ {
			if !testIPFunc(ip, cfg, record) {
				record = nil
				continue _s
			}
		}
		record.RTT = record.RTT / time.Duration(gcfg.ScanCountPerIP)

		select {
		case <-ctx.Done():
			return
		default:
			srs.AddRecord(record)
		}
	}
}

func StartScan(srs *ScanRecords, gcfg *GScanConfig, cfg *ScanConfig, ipqueue chan string) {
	var wg sync.WaitGroup
	wg.Add(gcfg.ScanWorker)

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := make(chan string, 100)
	for i := 0; i < gcfg.ScanWorker; i++ {
		go testip_worker(ctx, ch, gcfg, cfg, srs, &wg)
	}

	for ip := range ipqueue {
		select {
		case ch <- ip:
		case <-interrupt:
			return
		}
		if srs.RecordSize() >= cfg.RecordLimit {
			break
		}
	}

	close(ch)
	wg.Wait()
}
