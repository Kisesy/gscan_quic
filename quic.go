package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"time"

	quic "github.com/phuslu/quic-go"
	"github.com/phuslu/quic-go/h2quic"
)

var quicTlsCfg = &tls.Config{
	InsecureSkipVerify: true,
}

func testQuic(ip string, config *GScanConfig, record *ScanRecord) bool {
	addr := net.JoinHostPort(ip, "443")

	start := time.Now()
	success := make(chan bool, 5)

	go func() {
		<-time.After(config.Quic.ScanMaxRTT * time.Millisecond)
		success <- false
	}()

	var quicSessn quic.Session
	defer func() {
		if quicSessn != nil {
			quicSessn.Close(nil)
		}
	}()

	tr := &h2quic.RoundTripper{DisableCompression: true}
	defer tr.Close()

	quicCfg := &quic.Config{
		HandshakeTimeout: config.Quic.HandshakeTimeout * time.Millisecond,
		// IdleTimeout:      config.ScanMaxSSLRTT,
		KeepAlive: false,
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return false
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return false
	}

	udpConn.SetDeadline(time.Now().Add(config.Quic.ScanMaxRTT * time.Millisecond))
	defer udpConn.Close()

	go func(chan bool) {
		var err error
		quicTlsCfg.ServerName = config.Quic.ServerName[rand.Intn(len(config.Quic.ServerName))]
		quicSessn, err = quic.Dial(udpConn, udpAddr, addr, quicTlsCfg, quicCfg)
		if err != nil {
			// log.Println(err)
			success <- false
			return
		}
		// 只会验证证书存在
		cs := quicSessn.ConnectionState()
		if cs == nil {
			success <- false
			return
		}
		pcs := cs.PeerCertificates
		if len(pcs) < 2 {
			success <- false
			return
		}
		// 验证证书
		if config.Quic.Level > 1 { // 2
			pkp := sha256.Sum256(pcs[1].RawSubjectPublicKeyInfo)
			if !bytes.Equal(g2pkp, pkp[:]) && !bytes.Equal(g3pkp, pkp[:]) { // && !bytes.Equal(g3ecc, pkp[:]) {
				success <- false
				return
			}
		}

		tr.DialAddr = func(hostname string, tlsConfig *tls.Config, config *quic.Config) (quic.Session, error) {
			return quicSessn, err
		}
		hclient := &http.Client{
			Transport: tr,
		}

		if config.Quic.Level > 2 { // 3
			for _, verifyHost := range config.Quic.HTTPVerifyHosts {
				req, _ := http.NewRequest(http.MethodHead, "https://"+verifyHost, nil)
				req.Close = true
				resp, err := hclient.Do(req)
				if resp != nil && resp.Body != nil {
					io.Copy(ioutil.Discard, resp.Body)
					resp.Body.Close()
				}
				if err != nil || resp.StatusCode >= 400 {
					success <- false
					return
				}
			}
		}
		success <- true
	}(success)

	if <-success == false {
		return false
	}

	sslRTT := time.Since(start)
	record.SSLRTT = record.SSLRTT + sslRTT
	return true
}
