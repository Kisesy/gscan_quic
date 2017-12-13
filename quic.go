package main

import (
	"bytes"
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
	result := make(chan bool, 5)

	go func() {
		<-time.After(config.Quic.ScanMaxRTT * time.Millisecond)
		result <- false
	}()

	var quicSessn quic.Session
	defer func() {
		if quicSessn != nil {
			quicSessn.Close(nil)
		}
	}()

	quicCfg := &quic.Config{
		HandshakeTimeout: config.Quic.HandshakeTimeout * time.Millisecond,
		KeepAlive:        false,
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

	go func() {
		var err error
		quicTlsCfg.ServerName = config.Quic.ServerName[rand.Intn(len(config.Quic.ServerName))]
		quicSessn, err = quic.Dial(udpConn, udpAddr, addr, quicTlsCfg, quicCfg)
		if err != nil {
			// log.Println(err)
			result <- false
			return
		}
		// lv1 只会验证证书是否存在
		cs := quicSessn.ConnectionState()
		if cs == nil {
			result <- false
			return
		}
		pcs := cs.PeerCertificates
		if len(pcs) < 2 {
			result <- false
			return
		}

		// lv2 验证证书是否正确
		if config.Quic.Level > 1 {
			pkp := pcs[1].RawSubjectPublicKeyInfo
			if !bytes.Equal(g2pkp, pkp) && !bytes.Equal(g3pkp, pkp) { // && !bytes.Equal(g3ecc, pkp[:]) {
				result <- false
				return
			}
		}

		// lv3 使用 http 访问来验证
		if config.Quic.Level > 2 {
			tr := &h2quic.RoundTripper{DisableCompression: true}
			defer tr.Close()

			tr.DialAddr = func(hostname string, tlsConfig *tls.Config, config *quic.Config) (quic.Session, error) {
				return quicSessn, err
			}
			hclient := &http.Client{
				Transport: tr,
			}
			for _, verifyHost := range config.Quic.HTTPVerifyHosts {
				req, _ := http.NewRequest(http.MethodHead, "https://"+verifyHost, nil)
				req.Close = true
				resp, err := hclient.Do(req)
				if resp != nil && resp.Body != nil {
					io.Copy(ioutil.Discard, resp.Body)
					resp.Body.Close()
				}
				if err != nil || resp.StatusCode >= 400 {
					result <- false
					return
				}
			}
		}

		result <- true
	}()

	record.RTT = record.RTT + time.Since(start)
	return <-result
}
