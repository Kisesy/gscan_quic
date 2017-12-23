package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	quic "github.com/phuslu/quic-go"
	"github.com/phuslu/quic-go/h2quic"
)

func testQuic(ip string, config *GScanConfig, record *ScanRecord) bool {
	addr := net.JoinHostPort(ip, "443")

	start := time.Now()
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return false
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return false
	}
	udpConn.SetDeadline(time.Now().Add(config.Quic.ScanMaxRTT))
	defer udpConn.Close()

	quicCfg := &quic.Config{
		HandshakeTimeout: config.Quic.HandshakeTimeout,
		KeepAlive:        false,
	}

	serverName := config.Quic.ServerName[rand.Intn(len(config.Quic.ServerName))]
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
	}
	quicSessn, err := quic.Dial(udpConn, udpAddr, addr, tlsCfg, quicCfg)
	if err != nil {
		return false
	}
	defer quicSessn.Close(nil)

	// lv1 只会验证证书是否存在
	cs := quicSessn.ConnectionState()
	if cs == nil {
		return false
	}
	pcs := cs.PeerCertificates
	if pcs == nil && len(pcs) < 2 {
		return false
	}

	// lv2 验证证书是否正确
	if config.Quic.Level > 1 {
		pkp := pcs[1].RawSubjectPublicKeyInfo
		if !bytes.Equal(g2pkp, pkp) && !bytes.Equal(g3pkp, pkp) { // && !bytes.Equal(g3ecc, pkp[:]) {
			return false
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
		req, _ := http.NewRequest(http.MethodHead, "https://"+serverName, nil)
		req.Close = true
		resp, err := hclient.Do(req)
		if resp != nil && resp.Body != nil {
			io.Copy(ioutil.Discard, resp.Body)
			resp.Body.Close()
		}
		if err != nil || resp.StatusCode >= 400 || !strings.Contains(resp.Header.Get("Alt-Svc"), `quic=":443"`) {
			return false
		}
	}

	record.RTT = record.RTT + time.Since(start)
	return true
}
