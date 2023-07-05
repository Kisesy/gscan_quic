package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"math/rand"
	"net"
	"net/http"
	"time"
)

var gpkp, _ = base64.StdEncoding.DecodeString("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9Yjf52KMHjf4N0KQf2yH0PtlgiX96MtrpP9t6Voj4pn2HOmSA5kTfAkKivpC1l5WJKp6M4Qf0elpu7l07FdMZmiTdzdVU/45EE23NLtfJXc3OxeU6jzlndW8w7RD6y6nR++wRBFj2LRBhd1BMEiTG7+39uBFAiHglkIXz9krZVY0ByYEDaj9fcou7+pIfDdNPwCfg9/vdYQueVdc/FduGpb//Iyappm+Jdl/liwG9xEqAoCA62MYPFBJh+WKyl8ZK1mWgQCg+1HbyncLC8mWT+9wScdcbSD9mbS04soud/0t3Au2axMMjBkrF5aYufCL9qAnu7bjjVGPva7Hm7GJnQIDAQAB")

func testTls(ctx context.Context, ip string, config *ScanConfig, record *ScanRecord) bool {
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, config.ScanMaxRTT)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return false
	}
	defer conn.Close()

	var serverName string
	if len(config.ServerName) == 0 {
		serverName = randomHost()
	} else {
		serverName = randomChoice(config.ServerName)
	}

	tlscfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS11,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		ServerName: serverName,
	}

	tlsconn := tls.Client(conn, tlscfg)
	defer tlsconn.Close()

	tlsconn.SetDeadline(time.Now().Add(config.HandshakeTimeout))
	if err = tlsconn.Handshake(); err != nil {
		return false
	}
	if config.Level > 1 {
		pcs := tlsconn.ConnectionState().PeerCertificates
		if pcs == nil || len(pcs) < 2 {
			return false
		}
		if org := pcs[1].Subject.Organization; len(org) == 0 || org[0] != "Google Trust Services LLC" {
			return false
		}
		pkp := pcs[1].RawSubjectPublicKeyInfo
		if !bytes.Equal(gpkp, pkp) {
			return false
		}
	}
	if config.Level > 2 {
		url := "https://" + config.HTTPVerifyHosts[rand.Intn(len(config.HTTPVerifyHosts))]
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		req.Close = true
		c := http.Client{
			Transport: &http.Transport{
				DialTLS: func(network, addr string) (net.Conn, error) { return tlsconn, nil },
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: config.ScanMaxRTT - time.Since(start),
		}
		resp, _ := c.Do(req)
		if resp == nil || (resp.StatusCode < 200 || resp.StatusCode >= 400) {
			return false
		}
		if resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}

	if rtt := time.Since(start); rtt > config.ScanMinRTT {
		record.RTT += rtt
		return true
	}
	return false
}
