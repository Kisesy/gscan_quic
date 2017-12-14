package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
)

var (
	g2pkp, _ = base64.StdEncoding.DecodeString("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnCoEd1zYUJE6BqOC4NhQSLyJP/EZcBqIRn7gj8Xxic4h7lr+YQ23MkSJoHQLU09VpM6CYpXu61lfxuEFgBLEXpQ/vFtIOPRT9yTm+5HpFcTP9FMN9Er8n1Tefb6ga2+HwNBQHygwA0DaCHNRbH//OjynNwaOvUsRBOt9JN7m+fwxcfuU1WDzLkqvQtLL6sRqGrLMU90VS4sfyBlhH82dqD5jK4Q1aWWEyBnFRiL4U5W+44BKEMYq7LqXIBHHOZkQBKDwYXqVJYxOUnXitu0IyhT8ziJqs07PRgOXlwN+wLHee69FM8+6PnG33vQlJcINNYmdnfsOEXmJHjfFr45yaQIDAQAB")
	g3pkp, _ = base64.StdEncoding.DecodeString("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAylJL6h7/ziRrqNpyGGjVVl0OSFotNQl2Ws+kyByxqf5TifutNP+IW5+75+gAAdw1c3UDrbOxuaR9KyZ5zhVACu9RuJ8yjHxwhlJLFv5qJ2vmNnpiUNjfmonMCSnrTykUiIALjzgegGoYfB29lzt4fUVJNk9BzaLgdlc8aDF5ZMlu11EeZsOiZCx5wOdlw1aEU1pDbcuaAiDS7xpp0bCdc6LgKmBlUDHP+7MvvxGIQC61SRAPCm7cl/q/LJ8FOQtYVK8GlujFjgEWvKgaTUHFk5GiHqGL8v7BiCRJo0dLxRMB3adXEmliK+v+IO9p+zql8H4p7u2WFvexH6DkkCXgMwIDAQAB")
	g3ecc, _ = base64.StdEncoding.DecodeString("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEG4ANKJrwlpAPXThRcA3Z4XbkwQvWhj5J/kicXpbBQclS4uyuQ5iSOGKcuCRt8ralqREJXuRsnLZo0sIT680+VQ==")
)

var tlscfg = &tls.Config{
	InsecureSkipVerify: true,
	MinVersion:         tls.VersionTLS10,
	MaxVersion:         tls.VersionTLS12,
	CipherSuites: []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	},
}

func testTls(ip string, config *GScanConfig, record *ScanRecord) bool {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), config.Tls.ScanMaxRTT*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	serverName := config.Tls.ServerName[rand.Intn(len(config.Tls.ServerName))]
	tlscfg.ServerName = serverName
	tlsconn := tls.Client(conn, tlscfg)
	defer tlsconn.Close()

	tlsconn.SetDeadline(time.Now().Add(config.Tls.HandshakeTimeout * time.Millisecond))
	if err = tlsconn.Handshake(); err != nil {
		return false
	}
	if config.Tls.Level > 1 {
		pcs := tlsconn.ConnectionState().PeerCertificates
		if pcs == nil || len(pcs) < 3 {
			return false
		}
		if org := pcs[0].Subject.Organization; len(org) == 0 || org[0] != "Google Inc" {
			return false
		}
		pkp := pcs[1].RawSubjectPublicKeyInfo
		if !bytes.Equal(g2pkp, pkp) && !bytes.Equal(g3pkp, pkp) { // && !bytes.Equal(g3ecc, pkp[:]) {
			return false
		}
	}
	if config.Tls.Level > 2 {
		url := "https://" + serverName
		req, _ := http.NewRequest(http.MethodHead, url, nil)
		resp, err := httputil.NewClientConn(tlsconn, nil).Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return false
		}
	}
	record.RTT = record.RTT + time.Since(start)
	return true
}
