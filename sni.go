package main

import (
	"crypto/tls"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
)

func testSni(ip string, config *GScanConfig, record *ScanRecord) bool {
	tlscfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	start := time.Now()
	for _, serverName := range config.Sni.ServerName {
		conn, err := net.DialTimeout("tcp", ip+":443", config.Sni.ScanMaxRTT*time.Millisecond)
		if err != nil {
			return false
		}
		defer conn.Close()

		tlscfg.ServerName = serverName
		tlsconn := tls.Client(conn, tlscfg)
		tlsconn.SetDeadline(time.Now().Add(config.Sni.HandshakeTimeout * time.Millisecond))
		defer tlsconn.Close()
		if err = tlsconn.Handshake(); err != nil {
			return false
		}
		// pcs := tlsconn.ConnectionState().PeerCertificates
		// if len(pcs) == 0 || pcs[0].Subject.CommonName != serverName {
		// 	// log.Println(ip, "3")
		// 	return false
		// }
		if config.Sni.Level > 1 {
			req, err := http.NewRequest(http.MethodGet, "https://"+serverName, nil)
			if err != nil {
				return false
			}
			resp, err := httputil.NewClientConn(tlsconn, nil).Do(req)
			if err != nil {
				return false
			}
			// io.Copy(os.Stdout, resp.Body)
			if resp.Body != nil {
				io.Copy(ioutil.Discard, resp.Body)
				resp.Body.Close()
			}
			if resp.StatusCode != 200 {
				return false
			}
		}
	}

	sslRTT := time.Since(start)
	record.SSLRTT = record.SSLRTT + sslRTT
	return true
}
