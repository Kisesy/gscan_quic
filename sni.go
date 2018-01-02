package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
)

func testSni(ip string, config *GScanConfig, record *ScanRecord) bool {
	tlscfg := &tls.Config{
		InsecureSkipVerify: true,
	}

	for _, serverName := range config.Sni.ServerName {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), config.Sni.ScanMaxRTT)
		if err != nil {
			return false
		}

		tlscfg.ServerName = serverName
		tlsconn := tls.Client(conn, tlscfg)
		tlsconn.SetDeadline(time.Now().Add(config.Sni.HandshakeTimeout))
		if err = tlsconn.Handshake(); err != nil {
			tlsconn.Close()
			return false
		}
		if config.Sni.Level > 1 {
			pcs := tlsconn.ConnectionState().PeerCertificates
			if pcs == nil || len(pcs) == 0 || pcs[0].Subject.CommonName != serverName {
				tlsconn.Close()
				return false
			}
		}
		if config.Sni.Level > 2 {
			req, err := http.NewRequest(http.MethodHead, "https://"+serverName, nil)
			if err != nil {
				tlsconn.Close()
				return false
			}
			resp, err := httputil.NewClientConn(tlsconn, nil).Do(req)
			if err != nil {
				tlsconn.Close()
				return false
			}
			// io.Copy(os.Stdout, resp.Body)
			// if resp.Body != nil {
			// 	io.Copy(ioutil.Discard, resp.Body)
			// 	resp.Body.Close()
			// }
			if resp.StatusCode >= 400 {
				tlsconn.Close()
				return false
			}
		}

		tlsconn.Close()

		rtt := time.Since(start)
		if rtt < config.Sni.ScanMinRTT {
			return false
		}
		record.RTT += rtt
	}
	return true
}
