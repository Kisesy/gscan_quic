package main

// Copyright 2009 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// taken from http://golang.org/src/pkg/net/ipraw_test.go

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"time"
)

func testPing(ctx context.Context, ip string, config *ScanConfig, record *ScanRecord) bool {
	start := time.Now()
	if err := Pinger(ip, config.ScanMaxRTT); err != nil {
		return false
	}
	if rtt := time.Since(start); rtt > config.ScanMinRTT {
		record.RTT += rtt
		return true
	}
	return false
}

const (
	icmpv4EchoRequest = 8
	icmpv4EchoReply   = 0
	icmpv6EchoRequest = 128
	icmpv6EchoReply   = 129
)

var ErrPingConnFailed = errors.New("ping: connect failed")

type icmpMessage struct {
	Type     int             // type
	Code     int             // code
	Checksum int             // checksum
	Body     icmpMessageBody // body
}

type icmpMessageBody interface {
	Len() int
	Marshal() ([]byte, error)
}

// Marshal returns the binary enconding of the ICMP echo request or
// reply message m.
func (m *icmpMessage) Marshal() ([]byte, error) {
	b := []byte{byte(m.Type), byte(m.Code), 0, 0}
	if m.Body != nil && m.Body.Len() != 0 {
		mb, err := m.Body.Marshal()
		if err != nil {
			return nil, err
		}
		b = append(b, mb...)
	}
	switch m.Type {
	case icmpv6EchoRequest, icmpv6EchoReply:
		return b, nil
	}
	csumcv := len(b) - 1 // checksum coverage
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	if csumcv&1 == 0 {
		s += uint32(b[csumcv])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	// Place checksum back in header; using ^= avoids the
	// assumption the checksum bytes are zero.
	b[2] ^= byte(^s & 0xff)
	b[3] ^= byte(^s >> 8)
	return b, nil
}

// parseICMPMessage parses b as an ICMP message.
func parseICMPMessage(b []byte) (*icmpMessage, error) {
	msglen := len(b)
	if msglen < 4 {
		return nil, errors.New("message too short")
	}
	m := &icmpMessage{Type: int(b[0]), Code: int(b[1]), Checksum: int(b[2])<<8 | int(b[3])}
	if msglen > 4 {
		var err error
		switch m.Type {
		case icmpv4EchoRequest, icmpv4EchoReply, icmpv6EchoRequest, icmpv6EchoReply:
			m.Body, err = parseICMPEcho(b[4:])
			if err != nil {
				return nil, err
			}
		}
	}
	return m, nil
}

// imcpEcho represenets an ICMP echo request or reply message body.
type icmpEcho struct {
	ID   int    // identifier
	Seq  int    // sequence number
	Data []byte // data
}

func (p *icmpEcho) Len() int {
	if p == nil {
		return 0
	}
	return 4 + len(p.Data)
}

// Marshal returns the binary enconding of the ICMP echo request or
// reply message body p.
func (p *icmpEcho) Marshal() ([]byte, error) {
	b := make([]byte, 4+len(p.Data))
	b[0], b[1] = byte(p.ID>>8), byte(p.ID&0xff)
	b[2], b[3] = byte(p.Seq>>8), byte(p.Seq&0xff)
	copy(b[4:], p.Data)
	return b, nil
}

// parseICMPEcho parses b as an ICMP echo request or reply message body.
func parseICMPEcho(b []byte) (*icmpEcho, error) {
	bodylen := len(b)
	p := &icmpEcho{ID: int(b[0])<<8 | int(b[1]), Seq: int(b[2])<<8 | int(b[3])}
	if bodylen > 4 {
		p.Data = make([]byte, bodylen-4)
		copy(p.Data, b[4:])
	}
	return p, nil
}

func Ping(address string, timeout time.Duration) error {
	return Pinger(address, timeout)
}

func Pinger(address string, timeout time.Duration) error {
	typ := icmpv4EchoRequest
	network := "ip4:icmp"

	isIpv6 := false
	if ip := net.ParseIP(address); ip != nil && ip.To4() == nil {
		typ = icmpv6EchoRequest
		network = "ip6:ipv6-icmp"
		isIpv6 = true
	}

	c, err := net.Dial(network, address)
	if err != nil {
		return ErrPingConnFailed
	}
	defer c.Close()
	deadline := time.Now().Add(timeout)
	c.SetReadDeadline(deadline)

	xid, xseq := os.Getpid()&0xffff, 1
	wb, err := (&icmpMessage{
		Type: typ, Code: 0,
		Body: &icmpEcho{
			ID: xid, Seq: xseq,
			Data: bytes.Repeat([]byte("Go Go Gadget Ping!!!"), 3),
		},
	}).Marshal()
	if err != nil {
		return err
	}
	if _, err = c.Write(wb); err != nil {
		return err
	}
	var m *icmpMessage
	rb := make([]byte, 20+len(wb))
	for {
		// read_timeout := deadline.Sub(time.Now())
		// c.SetReadDeadline(time.Now().Add(read_timeout))
		if _, err = c.Read(rb); err != nil {
			return err
		}
		if !isIpv6 {
			rb = ipv4Payload(rb)
		}
		if m, err = parseICMPMessage(rb); err != nil {
			return err
		}
		switch m.Type {
		case icmpv4EchoRequest, icmpv6EchoRequest:
			continue
		}
		break
	}
	return nil
}

func ipv4Payload(b []byte) []byte {
	if len(b) < 20 {
		return b
	}
	hdrlen := int(b[0]&0x0f) << 2
	return b[hdrlen:]
}
