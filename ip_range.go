package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

func inet_ntoa(ipnr int64) net.IP {
	var bytes [4]byte
	bytes[3] = byte(ipnr & 0xFF)
	bytes[2] = byte((ipnr >> 8) & 0xFF)
	bytes[1] = byte((ipnr >> 16) & 0xFF)
	bytes[0] = byte((ipnr >> 24) & 0xFF)
	return net.IP(bytes[:])
}

func inet_aton(ipnr net.IP) int64 {
	bits := strings.Split(ipnr.String(), ".")

	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])

	var sum int64
	sum += int64(b0) << 24
	sum += int64(b1) << 16
	sum += int64(b2) << 8
	sum += int64(b3)
	return sum
}

type IPRange struct {
	StartIP int64
	EndIP   int64
}

func parseIPRange(start, end string) (*IPRange, error) {
	start = strings.TrimSpace(start)
	end = strings.TrimSpace(end)

	if !strings.Contains(end, ".") {
		ss := strings.Split(start, ".")
		st := strings.Join(ss[0:3], ".")
		end = st + "." + end
		//		fmt.Printf("###%v  ", st)
		//		return nil, fmt.Errorf("Invalid IPRange %s-%s", start, end)
	}
	//fmt.Printf("##%s %s\n",start, end)
	si := net.ParseIP(start)
	ei := net.ParseIP(end)

	iprange := new(IPRange)
	iprange.StartIP = inet_aton(si)
	iprange.EndIP = inet_aton(ei)
	if iprange.StartIP > iprange.EndIP {
		return nil, fmt.Errorf("Invalid IPRange %s-%s", start, end)
	}
	return iprange, nil
}

func parseIPRangeFile(file string) ([]*IPRange, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ipranges := make([]*IPRange, 0)
	scanner := bufio.NewScanner(f)
	lineno := 1
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		//comment start with '#'
		if strings.HasPrefix(line, "#") || len(line) == 0 {
			continue
		}
		var startIP, endIP string
		// 1.9.22.0/24-1.9.22.0/24
		if strings.Contains(line, "-") && strings.Contains(line, "/") {
			ss := strings.Split(line, "-")
			if len(ss) != 2 {
				log.Printf("[WARNING] Invalid line:[%d] %s in IP Range file:%s", lineno, line, file)
				continue
			}
			iprange1, iprange2 := ss[0], ss[1]
			if strings.Contains(iprange1, "/") {
				startIP = iprange1[:strings.Index(iprange1, "/")]
			} else {
				// 1.9.22.0-1.9.23.0/24
				startIP = iprange1
			}

			if net.ParseIP(startIP) == nil {
				log.Printf("[WARNING] Invalid line:[%d] %s in IP Range file:%s", lineno, line, file)
				continue
			}
			ip, ipnet, err := net.ParseCIDR(iprange2)
			if nil != err {
				log.Printf("[WARNING] Invalid line:[%d] %s in IP Range file:%s", lineno, line, file)
				continue
			}
			ones, _ := ipnet.Mask.Size()
			v := inet_aton(ip)
			tmp := uint32(0xFFFFFFFF)
			tmp = tmp >> uint32(ones)
			v = v | int64(tmp)
			endip := inet_ntoa(v)
			endIP = endip.String()
		} else if strings.Contains(line, "/") {
			ip, ipnet, err := net.ParseCIDR(line)
			if nil != err {
				log.Printf("[WARNING] Invalid line:[%d] %s in IP Range file:%s", lineno, line, file)
				continue
			}
			startIP = ip.String()
			ones, _ := ipnet.Mask.Size()
			v := inet_aton(ip)
			tmp := uint32(0xFFFFFFFF)
			tmp = 0xFFFFFFFF
			tmp = tmp >> uint32(ones)
			v = v | int64(tmp)
			endip := inet_ntoa(v)
			endIP = endip.String()
		} else if strings.Contains(line, "-") {
			ss := strings.Split(line, "-")
			if len(ss) != 2 {
				log.Printf("[WARNING] Invalid line:[%d] %s in IP Range file:%s", lineno, line, file)
				continue
			}
			startIP, endIP = ss[0], ss[1]
		} else {
			if net.ParseIP(line) == nil {
				log.Printf("[WARNING] Invalid line:[%d] %s in IP Range file:%s", lineno, line, file)
				continue
			}
			startIP, endIP = line, line
		}

		iprange, err := parseIPRange(startIP, endIP)
		if nil != err {
			log.Printf("[WARNING] Invalid line:[%d] %s in IP Range file:%s", lineno, line, file)
			continue
		}
		ipranges = append(ipranges, iprange)
		lineno = lineno + 1
	}

	// if len(ipranges) > 5 {
	// 	dest := make([]*IPRange, len(ipranges))
	// 	perm := rand.Perm(len(ipranges))
	// 	for i, v := range perm {
	// 		dest[v] = ipranges[i]
	// 	}
	// 	ipranges = dest
	// }

	// 去重操作
	/*
		"1.9.22.0-255"
		"1.9.0.0/16"
		"1.9.22.0-255"
		"1.9.22.0-255"
		"1.9.22.0-1.9.22.255"
		"1.9.0.0/16"
		"3.3.3.0/24"
		"3.3.0.0/16"
		"3.3.3.0-255"
		"1.1.1.0/24"
		"1.9.0.0/16"
			  +
			  |
			  |
			  v
		&main.IPRange{StartIP:17367040, EndIP:17432575},
		&main.IPRange{StartIP:50528256, EndIP:50593791},
		&main.IPRange{StartIP:16843008, EndIP:16843263},
	*/
	sort.Slice(ipranges, func(i int, j int) bool {
		return ipranges[i].EndIP-ipranges[i].StartIP > ipranges[j].EndIP-ipranges[j].StartIP
	})
	var newIpranges []*IPRange
	for _, iprange := range ipranges {
		if !contains(newIpranges, iprange) {
			newIpranges = append(newIpranges, iprange)
		}
	}
	return newIpranges, nil
}

func contains(ipranges []*IPRange, iprange *IPRange) bool {
	for _, x := range ipranges {
		if x.StartIP <= iprange.StartIP && x.EndIP >= iprange.EndIP {
			return true
		}
	}
	return false
}
