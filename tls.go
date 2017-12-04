package main

import (
	"encoding/base64"
)

var (
	g2pkp, _ = base64.StdEncoding.DecodeString("7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=")
	g3pkp, _ = base64.StdEncoding.DecodeString("f8NnEFZxQ4ExFOhSN7EiFWtiudZQVD2oY60uauV/n78=")
	// g3ecc, _ = base64.StdEncoding.DecodeString("ekG8/PoSqjfKunOaS9iIzR3hZAJptWJKV7CgyriO+MA=")
)

func testTls(ip string, config *GScanConfig, record *ScanRecord) bool {

	return false
}
