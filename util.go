package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path"
	"strings"
	"sync"
)

// 代码来自: goproxy
func readJsonConfig(filename string, config interface{}) error {
	fileext := path.Ext(filename)
	filename1 := strings.TrimSuffix(filename, fileext) + ".user" + fileext

	cm := make(map[string]interface{})
	for i, name := range []string{filename, filename1} {
		data, err := os.ReadFile(name)
		if err != nil {
			if i == 0 {
				return err
			} else {
				continue
			}
		}
		data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
		data, err = readJson(bytes.NewReader(data))
		if err != nil {
			return err
		}

		cm1 := make(map[string]interface{})

		d := json.NewDecoder(bytes.NewReader(data))
		d.UseNumber()

		if err = d.Decode(&cm1); err != nil {
			return err
		}

		if err = mergeMap(cm, cm1); err != nil {
			return err
		}
	}

	data, err := json.Marshal(cm)
	if err != nil {
		return err
	}

	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()

	return d.Decode(config)
}

func readJson(r io.Reader) ([]byte, error) {
	scanner := bufio.NewScanner(r)
	var b bytes.Buffer
	prev := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "}") || strings.HasPrefix(line, "]") {
			prev = strings.TrimSuffix(prev, ",")
		}

		b.WriteString(prev)
		prev = line
	}
	b.WriteString(prev)
	return b.Bytes(), scanner.Err()
}

func mergeMap(m1 map[string]interface{}, m2 map[string]interface{}) error {
	for key, value := range m2 {

		m1v, m1_has_key := m1[key]
		m2v, m2v_is_map := value.(map[string]interface{})
		m1v1, m1v_is_map := m1v.(map[string]interface{})

		switch {
		case !m1_has_key, !m2v_is_map:
			m1[key] = value
		case !m1v_is_map:
			return fmt.Errorf("m1v=%#v is not a map, but m2v=%#v is a map", m1v, m2v)
		default:
			mergeMap(m1v1, m2v)
		}
	}

	return nil
}

func randInt(l, u int) int {
	return rand.Intn(u-l) + l
}

func randomChoice[T any](a []T) T {
	return a[rand.Intn(len(a))]
}

// 生成两段或三段的随机字符串当作 host
// llm.xadl
// unupk.bfrf.pvi
func randomHost() string {
	a := make([][]byte, randInt(2, 4))
	for i := range a {
		m := randInt(3, 7)
		b := make([]byte, m)
		for j := 0; j < m; j++ {
			b[j] = byte(randInt(97, 122))
		}
		a[i] = b
	}
	return string(bytes.Join(a, []byte{46}))
}

func or[T comparable](vals ...T) T {
	var zero T
	for _, val := range vals {
		if val != zero {
			return val
		}
	}
	return zero
}

// pathExist 返回文件或文件夹是否存在
func pathExist(name string) bool {
	_, err := os.Stat(name)
	return !os.IsNotExist(err)
}

func ops(count, threads int, op func(i, thread int)) {
	var wg sync.WaitGroup
	wg.Add(threads)
	for i := 0; i < threads; i++ {
		s, e := count/threads*i, count/threads*(i+1)
		if i == threads-1 {
			e = count
		}
		go func(i, s, e int) {
			for j := s; j < e; j++ {
				op(j, i)
			}
			wg.Done()
		}(i, s, e)
	}
	wg.Wait()
}
