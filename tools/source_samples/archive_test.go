package main

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

func TestZIPPrefixWithoutCentralDirectory(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create("geolocation.csv")
	if err != nil {
		t.Fatal(err)
	}
	want := "network,country\n1.1.1.0/24,AU\n"
	f.Write([]byte(want))
	w.Close()
	data := buf.Bytes()
	data = data[:bytes.Index(data, []byte("PK\x01\x02"))]
	got, err := decodeSample("csv-zip", data)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.data) != want || got.archiveEntry != "geolocation.csv" || got.observedKind != "csv-fragment" {
		t.Fatalf("ZIP prefix = %+v", got)
	}
}

func TestRejectNonDataResponses(t *testing.T) {
	for _, data := range []string{"<!DOCTYPE html><html>Login</html>", "version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 123\n", "{\"error\":\"authentication required\"}"} {
		if _, err := decodeSample("csv", []byte(data)); err == nil {
			t.Fatalf("accepted non-data response %q", data)
		}
	}
}

func TestZIPRejectsTraversal(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, _ := w.Create("../escape.csv")
	f.Write([]byte("ip\n1.1.1.1\n"))
	w.Close()
	if _, err := decodeSample("csv-zip", buf.Bytes()); err == nil {
		t.Fatal("accepted traversal member")
	}
}

func TestRawSubscriptionIPIsFiltered(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "192.0.2.1", "100.64.0.1", "198.18.0.1", "2001:db8::1"} {
		if got := sanitizeSubscriptionLine(value); strings.Contains(got, value) {
			t.Fatalf("special address retained: %s", got)
		}
	}
}
