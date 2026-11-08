package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"
)

// Opt-in build-time resolution avoids fake-IP system DNS without permitting
// reserved destinations. Only explicitly selected download hosts reach this code.
func publicDownloadResolver() func(context.Context, string, string) ([]netip.Addr, error) {
	client := &http.Client{
		Transport:     &http.Transport{DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext},
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("DNS redirects forbidden") },
	}
	var mu sync.Mutex
	cache := make(map[string][]netip.Addr)
	return func(ctx context.Context, _, host string) ([]netip.Addr, error) {
		if ip, err := netip.ParseAddr(host); err == nil {
			return []netip.Addr{ip}, nil
		}
		mu.Lock()
		cached := cache[host]
		mu.Unlock()
		if cached != nil {
			return append([]netip.Addr(nil), cached...), nil
		}
		var ips []netip.Addr
		for _, kind := range []string{"A", "AAAA"} {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://1.1.1.1/dns-query?name="+url.QueryEscape(host)+"&type="+kind, nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Accept", "application/dns-json")
			resp, err := client.Do(req)
			if err != nil {
				return nil, errors.New("public download-host DNS request failed")
			}
			data, err := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
			resp.Body.Close()
			if err != nil || resp.StatusCode != http.StatusOK || len(data) > 64<<10 {
				return nil, errors.New("invalid public DNS response")
			}
			found, err := decodeDNSAnswers(data)
			if err != nil {
				return nil, err
			}
			ips = append(ips, found...)
		}
		if len(ips) == 0 {
			return nil, errors.New("download host has no public DNS addresses")
		}
		mu.Lock()
		cache[host] = append([]netip.Addr(nil), ips...)
		mu.Unlock()
		return ips, nil
	}
}

func decodeDNSAnswers(data []byte) ([]netip.Addr, error) {
	var response struct {
		Status int `json:"Status"`
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(data, &response); err != nil || response.Status != 0 {
		return nil, errors.New("download-host DNS lookup failed")
	}
	var ips []netip.Addr
	for _, answer := range response.Answer {
		if answer.Type != 1 && answer.Type != 28 {
			continue
		}
		ip, err := netip.ParseAddr(answer.Data)
		if err != nil || !isPublicAddress(ip) {
			return nil, errors.New("DNS returned a private or special destination")
		}
		ips = append(ips, ip.Unmap())
	}
	return ips, nil
}
