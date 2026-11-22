package app

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"dddd-next/internal/discovery/httpprobe"
	"dddd-next/internal/types"
)

func (p *Pipeline) recordAsset(a types.Asset) {
	if p.assets == nil {
		return
	}
	if a.URL != "" {
		u, err := url.Parse(a.URL)
		if err == nil {
			if a.Host == "" {
				a.Host = u.Hostname()
			}
			if a.Port == 0 {
				a.Port, _ = strconv.Atoi(u.Port())
				if a.Port == 0 {
					if u.Scheme == "https" {
						a.Port = 443
					} else if u.Scheme == "http" {
						a.Port = 80
					}
				}
			}
		}
	}
	if a.Host == "" {
		a.Host = a.IP
	}
	if a.Host == "" {
		return
	}
	if a.IP == "" && net.ParseIP(a.Host) != nil {
		a.IP = a.Host
	}
	p.assetErr = errors.Join(p.assetErr, p.assets.WriteAsset(a))
}

func (p *Pipeline) recordWebAsset(resp httpprobe.Response, names []string) {
	service := ""
	if u, err := url.Parse(resp.URL); err == nil {
		service = u.Scheme
	}
	p.recordAsset(types.Asset{URL: resp.URL, IP: strings.Join(resp.A, ";"), Title: resp.Title, Service: service, Fingerprints: names, Source: "http", Status: fmt.Sprintf("http:%d", resp.StatusCode)})
}
