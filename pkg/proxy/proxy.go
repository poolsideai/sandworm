package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"sync"
	"time"
)

type RequestLog struct {
	Timestamp time.Time `json:"timestamp"`
	Method    string    `json:"method"`
	Host      string    `json:"host"`
	URL       string    `json:"url"`
	Remote    string    `json:"remote"`
	Allowed   bool      `json:"allowed"`
}

type RequestStats struct {
	AllowedCount int `json:"allowedCount"`
	BlockedCount int `json:"blockedCount"`
}

type DomainStats struct {
	Domain       string `json:"domain,omitempty"`
	CIDR         string `json:"cidr,omitempty"`
	AllowedCount int    `json:"allowedCount"`
	BlockedCount int    `json:"blockedCount"`
}

type Proxy struct {
	allowedDomains map[string]bool
	allowedCIDRs   map[string]bool
	server         *http.Server
	adminServer    *http.Server
	mu             sync.RWMutex
	port           int
	adminEnabled   bool

	requestStats    map[string]*RequestStats // domain/cidr -> stats
	totalRequests   int
	allowedRequests int
	blockedRequests int
	recentRequests  []RequestLog
	maxRecentReqs   int
}

func NewProxy(port int, adminEnabled bool, allowedDomains []string, allowedCIDRs []string) *Proxy {
	domainMap := make(map[string]bool)
	for _, domain := range allowedDomains {
		if domain != "" {
			domainMap[domain] = true
		}
	}

	cidrMap := make(map[string]bool)
	for _, cidr := range allowedCIDRs {
		if cidr != "" {
			cidrMap[cidr] = true
		}
	}

	return &Proxy{
		allowedDomains: domainMap,
		allowedCIDRs:   cidrMap,
		port:           port,
		adminEnabled:   adminEnabled,
		requestStats:   make(map[string]*RequestStats),
		recentRequests: make([]RequestLog, 0),
		maxRecentReqs:  100,
	}
}

func (p *Proxy) isAllowed(host string) (bool, string) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.allowedDomains[host] {
		return true, host
	}

	ip := net.ParseIP(host)
	if ip != nil {
		for cidr := range p.allowedCIDRs {
			_, network, err := net.ParseCIDR(cidr)
			if err == nil && network.Contains(ip) {
				return true, cidr
			}
		}
	}

	return false, ""
}

func (p *Proxy) logRequest(method, host, url, remote string, allowed bool, matchedRule string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.totalRequests++

	statsKey := host
	if matchedRule != "" {
		statsKey = matchedRule
	}

	if p.requestStats[statsKey] == nil {
		p.requestStats[statsKey] = &RequestStats{}
	}

	if allowed {
		p.allowedRequests++
		p.requestStats[statsKey].AllowedCount++
	} else {
		p.blockedRequests++
		p.requestStats[statsKey].BlockedCount++
	}

	logEntry := RequestLog{
		Timestamp: time.Now(),
		Method:    method,
		Host:      host,
		URL:       url,
		Remote:    remote,
		Allowed:   allowed,
	}

	p.recentRequests = append(p.recentRequests, logEntry)
	if len(p.recentRequests) > p.maxRecentReqs {
		p.recentRequests = p.recentRequests[1:]
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" && r.URL.Host != "" {
		host = r.URL.Host
	}

	slog.Info("Proxy request",
		"method", r.Method,
		"host", host,
		"url", r.URL.String(),
		"remote", r.RemoteAddr)

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
		port = "80"
	}

	allowed, matchedRule := p.isAllowed(host)
	p.logRequest(r.Method, host, r.URL.String(), r.RemoteAddr, allowed, matchedRule)

	if !allowed {
		slog.Warn("CONNECT request blocked", "host", host)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	slog.Debug("CONNECT tunnel establishing", "host", host, "port", port)
	destConn, err := net.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		slog.Error("Failed to connect to destination", "host", host, "port", port, "error", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		slog.Error("Hijacking not supported")
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		slog.Error("Failed to hijack connection", "error", err)
		http.Error(w, "Failed to hijack connection", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	slog.Info("CONNECT tunnel established", "host", host, "port", port)
	go io.Copy(destConn, clientConn)
	io.Copy(clientConn, destConn)
}

// NOTICE(sarna): creatively borrowed from https://go.dev/src/net/http/httputil/reverseproxy.go
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// NOTICE(sarna): creatively borrowed from https://go.dev/src/net/http/httputil/reverseproxy.go
func removeHopByHopHeaders(h http.Header) {
	// RFC 7230, section 6.1: Remove headers listed in the "Connection" header.
	for _, f := range h["Connection"] {
		for _, sf := range strings.Split(f, ",") {
			if sf = textproto.TrimString(sf); sf != "" {
				h.Del(sf)
			}
		}
	}
	// RFC 2616, section 13.5.1: Remove a set of known hop-by-hop headers.
	// This behavior is superseded by the RFC 7230 Connection header, but
	// preserve it for backwards compatibility.
	for _, f := range hopHeaders {
		h.Del(f)
	}
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	var host string
	if r.URL.Host != "" {
		host = r.URL.Host
	} else if r.Host != "" {
		host = r.Host
	} else {
		slog.Warn("HTTP request with no host")
		http.Error(w, "Bad Request: No host", http.StatusBadRequest)
		return
	}

	hostOnly, _, err := net.SplitHostPort(host)
	if err != nil {
		hostOnly = host
	}

	allowed, matchedRule := p.isAllowed(hostOnly)
	p.logRequest(r.Method, hostOnly, r.URL.String(), r.RemoteAddr, allowed, matchedRule)

	if !allowed {
		slog.Warn("HTTP request blocked", "host", hostOnly)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	targetURL := r.URL
	if targetURL.Scheme == "" {
		_, port, err := net.SplitHostPort(host)
		if err == nil && port == "443" {
			targetURL.Scheme = "https"
		} else {
			targetURL.Scheme = "http"
		}
	}
	if targetURL.Host == "" {
		targetURL.Host = host
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequest(r.Method, targetURL.String(), r.Body)
	if err != nil {
		slog.Error("Failed to create HTTP request", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	removeHopByHopHeaders(r.Header)
	for name, values := range r.Header {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Failed to forward HTTP request", "host", hostOnly, "error", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	viaValue := fmt.Sprintf("%d.0 sandworm-proxy", r.ProtoMajor)
	if existingVia := w.Header().Get("Via"); existingVia != "" {
		viaValue = existingVia + ", " + viaValue
	}
	w.Header().Set("Via", viaValue)

	w.WriteHeader(resp.StatusCode)
	written, err := io.Copy(w, resp.Body)
	if err != nil {
		slog.Debug("Error copying HTTP response body", "error", err)
	} else {
		slog.Debug("HTTP request forwarded successfully", "host", hostOnly, "bytes", written)
	}
}

func (p *Proxy) Start(ctx context.Context) error {
	p.server = &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", p.port),
		Handler: p,
	}

	listener, err := net.Listen("tcp4", p.server.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", p.server.Addr, err)
	}

	slog.Info("Starting proxy",
		"addr", p.server.Addr,
		"allowed_domains", p.getAllowedDomains(),
		"allowed_cidrs", p.getAllowedCIDRs())

	go func() {
		if err := p.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			slog.Error("Proxy server error", "error", err)
		}
	}()

	if p.adminEnabled {
		adminPort := p.port + 1
		p.adminServer = &http.Server{
			Addr:    fmt.Sprintf("0.0.0.0:%d", adminPort),
			Handler: p.setupAdminHandlers(),
		}

		adminListener, err := net.Listen("tcp4", p.adminServer.Addr)
		if err != nil {
			slog.Warn("Failed to start admin panel", "addr", p.adminServer.Addr, "error", err)
		} else {
			slog.Info("Starting admin panel", "addr", p.adminServer.Addr)
			go func() {
				if err := p.adminServer.Serve(adminListener); err != nil && err != http.ErrServerClosed {
					slog.Error("Admin server error", "error", err)
				}
			}()
		}
	}

	go func() {
		<-ctx.Done()
		slog.Info("Stopping proxy")
		p.Stop()
	}()

	return nil
}

func (p *Proxy) getAllowedDomains() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	domains := make([]string, 0, len(p.allowedDomains))
	for domain := range p.allowedDomains {
		domains = append(domains, domain)
	}
	return domains
}

func (p *Proxy) getAllowedCIDRs() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	cidrs := make([]string, 0, len(p.allowedCIDRs))
	for cidr := range p.allowedCIDRs {
		cidrs = append(cidrs, cidr)
	}
	return cidrs
}

func (p *Proxy) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var errs []error

	if p.server != nil {
		if err := p.server.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("proxy server shutdown: %w", err))
		}
	}

	if p.adminServer != nil {
		if err := p.adminServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("admin server shutdown: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}

	return nil
}

func (p *Proxy) GetPort() int {
	return p.port
}
