package proxy

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"net"
	"net/http"
	"sort"
	"strings"
)

//go:embed admin_panel.html
var adminPanelHTML string

type AdminPanelData struct {
	Domains string
	CIDRs   string
}

type AdminStatsResponse struct {
	TotalRequests   int           `json:"totalRequests"`
	AllowedRequests int           `json:"allowedRequests"`
	BlockedRequests int           `json:"blockedRequests"`
	DomainStats     []DomainStats `json:"domainStats"`
	RecentRequests  []RequestLog  `json:"recentRequests"`
}

func (p *Proxy) setupAdminHandlers() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", p.handleAdminPanel)
	mux.HandleFunc("/admin/api/stats", p.handleAdminStats)
	mux.HandleFunc("/admin/api/rules", p.handleAdminRules)

	return mux
}

func (p *Proxy) handleAdminPanel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	p.mu.RLock()
	domains := make([]string, 0, len(p.allowedDomains))
	for domain := range p.allowedDomains {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	cidrs := make([]string, 0, len(p.allowedCIDRs))
	for cidr := range p.allowedCIDRs {
		cidrs = append(cidrs, cidr)
	}
	sort.Strings(cidrs)
	p.mu.RUnlock()

	data := AdminPanelData{
		Domains: strings.Join(domains, "\n"),
		CIDRs:   strings.Join(cidrs, "\n"),
	}

	tmpl, err := template.New("admin").Parse(adminPanelHTML)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	tmpl.Execute(w, data)
}

func (p *Proxy) handleAdminStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	domainStats := make([]DomainStats, 0, len(p.requestStats))
	for domain, stats := range p.requestStats {
		if _, _, err := net.ParseCIDR(domain); err == nil {
			domainStats = append(domainStats, DomainStats{
				CIDR:         domain,
				AllowedCount: stats.AllowedCount,
				BlockedCount: stats.BlockedCount,
			})
		} else {
			domainStats = append(domainStats, DomainStats{
				Domain:       domain,
				AllowedCount: stats.AllowedCount,
				BlockedCount: stats.BlockedCount,
			})
		}
	}
	sort.Slice(domainStats, func(i, j int) bool {
		domainI := domainStats[i].Domain + domainStats[i].CIDR
		domainJ := domainStats[j].Domain + domainStats[j].CIDR
		return domainI < domainJ
	})

	response := AdminStatsResponse{
		TotalRequests:   p.totalRequests,
		AllowedRequests: p.allowedRequests,
		BlockedRequests: p.blockedRequests,
		DomainStats:     domainStats,
		RecentRequests:  p.recentRequests,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (p *Proxy) handleAdminRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Domains []string `json:"domains"`
		CIDRs   []string `json:"cidrs"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid JSON"})
		return
	}

	// Validate domains and CIDRs
	for _, domain := range request.Domains {
		if len(domain) == 0 || domain == "." {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid domain: " + domain})
			return
		}
	}

	for _, cidr := range request.CIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid CIDR: " + cidr})
			return
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Update allowed domains and CIDRs directly
	p.allowedDomains = make(map[string]bool)
	for _, domain := range request.Domains {
		if len(domain) > 0 && domain != "." {
			p.allowedDomains[domain] = true
		}
	}

	p.allowedCIDRs = make(map[string]bool)
	for _, cidr := range request.CIDRs {
		if _, _, err := net.ParseCIDR(cidr); err == nil {
			p.allowedCIDRs[cidr] = true
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}