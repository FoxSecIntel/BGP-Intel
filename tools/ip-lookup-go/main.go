package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

type IPLookupResult struct {
	IP              string `json:"ip"`
	IPVersion       string `json:"ip_version,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	ASN             string `json:"asn,omitempty"`
	Organisation    string `json:"organisation,omitempty"`
	BGPPrefix       string `json:"bgp_prefix,omitempty"`
	CountryCode     string `json:"country_code,omitempty"`
	AbuseEmail      string `json:"abuse_email,omitempty"`
	RIR             string `json:"rir,omitempty"`
	LookupSource    string `json:"lookup_source,omitempty"`
	LookupLatencyMs int64  `json:"lookup_latency_ms,omitempty"`
	Error           string `json:"error,omitempty"`
}

type rdapEntity struct {
	Roles      []string      `json:"roles"`
	VCardArray []interface{} `json:"vcardArray"`
}

type rdapResponse struct {
	Name     string       `json:"name"`
	Handle   string       `json:"handle"`
	Port43   string       `json:"port43"`
	Country  string       `json:"country"`
	Entities []rdapEntity `json:"entities"`
}

func main() {
	var (
		ipArg   = flag.String("ip", "", "Single IP address to analyse")
		fileArg = flag.String("file", "", "Path to file containing IP addresses (one per line)")
		workers = flag.Int("workers", 50, "Number of concurrent workers")
		timeout = flag.Duration("timeout", 2*time.Second, "Per-lookup timeout")
		jsonOut = flag.Bool("json", false, "Output as JSON")
	)
	flag.Parse()

	if *ipArg == "" && *fileArg == "" {
		fmt.Fprintln(os.Stderr, "Please provide --ip or --file")
		flag.Usage()
		os.Exit(2)
	}
	if *workers < 1 {
		fmt.Fprintln(os.Stderr, "Workers must be at least 1")
		os.Exit(2)
	}

	ips, err := collectIPs(*ipArg, *fileArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read targets: %v\n", err)
		os.Exit(1)
	}
	if len(ips) == 0 {
		fmt.Fprintln(os.Stderr, "No valid IP targets found")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Analysing %d target(s) with %d worker(s)...\n", len(ips), *workers)

	results := runWorkerPool(ips, *workers, *timeout)
	sort.Slice(results, func(i, j int) bool { return results[i].IP < results[j].IP })

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
		return
	}

	printTable(results)
}

func collectIPs(single, filePath string) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string

	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || strings.HasPrefix(v, "#") {
			return
		}
		ip := net.ParseIP(v)
		if ip == nil {
			return
		}
		norm := ip.String()
		if _, ok := seen[norm]; ok {
			return
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}

	if single != "" {
		add(single)
	}

	if filePath != "" {
		f, err := os.Open(filePath)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		sc := bufio.NewScanner(f)
		for sc.Scan() {
			add(sc.Text())
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}

	return out, nil
}

func runWorkerPool(ips []string, workerCount int, timeout time.Duration) []IPLookupResult {
	jobs := make(chan string)
	results := make(chan IPLookupResult, len(ips))
	var wg sync.WaitGroup

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				results <- lookupIP(ip, timeout)
			}
		}()
	}

	go func() {
		for _, ip := range ips {
			jobs <- ip
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	var out []IPLookupResult
	for r := range results {
		out = append(out, r)
	}
	return out
}

func lookupIP(ip string, timeout time.Duration) IPLookupResult {
	start := time.Now()
	res := IPLookupResult{IP: ip}
	if strings.Contains(ip, ":") {
		res.IPVersion = "IPv6"
	} else {
		res.IPVersion = "IPv4"
	}

	ptrCtx, ptrCancel := context.WithTimeout(context.Background(), timeout)
	defer ptrCancel()
	if host, err := reverseDNS(ptrCtx, ip); err == nil {
		res.Hostname = host
	}

	rdapCtx, rdapCancel := context.WithTimeout(context.Background(), timeout)
	defer rdapCancel()
	asn, org, abuseEmail, rir, country, err := rdapLookup(rdapCtx, ip)
	if err == nil {
		res.ASN = asn
		res.Organisation = org
		res.AbuseEmail = abuseEmail
		res.RIR = rir
		res.CountryCode = strings.ToUpper(strings.TrimSpace(country))
		res.LookupSource = "RDAP"
	} else if res.Hostname == "" {
		res.Error = err.Error()
	}

	// ASN/RIR/BGP fallback via Team Cymru whois, useful when RDAP omits AS handle.
	if res.ASN == "" || strings.EqualFold(res.ASN, "Unknown") || res.RIR == "" || strings.EqualFold(res.RIR, "Unknown") || res.BGPPrefix == "" {
		asnCtx, asnCancel := context.WithTimeout(context.Background(), timeout)
		defer asnCancel()
		if a, o, r, pfx, e := cymruLookup(asnCtx, ip); e == nil {
			if (res.ASN == "" || strings.EqualFold(res.ASN, "Unknown")) && a != "" {
				res.ASN = a
			}
			if (res.Organisation == "" || strings.EqualFold(res.Organisation, "Unknown")) && o != "" {
				res.Organisation = o
			}
			if (res.RIR == "" || strings.EqualFold(res.RIR, "Unknown")) && r != "" {
				res.RIR = strings.ToUpper(r)
			}
			if res.BGPPrefix == "" && pfx != "" {
				res.BGPPrefix = pfx
			}
			if res.LookupSource == "RDAP" {
				res.LookupSource = "RDAP+Cymru"
			} else {
				res.LookupSource = "Cymru"
			}
		}
	}

	if res.ASN == "" {
		res.ASN = "Unknown"
	}
	if res.Organisation == "" {
		res.Organisation = "Unknown"
	}
	if res.AbuseEmail == "" {
		res.AbuseEmail = "Unknown"
	}
	if res.RIR == "" {
		res.RIR = "Unknown"
	}
	if res.BGPPrefix == "" {
		res.BGPPrefix = "Unknown"
	}
	if res.CountryCode == "" {
		res.CountryCode = "Unknown"
	}
	if res.LookupSource == "" {
		res.LookupSource = "Unknown"
	}
	res.LookupLatencyMs = time.Since(start).Milliseconds()

	return res
}

func reverseDNS(ctx context.Context, ip string) (string, error) {
	type result struct {
		names []string
		err   error
	}
	ch := make(chan result, 1)

	go func() {
		names, err := net.LookupAddr(ip)
		ch <- result{names: names, err: err}
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case r := <-ch:
		if r.err != nil || len(r.names) == 0 {
			return "", errors.New("PTR not found")
		}
		host := strings.TrimSuffix(r.names[0], ".")
		return host, nil
	}
}

func rdapLookup(ctx context.Context, ip string) (asn string, org string, abuseEmail string, rir string, country string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://rdap.org/ip/"+ip, nil)
	if err != nil {
		return "", "", "", "", "", err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(io.Discard, resp.Body)
		return "", "", "", "", "", fmt.Errorf("RDAP HTTP %d", resp.StatusCode)
	}

	var rr rdapResponse
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return "", "", "", "", "", err
	}

	asn = extractASN(rr.Handle)
	if asn == "" {
		asn = extractASN(rr.Name)
	}
	org = strings.TrimSpace(rr.Name)
	if org == "" {
		org = extractOrgFromEntities(rr.Entities)
	}
	abuseEmail = extractAbuseEmail(rr.Entities)
	rir = inferRIR(rr.Port43)
	country = strings.TrimSpace(rr.Country)

	if org == "" {
		org = "Unknown"
	}
	if asn == "" {
		asn = "Unknown"
	}
	if abuseEmail == "" {
		abuseEmail = "Unknown"
	}
	if rir == "" {
		rir = "Unknown"
	}
	if country == "" {
		country = "Unknown"
	}

	return asn, org, abuseEmail, rir, country, nil
}

func extractASN(s string) string {
	s = strings.ToUpper(s)
	idx := strings.Index(s, "AS")
	if idx == -1 {
		return ""
	}
	j := idx + 2
	for j < len(s) && s[j] >= '0' && s[j] <= '9' {
		j++
	}
	if j > idx+2 {
		return s[idx:j]
	}
	return ""
}

func extractOrgFromEntities(entities []rdapEntity) string {
	for _, e := range entities {
		if len(e.VCardArray) < 2 {
			continue
		}
		rows, ok := e.VCardArray[1].([]interface{})
		if !ok {
			continue
		}
		for _, row := range rows {
			parts, ok := row.([]interface{})
			if !ok || len(parts) < 4 {
				continue
			}
			key, _ := parts[0].(string)
			if strings.EqualFold(key, "fn") {
				if v, ok := parts[3].(string); ok && strings.TrimSpace(v) != "" {
					return strings.TrimSpace(v)
				}
			}
		}
	}
	return ""
}

func extractAbuseEmail(entities []rdapEntity) string {
	var fallback string
	for _, e := range entities {
		if len(e.VCardArray) < 2 {
			continue
		}
		rows, ok := e.VCardArray[1].([]interface{})
		if !ok {
			continue
		}
		isAbuseRole := false
		for _, r := range e.Roles {
			if strings.EqualFold(strings.TrimSpace(r), "abuse") {
				isAbuseRole = true
				break
			}
		}
		for _, row := range rows {
			parts, ok := row.([]interface{})
			if !ok || len(parts) < 4 {
				continue
			}
			key, _ := parts[0].(string)
			if strings.EqualFold(key, "email") {
				if v, ok := parts[3].(string); ok {
					em := strings.TrimSpace(v)
					if em == "" {
						continue
					}
					if isAbuseRole {
						return em
					}
					if fallback == "" {
						fallback = em
					}
				}
			}
		}
	}
	return fallback
}

func inferRIR(port43 string) string {
	p := strings.ToLower(strings.TrimSpace(port43))
	switch {
	case strings.Contains(p, "arin"):
		return "ARIN"
	case strings.Contains(p, "ripe"):
		return "RIPE"
	case strings.Contains(p, "apnic"):
		return "APNIC"
	case strings.Contains(p, "lacnic"):
		return "LACNIC"
	case strings.Contains(p, "afrinic"):
		return "AFRINIC"
	default:
		return ""
	}
}

func cymruLookup(ctx context.Context, ip string) (asn string, org string, rir string, prefix string, err error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", "whois.cymru.com:43")
	if err != nil {
		return "", "", "", "", err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	query := fmt.Sprintf(" -v %s\n", ip)
	if _, err := conn.Write([]byte(query)); err != nil {
		return "", "", "", "", err
	}

	sc := bufio.NewScanner(conn)
	lines := []string{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := sc.Err(); err != nil {
		return "", "", "", "", err
	}
	if len(lines) < 2 {
		return "", "", "", "", errors.New("cymru response empty")
	}

	// Format: AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
	parts := strings.Split(lines[1], "|")
	if len(parts) < 7 {
		return "", "", "", "", errors.New("cymru parse error")
	}
	rawASN := strings.TrimSpace(parts[0])
	rawPrefix := strings.TrimSpace(parts[2])
	rawRIR := strings.TrimSpace(parts[4])
	rawOrg := strings.TrimSpace(parts[6])
	if rawASN != "" {
		asn = "AS" + rawASN
	}
	org = rawOrg
	rir = strings.ToUpper(rawRIR)
	prefix = rawPrefix
	return asn, org, rir, prefix, nil
}

func printTable(results []IPLookupResult) {
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tVersion\tHostname\tASN\tBGP Prefix\tOrganisation\tCountry\tAbuse Email\tRIR\tSource\tLatency(ms)\tStatus")
	for _, r := range results {
		status := "OK"
		if r.Error != "" {
			status = r.Error
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
			emptyDash(r.IP),
			emptyDash(r.IPVersion),
			emptyDash(r.Hostname),
			emptyDash(r.ASN),
			emptyDash(r.BGPPrefix),
			emptyDash(r.Organisation),
			emptyDash(r.CountryCode),
			emptyDash(r.AbuseEmail),
			emptyDash(r.RIR),
			emptyDash(r.LookupSource),
			r.LookupLatencyMs,
			status,
		)
	}
	_ = w.Flush()
}

func emptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
