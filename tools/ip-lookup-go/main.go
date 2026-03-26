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
	IP           string `json:"ip"`
	Hostname     string `json:"hostname,omitempty"`
	ASN          string `json:"asn,omitempty"`
	Organisation string `json:"organisation,omitempty"`
	Error        string `json:"error,omitempty"`
}

type rdapEntity struct {
	VCardArray []interface{} `json:"vcardArray"`
}

type rdapResponse struct {
	Name     string       `json:"name"`
	Handle   string       `json:"handle"`
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
	res := IPLookupResult{IP: ip}

	ptrCtx, ptrCancel := context.WithTimeout(context.Background(), timeout)
	defer ptrCancel()
	if host, err := reverseDNS(ptrCtx, ip); err == nil {
		res.Hostname = host
	}

	rdapCtx, rdapCancel := context.WithTimeout(context.Background(), timeout)
	defer rdapCancel()
	asn, org, err := rdapLookup(rdapCtx, ip)
	if err == nil {
		res.ASN = asn
		res.Organisation = org
	} else if res.Hostname == "" {
		res.Error = err.Error()
	}

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

func rdapLookup(ctx context.Context, ip string) (asn string, org string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://rdap.org/ip/"+ip, nil)
	if err != nil {
		return "", "", err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(io.Discard, resp.Body)
		return "", "", fmt.Errorf("RDAP HTTP %d", resp.StatusCode)
	}

	var rr rdapResponse
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return "", "", err
	}

	asn = extractASN(rr.Handle)
	if asn == "" {
		asn = extractASN(rr.Name)
	}
	org = strings.TrimSpace(rr.Name)
	if org == "" {
		org = extractOrgFromEntities(rr.Entities)
	}
	if org == "" {
		org = "Unknown"
	}
	if asn == "" {
		asn = "Unknown"
	}

	return asn, org, nil
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

func printTable(results []IPLookupResult) {
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tHostname\tASN\tOrganisation\tStatus")
	for _, r := range results {
		status := "OK"
		if r.Error != "" {
			status = r.Error
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			emptyDash(r.IP),
			emptyDash(r.Hostname),
			emptyDash(r.ASN),
			emptyDash(r.Organisation),
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
