package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/resolver/auth"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
)

const defaultTimeout = 10 * time.Second

const (
	exitOK         = 0
	exitQueryError = 1
	exitUsage      = 2
)

// env carries what run needs from the outside, so tests can swap the
// transport and the clock.
type env struct {
	stdout, stderr io.Writer
	now            func() time.Time
	newResolver    func(cfg config) verifier.Resolver
}

type config struct {
	server  string // normalised ip:port
	anchors *dnssec.RootAnchors
	cd      bool
	timeout time.Duration
	queries []query
}

type query struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	qtype uint16
}

// line is one output record.
type line struct {
	Query  query            `json:"query"`
	Server string           `json:"server"`
	Error  string           `json:"error,omitempty"`
	Result *verifier.Result `json:"result"`
}

// authResolver queries cfg.server directly: UDP, then TCP on truncation.
func authResolver(cfg config) verifier.Resolver {
	c := auth.NewClient(
		auth.WithServers(cfg.server),
		auth.WithTimeout(cfg.timeout),
		auth.WithCheckingDisabled(cfg.cd),
	)
	return verifier.ResolverFunc(c.Resolve)
}

func run(args []string, e env) int {
	cfg, err := parseArgs(args, e.stderr)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		return exitUsage
	}
	v, err := verifier.NewVerifier(
		verifier.WithResolver(e.newResolver(cfg)),
		verifier.WithTrustAnchors(cfg.anchors),
		verifier.WithClock(e.now),
	)
	if err != nil {
		fmt.Fprintln(e.stderr, "dnsview:", err)
		return exitUsage
	}
	enc := json.NewEncoder(e.stdout)
	enc.SetEscapeHTML(false)
	status := exitOK
	for _, q := range cfg.queries {
		l := validate(v, cfg, q)
		if l.Error != "" {
			status = exitQueryError
		}
		if err := enc.Encode(l); err != nil {
			fmt.Fprintln(e.stderr, "dnsview:", err)
			return exitQueryError
		}
	}
	return status
}

func validate(v *verifier.Verifier, cfg config, q query) line {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()
	res, err := v.Validate(ctx, q.Name, q.qtype)
	l := line{Query: q, Server: cfg.server, Result: res}
	if err != nil {
		l.Error = err.Error()
	}
	return l
}

// parseArgs reports its own errors (with usage) on stderr.
func parseArgs(args []string, stderr io.Writer) (config, error) {
	fs := flag.NewFlagSet("dnsview", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: dnsview -server ADDR [-type A,AAAA] [-anchors FILE] [-cd] [-timeout 10s] NAME...")
		fs.PrintDefaults()
	}
	server := fs.String("server", "", "server to query, ip or ip:port (required)")
	anchorsPath := fs.String("anchors", "", "root trust anchors JSON (default: built-in IANA root anchors)")
	typeList := fs.String("type", "A", "comma-separated RR types; mnemonics or TYPE<n>, any case")
	cd := fs.Bool("cd", false, "set the CD (checking disabled) bit on queries")
	timeout := fs.Duration("timeout", defaultTimeout, "time limit for each query's validation")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	fail := func(err error) (config, error) {
		fmt.Fprintln(stderr, "dnsview:", err)
		fs.Usage()
		return config{}, err
	}
	if *server == "" {
		return fail(errors.New("-server is required"))
	}
	if fs.NArg() == 0 {
		return fail(errors.New("at least one NAME is required"))
	}
	if *timeout <= 0 {
		return fail(fmt.Errorf("-timeout must be positive, got %s", *timeout))
	}
	qtypes, err := parseTypes(*typeList)
	if err != nil {
		return fail(err)
	}
	anchors, err := loadAnchors(*anchorsPath)
	if err != nil {
		return fail(err)
	}
	return config{
		server:  auth.NormalizeAddr(*server),
		anchors: anchors,
		cd:      *cd,
		timeout: *timeout,
		queries: crossQueries(fs.Args(), qtypes),
	}, nil
}

func parseTypes(list string) ([]uint16, error) {
	var out []uint16
	for _, s := range strings.Split(list, ",") {
		t, err := types.StringToRRType(strings.ToUpper(strings.TrimSpace(s)))
		if err != nil {
			return nil, fmt.Errorf("-type %q: %w", s, err)
		}
		out = append(out, t)
	}
	return out, nil
}

func crossQueries(names []string, qtypes []uint16) []query {
	out := make([]query, 0, len(names)*len(qtypes))
	for _, n := range names {
		for _, t := range qtypes {
			out = append(out, query{Name: n, Type: typeName(t), qtype: t})
		}
	}
	return out
}

func typeName(t uint16) string {
	if s, err := types.RRTypeToString(t); err == nil {
		return s
	}
	return fmt.Sprintf("TYPE%d", t)
}

func loadAnchors(path string) (*dnssec.RootAnchors, error) {
	if path == "" {
		return dnssec.BuiltinRootAnchors(), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("-anchors: %w", err)
	}
	defer f.Close()
	a, err := dnssec.ReadAnchors(f)
	if err != nil {
		return nil, fmt.Errorf("-anchors %s: %w", path, err)
	}
	return a, nil
}
