// Command dnsview validates DNS queries against one server with the
// chain-of-trust verifier and prints each [verifier.Result] as one line
// of JSON. It is a diagnostic tool: it shows, query by query, what the
// verifier concluded and why.
//
// Usage:
//
//	dnsview -server ADDR [-type A,AAAA] [-anchors FILE] [-cd] [-opkey] [-timeout 10s] NAME...
//
// Each NAME is queried for each -type, in order, and produces one line:
//
//	{"query":{"name":"…","type":"A"},"server":"…","error":"…","result":{…}}
//
// "error" is present only when validation could not run to completion;
// "result" is the verifier's Result as it marshals itself (DESIGN.md
// MUST 10), or null when no Result was produced. Queries go to the
// server over UDP, retried over TCP when the answer is truncated.
// Without -anchors the built-in IANA root anchors are used.
//
// With -opkey, -type defaults to TLSA, and a line whose validated answer
// is a TLSA RRset (or an OPKEY RRset, once that type value is allocated)
// also carries the records read as OPKEY RDATA
// (draft-shigeya-dns-opkey-00), each marked usable or not with the
// reason:
//
//	"opkey":{"records":[{"value":"3 1 1 …","usable":true},
//	                    {"value":"0 0 0 …","usable":false,"reason":"OPKEY usage 0 (want 3)"}]}
//
// NAME is the full owner name; dnsview composes no names. A record that
// is not valid TLSA RDATA fails the RRset: "opkey" then has an "error"
// and no records. Without -opkey the output is unchanged.
//
// Exit status: 0 when every query produced a result without error (and,
// under -opkey, every OPKEY view decoded), 1 when at least one did not,
// 2 on a usage error.
package main

import (
	"os"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:], env{
		stdout:      os.Stdout,
		stderr:      os.Stderr,
		now:         time.Now,
		newResolver: authResolver,
	}))
}
