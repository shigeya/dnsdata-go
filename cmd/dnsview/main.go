// Command dnsview validates DNS queries against one server with the
// chain-of-trust verifier and prints each [verifier.Result] as one line
// of JSON. It is a diagnostic tool: it shows, query by query, what the
// verifier concluded and why.
//
// Usage:
//
//	dnsview -server ADDR [-type A,AAAA] [-anchors FILE] [-cd] [-timeout 10s] NAME...
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
// Exit status: 0 when every query produced a result without error, 1
// when at least one did not, 2 on a usage error.
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
