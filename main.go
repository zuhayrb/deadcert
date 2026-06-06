package main

import "os"

/*
Exist Codes:
0 - Success
1 - One or more certificates are: expired, expiring within --warn-days, or the domain is unreachable.
2 - Usage error: bad flag, missing domain, file not found, etc.
*/
func main() {
	if len(os.Args) < 3 {
		println("Usage: deadcert check <domain> [domain2 ...]")
		return
	}
	command := os.Args[1]
	switch command {
	case "check":
		domains := os.Args[2:]
		for _, domain := range domains {
			checkDomain(domain)
		}
	default:
		println("Unknown command:", command)
		os.Exit(2)
	}
}
