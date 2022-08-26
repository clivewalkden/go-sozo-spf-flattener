package main

import (
	"fmt"
	flag "github.com/spf13/pflag"
	"io/ioutil"
	"os"
	spf "spf"
	"strings"
)

var topDomain string
var spfSubdomainPrefix string
var spfFile string
var dryRun bool

func init() {
	flag.StringVarP(&spfFile, "spf-file", "f", "", "File that contains a valid spf format TXT record (required)")
	flag.StringVarP(&spfSubdomainPrefix, "spf-prefix", "p", "_spf", "Prefix for subdomains when multiple are needed.")
	flag.Parse()

	if flag.NArg() != 1 || spfFile == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -f spf-file [-p subdomain-prefix] domain\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Use the SPF record for flattening\n")
		flag.PrintDefaults()
		os.Exit(1)
	}
	topDomain = flag.Arg(0)
}

func main() {
	dat, err := ioutil.ReadFile(spfFile)
	if err != nil {
		panic(err)
	}
	spfString := strings.TrimSpace(string(dat))

	providedSPF := spf.NewSPF()
	providedSPF.Parse(spfString)
}
