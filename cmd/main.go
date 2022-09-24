package main

import (
	"fmt"
	"github.com/clivewalkden/go-sozo-spf-flattener/reporting"
	"github.com/clivewalkden/go-sozo-spf-flattener/spf"
	flag "github.com/spf13/pflag"
	"io/ioutil"
	"os"
	"strings"
)

var topDomain string
var spfSubdomainPrefix string
var spfFile string

func init() {
	flag.StringVarP(&spfFile, "spf-file", "o", "", "File to output data to (required)")
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
	domainSPF := spf.SPFLookup(topDomain)
	spfString := strings.TrimSpace(domainSPF)
	err := ioutil.WriteFile(spfFile+".backup", []byte(spfString), 0644)
	if err != nil {
		panic(err)
	}

	finalSPF := spf.NewSPF()
	finalSPF.Parse(domainSPF)

	fmt.Printf("finalSPF: %s\n", finalSPF)
	topRecord, records, err := reporting.Report(finalSPF, topDomain, spfSubdomainPrefix)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}

	// Final output
	fmt.Printf("TXT\t %s\t %s\n", topDomain, topRecord.Txt)
	fmt.Printf("Length: %d\n", len([]rune(topRecord.Txt)))
	if len(records) > 0 {
		for _, record := range records {
			fmt.Printf("TXT\t %s\t %s\n", record.Name+"."+topDomain, record.Txt)
			fmt.Printf("Length: %d\n", len([]rune(record.Txt)))
		}
	}
}
