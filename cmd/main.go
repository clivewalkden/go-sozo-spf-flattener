package main

import (
	"fmt"
	flag "github.com/spf13/pflag"
	"go-sozo-spf-flattener/cmd/tools"
	"log"
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
		fmt.Fprintf(os.Stderr, "Usage: %s -o spf-file [-p subdomain-prefix] domain\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Use the SPF record for flattening\n")
		flag.PrintDefaults()
		os.Exit(1)
	}
	topDomain = flag.Arg(0)

	err := os.Mkdir("results", 0775)
	if err != nil {
		// Nothing to report, just means the directory already exists
	}
}

func main() {
	domainSPF := tools.Lookup(topDomain)
	spfString := strings.TrimSpace(domainSPF)
	err := os.WriteFile("results/"+spfFile+".backup", []byte(spfString), 0644)
	if err != nil {
		panic(err)
	}

	finalSPF := tools.NewSPF()
	finalSPF.Parse(domainSPF)

	fmt.Printf("finalSPF: #{finalSPF}\n")
	topRecord, records, err := tools.Report(finalSPF, topDomain, spfSubdomainPrefix)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}

	// Final output
	// If the file doesn't exist, create it, or append to the file
	f, err := os.OpenFile("results/"+spfFile+".new", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	err = os.Truncate("results/"+spfFile+".new", 0)
	if err != nil {
		log.Fatal(err)

	}
	if _, err := f.Write([]byte("TXT\t " + topDomain + "\t " + topRecord.Txt + "\n")); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("TXT\t %s\t %s\n", topDomain, topRecord.Txt)
	//fmt.Printf("Length: %d\n", len([]rune(topRecord.Txt)))
	if len(records) > 0 {
		for _, record := range records {
			fmt.Printf("TXT\t %s\t %s\n", record.Name+"."+topDomain, record.Txt)
			if _, err := f.Write([]byte("TXT\t " + record.Name + "." + topDomain + "\t " + record.Txt + "\n")); err != nil {
				log.Fatal(err)
			}
			//fmt.Printf("Length: %d\n", len([]rune(record.Txt)))
		}
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
}
