package tools

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
)

type TXTRecord struct {
	Name string
	Txt  string
}

type DNSReport struct {
	topDomain       string
	spfDomainPrefix string
}

func NewDNSReport(topDomain, spfSubdomainPrefix string) *DNSReport {
	return &DNSReport{
		topDomain:       topDomain,
		spfDomainPrefix: spfSubdomainPrefix,
	}
}

var domain string
var prefix string

func Report(final *SPF, topDomain string, spfDomainPrefix string) (TXTRecord, []TXTRecord, error) {
	records := []TXTRecord{}
	var topRecord TXTRecord

	domain = topDomain
	prefix = spfDomainPrefix
	r := NewDNSReport(domain, prefix)
	flat, err := final.Flatten()
	if err != nil {
		return topRecord, records, err
	}

	// Check the number of lookups for splitting
	fmt.Printf("Flat Lookup Count: %d\n", flat.LookupCount)
	if flat.LookupCount <= 10 {
		// Can leave the original record in place
		topRecord = TXTRecord{
			Name: "record",
			Txt:  final.AsTXTRecord(),
		}
	} else {
		// Need to convert and flatten the record
		splits, err := flat.Split()
		if err != nil {
			return topRecord, records, err
		}
		records, topRecord = r.makeRecords(splits)
	}

	return topRecord, records, nil
}

func (r *DNSReport) makeRecords(splits []*SPF) ([]TXTRecord, TXTRecord) {
	records := []TXTRecord{}

	topSPF := NewSPF()
	topSPF.All = splits[0].All

	for _, split := range splits {
		txt := split.AsTXTRecord()
		sig := hash(txt)
		subdomain := r.spfDomainPrefix + sig
		record := TXTRecord{
			Name: subdomain,
			Txt:  txt,
		}
		records = append(records, record)
		topSPF.Include = append(topSPF.Include, subdomain+"."+r.topDomain)
	}

	return records, TXTRecord{
		Name: r.topDomain,
		Txt:  topSPF.AsTXTRecord(),
	}
}

func hash(txt string) string {
	sum := sha1.Sum([]byte(txt))
	return hex.EncodeToString(sum[0:3])
}
