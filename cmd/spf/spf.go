package spf

import (
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"strings"
)

// http://www.openspf.org/RFC_4408#rsize
// A TXT response should never exceed 512 bytes. This includes the domain name
// and any other TXT records returned in the same response.
// A standard record looks like:
// v=spf1 ip4:123.123.123.123/12 ip6:1234:1234:1234::12 -all
// [--7--][---------23----------][---------23----------][-4]
// Therefore, to guarantee we don't exceed 450 octets:
// 450 >= 7 + 23*ips + 4
//  19 >= ips
const MAX_CIDRS = 19

type SPF struct {
	V           string
	Ip4         []string
	Ip6         []string
	Include     []string
	All         byte
	LookupCount int
}

var querydomain string

func NewSPF() *SPF {
	return &SPF{
		V:           "spf1",
		Ip4:         []string{},
		Ip6:         []string{},
		Include:     []string{},
		All:         '?',
		LookupCount: 0,
	}
}

func (s *SPF) Clone() *SPF {
	rec := NewSPF()
	return rec.Append(s)
}

func Lookup(domain string) string {
	querydomain = domain
	record, err := recordRetrievalTXT(domain)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Record: %s\n", record)

	return record
}

func (s *SPF) Flatten() (*SPF, error) {
	aggregate := NewSPF()
	aggregate.LookupCount = s.LookupCount
	// Copy existing ip4/ip6 records
	if len(s.Ip4) > 0 {
		aggregate.Ip4 = make([]string, len(s.Ip4))
		copy(aggregate.Ip4, s.Ip4)
	}
	if len(s.Ip6) > 0 {
		aggregate.Ip6 = make([]string, len(s.Ip6))
		copy(aggregate.Ip6, s.Ip6)
	}
	aggregate.All = s.All

	// Now to flatten the rest
	for _, include := range s.Include {
		fmt.Printf("Checking Include: %s\n", include)
		txts, err := net.LookupTXT(include)
		fmt.Printf("Returned txts: %s\n", txts)
		aggregate.LookupCount++
		if err != nil {
			return nil, err
		}

		for _, txt := range txts {
			rec := NewSPF()
			rec.Parse(txt)
			if len(rec.Include) > 0 {
				rec, err = rec.Flatten()
				if err != nil {
					return nil, err
				}
			}
			aggregate.Append(rec)
			aggregate.LookupCount += rec.LookupCount
		}
	}

	return aggregate, nil
}

func (s *SPF) Append(spfs ...*SPF) *SPF {
	for _, spf := range spfs {
		for _, ip4 := range spf.Ip4 {
			// Make sure we only add the IP once
			if !strInSlice(ip4, s.Ip4) {
				s.Ip4 = append(s.Ip4, ip4)
			}
		}
		for _, ip6 := range spf.Ip6 {
			// Make sure we only add the IP once
			if !strInSlice(ip6, s.Ip6) {
				s.Ip6 = append(s.Ip6, ip6)
			}
		}
		s.Include = append(s.Include, spf.Include...)
		if s.All != spf.All {
			if s.All == '-' || spf.All == '-' {
				s.All = '-'
			} else {
				s.All = '~'
			}
		}
	}
	return s
}

func (s *SPF) Parse(record string) error {
	if !strings.HasPrefix(record, "v=spf1") {
		return errors.New("not a valid SPF record: " + record)
	}

	// Empty any existing data
	s.Ip4 = []string{}
	s.Ip6 = []string{}
	s.Include = []string{}

	// Parse
	for _, part := range strings.Split(record, " ") {
		switch {
		case strings.HasPrefix(part, "v="):
			s.V = part[2:]
		case strings.HasPrefix(part, "ip4:"):
			s.Ip4 = append(s.Ip4, part[4:])
		case strings.HasPrefix(part, "ip6:"):
			s.Ip6 = append(s.Ip6, part[4:])
		case strings.HasPrefix(part, "include:"):
			s.Include = append(s.Include, part[8:])
		case strings.HasSuffix(part, "all"):
			s.All = part[0]
		case strings.HasPrefix(part, "mx"):
			records, _ := recordRetrievalMX()
			for _, record := range records {
				if IsIPv4(record) {
					s.Ip4 = append(s.Ip4, record)
				} else if IsIPv6(record) {
					s.Ip6 = append(s.Ip6, record)
				}
				s.LookupCount++
			}
		case strings.HasPrefix(part, "a"):
			records, _ := recordRetrievalA()
			for _, record := range records {
				if IsIPv4(record) {
					s.Ip4 = append(s.Ip4, record)
				} else if IsIPv6(record) {
					s.Ip6 = append(s.Ip6, record)
				}
				s.LookupCount++
			}
		default:
			log.Printf("Unrecognised SPF part: %s\n", part)
		}
	}

	return nil
}

func (s *SPF) AsTXTRecord() string {
	parts := []string{"v=spf1"}
	for _, ip4 := range s.Ip4 {
		parts = append(parts, "ip4:"+ip4)
	}
	for _, ip6 := range s.Ip6 {
		parts = append(parts, "ip6:"+ip6)
	}
	for _, include := range s.Include {
		parts = append(parts, "include:"+include)
	}
	parts = append(parts, string(s.All)+"all")
	return strings.Join(parts, " ")
}

func (s *SPF) Split() ([]*SPF, error) {
	if len(s.Include) > 0 {
		return nil, errors.New("record cannot have includes when splitting")
	}
	spf := s.Clone()

	numRecords := int(math.Ceil(float64(len(spf.Ip4)+len(spf.Ip6)) / MAX_CIDRS))
	if numRecords == 1 {
		return []*SPF{spf}, nil
	}

	records := []*SPF{}
	for i := 0; i < numRecords; i++ {
		space := MAX_CIDRS
		rec := NewSPF()

		fours := int(math.Min(float64(space), float64(len(spf.Ip4))))
		rec.Ip4 = spf.Ip4[0:fours]
		space -= fours
		spf.Ip4 = spf.Ip4[fours:]

		sixes := int(math.Min(float64(space), float64(len(spf.Ip6))))
		rec.Ip6 = spf.Ip6[0:sixes]
		space -= sixes
		spf.Ip6 = spf.Ip6[sixes:]

		rec.All = spf.All

		records = append(records, rec)
	}
	return records, nil
}

func recordRetrievalTXT(domain string) (string, error) {
	var records string
	rs, err := net.LookupTXT(domain)
	if err != nil {
		fmt.Println("Error getting text records")
		fmt.Println(err)
		os.Exit(1)
	}

	for _, rr := range rs {
		if strings.HasPrefix(rr, "v=spf") {
			fmt.Println(rr)
			records = rr
		}
	}

	if len(records) == 0 {
		return "", errors.New("no SPF record found")
	}

	return records, nil
}

func recordRetrievalMX() ([]string, error) {
	var records []string
	fmt.Printf("mx domain: %s\n", querydomain)
	rs, err := net.LookupMX(querydomain)
	if err != nil {
		fmt.Println("Error getting mx records")
		fmt.Println(err)
		os.Exit(1)
	}

	if len(rs) > 0 {
		for _, rr := range rs {
			// trim the suffixing .
			mxrecord := trimSuffix(rr.Host, ".")
			// query the MX record for the ip
			irs, _ := net.LookupIP(mxrecord)
			for _, ir := range irs {
				records = append(records, ir.String())
			}
		}
	}

	return records, nil
}

func recordRetrievalA() ([]string, error) {
	var records []string
	fmt.Printf("a domain: %s\n", querydomain)
	ips, err := net.LookupIP(querydomain)
	if err != nil {
		fmt.Println("Error getting a records")
		fmt.Println(err)
		os.Exit(1)
	}

	if len(ips) > 0 {
		for _, ip := range ips {
			records = append(records, ip.String())
		}
	}

	return records, nil
}

func strInSlice(s string, a []string) bool {
	for _, e := range a {
		if e == s {
			return true
		}
	}
	return false
}

func trimSuffix(s, suffix string) string {
	if strings.HasSuffix(s, suffix) {
		s = s[:len(s)-len(suffix)]
	}
	return s
}

func IsIPv4(address string) bool {
	return strings.Count(address, ":") < 2
}

func IsIPv6(address string) bool {
	return strings.Count(address, ":") >= 2
}
