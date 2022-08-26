package spf

import (
	"net"
)

type TXTQuery interface {
	Query(string) ([]string, error)
}

type SimpleTXTQuery struct {
}

func (q SimpleTXTQuery) Query(name string) ([]string, error) {
	return net.LookupTXT(name)
}
