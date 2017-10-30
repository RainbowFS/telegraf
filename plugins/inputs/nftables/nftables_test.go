package nftables

import "testing"
import (
	"github.com/stretchr/testify/assert"
)

func TestParseFlowTable(t *testing.T) {
	ft := NFTables{}
	types, matcher := ft.parseTypes("flow table oft { ip saddr . ip daddr counter}  tcp dport 5000", "oft")

	assert.Equal(t, 2, len(types));
	assert.Equal(t, "ip.saddr", types[0]);
	assert.Equal(t, "ip.daddr", types[1]);
	assert.Equal(t, "tcp.dport.5000", matcher);
}
