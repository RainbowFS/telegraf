package nftables

import "testing"
import (
	"github.com/stretchr/testify/assert"
)

var singleton_table = `table ip filter {
chain prerouting {
type filter hook prerouting priority 0; policy accept;
ip saddr . ip daddr . tcp sport { 10.1.6.1 . 172.17.0.4 . 5001} jump h7_ipcli2_h6_ipsrv2
ip daddr . ip saddr . tcp dport { 10.1.6.1 . 172.17.0.4 . 5001} jump h6_ipsrv2_h7_ipcli2
ip saddr . ip daddr . tcp sport { 10.1.6.1 . 172.17.0.3 . 5001} jump h7_ipcli_h6_ipsrv2
ip daddr . ip saddr . tcp dport { 10.1.6.1 . 172.17.0.3 . 5001} jump h6_ipsrv2_h7_ipcli
ip saddr . ip daddr . tcp sport { 10.1.6.1 . 172.17.0.2 . 5001} jump h7_ipsrv_h6_ipsrv2
ip daddr . ip saddr . tcp dport { 10.1.6.1 . 172.17.0.2 . 5001} jump h6_ipsrv2_h7_ipsrv
ip saddr . ip daddr . tcp sport { 10.1.6.1 . 172.17.0.4 . 5000} jump h7_ipcli2_h6_ipsrv
ip daddr . ip saddr . tcp dport { 10.1.6.1 . 172.17.0.4 . 5000} jump h6_ipsrv_h7_ipcli2
ip saddr . ip daddr . tcp sport { 10.1.6.1 . 172.17.0.3 . 5000} jump h7_ipcli_h6_ipsrv
ip daddr . ip saddr . tcp dport { 10.1.6.1 . 172.17.0.3 . 5000} jump h6_ipsrv_h7_ipcli
ip saddr . ip daddr . tcp sport { 10.1.6.1 . 172.17.0.2 . 5000} jump h7_ipsrv_h6_ipsrv
ip daddr . ip saddr . tcp dport { 10.1.6.1 . 172.17.0.2 . 5000} jump h6_ipsrv_h7_ipsrv
ip saddr . ip daddr . tcp sport { 10.1.5.1 . 172.17.0.4 . 5000} jump h7_ipcli2_h5_ipsrv
ip daddr . ip saddr . tcp dport { 10.1.5.1 . 172.17.0.4 . 5000} jump h5_ipsrv_h7_ipcli2
ip saddr . ip daddr . tcp sport { 10.1.5.1 . 172.17.0.3 . 5000} jump h7_ipcli_h5_ipsrv
ip daddr . ip saddr . tcp dport { 10.1.5.1 . 172.17.0.3 . 5000} jump h5_ipsrv_h7_ipcli
ip saddr . ip daddr . tcp sport { 10.1.5.1 . 172.17.0.2 . 5000} jump h7_ipsrv_h5_ipsrv
ip daddr . ip saddr . tcp dport { 10.1.5.1 . 172.17.0.2 . 5000} jump h5_ipsrv_h7_ipsrv
ip daddr . ip saddr  { 10.1.5.1 . 172.17.0.2 } jump h5_h7
}

chain h7_ipcli2_h6_ipsrv2 {
counter packets 169252 bytes 9461164
}

chain h6_ipsrv2_h7_ipcli2 {
counter packets 111291 bytes 6265506204
}

chain h5_h7 {
counter packets 123 bytes 456
}

chain h7_ipcli_h6_ipsrv2 {
counter packets 0 bytes 0
}

chain h6_ipsrv2_h7_ipcli {
counter packets 0 bytes 0
}

chain h7_ipsrv_h6_ipsrv2 {
counter packets 0 bytes 0
}

chain h6_ipsrv2_h7_ipsrv {
counter packets 0 bytes 0
}

chain h7_ipcli2_h6_ipsrv {
counter packets 0 bytes 0
}

chain h6_ipsrv_h7_ipcli2 {
counter packets 0 bytes 0
}

chain h7_ipcli_h6_ipsrv {
counter packets 288101 bytes 16072572
}

chain h6_ipsrv_h7_ipcli {
counter packets 230456 bytes 13042847184
}

chain h7_ipsrv_h6_ipsrv {
counter packets 0 bytes 0
}

chain h6_ipsrv_h7_ipsrv {
counter packets 0 bytes 0
}

chain h7_ipcli2_h5_ipsrv {
counter packets 0 bytes 0
}

chain h5_ipsrv_h7_ipcli2 {
counter packets 0 bytes 0
}

chain h7_ipcli_h5_ipsrv {
counter packets 0 bytes 0
}

chain h5_ipsrv_h7_ipcli {
counter packets 0 bytes 0
}

chain h7_ipsrv_h5_ipsrv {
counter packets 0 bytes 0
}

chain h5_ipsrv_h7_ipsrv {
counter packets 0 bytes 0
}
}`


func TestParseSingletonChain(t *testing.T) {
	ft := NFTables{}

	res := ft.parseSingletonChain(singleton_table)

	assert.Equal(t, int64(288101), res["h7_ipcli_h6_ipsrv"].Packets)
	assert.Equal(t, int64(16072572), res["h7_ipcli_h6_ipsrv"].Bytes)

	assert.Equal(t, int64(230456), res["h6_ipsrv_h7_ipcli"].Packets)
	assert.Equal(t, int64(13042847184), res["h6_ipsrv_h7_ipcli"].Bytes)

	assert.Equal(t, int64(169252), res["h7_ipcli2_h6_ipsrv2"].Packets)
	assert.Equal(t, int64(9461164), res["h7_ipcli2_h6_ipsrv2"].Bytes)

	assert.Equal(t, int64(111291), res["h6_ipsrv2_h7_ipcli2"].Packets)
	assert.Equal(t, int64(6265506204), res["h6_ipsrv2_h7_ipcli2"].Bytes)
	assert.Equal(t, int64(456), res["h5_h7"].Bytes)
	assert.Equal(t, int64(123), res["h5_h7"].Packets)

}
