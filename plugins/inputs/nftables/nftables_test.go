package nftables

import "testing"
import (
	"github.com/stretchr/testify/assert"
)

func TestParseTableData(t *testing.T) {

	data := `table ip filter
table ip toto`

	nft := NFTables{}
	tables := nft.ParseTable(data)
	assert.Equal(t, 2, len(tables))
	assert.Equal(t, "filter", tables[0].Name)
	assert.Equal(t, "toto", tables[0].Name)

}

