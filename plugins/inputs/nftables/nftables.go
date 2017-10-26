package nftables

import (
	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/inputs"
	"os/exec"
	"fmt"
	"regexp"
	"strings"
)

type NFTables struct {
	FlowTables []string
}

var NFTableConfig = `
  ## Configuration for nftables, LIG
  flowTables = [
     "filter.cnt-ftable",

  ]
`

type Table struct {
	Name   string
	Chains []Chain
}

type Chain struct {
	Name       string
	Flowtables []FlowTable
}

type FlowTable struct {
	Name     string
	Types    []string
	Elements []Element
}

type Element struct {
	Keys    []string
	Counter Counter
}

type Counter struct {
	Packets int64
	Bytes   int64
}

func (selt *NFTables) parseFlowTableOutput(data string, tableName string, flowTableName string) (elements []Element) {

	r := regexp.MustCompile("table ip " + tableName + " \\{.*flow table " + flowTableName + " \\{.*elements = \\{([^\\}]*)\\}.*\\}.*")
	match := r.FindAllStringSubmatch(strings.Replace(data, "\n", " ", -1), -1)
	if len(match) > 0 {
		candidate := match[0][1]
		for _, entry := range strings.Split(candidate, ",") {
			parsedEntry := strings.Split(entry, " : ")
			keysStr, counterStr := parsedEntry[0], parsedEntry[1]

			unTrimmedKeys := strings.Split(keysStr, " . ")
			keys := []string{}
			for _, key := range unTrimmedKeys {
				keys = append(keys, strings.Trim(key, " "))
			}

			counter := Counter{}
			fmt.Sscanf(counterStr, "counter packets %d bytes %d", &(counter.Packets), &(counter.Bytes))
			elements = append(elements, Element{Keys: keys, Counter: counter})

		}
	}

	return elements
}

func (self *NFTables) queryFlowTables() ([] Table) {
	const tableName = "filter"
	var flowTableNames = [...]string{"ift", "oft", "fft"}

	//types := []string{"ether_saddr", "ether_daddr", "ip_saddr", "ip_daddr"}
	types := []string{"ip_saddr", "ip_daddr"}

	nftablePath, err := exec.LookPath("nft")
	if err != nil {
		panic(err)
	}

	chains := []Chain{}

	for _, flowTableName := range flowTableNames {
		chain := Chain{Name: "dummy"}
		var args []string
		name := "sudo"
		args = append(args, nftablePath)
		args = append(args, "list", "flow", "table", tableName)
		args = append(args, flowTableName)

		c := exec.Command(name, args...)
		if out, err := c.Output(); err == nil {
			elements := self.parseFlowTableOutput(string(out), tableName, flowTableName)
			chain.Flowtables = append(chain.Flowtables, FlowTable{Name: flowTableName, Elements: elements, Types: types})
			chains = append(chains, chain)

		} else {

			panic(err)
		}

	}

	table := Table{Name: "filter", Chains: chains}

	return []Table{table}

}

func (s *NFTables) SampleConfig() string {
	return NFTableConfig
}

func (s *NFTables) Description() string {
	return "Gather flow data from an nftable table"
}

func (self *NFTables) Gather(acc telegraf.Accumulator) error {

	tables := self.queryFlowTables()

	for _, table := range (tables) {
		for _, chain := range (table.Chains) {
			for _, flowTable := range (chain.Flowtables) {
				for _, flowElement := range (flowTable.Elements) {

					fields := make(map[string]interface{})
					tags := make(map[string]string)

					fields["bytes"] = flowElement.Counter.Bytes
					fields["packets"] = flowElement.Counter.Packets

					for typeIndex, typeValue := range (flowTable.Types) {
						tags[typeValue] = flowElement.Keys[typeIndex]

					}

					acc.AddFields("nftables", fields, tags)

				}
			}
		}
	}

	return nil
}

func init() {
	inputs.Add("nftables", func() telegraf.Input {
		return &NFTables{}
	})
}
