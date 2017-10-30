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
     "filter.oft",
	"filter.ift",
"filter.fft",

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

func (self *NFTables) parseTypes(data string, flowTableName string) (types []string, matchPatter string) {
	//eg.		flow table oft { ip saddr . ip daddr counter}  tcp dport 5000

	r := regexp.MustCompile("flow table " + flowTableName + " \\{(?: (.*) )counter\\}(.*)")
	match := r.FindAllStringSubmatch(data, -1)
	if len(match) > 0 {
		for _, aType := range strings.Split(match[0][1], ".") {
			types = append(types, strings.Replace(strings.Trim(aType, " "), " ", ".", -1))
		}

		matchPatter = match[0][1]

	}

	return types, matchPatter

}

func (self *NFTables) queryTypes(table string, chain string, flowTableName string) (types []string) {

	nftablePath, err := exec.LookPath("nft")
	if err != nil {
		panic(err)
	}

	var args []string
	name := "sudo"
	args = append(args, nftablePath,"-nn")
	args = append(args, "list", "flow", "table", "filter","|", "grep", flowTableName)

	c := exec.Command(name, args...)
	if out, err := c.Output(); err == nil {
		types, _ := self.parseTypes(string(out), flowTableName)
		return types

	} else {

		panic(err)
	}

}

func (self *NFTables) queryFlowTable(tableName string, chainName string, flowTableName string) (FlowTable) {

	//types := []string{"ether_saddr", "ether_daddr", "ip_saddr", "ip_daddr"}

	types := self.queryTypes(tableName, chainName, flowTableName)

	nftablePath, err := exec.LookPath("nft")
	if err != nil {
		panic(err)
	}

	var args []string
	name := "sudo"
	args = append(args, nftablePath)
	args = append(args, "list", "flow", "table", tableName)
	args = append(args, flowTableName)

	c := exec.Command(name, args...)
	if out, err := c.Output(); err == nil {
		elements := self.parseFlowTableOutput(string(out), tableName, flowTableName)
		return FlowTable{Name: flowTableName, Elements: elements, Types: types}

	} else {
		panic(nil)
	}

}

func (s *NFTables) SampleConfig() string {
	return NFTableConfig
}

func (s *NFTables) Description() string {
	return "Gather flow data from an nftable table"
}

func (self *NFTables) Gather(acc telegraf.Accumulator) error {

	for _, configId := range self.FlowTables {
		if tokens := strings.Split(configId, "."); len(tokens) == 3 {
			tableName := tokens[0]
			chainName := tokens[1]
			flowTableName := tokens[2]

			flowTable := self.queryFlowTable(tableName, chainName, flowTableName)
			types := self.queryTypes(tableName, chainName, flowTableName)

			for _, element := range flowTable.Elements {

				fields := make(map[string]interface{})
				fields["bytes"] = element.Counter.Bytes
				fields["packets"] = element.Counter.Packets

				tags := make(map[string]string)

				for typeIndex, typeValue := range (flowTable.Types) {
					tags[typeValue] = types[typeIndex]
				}

				acc.AddFields("nftables", fields, tags)

			}

		} else {
			panic("invalid configuration " + configId)
		}

	}

	return nil
}

func init() {
	inputs.Add("nftables", func() telegraf.Input {
		return &NFTables{}
	})
}
