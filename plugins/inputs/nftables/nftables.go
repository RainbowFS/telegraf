package nftables

import (
	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/inputs"
	"os/exec"
	"fmt"
	"regexp"
	"strings"
	"log"
	"errors"
	"strconv"
)

type NFTables struct {
	FlowTables []string
	Tables     []string
}

var NFTableConfig = `
  ## Configuration for nftables, LIG

  tables = [ "filter" ]
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

func (self *NFTables) parseFlowTableOutput(data string, tableName string, flowTableName string) (elements []Element) {

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
			types = append(types, strings.Replace(strings.Trim(aType, " "), " ", "_", -1))
		}

		matchPatter = match[0][1]

	}

	return types, matchPatter

}

func (self *NFTables) queryTypes(table string, chain string, flowTableName string) (types []string, err error) {

	nftablePath, err := exec.LookPath("nft")
	if err != nil {
		panic("nft is not installed")
	}

	var args []string
	name := "sudo"
	args = append(args, nftablePath, "-nn")
	args = append(args, "list", "table", table)

	c := exec.Command(name, args...)
	if out, err2 := c.CombinedOutput(); err2 == nil {

		c := regexp.MustCompile("(?sm).*chain " + chain + " \\{.*(flow table " + flowTableName + ".*)\\}")
		if match := c.FindStringSubmatch(string(out)); len(match) >= 1 {
			flowTableDesc := strings.Split(match[1], "\n")[0]
			types, _ := self.parseTypes(flowTableDesc, flowTableName)
			return types, nil
		}

	}

	return []string{}, err

}

func (self *NFTables) queryFlowTable(tableName string, chainName string, flowTableName string) (FlowTable, error) {

	//types := []string{"ether_saddr", "ether_daddr", "ip_saddr", "ip_daddr"}

	if nftablePath, err := exec.LookPath("nft"); err == nil {

		if types, err := self.queryTypes(tableName, chainName, flowTableName); err == nil {

			var args []string
			name := "sudo"
			args = append(args, nftablePath, "-nn")
			args = append(args, "list", "flow", "table", tableName)
			args = append(args, flowTableName)

			c := exec.Command(name, args...)
			if out, err := c.Output(); err == nil {
				elements := self.parseFlowTableOutput(string(out), tableName, flowTableName)
				return FlowTable{Name: flowTableName, Elements: elements, Types: types}, nil

			}

		}

	}
	return FlowTable{}, errors.New("failed to query" + tableName + "." + chainName + "." + flowTableName + ". Ignoring")

}

func (s *NFTables) SampleConfig() string {
	return NFTableConfig
}

func (s *NFTables) Description() string {
	return "Gather chain data and flow data from an nftable table"
}

func (self *NFTables) Gather(acc telegraf.Accumulator) error {

	for _, configId := range self.FlowTables {

		if tokens := strings.Split(configId, "."); len(tokens) == 3 {
			tableName := tokens[0]
			chainName := tokens[1]
			flowTableName := tokens[2]

			if flowTable, err := self.queryFlowTable(tableName, chainName, flowTableName); err == nil {

				if types, err := self.queryTypes(tableName, chainName, flowTableName); err == nil {

					for _, element := range flowTable.Elements {

						fields := make(map[string]interface{})
						fields["bytes"] = element.Counter.Bytes
						fields["packets"] = element.Counter.Packets

						tags := make(map[string]string)

						for typeIndex, typeValue := range types {
							tags[typeValue] = element.Keys[typeIndex]
						}

						tags["chain"] = chainName
						tags["flowTable"] = flowTableName

						acc.AddFields("nftables", fields, tags)

					}
				}

			} else {
				log.Println(err) //ignoring this error

			}

		} else {
			log.Println("ignoring invalid configuration " + configId + " flow table is probably missing")
		}

	}

	for _, tableName := range self.Tables {

		if data, err := self.getTableData(tableName); err == nil {
			counters := self.parseSingletonChain(data)

			for chain, counter := range counters {

				chainItems := strings.Split(chain, "_")

				host_src := chainItems[0]
				app_src := chainItems[1]
				host_dst := chainItems[2]
				app_dst := chainItems[3]

				fields := make(map[string]interface{})
				fields["bytes"] = counter.Bytes
				fields["packets"] = counter.Packets

				tags := make(map[string]string)

				tags["host_src"] = host_src
				tags["host_dst"] = host_dst
				tags["app_src"] = app_src
				tags["app_dst"] = app_dst

				tags["host_app_src"] = host_src + "_" + app_src
				tags["host_app_dst"] = host_dst + "_" + app_dst
				tags["chain"] = chain

				acc.AddFields("nftables", fields, tags)
			}

		}

	}

	return nil
}

func (self *NFTables) getTableData(tableName string) (string, error) {

	if nftablePath, err := exec.LookPath("nft"); err == nil {
		var args []string
		name := "sudo"
		args = append(args, nftablePath, "-nn")
		args = append(args, "list", "table", tableName)

		c := exec.Command(name, args...)
		if out, err := c.Output(); err == nil {
			return string(out), nil
		}
	}

	return "", errors.New("failed to load table data for table " + tableName)

}

func (self *NFTables) parseSingletonChain(data string) map[string]Counter {

	res := make(map[string]Counter)

	data = strings.Replace(data, "\n", " ", -1)
	r := regexp.MustCompile("chain ([a-zA-Z0-9]+_[a-zA-Z0-9]+_[a-zA-Z0-9]+_[a-zA-Z0-9]+) \\{.*?counter packets ([0-9]+) bytes ([0-9]+)")
	matches := r.FindAllStringSubmatch(data, -1)

	for _, match := range matches {
		chainName := match[1]

		packets, _ := strconv.ParseInt(match[2], 10, 64)
		bytes, _ := strconv.ParseInt(match[3], 10, 64)

		res[chainName] = Counter{packets, bytes}

	}

	return res

}

func init() {
	inputs.Add("nftables", func() telegraf.Input {
		return &NFTables{}
	})
}
