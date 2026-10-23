// Package aghyaml edits the three AdGuardHome.yaml settings a bind change
// needs, leaving everything else in the file untouched.
package aghyaml

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Binds is what the agent reads and writes.
type Binds struct {
	DNSBindHosts []string
	DNSPort      int
	HTTPAddress  string // "host:port"
}

// Read parses the current values.
func Read(raw []byte) (Binds, error) {
	var doc struct {
		DNS struct {
			BindHosts []string `yaml:"bind_hosts"`
			Port      int      `yaml:"port"`
		} `yaml:"dns"`
		HTTP struct {
			Address string `yaml:"address"`
		} `yaml:"http"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return Binds{}, err
	}
	return Binds{DNSBindHosts: doc.DNS.BindHosts, DNSPort: doc.DNS.Port, HTTPAddress: doc.HTTP.Address}, nil
}

// Apply rewrites raw with the given binds, preserving the rest of the document
// (comments included, thanks to the yaml.v3 node API).
func Apply(raw []byte, b Binds) ([]byte, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil, fmt.Errorf("AdGuardHome.yaml is not a mapping document")
	}
	top := root.Content[0]
	if top.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("AdGuardHome.yaml top level is not a mapping")
	}
	dns := ensureMap(top, "dns")
	hosts := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, h := range b.DNSBindHosts {
		hosts.Content = append(hosts.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: h})
	}
	setKey(dns, "bind_hosts", hosts)
	setKey(dns, "port", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprint(b.DNSPort)})
	httpm := ensureMap(top, "http")
	setKey(httpm, "address", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: b.HTTPAddress})
	return yaml.Marshal(&root)
}

// ApplyFile reads, edits and writes a file in place (mode preserved).
func ApplyFile(path string, b Binds) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	out, err := Apply(raw, b)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, st.Mode().Perm())
}

func ensureMap(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			if m.Content[i+1].Kind != yaml.MappingNode {
				m.Content[i+1] = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			}
			return m.Content[i+1]
		}
	}
	k := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	v := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	m.Content = append(m.Content, k, v)
	return v
}

func setKey(m *yaml.Node, key string, val *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			// Keep the comment attached to the key line.
			val.HeadComment = m.Content[i+1].HeadComment
			val.LineComment = m.Content[i+1].LineComment
			m.Content[i+1] = val
			return
		}
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, val)
}
