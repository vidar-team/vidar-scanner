package PocEngine

type PocSpec struct {
	ID       string       `yaml:"id"`
	Requests []PocRequest `yaml:"request"`
}

type PocRequest struct {
	Name    string            `yaml:"name"`
	Method  string            `yaml:"method"`
	Path    []string          `yaml:"path"`
	Headers map[string]string `yaml:"header"`
	Body    string            `yaml:"body"`

	MatchersCondition string    `yaml:"matchers-condition"`
	Matchers          []Matcher `yaml:"matchers"`
}

type Matcher struct {
	Type      string   `yaml:"type"`
	Part      string   `yaml:"part"`
	Condition string   `yaml:"condition"`
	Status    []int    `yaml:"status"`
	Words     []string `yaml:"words"`
	Regex     []string `yaml:"regex"`
}
