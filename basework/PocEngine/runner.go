package PocEngine

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

type RunResult struct {
	Matched    bool
	Reason     string
	Fields     map[string]string
	RequestRaw string
}

func normalizeKey(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if r == '\ufeff' || r == '\u200b' || r == '\u200c' || r == '\u200d' {
			return -1
		}
		if unicode.Is(unicode.Cf, r) {
			return -1
		}
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
	return strings.ToLower(s)
}

func LoadSpecFromFile(path string) (*PocSpec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		b = b[3:]
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("yaml root is not a mapping")
	}
	root := doc.Content[0]

	var id string
	var reqNode *yaml.Node

	for i := 0; i+1 < len(root.Content); i += 2 {
		k := root.Content[i]
		v := root.Content[i+1]

		nk := normalizeKey(k.Value)
		if nk == "id" {
			id = v.Value
		}
		if nk == "requests" || nk == "request" {
			reqNode = v
		}
	}

	if reqNode == nil {
		return nil, fmt.Errorf("yaml has no requests (top-level keys include id/requests but key may contain invisible chars)")
	}
	if reqNode.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("requests must be a YAML list")
	}

	tmpBytes, err := yaml.Marshal(reqNode)
	if err != nil {
		return nil, err
	}
	var reqs []PocRequest
	if err := yaml.Unmarshal(tmpBytes, &reqs); err != nil {
		return nil, err
	}
	if len(reqs) == 0 {
		return nil, fmt.Errorf("requests decoded to empty list (check indentation / tabs)")
	}

	return &PocSpec{ID: id, Requests: reqs}, nil
}

func NewDefaultHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

func RunOnce(client *http.Client, baseURL string, spec *PocSpec) (*RunResult, error) {
	req0 := spec.Requests[0]

	method := strings.ToUpper(strings.TrimSpace(req0.Method))
	if method == "" {
		method = "GET"
	}
	if len(req0.Path) == 0 {
		return nil, fmt.Errorf("request path is empty")
	}

	url := strings.TrimRight(baseURL, "/") + req0.Path[0]

	var bodyReader io.Reader
	if req0.Body != "" {
		bodyReader = bytes.NewBufferString(req0.Body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	for k, v := range req0.Headers {
		req.Header.Set(k, v)
	}

	reqDump := buildRequestRaw(method, url, req0.Headers, req0.Body)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	respBody := string(respBodyBytes)

	ok, reason, err := evalMatchers(resp, respBody, req0.MatchersCondition, req0.Matchers)
	if err != nil {
		return nil, err
	}

	res := &RunResult{
		Matched:    ok,
		Reason:     reason,
		RequestRaw: reqDump,
	}
	if ok && len(req0.Extractors) > 0 {
		fields, err := runExtractors(respBody, req0.Extractors)
		if err != nil {
			return nil, err
		}
		res.Fields = fields
	}
	return res, nil
}

func evalMatchers(resp *http.Response, body string, cond string, ms []Matcher) (bool, string, error) {
	if len(ms) == 0 {
		return false, "no matchers", nil
	}
	cond = strings.ToLower(strings.TrimSpace(cond))
	if cond == "" {
		cond = "and"
	}
	if cond != "and" && cond != "or" {
		return false, "", fmt.Errorf("invalid matchers-condition: %s", cond)
	}

	passCount := 0
	for i, m := range ms {
		ok, err := evalOneMatcher(resp, body, m)
		if err != nil {
			return false, "", fmt.Errorf("matcher[%d] error: %w", i, err)
		}
		if ok {
			passCount++
		} else if cond == "and" {
			return false, fmt.Sprintf("matcher[%d] failed", i), nil
		}
	}

	if cond == "or" {
		if passCount > 0 {
			return true, "matched (or)", nil
		}
		return false, "no matcher matched (or)", nil
	}

	return passCount == len(ms), "matched (and)", nil
}

func evalOneMatcher(resp *http.Response, body string, m Matcher) (bool, error) {
	t := strings.ToLower(strings.TrimSpace(m.Type))
	part := strings.ToLower(strings.TrimSpace(m.Part))
	if part == "" {
		part = "body"
	}

	switch t {
	case "status":
		if len(m.Status) == 0 {
			return false, fmt.Errorf("status matcher needs status[]")
		}
		for _, code := range m.Status {
			if resp.StatusCode == code {
				return true, nil
			}
		}
		return false, nil

	case "word":
		if part != "body" {
			return false, fmt.Errorf("word matcher only supports part=body")
		}
		if len(m.Words) == 0 {
			return false, fmt.Errorf("word matcher needs words[]")
		}
		inner := strings.ToLower(strings.TrimSpace(m.Condition))
		if inner == "" {
			inner = "and"
		}
		if inner != "and" && inner != "or" {
			return false, fmt.Errorf("invalid matcher.condition: %s", inner)
		}

		hit := 0
		for _, w := range m.Words {
			if strings.Contains(body, w) {
				hit++
			} else if inner == "and" {
				return false, nil
			}
		}
		if inner == "or" {
			return hit > 0, nil
		}
		return hit == len(m.Words), nil

	case "regex":
		if part != "body" {
			return false, fmt.Errorf("regex matcher only supports part=body")
		}
		if len(m.Regex) == 0 {
			return false, fmt.Errorf("regex matcher needs regex[]")
		}
		inner := strings.ToLower(strings.TrimSpace(m.Condition))
		if inner == "" {
			inner = "and"
		}
		if inner != "and" && inner != "or" {
			return false, fmt.Errorf("invalid matcher.condition: %s", inner)
		}

		hit := 0
		for _, r := range m.Regex {
			re, err := regexp.Compile(r)
			if err != nil {
				return false, err
			}
			if re.MatchString(body) {
				hit++
			} else if inner == "and" {
				return false, nil
			}
		}
		if inner == "or" {
			return hit > 0, nil
		}
		return hit == len(m.Regex), nil

	default:
		return false, fmt.Errorf("unknown matcher type: %s", m.Type)
	}
}

func runExtractors(body string, extractors []Extractor) (map[string]string, error) {
	out := map[string]string{}
	for i, ex := range extractors {
		typ := strings.ToLower(strings.TrimSpace(ex.Type))
		if typ == "" {
			continue
		}
		switch typ {
		case "regex":
			name := strings.TrimSpace(ex.Name)
			if name == "" {
				return nil, fmt.Errorf("extractor[%d] missing name", i)
			}
			pat := ex.Regex
			if strings.TrimSpace(pat) == "" {
				return nil, fmt.Errorf("extractor[%d] missing regex", i)
			}
			g := ex.Group
			if g <= 0 {
				g = 1
			}
			re, err := regexp.Compile(pat)
			if err != nil {
				return nil, fmt.Errorf("extractor[%d] regex compile error: %w", i, err)
			}
			m := re.FindStringSubmatch(body)
			if len(m) > g {
				out[name] = m[g]
			}
		default:
			return nil, fmt.Errorf("unknown extractor type: %s", ex.Type)
		}
	}
	return out, nil
}

func buildRequestRaw(method, url string, headers map[string]string, body string) string {
	var sb strings.Builder
	sb.WriteString(method)
	sb.WriteString(" ")
	sb.WriteString(url)
	sb.WriteString("\n")

	if len(headers) > 0 {
		for k, v := range headers {
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteString("\n")
		}
	}

	sb.WriteString("\n")
	if body != "" {
		sb.WriteString(body)
	}
	return sb.String()
}
