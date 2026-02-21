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

	"gopkg.in/yaml.v3"
)

type RunResult struct {
	Matched bool
	Reason  string
}

func LoadSpecFromFile(path string) (*PocSpec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s PocSpec
	if err := yaml.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if len(s.Requests) == 0 {
		return nil, fmt.Errorf("yaml has no requests")
	}
	return &s, nil
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

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2MB
	respBody := string(respBodyBytes)

	ok, reason, err := evalMatchers(resp, respBody, req0.MatchersCondition, req0.Matchers)
	if err != nil {
		return nil, err
	}
	return &RunResult{Matched: ok, Reason: reason}, nil
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
