package PocEngine

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// RunResult 执行结果结构
type RunResult struct {
	Matched    bool
	Reason     string
	Fields     map[string]string
	RequestRaw string
	TemplateID string
	Severity   string
}

// PocSpec 模板结构（兼容旧接口）
type PocSpec struct {
	ID string
}

// Matcher 匹配器结构（兼容旧接口定义）
type Matcher struct {
	Type      string
	Part      string
	Condition string
	Status    []int
	Words     []string
	Regex     []string
}

// Extractor 提取器结构（兼容旧接口定义）
type Extractor struct {
	Type  string
	Name  string
	Regex string
	Group int
}

// PocRequest 请求结构（兼容旧接口定义）
type PocRequest struct {
	Method            string
	Path              []string
	Headers           map[string]string
	Body              string
	MatchersCondition string
	Matchers          []Matcher
	Extractors        []Extractor
}

// NewDefaultHTTPClient 创建默认HTTP客户端
func NewDefaultHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

// LoadSpecFromFile 加载模板文件（兼容旧接口）
func LoadSpecFromFile(path string) (*PocSpec, error) {
	return &PocSpec{}, nil
}

// RunOnce 执行单个模板（兼容旧接口，建议使用RunWithTemplates）
func RunOnce(client *http.Client, baseURL string, spec *PocSpec) (*RunResult, error) {
	return &RunResult{
		Matched: false,
		Reason:  "use RunWithTemplates for better performance",
	}, nil
}

// RunWithTemplates 使用Nuclei SDK批量执行模板
func RunWithTemplates(target string, templatePaths []string, timeout time.Duration, callback func(*RunResult)) (int, int, int, error) {
	// 创建Nuclei引擎
	ne, err := nuclei.NewNucleiEngine(
		nuclei.WithTemplatesOrWorkflows(
			nuclei.TemplateSources{
				Templates: templatePaths,
			},
		),
		nuclei.WithConcurrency(nuclei.Concurrency{
			TemplateConcurrency:         25,
			HostConcurrency:             25,
			HeadlessHostConcurrency:     10,
			HeadlessTemplateConcurrency: 10,
			JavascriptTemplateConcurrency: 25,
			TemplatePayloadConcurrency:  25,
			ProbeConcurrency:            50,
		}),
		nuclei.WithGlobalRateLimit(150, time.Second),
	)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to create nuclei engine: %w", err)
	}

	// 统计计数
	var total, matched, failed int
	var mu sync.Mutex

	// 加载目标
	ne.LoadTargets([]string{target}, false)

	// 执行扫描并处理回调
	err = ne.ExecuteWithCallback(func(event *output.ResultEvent) {
		mu.Lock()
		total++
		mu.Unlock()

		result := convertResult(event)
		if result.Matched {
			mu.Lock()
			matched++
			mu.Unlock()
		}

		if callback != nil {
			callback(result)
		}
	})

	// 关闭引擎
	ne.Close()

	if err != nil {
		failed = total - matched
	}

	return total, matched, failed, err
}

// RunWithTemplatesThreadSafe 线程安全的批量执行（支持多目标并发）
func RunWithTemplatesThreadSafe(targets []string, templatePaths []string, timeout time.Duration, callback func(*RunResult)) (int, int, int, error) {
	// 创建线程安全的Nuclei引擎
	ne, err := nuclei.NewThreadSafeNucleiEngine()
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to create thread-safe nuclei engine: %w", err)
	}
	defer ne.Close()

	var total, matched, failed int
	var mu sync.Mutex
	wg := &sync.WaitGroup{}

	// 对每个目标执行扫描
	for _, target := range targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()

			err := ne.ExecuteNucleiWithOpts(
				[]string{t},
				nuclei.WithTemplatesOrWorkflows(
					nuclei.TemplateSources{
						Templates: templatePaths,
					},
				),
			)

			mu.Lock()
			total++
			if err != nil {
				failed++
			}
			mu.Unlock()
		}(target)
	}

	wg.Wait()

	return total, matched, failed, nil
}

// convertResult 将Nuclei的ResultEvent转换为RunResult
func convertResult(event *output.ResultEvent) *RunResult {
	severity := event.Info.SeverityHolder.Severity.String()

	result := &RunResult{
		Matched:    event.MatcherStatus,
		TemplateID: event.TemplateID,
		Reason:     event.Info.Name,
		Severity:   severity,
		Fields:     make(map[string]string),
	}

	// 处理提取的数据 - ExtractedResults是[]string
	if len(event.ExtractedResults) > 0 {
		for i, v := range event.ExtractedResults {
			result.Fields[fmt.Sprintf("extract_%d", i)] = v
		}
	}

	// 处理Metadata中的额外数据
	if len(event.Metadata) > 0 {
		for k, v := range event.Metadata {
			if strVal, ok := v.(string); ok {
				result.Fields[k] = strVal
			} else {
				result.Fields[k] = fmt.Sprintf("%v", v)
			}
		}
	}

	// 处理请求原始数据
	if event.Request != "" {
		result.RequestRaw = event.Request
	}

	return result
}

// FormatResult 格式化输出结果
func FormatResult(res *RunResult, filePath string) string {
	var sb strings.Builder

	if res.Matched {
		sb.WriteString(fmt.Sprintf("[+] MATCHED  id=%s  file=%s  severity=%s\n",
			res.TemplateID, filePath, res.Severity))
		sb.WriteString(fmt.Sprintf("    reason=%s\n", res.Reason))

		if res.RequestRaw != "" {
			sb.WriteString("----- request -----\n")
			sb.WriteString(res.RequestRaw)
			sb.WriteString("\n-------------------\n")
		}

		if len(res.Fields) > 0 {
			for k, v := range res.Fields {
				sb.WriteString(fmt.Sprintf("    %s: %s\n", k, v))
			}
		}
	} else {
		sb.WriteString(fmt.Sprintf("[-] NOT MATCHED  id=%s  file=%s  reason=%s\n",
			res.TemplateID, filePath, res.Reason))
	}

	return sb.String()
}