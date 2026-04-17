package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"vidar-scan/basework/PocEngine"

	"github.com/spf13/cobra"
)

var (
	pocURL      string
	pocTemplate string
	pocTimeout  time.Duration
)

var pocCmd = &cobra.Command{
	Use:   "poc",
	Short: "Scan a target with local YAML POCs (file or directory) using Nuclei SDK",
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(pocURL) == "" {
			return fmt.Errorf("missing -u/--url")
		}
		if strings.TrimSpace(pocTemplate) == "" {
			return fmt.Errorf("missing -t/--template")
		}

		paths, err := expandTemplates(pocTemplate)
		if err != nil {
			return err
		}
		if len(paths) == 0 {
			return fmt.Errorf("no yaml templates found: %s", pocTemplate)
		}

		fmt.Printf("Loaded %d templates from %s\n", len(paths), pocTemplate)
		fmt.Println("-----START-----")

		// 使用Nuclei SDK批量执行模板
		total, matched, failed, err := PocEngine.RunWithTemplates(
			pocURL,
			paths,
			pocTimeout,
			func(res *PocEngine.RunResult) {
				// 处理每个结果
				id := res.TemplateID
				if id == "" {
					id = "unknown"
				}

				// 找到对应的模板文件路径
				filePath := findTemplatePath(paths, id)

				if res.Matched {
					fmt.Printf("[+] MATCHED  id=%s  file=%s  severity=%s\n",
						id, filePath, res.Severity)
					fmt.Printf("    reason=%s\n", res.Reason)

					if res.RequestRaw != "" {
						fmt.Println("----- request -----")
						fmt.Print(res.RequestRaw)
						fmt.Println("\n-------------------")
					}

					if len(res.Fields) > 0 {
						for k, v := range res.Fields {
							fmt.Printf("    %s: %s\n", k, v)
						}
					}
				} else {
					fmt.Printf("[-] NOT MATCHED  id=%s  file=%s  reason=%s\n",
						id, filePath, res.Reason)
				}
			},
		)

		fmt.Println("-----OVER-----")

		if err != nil {
			fmt.Printf("[!] Error: %v\n", err)
		}

		fmt.Printf("\n== SUMMARY == total=%d matched=%d failed=%d\n", total, matched, failed)
		return nil
	},
}

// expandTemplates 扩展模板路径（支持单文件或目录）
func expandTemplates(path string) ([]string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	// 单文件
	if !fi.IsDir() {
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil, fmt.Errorf("template must be .yaml/.yml: %s", path)
		}
		return []string{path}, nil
	}

	// 目录递归
	var out []string
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext == ".yaml" || ext == ".yml" {
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Strings(out)
	return out, nil
}

// findTemplatePath 根据模板ID查找文件路径（简化版）
func findTemplatePath(paths []string, templateID string) string {
	// Nuclei返回的是模板ID，我们需要找到对应的文件
	// 这里简化处理，返回第一个匹配的路径或空
	for _, p := range paths {
		// 可以根据文件名或内容匹配，这里简化
		base := filepath.Base(p)
		if strings.Contains(base, templateID) || strings.Contains(templateID, base) {
			return p
		}
	}
	// 如果找不到，返回"unknown"
	if len(paths) > 0 {
		return paths[0]
	}
	return "unknown"
}

func init() {
	rootCmd.AddCommand(pocCmd)
	pocCmd.Flags().StringVarP(&pocURL, "url", "u", "", "target base url, e.g. https://example.com")
	pocCmd.Flags().StringVarP(&pocTemplate, "template", "t", "", "path to YAML poc template OR a directory containing YAMLs")
	pocCmd.Flags().DurationVar(&pocTimeout, "timeout", 8*time.Second, "http timeout")
}
