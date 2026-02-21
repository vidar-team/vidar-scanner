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
	Short: "Scan a target with local YAML POCs (file or directory)",
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

		client := PocEngine.NewDefaultHTTPClient(pocTimeout)

		total := 0
		matched := 0
		failed := 0

		for _, p := range paths {
			total++

			spec, err := PocEngine.LoadSpecFromFile(p)
			if err != nil {
				failed++
				fmt.Printf("[!] LOAD FAIL  file=%s  err=%v\n", p, err)
				continue
			}

			res, err := PocEngine.RunOnce(client, pocURL, spec)
			if err != nil {
				failed++
				id := strings.TrimSpace(spec.ID)
				if id == "" {
					id = "unknown"
				}
				fmt.Printf("[!] RUN FAIL   id=%s  file=%s  err=%v\n", id, p, err)
				continue
			}

			id := strings.TrimSpace(spec.ID)
			if id == "" {
				id = "unknown"
			}

			if res.Matched {
				matched++
				fmt.Printf("[+] MATCHED  id=%s  file=%s  reason=%s\n", id, p, res.Reason)

				if strings.TrimSpace(res.RequestRaw) != "" {
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
				fmt.Printf("[-] NOT MATCHED  id=%s  file=%s  reason=%s\n", id, p, res.Reason)
			}
		}

		fmt.Printf("\n== SUMMARY == total=%d matched=%d failed=%d\n", total, matched, failed)
		return nil
	},
}

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

func init() {
	rootCmd.AddCommand(pocCmd)
	pocCmd.Flags().StringVarP(&pocURL, "url", "u", "", "target base url, e.g. https://example.com")
	pocCmd.Flags().StringVarP(&pocTemplate, "template", "t", "", "path to YAML poc template OR a directory containing YAMLs")
	pocCmd.Flags().DurationVar(&pocTimeout, "timeout", 8*time.Second, "http timeout")
}
