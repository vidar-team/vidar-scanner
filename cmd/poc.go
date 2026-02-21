package cmd

import (
	"fmt"
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
	Short: "Scan a target with a local YAML POC",
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(pocURL) == "" {
			return fmt.Errorf("missing -u/--url")
		}
		if strings.TrimSpace(pocTemplate) == "" {
			return fmt.Errorf("missing -t/--template")
		}

		spec, err := PocEngine.LoadSpecFromFile(pocTemplate)
		if err != nil {
			return err
		}

		client := PocEngine.NewDefaultHTTPClient(pocTimeout)
		res, err := PocEngine.RunOnce(client, pocURL, spec)
		if err != nil {
			return err
		}

		id := strings.TrimSpace(spec.ID)
		if id == "" {
			id = "unknown"
		}

		if res.Matched {
			fmt.Printf("[+] MATCHED  id=%s  reason=%s\n", id, res.Reason)
		} else {
			fmt.Printf("[-] NOT MATCHED  id=%s  reason=%s\n", id, res.Reason)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(pocCmd)
	pocCmd.Flags().StringVarP(&pocURL, "url", "u", "", "target base url, e.g. https://example.com")
	pocCmd.Flags().StringVarP(&pocTemplate, "template", "t", "", "path to YAML poc template")
	pocCmd.Flags().DurationVar(&pocTimeout, "timeout", 8*time.Second, "http timeout")
}
