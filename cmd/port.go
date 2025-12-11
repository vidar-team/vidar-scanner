/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"
	"vidar-scan/Scanner"
	"vidar-scan/basework"

	"github.com/spf13/cobra"
)

var (
	PortTargetUrl string
	PortRange     string
)

// portCmd represents the port command
var portCmd = &cobra.Command{
	Use:   "port",
	Short: "port scanning",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		StartPort, EndPort, err := basework.ParsePort(PortRange)

		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Printf("[INFO] 开始端口扫描...\n")
		fmt.Printf("[INFO] 目标 URL: %s\n", PortTargetUrl)
		fmt.Printf("[INFO] 端口范围: %d-%d\n", StartPort, EndPort)

		scanner.PortScan(PortTargetUrl, StartPort, EndPort)

		fmt.Printf("[INFO] 端口扫描结束。\n")

	},
}

func init() {
	rootCmd.AddCommand(portCmd)

	portCmd.Flags().StringVarP(&PortTargetUrl, "url", "u", "", "Target URL (required)")
	portCmd.Flags().StringVarP(&PortRange, "port", "p", "0-65535", "Port range")

	portCmd.MarkFlagRequired("url")
}
