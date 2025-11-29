/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"vidar-scan/Scanner"

	"github.com/spf13/cobra"
)

var (
	DirTargetUrl   string
	DictionaryPath string
	Cookie         string
)

// dirCmd represents the dir command
var dirCmd = &cobra.Command{
	Use:   "dir",
	Short: "dir scanning",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("[INFO] 开始目录扫描...\n")
		fmt.Printf("[INFO] 目标 URL: %s\n", DirTargetUrl)
		fmt.Printf("[INFO] 使用字典: %s\n", DictionaryPath)

		scanner.Getscan(DirTargetUrl, DictionaryPath)

		fmt.Printf("[INFO] 目录扫描结束。\n")
	},
}

func init() {
	rootCmd.AddCommand(dirCmd)

	dirCmd.Flags().StringVarP(&DirTargetUrl, "url", "u", "", "Target URL (required)")
	dirCmd.Flags().StringVarP(&DictionaryPath, "dict", "d", "", "Dictionary Path (required)")
	dirCmd.Flags().StringVarP(&Cookie, "cookie", "c", "", "Cookie")

	dirCmd.MarkFlagRequired("url")
	dirCmd.MarkFlagRequired("dict")
}
