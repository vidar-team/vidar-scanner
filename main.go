package main

import (
	"fmt"
	"os"

	"vidar-scan/Scanner" // 导入你的 getscan 包
)

func main() {
	// os.Args 是一个包含所有命令行参数的列表
	// os.Args[0] 是程序的名称（例如 "main" 或 "vidar-scan"）
	// os.Args[1] 是我们想要的 URL
	// os.Args[2] 是我们想要的文件名

	// 检查用户是否提供了足够的参数
	if len(os.Args) != 3 {
		fmt.Println("错误: 参数不足！")
		fmt.Println("使用方法: go run . <target-url> <dictionary-file>")
		fmt.Println("例如: go run . http://example.com/ /path/to/dict.txt")
		os.Exit(1) // 退出程序
	}

	// 1. 从命令行获取 URL
	targetUrl := os.Args[1]

	// 2. 从命令行获取文件名
	dictFilename := os.Args[2]

	fmt.Printf("[INFO] 开始扫描...\n")
	fmt.Printf("[INFO] 目标 URL: %s\n", targetUrl)
	fmt.Printf("[INFO] 使用字典: %s\n", dictFilename)

	// 3. 调用你的 Getscan 函数
	scanner.Getscan(targetUrl, dictFilename)

	fmt.Printf("[INFO] 扫描结束。\n")
}