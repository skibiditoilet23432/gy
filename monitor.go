package server

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http/httputil"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/inancgumus/screen"
	"github.com/kor44/gofilter"
	"github.com/shirou/gopsutil/cpu"
	"golang.org/x/term"

	"goProxy/core/domains"
	"goProxy/core/firewall"
	"goProxy/core/pnc"
	"goProxy/core/proxy"
	"goProxy/core/utils"
)

var (
	PrintMutex = &sync.Mutex{}
	helpMode   = false
)

func Monitor() {
	defer pnc.PanicHndl()
	PrintMutex.Lock()
	screen.Clear()
	screen.MoveTopLeft()
	PrintMutex.Unlock()

	proxy.LastSecondTime = time.Now()
	proxy.LastSecondTimeFormated = proxy.LastSecondTime.Format("15:04:05")
	proxy.LastSecondTimestamp = int(proxy.LastSecondTime.Unix())
	proxy.Last10SecondTimestamp = utils.TrimTime(proxy.LastSecondTimestamp)
	proxy.CurrHour, _, _ = proxy.LastSecondTime.Clock()
	proxy.CurrHourStr = strconv.Itoa(proxy.CurrHour)

	go commands()
	go clearProxyCache()
	go generateOTPSecrets()
	go evaluateRatelimit()

	PrintMutex.Lock()
	fmt.Println("\033[" + fmt.Sprint(11+proxy.MaxLogLength) + ";1H")
	fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
	PrintMutex.Unlock()

	for {
		PrintMutex.Lock()
		tempWidth, tempHeight, _ := term.GetSize(int(os.Stdout.Fd()))
		proxy.TWidth = tempWidth + 18
		if tempHeight != proxy.THeight || tempWidth+18 != proxy.TWidth {
			proxy.THeight = tempHeight
			pHeight := tempHeight - 15
			proxy.MaxLogLength = max(0, pHeight)
			screen.Clear()
			screen.MoveTopLeft()
			fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
			fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
		}
		utils.ClearScreen(proxy.MaxLogLength)
		fmt.Print("\033[1;1H")
		firewall.Mutex.Lock()
		for name, data := range domains.DomainsData {
			checkAttack(name, data)
		}
		firewall.Mutex.Unlock()
		printStats()
		PrintMutex.Unlock()
		time.Sleep(1 * time.Second)
	}
}

func printStats() {
	proxy.LastSecondTime = time.Now()
	proxy.LastSecondTimeFormated = proxy.LastSecondTime.Format("15:04:05")
	proxy.LastSecondTimestamp = int(proxy.LastSecondTime.Unix())
	proxy.Last10SecondTimestamp = utils.TrimTime(proxy.LastSecondTimestamp)
	proxy.CurrHour, _, _ = proxy.LastSecondTime.Clock()
	proxy.CurrHourStr = strconv.Itoa(proxy.CurrHour)

	result, err := cpu.Percent(0, false)
	if err != nil {
		proxy.CpuUsage = "ERR"
	} else if len(result) > 0 {
		proxy.CpuUsage = fmt.Sprintf("%.2f%%", result[0])
	} else {
		proxy.CpuUsage = "100.00%"
	}

	var ramStats runtime.MemStats
	runtime.ReadMemStats(&ramStats)
	proxy.RamUsage = fmt.Sprintf("%.2f%%", float64(ramStats.Alloc)/float64(ramStats.Sys)*100)

	fmt.Println("┌────────────────────────────────────────────────┐")
	fmt.Printf("│ 🕒 Time       : %-31s │\n", proxy.LastSecondTimeFormated)
	fmt.Printf("│ 🧠 CPU Usage  : %-31s │\n", proxy.CpuUsage)
	fmt.Printf("│ 💾 RAM Usage  : %-31s │\n", proxy.RamUsage)
	fmt.Println("├────────────────────────────────────────────────┤")

	firewall.Mutex.Lock()
	domainData := domains.DomainsData[proxy.WatchedDomain]
	firewall.Mutex.Unlock()

	if domainData.Stage == 0 && proxy.WatchedDomain != "debug" {
		if proxy.WatchedDomain != "" {
			fmt.Printf("│ ⚠️  Domain \"%s\" not found\n", proxy.WatchedDomain)
		}
		fmt.Println("├────────────────────────────────────────────────┤")
		fmt.Println("│ 🌐 Available Domains                          │")
		for i, dName := range domains.Domains {
			if i < proxy.MaxLogLength {
				fmt.Printf("│   • %-40s │\n", dName)
			}
		}
		fmt.Println("└────────────────────────────────────────────────┘")
		return
	}

	if helpMode {
		fmt.Println("│ 📖 Commands                                     │")
		fmt.Println("├────────────────────────────────────────────────┤")
		fmt.Println("│ help         Show help                         │")
		fmt.Println("│ stage [n]    Lock stage                        │")
		fmt.Println("│ domain [d]   Switch domain                     │")
		fmt.Println("│ add          Add domain                        │")
		fmt.Println("│ rtlogs       Toggle real-time logs             │")
		fmt.Println("│ clrlogs      Clear logs                        │")
		fmt.Println("│ cachemode    Toggle cache                      │")
		fmt.Println("│ delcache     Clear cache                       │")
		fmt.Println("│ reload       Reload config                     │")
		fmt.Println("└────────────────────────────────────────────────┘")
		return
	}

	fmt.Printf("│ 🌐 Domain     : %-31s │\n", proxy.WatchedDomain)
	fmt.Printf("│ 🚦 Stage      : %-31d │\n", domainData.Stage)
	fmt.Printf("│ 🔒 Locked     : %-31t │\n", domainData.StageManuallySet)
	fmt.Println("├────────────────────────────────────────────────┤")
	fmt.Printf("│ 📈 Total RPS  : %-31d │\n", domainData.RequestsPerSecond)
	fmt.Printf("│ 🚪 Bypassed   : %-31d │\n", domainData.RequestsBypassedPerSecond)
	fmt.Println("├────────────────────────────────────────────────┤")
	fmt.Println("│ 📋 Latest Logs                                 │")
	for _, log := range domainData.LastLogs {
		trimmed := log
		if len(log)+4 > proxy.TWidth {
			trimmed = log[:len(log)-(len(log)+4-proxy.TWidth)] + " ..."
		}
		fmt.Printf("│   %s\n", trimmed)
	}
	fmt.Println("└────────────────────────────────────────────────┘")
	utils.MoveInputLine()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
