package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	spinnerStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("63"))
	helpStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Margin(1, 0)
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("161"))
	//infoStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("33"))
	appStyle = lipgloss.NewStyle().Margin(1, 2, 0, 2)
)

type Config struct {
	SessionURL string
	PingURL    string
	IPCheckURL string
}

type AccountInfo struct {
	UID       string `json:"uid"`
	BrowserID string `json:"browser_id"`
	Name      string `json:"name"`
}

type IPInfo struct {
	IP string `json:"ip"`
}

type StatusMsg struct {
	status string
	err    error
}

type model struct {
	spinner  spinner.Model
	messages []string
	quitting bool
}

func newModel() model {
	const numLastMessages = 10
	s := spinner.New()
	s.Style = spinnerStyle
	return model{
		spinner:  s,
		messages: make([]string, numLastMessages),
	}
}

func (m model) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" {
			m.quitting = true
			return m, tea.Quit
		}
		return m, nil // ignore other keys
	case StatusMsg:
		var statusText string
		if msg.err != nil {
			statusText = errorStyle.Render(fmt.Sprintf("❌ %s: %v", msg.status, msg.err))
		} else {
			statusText = successStyle.Render(fmt.Sprintf("✓ %s", msg.status))
		}
		m.messages = append(m.messages[1:], statusText)
		return m, nil
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	default:
		return m, nil
	}
}

func (m model) View() string {
	var s string

	if m.quitting {
		s += "Shutting down NodePay client..."
	} else {
		s += m.spinner.View() + " Running NodePay client..."
	}

	s += "\n\n"

	for _, msg := range m.messages {
		if msg != "" {
			s += msg + "\n"
		}
	}

	if !m.quitting {
		s += helpStyle.Render("Press 'q' to exit")
	}

	return appStyle.Render(s)
}

func setupClient(proxy string) *fasthttp.Client {
	client := &fasthttp.Client{
		ReadTimeout:        30 * time.Second,
		WriteTimeout:       30 * time.Second,
		MaxConnWaitTimeout: 30 * time.Second,
	}

	if proxy != "" {
		switch {
		case strings.HasPrefix(proxy, "http://"):
			client.Dial = fasthttpproxy.FasthttpHTTPDialer(proxy)
		case strings.HasPrefix(proxy, "socks5://"):
			client.Dial = fasthttpproxy.FasthttpSocksDialer(proxy)
		default:
			// user:pass@host:port format
			if strings.Contains(proxy, "@") {
				proxy = "socks5://" + proxy
			} else {
				// host:port format
				proxy = "socks5://" + proxy
			}
			client.Dial = fasthttpproxy.FasthttpSocksDialer(proxy)
		}
	}

	client.TLSConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	return client
}

func getProxyIP(client *fasthttp.Client, program *tea.Program, config Config) (string, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	req.SetRequestURI(config.IPCheckURL)
	req.Header.SetMethod("GET")

	if err := client.DoTimeout(req, resp, 30*time.Second); err != nil {
		return "", err
	}

	var ipInfo IPInfo
	if err := json.Unmarshal(resp.Body(), &ipInfo); err != nil {
		return "", err
	}

	return ipInfo.IP, nil
}

func getSession(client *fasthttp.Client, token string, config Config) (*AccountInfo, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	req.SetRequestURI(config.SessionURL)
	req.Header.SetMethod("POST")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")
	req.SetBody([]byte("{}"))

	if err := client.DoTimeout(req, resp, 30*time.Second); err != nil {
		return nil, err
	}

	var response struct {
		Data AccountInfo `json:"data"`
	}
	if err := json.Unmarshal(resp.Body(), &response); err != nil {
		return nil, err
	}

	return &response.Data, nil
}

func generateBrowserID(token string) string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s_%d", token, time.Now().UnixNano())))
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

func sendPing(client *fasthttp.Client, config Config, token string, accountInfo AccountInfo) error {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	req.SetRequestURI(config.PingURL)
	req.Header.SetMethod("POST")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	pingData := map[string]interface{}{
		"id":         accountInfo.UID,
		"browser_id": accountInfo.BrowserID,
		"timestamp":  int(time.Now().Unix()),
		"version":    "2.2.7",
	}

	pingJSON, err := json.Marshal(pingData)
	if err != nil {
		return err
	}

	req.SetBody(pingJSON)
	return client.DoTimeout(req, resp, 30*time.Second)
}

func connectAndPing(ctx context.Context, program *tea.Program, config Config, proxy, token string) {
	client := setupClient(proxy)

	capturedIP, err := getProxyIP(client, program, config)
	if err != nil {
		program.Send(StatusMsg{status: "IP Check Failed", err: err})
		return
	}
	program.Send(StatusMsg{status: fmt.Sprintf("Connected with IP: %s", capturedIP)})

	accountInfo, err := getSession(client, token, config)
	if err != nil {
		h := sha256.New()
		h.Write([]byte(token))
		accountInfo = &AccountInfo{
			UID:       fmt.Sprintf("%x", h.Sum(nil))[:16],
			BrowserID: generateBrowserID(token),
		}
		program.Send(StatusMsg{status: "Using fallback session", err: err})
	} else {
		if accountInfo.BrowserID == "" {
			accountInfo.BrowserID = generateBrowserID(token)
		}
		program.Send(StatusMsg{status: fmt.Sprintf("Session established for %s", accountInfo.Name)})
	}

	browserIDDisplay := accountInfo.BrowserID
	if len(browserIDDisplay) > 8 {
		browserIDDisplay = browserIDDisplay[:8]
	}

	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := sendPing(client, config, token, *accountInfo); err != nil {
				program.Send(StatusMsg{status: "Ping failed", err: err})
				continue
			}
			program.Send(StatusMsg{
				status: fmt.Sprintf("Ping sent - Browser: %s, IP: %s", browserIDDisplay, capturedIP),
			})
		}
	}
}

func readLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}

func main() {
	config := Config{
		SessionURL: "http://18.136.143.169/api/auth/session",
		PingURL:    "https://52.77.10.116/api/network/ping",
		IPCheckURL: "https://ipinfo.io/json",
	}

	tokens, err := readLines("token.txt")
	if err != nil {
		fmt.Printf("Error reading tokens: %v\n", err)
		return
	}

	proxies, err := readLines("proxy.txt")
	if err != nil {
		fmt.Printf("Error reading proxies: %v\n", err)
		return
	}

	if len(tokens) == 0 || len(proxies) == 0 {
		fmt.Println("No tokens or proxies found")
		return
	}

	p := tea.NewProgram(newModel())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup

	// mapping token to multiple proxy
	tokenProxies := make(map[string][]string)
	proxiesPerToken := len(proxies) / len(tokens)
	remainingProxies := len(proxies) % len(tokens)
	currentProxyIndex := 0

	// distribute proxy to each token
	for _, token := range tokens {
		numProxies := proxiesPerToken
		if remainingProxies > 0 {
			numProxies++
			remainingProxies--
		}

		tokenProxies[token] = proxies[currentProxyIndex : currentProxyIndex+numProxies]
		currentProxyIndex += numProxies
	}

	// run goroutine for each token-proxy
	for token, proxyList := range tokenProxies {
		for _, proxy := range proxyList {
			wg.Add(1)
			go func(t, proxy string) {
				defer wg.Done()
				connectAndPing(ctx, p, config, proxy, t)
			}(token, proxy)
		}
	}

	go func() {
		<-signals
		cancel()
	}()

	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running program: %v\n", err)
		os.Exit(1)
	}
}
