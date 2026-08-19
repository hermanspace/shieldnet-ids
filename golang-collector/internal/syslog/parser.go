// parser.go bertugas mengurai pesan syslog mentah dari router MikroTik
// menjadi struct terstruktur yang dapat disimpan ke database dan dianalisis.
// Format syslog MikroTik berbeda dengan syslog standar sehingga perlu parser khusus.
package syslog

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"thesis-ids/golang-collector/internal/database"
)

// pola regex untuk mengekstrak informasi dari berbagai format syslog MikroTik
var (
	// Pola untuk syslog firewall MikroTik: "src-mac XX, proto TCP, IP:port->IP:port"
	reFirewall = regexp.MustCompile(
		`(?i)proto\s+(\w+)[^,]*,\s*([\d.]+):(\d+)->([\d.]+):(\d+)`,
	)

	// Pola untuk syslog login gagal: "login failure for user X from IP"
	reLoginFail = regexp.MustCompile(
		`(?i)login\s+failure.*?from\s+([\d.]+)`,
	)

	// Pola untuk mengekstrak IP sumber dari format umum
	reSourceIP = regexp.MustCompile(`([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})`)
)

// ParsedSyslog menyimpan hasil parsing satu pesan syslog MikroTik.
type ParsedSyslog struct {
	SourceIP   string
	SourcePort int
	DestPort   int
	Protocol   string
	EventType  string
}

// Parse mengurai pesan syslog mentah menjadi struct terstruktur.
// Fungsi ini mencoba beberapa pola regex secara berurutan sesuai format MikroTik.
func Parse(rawMessage string, nodeID, nodeIP string) database.Syslog {
	syslog := database.Syslog{
		Time:       time.Now(),
		NodeID:     nodeID,
		NodeIP:     nodeIP,
		RawMessage: rawMessage,
		EventType:  classifyEvent(rawMessage),
	}

	// Coba parse sebagai pesan firewall (paling umum dari MikroTik)
	if matches := reFirewall.FindStringSubmatch(rawMessage); len(matches) >= 6 {
		syslog.Protocol = strings.ToUpper(matches[1])
		syslog.SourceIP = matches[2]
		syslog.SourcePort = toInt(matches[3])
		syslog.DestPort = toInt(matches[5])
		return syslog
	}

	// Coba parse sebagai pesan login gagal
	if matches := reLoginFail.FindStringSubmatch(rawMessage); len(matches) >= 2 {
		syslog.SourceIP = matches[1]
		syslog.Protocol = "TCP"
		syslog.DestPort = 22 // Asumsikan SSH
		return syslog
	}

	// Fallback: ambil IP pertama yang ditemukan sebagai source IP
	if matches := reSourceIP.FindAllString(rawMessage, -1); len(matches) > 0 {
		// Abaikan IP yang terlihat seperti IP lokal server (biasanya 127.x.x.x)
		for _, ip := range matches {
			if !strings.HasPrefix(ip, "127.") {
				syslog.SourceIP = ip
				break
			}
		}
	}

	// Jika tidak bisa parse IP, gunakan placeholder
	if syslog.SourceIP == "" {
		syslog.SourceIP = "0.0.0.0"
	}

	return syslog
}

// classifyEvent menentukan tipe event berdasarkan isi pesan syslog.
// Klasifikasi ini membantu analisis dan filtering di dashboard.
func classifyEvent(message string) string {
	lower := strings.ToLower(message)

	switch {
	case strings.Contains(lower, "login failure") || strings.Contains(lower, "login fail"):
		return "login_fail"
	case strings.Contains(lower, "port scan") || strings.Contains(lower, "portscan"):
		return "port_scan"
	case strings.Contains(lower, "brute"):
		return "brute_force"
	case strings.Contains(lower, "syn flood") || strings.Contains(lower, "syn-flood"):
		return "syn_flood"
	case strings.Contains(lower, "firewall") || strings.Contains(lower, "blocked") || strings.Contains(lower, "dropped"):
		return "firewall_block"
	case strings.Contains(lower, "access denied"):
		return "access_denied"
	default:
		return "general"
	}
}

// toInt mengkonversi string menjadi integer, mengembalikan 0 jika gagal.
func toInt(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}
