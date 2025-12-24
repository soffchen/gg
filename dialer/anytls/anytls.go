package anytls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"sync"

	"github.com/mzz2017/gg/common"
	"github.com/mzz2017/gg/dialer"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"

	"anytls/proxy/padding"
	"anytls/proxy/session"
)

func init() {
	dialer.FromLinkRegister("anytls", NewAnyTLS)
	dialer.FromClashRegister("anytls", NewAnyTLSFromClashObj)
}

// AnyTLS represents anytls proxy configuration
type AnyTLS struct {
	Name          string `json:"name"`
	Server        string `json:"server"`
	Port          int    `json:"port"`
	Password      string `json:"password"`
	Sni           string `json:"sni"`
	AllowInsecure bool   `json:"allowInsecure"`
}

// NewAnyTLS creates a new dialer from anytls:// URL
func NewAnyTLS(link string, opt *dialer.GlobalOption) (*dialer.Dialer, error) {
	s, err := ParseAnyTLSURL(link)
	if err != nil {
		return nil, err
	}
	if opt.AllowInsecure {
		s.AllowInsecure = true
	}
	return s.Dialer()
}

// NewAnyTLSFromClashObj creates a new dialer from Clash configuration
func NewAnyTLSFromClashObj(o *yaml.Node, opt *dialer.GlobalOption) (*dialer.Dialer, error) {
	s, err := ParseClash(o)
	if err != nil {
		return nil, err
	}
	if opt.AllowInsecure {
		s.AllowInsecure = true
	}
	return s.Dialer()
}

// Dialer creates the actual proxy dialer
func (s *AnyTLS) Dialer() (*dialer.Dialer, error) {
	addr := net.JoinHostPort(s.Server, strconv.Itoa(s.Port))

	// Determine SNI
	sni := s.Sni
	if sni == "" {
		sni = s.Server
	}

	// Check if SNI is an IP address - if so, don't send SNI
	var serverName string
	if ip := net.ParseIP(sni); ip == nil {
		serverName = sni
	}

	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: s.AllowInsecure,
	}

	// Create password hash
	passwordHash := sha256.Sum256([]byte(s.Password))

	// Create the anytls dialer
	d := &anytlsDialer{
		addr:         addr,
		tlsConfig:    tlsConfig,
		passwordHash: passwordHash[:],
		name:         s.Name,
		protocol:     "anytls",
		link:         s.ExportToURL(),
	}

	return dialer.NewDialer(d, true, s.Name, "anytls", s.ExportToURL()), nil
}

// anytlsDialer implements proxy.Dialer interface
type anytlsDialer struct {
	addr         string
	tlsConfig    *tls.Config
	passwordHash []byte
	name         string
	protocol     string
	link         string

	clientOnce sync.Once
	client     *session.Client
}

func (d *anytlsDialer) initClient() {
	d.clientOnce.Do(func() {
		d.client = session.NewClient(
			context.Background(),
			d.dialTLS,
			&padding.DefaultPaddingFactory,
			0, // use default idle session check interval
			0, // use default idle session timeout
			0, // no minimum idle sessions
		)
	})
}

func (d *anytlsDialer) dialTLS(ctx context.Context) (net.Conn, error) {
	// Dial TCP
	var dialerNet net.Dialer
	conn, err := dialerNet.DialContext(ctx, "tcp", d.addr)
	if err != nil {
		return nil, err
	}

	// Wrap with TLS
	tlsConn := tls.Client(conn, d.tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}

	// Send password hash with padding
	// Get padding0 length from the padding scheme (packet 0)
	paddingF := padding.DefaultPaddingFactory.Load()
	pktSizes := paddingF.GenerateRecordPayloadSizes(0)
	paddingLen := 0
	if len(pktSizes) > 0 && pktSizes[0] > 0 {
		// Subtract the auth overhead (32 bytes hash + 2 bytes length = 34 bytes)
		paddingLen = pktSizes[0] - 34
		if paddingLen < 0 {
			paddingLen = 0
		}
	}

	authBuf := make([]byte, 32+2+paddingLen)
	copy(authBuf[:32], d.passwordHash)
	authBuf[32] = byte(paddingLen >> 8)
	authBuf[33] = byte(paddingLen)
	// padding bytes can be zero

	if _, err := tlsConn.Write(authBuf); err != nil {
		tlsConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

// Dial implements proxy.Dialer interface
func (d *anytlsDialer) Dial(network, addr string) (net.Conn, error) {
	d.initClient()

	// Create a stream through the session pool
	stream, err := d.client.CreateStream(context.Background())
	if err != nil {
		return nil, fmt.Errorf("[anytls]: create stream: %w", err)
	}

	// Send SOCKS address format target
	socksAddr, err := buildSocksAddr(addr)
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("[anytls]: build socks addr: %w", err)
	}

	if _, err := stream.Write(socksAddr); err != nil {
		stream.Close()
		return nil, fmt.Errorf("[anytls]: write socks addr: %w", err)
	}

	return stream, nil
}

// buildSocksAddr builds SOCKS5 address format
// Format: ATYP (1 byte) + Address + Port (2 bytes)
// ATYP: 0x01 = IPv4, 0x03 = Domain, 0x04 = IPv6
func buildSocksAddr(addr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	var buf []byte

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4
			buf = make([]byte, 1+4+2)
			buf[0] = 0x01
			copy(buf[1:5], ip4)
			buf[5] = byte(port >> 8)
			buf[6] = byte(port)
		} else {
			// IPv6
			buf = make([]byte, 1+16+2)
			buf[0] = 0x04
			copy(buf[1:17], ip.To16())
			buf[17] = byte(port >> 8)
			buf[18] = byte(port)
		}
	} else {
		// Domain
		if len(host) > 255 {
			return nil, fmt.Errorf("domain name too long: %s", host)
		}
		buf = make([]byte, 1+1+len(host)+2)
		buf[0] = 0x03
		buf[1] = byte(len(host))
		copy(buf[2:2+len(host)], host)
		buf[2+len(host)] = byte(port >> 8)
		buf[3+len(host)] = byte(port)
	}

	return buf, nil
}

// ParseAnyTLSURL parses anytls:// URL
// Format: anytls://auth@hostname[:port]/?sni=xxx&insecure=0|1
func ParseAnyTLSURL(u string) (*AnyTLS, error) {
	t, err := url.Parse(u)
	if err != nil {
		return nil, fmt.Errorf("invalid anytls format: %w", err)
	}

	if t.Scheme != "anytls" {
		return nil, fmt.Errorf("invalid scheme: %s", t.Scheme)
	}

	port := 443
	if t.Port() != "" {
		port, err = strconv.Atoi(t.Port())
		if err != nil {
			return nil, dialer.InvalidParameterErr
		}
	}

	password := ""
	if t.User != nil {
		password = t.User.Username()
	}

	sni := t.Query().Get("sni")
	insecure := t.Query().Get("insecure")

	return &AnyTLS{
		Name:          t.Fragment,
		Server:        t.Hostname(),
		Port:          port,
		Password:      password,
		Sni:           sni,
		AllowInsecure: common.StringToBool(insecure),
	}, nil
}

// ParseClash parses Clash/Mihomo configuration format
func ParseClash(o *yaml.Node) (*AnyTLS, error) {
	type AnyTLSOption struct {
		Name           string `yaml:"name"`
		Server         string `yaml:"server"`
		Port           int    `yaml:"port"`
		Password       string `yaml:"password"`
		SNI            string `yaml:"sni,omitempty"`
		SkipCertVerify bool   `yaml:"skip-cert-verify,omitempty"`
	}

	var option AnyTLSOption
	if err := o.Decode(&option); err != nil {
		return nil, err
	}

	return &AnyTLS{
		Name:          option.Name,
		Server:        option.Server,
		Port:          option.Port,
		Password:      option.Password,
		Sni:           option.SNI,
		AllowInsecure: option.SkipCertVerify,
	}, nil
}

// ExportToURL exports the configuration to anytls:// URL
func (s *AnyTLS) ExportToURL() string {
	u := &url.URL{
		Scheme:   "anytls",
		User:     url.User(s.Password),
		Host:     net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Fragment: s.Name,
	}

	q := u.Query()
	if s.Sni != "" && s.Sni != s.Server {
		q.Set("sni", s.Sni)
	}
	if s.AllowInsecure {
		q.Set("insecure", "1")
	}

	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}

	return u.String()
}

var _ proxy.Dialer = (*anytlsDialer)(nil)
