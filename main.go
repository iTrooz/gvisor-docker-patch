package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	tableName             = "copilot_inject"
	chainName             = "output_dns_dnat"
	netlinkRequestTimeout = 5 * time.Second
)

var (
	localDNSv4 = net.ParseIP("127.0.0.11").To4()
	dnsPort    = []byte{0x00, 0x35}
)

func main() {
	fmt.Println("installing DNS nftables redirect rule for Docker")

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if err := patchDNS(); err != nil {
		fmt.Fprintf(os.Stderr, "inject failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("DNS nftables redirect rule installed")
}

func patchDNS() error {
	log.Printf("connecting to nftables")
	conn, err := nftables.New(nftables.WithSockOptions(func(c *netlink.Conn) error {
		deadline := time.Now().Add(netlinkRequestTimeout)
		return c.SetDeadline(deadline)
	}))
	if err != nil {
		return fmt.Errorf("open nftables netlink connection: %w", err)
	}

	table, err := ensureTable(conn, tableName, nftables.TableFamilyIPv4)
	if err != nil {
		return err
	}
	log.Printf("using table family=%v name=%q", table.Family, table.Name)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables %s failed (need CAP_NET_ADMIN): %w", "table setup", err)
	}

	chain, err := ensureOutputNATChain(conn, table, chainName)
	if err != nil {
		return err
	}
	log.Printf("using chain name=%q hook=output type=nat", chain.Name)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables %s failed (need CAP_NET_ADMIN): %w", "chain setup", err)
	}

	gateway, err := defaultGatewayIPv4FromProc()
	if err != nil {
		return fmt.Errorf("discover default gateway: %w", err)
	}
	log.Printf("adding redirect rules: daddr=127.0.0.11 dport=53 -> %s:53", gateway.String())

	addDNSDNATRule(conn, table, chain, gateway, unix.IPPROTO_UDP)
	addDNSDNATRule(conn, table, chain, gateway, unix.IPPROTO_TCP)

	log.Printf("applying nftables redirect rule")
	if err := conn.Flush(); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("nftables rule apply failed: DNAT expression unsupported in this runtime/kernel path (ENOENT), even though base nft may work for simpler rules: %w", err)
		}
		return fmt.Errorf("nftables %s failed (need CAP_NET_ADMIN): %w", "rule apply", err)
	}
	log.Printf("nftables changes applied successfully")

	return nil
}

func addDNSDNATRule(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain, gateway net.IP, proto uint8) {
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// Match IPv4 protocol (UDP/TCP).
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
			// Match destination address = Docker embedded DNS resolver.
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: localDNSv4},
			// Match destination port = 53 (DNS).
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: dnsPort},
			// Load destination rewrite values into registers used by NAT expression.
			&expr.Immediate{Register: 1, Data: gateway.To4()},
			&expr.Immediate{Register: 2, Data: dnsPort},
			&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1, RegProtoMin: 2, Specified: true},
		},
	})
}

func defaultGatewayIPv4FromProc() (net.IP, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "Iface") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if fields[1] != "00000000" {
			continue
		}

		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil {
			continue
		}
		if flags&0x2 == 0 { // RTF_GATEWAY
			continue
		}

		gateway, err := strconv.ParseUint(fields[2], 16, 32)
		if err != nil {
			continue
		}

		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(gateway))
		return net.IPv4(b[0], b[1], b[2], b[3]).To4(), nil
	}

	if err := s.Err(); err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("default gateway route not found")
}

func ensureTable(conn *nftables.Conn, name string, family nftables.TableFamily) (*nftables.Table, error) {
	tables, err := conn.ListTables()
	if err != nil {
		return nil, fmt.Errorf("list nftables tables: %w", err)
	}

	for _, t := range tables {
		if t.Name == name && t.Family == family {
			log.Printf("found existing table %q", name)
			return t, nil
		}
	}

	t := &nftables.Table{Name: name, Family: family}
	log.Printf("creating table %q", name)
	conn.AddTable(t)
	return t, nil
}

func ensureOutputNATChain(conn *nftables.Conn, table *nftables.Table, name string) (*nftables.Chain, error) {
	chains, err := conn.ListChains()
	if err != nil {
		return nil, fmt.Errorf("list nftables chains: %w", err)
	}

	for _, c := range chains {
		if c.Table != nil && c.Table.Name == table.Name && c.Table.Family == table.Family && c.Name == name && c.Type == nftables.ChainTypeNAT && c.Hooknum != nil && *c.Hooknum == *nftables.ChainHookOutput {
			log.Printf("found existing chain %q", name)
			return c, nil
		}
	}

	priority := nftables.ChainPriorityNATDest
	policy := nftables.ChainPolicyAccept
	c := &nftables.Chain{
		Name:     name,
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookOutput,
		Priority: priority,
		Policy:   &policy,
	}
	log.Printf("creating chain %q on output hook", name)
	conn.AddChain(c)
	return c, nil
}
