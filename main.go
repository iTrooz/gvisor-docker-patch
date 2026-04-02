package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	tableName             = "copilot_inject"
	chainName             = "output_specific"
	netlinkRequestTimeout = 5 * time.Second
)

func main() {
	fmt.Println("installing DNS nftables rule for Docker..")

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if err := injectSpecificNftRule(); err != nil {
		fmt.Fprintf(os.Stderr, "inject failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("DNS nftables rule installed")
}

func injectSpecificNftRule() error {
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

	chain, err := ensureOutputFilterChain(conn, table, chainName)
	if err != nil {
		return err
	}
	log.Printf("using chain name=%q hook=output type=filter", chain.Name)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables %s failed (need CAP_NET_ADMIN): %w", "chain setup", err)
	}

	resolver := net.ParseIP("8.8.8.8").To4()
	if resolver == nil {
		return fmt.Errorf("invalid resolver IPv4 address")
	}
	log.Printf("adding rule: udp daddr=%s dport=53 accept", resolver.String())

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// Match IPv4 protocol = UDP.
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
			// Match destination address = 8.8.8.8.
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: resolver},
			// Match destination port = 53 (DNS).
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x00, 0x35}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	log.Printf("applying nftables rule")
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables %s failed (need CAP_NET_ADMIN): %w", "rule apply", err)
	}
	log.Printf("nftables changes applied successfully")

	return nil
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

func ensureOutputFilterChain(conn *nftables.Conn, table *nftables.Table, name string) (*nftables.Chain, error) {
	chains, err := conn.ListChains()
	if err != nil {
		return nil, fmt.Errorf("list nftables chains: %w", err)
	}

	for _, c := range chains {
		if c.Table != nil && c.Table.Name == table.Name && c.Table.Family == table.Family && c.Name == name {
			log.Printf("found existing chain %q", name)
			return c, nil
		}
	}

	priority := nftables.ChainPriorityFilter
	c := &nftables.Chain{
		Name:     name,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: priority,
	}
	log.Printf("creating chain %q on output hook", name)
	conn.AddChain(c)
	return c, nil
}
