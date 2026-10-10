//go:build e2e

// Command exfil is the fixture of the E2E exfiltration probe (V1 F2, task
// E3, scripts/verify-e2e.sh section 2h). A test tool, behind the e2e build
// tag: never part of a previewd build.
//
//	exfil listen -addr IP -dir DIR
//	    binds TCP and UDP on one free port of IP (the host bridge gateway),
//	    writes it to DIR/port, and counts every TCP connection in DIR/tcp
//	    and every UDP datagram (a DNS query) in DIR/udp.
//	exfil control-build -context DIR -tag TAG
//	    builds DIR with BuildKit on the engine's default network: the build
//	    previewd never sends. Its RUN must reach the listener, or the E3
//	    checks prove nothing. The image is removed afterwards.
package main

import (
	"archive/tar"
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/moby/moby/api/types/build"
	"github.com/moby/moby/client"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: exfil listen -addr IP -dir DIR | exfil control-build -context DIR -tag TAG")
	}
	var err error
	switch os.Args[1] {
	case "listen":
		err = listen(os.Args[2:])
	case "control-build":
		err = controlBuild(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fatalf("exfil %s: %v", os.Args[1], err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// counter persists a count with an atomic rename, so a reader never sees a
// torn file.
type counter struct {
	path string
	n    atomic.Int64
}

func (c *counter) inc() error {
	n := c.n.Add(1)
	return writeAtomic(c.path, strconv.FormatInt(n, 10))
}

func writeAtomic(path, v string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(v), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s: %w", tmp, err)
	}
	return nil
}

func listen(args []string) error {
	fs := flag.NewFlagSet("listen", flag.ContinueOnError)
	addrFlag := fs.String("addr", "", "IP to bind")
	dir := fs.String("dir", "", "directory of the counters")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ip, err := netip.ParseAddr(*addrFlag)
	if err != nil || *dir == "" {
		return errors.New("-addr IP and -dir DIR are required")
	}
	tcpLn, udpConn, err := bindPair(ip)
	if err != nil {
		return err
	}
	tcp := &counter{path: filepath.Join(*dir, "tcp")}
	udp := &counter{path: filepath.Join(*dir, "udp")}
	for _, c := range []*counter{tcp, udp} {
		if err := writeAtomic(c.path, "0"); err != nil {
			return err
		}
	}
	port := tcpLn.Addr().(*net.TCPAddr).Port
	if err := writeAtomic(filepath.Join(*dir, "port"), strconv.Itoa(port)); err != nil {
		return err
	}
	errs := make(chan error, 2)
	go func() {
		for {
			conn, err := tcpLn.Accept()
			if err != nil {
				errs <- fmt.Errorf("accept: %w", err)
				return
			}
			_ = conn.Close()
			if err := tcp.inc(); err != nil {
				errs <- err
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 64<<10)
		for {
			if _, _, err := udpConn.ReadFrom(buf); err != nil {
				errs <- fmt.Errorf("read datagram: %w", err)
				return
			}
			if err := udp.inc(); err != nil {
				errs <- err
				return
			}
		}
	}()
	return <-errs
}

// bindPair binds TCP and UDP on the same free port of ip.
func bindPair(ip netip.Addr) (net.Listener, net.PacketConn, error) {
	for range 20 {
		ln, err := net.Listen("tcp", netip.AddrPortFrom(ip, 0).String())
		if err != nil {
			return nil, nil, fmt.Errorf("listen tcp: %w", err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		pc, err := net.ListenPacket("udp", netip.AddrPortFrom(ip, uint16(port)).String()) // #nosec G115 -- a port from the kernel
		if err == nil {
			return ln, pc, nil
		}
		_ = ln.Close()
	}
	return nil, nil, errors.New("no port free for both TCP and UDP")
}

func controlBuild(args []string) error {
	fs := flag.NewFlagSet("control-build", flag.ContinueOnError)
	ctxDir := fs.String("context", "", "build context directory")
	tag := fs.String("tag", "", "image tag")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ctxDir == "" || *tag == "" {
		return errors.New("-context DIR and -tag TAG are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cli, err := client.New(client.FromEnv)
	if err != nil {
		return fmt.Errorf("docker client: %w", err)
	}
	defer func() { _ = cli.Close() }()

	pr, pw := io.Pipe()
	go func() { _ = pw.CloseWithError(tarDir(pw, *ctxDir)) }()
	// No NetworkMode: the engine's default network. Everything else as
	// previewd sends it.
	res, err := cli.ImageBuild(ctx, pr, client.ImageBuildOptions{
		Version: build.BuilderBuildKit, Dockerfile: "Dockerfile", Tags: []string{*tag},
		NoCache: true, Remove: true, ForceRemove: true,
	})
	if err != nil {
		return fmt.Errorf("build: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	sc := bufio.NewScanner(res.Body)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var msg struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(sc.Bytes(), &msg) == nil && msg.Error != "" {
			return fmt.Errorf("control build failed: %s", msg.Error)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read build output: %w", err)
	}
	if _, err := cli.ImageRemove(ctx, *tag, client.ImageRemoveOptions{Force: true}); err != nil {
		return fmt.Errorf("remove %s: %w", *tag, err)
	}
	return nil
}

// tarDir writes the regular files and directories of dir.
func tarDir(w io.Writer, dir string) error {
	tw := tar.NewWriter(w)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == dir {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		f, err := os.Open(path) // #nosec G304 -- the test's own context directory
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		_, err = io.Copy(tw, f)
		return err
	})
	if err != nil {
		return fmt.Errorf("tar %s: %w", dir, err)
	}
	return tw.Close()
}
