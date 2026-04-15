package loader

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Options controls how the DNS XDP object is loaded and attached.
type Options struct {
	ObjectPath string
	Interface  string
	PinPath    string
	AttachMode string
}

// Loader owns the loaded collection and the attached XDP link.
type Loader struct {
	opts       Options
	collection *ebpf.Collection
	link       link.Link
}

// Load loads the object file and optionally pins maps under PinPath.
func Load(opts Options) (*Loader, error) {
	if opts.ObjectPath == "" {
		return nil, errors.New("loader: object path is required")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("loader: remove memlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(opts.ObjectPath)
	if err != nil {
		return nil, fmt.Errorf("loader: load collection spec: %w", err)
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("loader: new collection: %w", err)
	}

	l := &Loader{
		opts:       opts,
		collection: collection,
	}
	if opts.PinPath != "" {
		if err := l.PinMaps(opts.PinPath); err != nil {
			_ = l.Close()
			return nil, err
		}
		if err := l.PinPrograms(opts.PinPath); err != nil {
			_ = l.Close()
			return nil, err
		}
	}

	return l, nil
}

// AttachXDP attaches the dns_ingress program to the configured interface.
func (l *Loader) AttachXDP() error {
	if l == nil {
		return errors.New("loader: nil loader")
	}
	if l.opts.Interface == "" {
		return errors.New("loader: interface is required")
	}
	if l.collection == nil {
		return errors.New("loader: collection is not loaded")
	}
	if l.link != nil {
		return nil
	}

	iface, err := net.InterfaceByName(l.opts.Interface)
	if err != nil {
		return fmt.Errorf("loader: lookup interface %q: %w", l.opts.Interface, err)
	}

	prog := l.collection.Programs["dns_ingress"]
	if prog == nil {
		return errors.New("loader: dns_ingress program not found")
	}

	mode, err := parseAttachMode(l.opts.AttachMode)
	if err != nil {
		return err
	}

	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     mode,
	})
	if err != nil {
		return fmt.Errorf("loader: attach xdp: %w", err)
	}

	l.link = lnk
	return nil
}

// PinMaps pins all loaded maps beneath pinPath.
func (l *Loader) PinMaps(pinPath string) error {
	if l == nil || l.collection == nil {
		return errors.New("loader: collection is not loaded")
	}
	if pinPath == "" {
		return nil
	}
	if err := os.MkdirAll(pinPath, 0o755); err != nil {
		return fmt.Errorf("loader: mkdir pin path: %w", err)
	}

	for name, m := range l.collection.Maps {
		if m == nil {
			continue
		}
		if err := m.Pin(filepath.Join(pinPath, name)); err != nil {
			return fmt.Errorf("loader: pin map %q: %w", name, err)
		}
	}
	return nil
}

// PinPrograms pins all loaded programs beneath pinPath.
func (l *Loader) PinPrograms(pinPath string) error {
	if l == nil || l.collection == nil {
		return errors.New("loader: collection is not loaded")
	}
	if pinPath == "" {
		return nil
	}
	if err := os.MkdirAll(pinPath, 0o755); err != nil {
		return fmt.Errorf("loader: mkdir program pin path: %w", err)
	}

	for name, prog := range l.collection.Programs {
		if prog == nil {
			continue
		}
		if err := prog.Pin(filepath.Join(pinPath, name)); err != nil {
			return fmt.Errorf("loader: pin program %q: %w", name, err)
		}
	}
	return nil
}

// Map returns a named map from the collection.
func (l *Loader) Map(name string) (*ebpf.Map, error) {
	if l == nil || l.collection == nil {
		return nil, errors.New("loader: collection is not loaded")
	}
	m := l.collection.Maps[name]
	if m == nil {
		return nil, fmt.Errorf("loader: map %q not found", name)
	}
	return m, nil
}

// Close detaches XDP and closes the loaded collection.
func (l *Loader) Close() error {
	if l == nil {
		return nil
	}

	var errs []error
	if l.link != nil {
		errs = append(errs, l.link.Close())
		l.link = nil
	}
	if l.collection != nil {
		l.collection.Close()
		l.collection = nil
	}

	return errors.Join(errs...)
}

func parseAttachMode(raw string) (link.XDPAttachFlags, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "generic":
		return link.XDPGenericMode, nil
	case "native", "driver":
		return link.XDPDriverMode, nil
	case "skb", "skbmode":
		return link.XDPGenericMode, nil
	default:
		return 0, fmt.Errorf("loader: unsupported attach mode %q", raw)
	}
}
