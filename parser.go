package sshvault

import (
	"flag"
	"fmt"
	"os"
)

// Parser interface
type Parser interface {
	Parse(fs *flag.FlagSet) (*Flags, error)
	isDir(path string) bool
	isFile(path string) bool
}

// Parse implements parser
type Parse struct {
	Flags
}

// Parse parse the command line flags
func (p *Parse) Parse(fs *flag.FlagSet) (*Flags, error) {
	fs.BoolVar(&p.Flags.Version, "v", false, "Print version")

	err := fs.Parse(os.Args[1:])
	if err != nil {
		return nil, err
	}
	return &p.Flags, nil
}
func (p *Parse) Usage(fs *flag.FlagSet) func() {
	return func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [create|decrypt|edit|encrypt|view] [-k key] [-u user] vault\n\n", os.Args[0])
		var flags []string
		fs.VisitAll(func(f *flag.Flag) {
			flags = append(flags, f.Name)
		})
	}
}

func (p *Parse) isDir(path string) bool {
	f, err := os.Stat(path)
	if err != nil {
		return false
	}
	if m := f.Mode(); m.IsDir() && m&400 != 0 {
		return true
	}
	return false
}

func (p *Parse) isFile(path string) bool {
	f, err := os.Stat(path)
	if err != nil {
		return false
	}
	if m := f.Mode(); !m.IsDir() && m.IsRegular() && m&400 != 0 {
		return true
	}
	return false
}

func (p *Parse) checkWrkdir(dir string) (err error) {
	if !p.isDir(dir) {
		err = fmt.Errorf("-d %q does not exist or has wrong permissions, use (\"%s -h\") for help.", dir, os.Args[0])
	}
	return
}

// ParseArgs parse command arguments
func ParseArgs(p Parser, fs *flag.FlagSet) (err error) {
	flags, err := p.Parse(fs)
	if err != nil {
		return
	}

	// if -v
	if flags.Version {
		return
	}

	// if no args
	if len(fs.Args()) < 1 {
		err = fmt.Errorf("Missing user, use (\"%s -h\") for help.", os.Args[0])
		return
	}
	return
}
