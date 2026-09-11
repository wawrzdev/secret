package secret

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type Store struct {
	path string
	fd   int
}

var errStoreMissing = errors.New("secret store does not exist")

var syncDirectory = unix.Fsync

const lockName = ".secret.lock"

func configRoot() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		if !filepath.IsAbs(x) {
			return "", errors.New("XDG_CONFIG_HOME must be absolute")
		}
		return x, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".config"), nil
}

func openStore(create bool) (*Store, error) {
	config, err := configRoot()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(config, "secrets")
	if create {
		if err := os.MkdirAll(config, 0700); err != nil {
			return nil, fmt.Errorf("create config directory: %w", err)
		}
		if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("create secret store: %w", err)
		}
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, errStoreMissing
		}
		return nil, fmt.Errorf("open secret store safely: %w", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if st.Mode&0777 != 0700 {
		unix.Close(fd)
		return nil, fmt.Errorf("secret store permissions are %04o, want 0700", st.Mode&0777)
	}
	return &Store{path: path, fd: fd}, nil
}

func (s *Store) Close() error { return unix.Close(s.fd) }

func openParent(root int, name string, create bool) (int, string, error) {
	parts := strings.Split(name, "/")
	fd, err := unix.Dup(root)
	if err != nil {
		return -1, "", err
	}
	for _, part := range parts[:len(parts)-1] {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil && create && errors.Is(e, unix.ENOENT) {
			if e = unix.Mkdirat(fd, part, 0700); e != nil && !errors.Is(e, unix.EEXIST) {
				unix.Close(fd)
				return -1, "", e
			}
			next, e = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		unix.Close(fd)
		if e != nil {
			return -1, "", fmt.Errorf("unsafe parent %q: %w", part, e)
		}
		var st unix.Stat_t
		if e = unix.Fstat(next, &st); e != nil || st.Mode&0777 != 0700 {
			unix.Close(next)
			if e != nil {
				return -1, "", e
			}
			return -1, "", fmt.Errorf("directory %q permissions are %04o, want 0700", part, st.Mode&0777)
		}
		fd = next
	}
	return fd, parts[len(parts)-1], nil
}

func statAt(fd int, base string) (*unix.Stat_t, error) {
	var st unix.Stat_t
	err := unix.Fstatat(fd, base, &st, unix.AT_SYMLINK_NOFOLLOW)
	return &st, err
}

func (s *Store) Write(name string, src io.Reader, replace bool) error {
	parent, base, err := openParent(s.fd, name, !replace)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	if st, e := statAt(parent, base); e == nil {
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			return errors.New("destination is not a regular file")
		}
		if !replace {
			return errors.New("secret already exists; use --replace")
		}
	} else if !errors.Is(e, unix.ENOENT) {
		return e
	} else if replace {
		return errors.New("secret does not exist; omit --replace to create it")
	}
	tmp := ".secret-tmp-" + strconv.Itoa(os.Getpid())
	var tfd int
	for i := 0; i < 100; i++ {
		candidate := tmp + "-" + strconv.Itoa(i)
		tfd, err = unix.Openat(parent, candidate, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if err == nil {
			tmp = candidate
			break
		}
		if !errors.Is(err, unix.EEXIST) {
			return err
		}
	}
	if tfd < 0 {
		return errors.New("cannot allocate temporary file")
	}
	keep := false
	defer func() {
		unix.Close(tfd)
		if !keep {
			unix.Unlinkat(parent, tmp, 0)
		}
	}()
	f := os.NewFile(uintptr(tfd), tmp)
	if _, err = io.Copy(f, src); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	tfd = -1
	if err != nil {
		return fmt.Errorf("write temporary secret: %w", err)
	}
	if replace {
		st, e := statAt(parent, base)
		if e != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
			return errors.New("destination changed during replacement")
		}
		if err = unix.Renameat(parent, tmp, parent, base); err != nil {
			return fmt.Errorf("publish replacement: %w", err)
		}
	} else {
		if err = unix.Linkat(parent, tmp, parent, base, 0); err != nil {
			if errors.Is(err, unix.EEXIST) {
				return errors.New("secret already exists; use --replace")
			}
			return fmt.Errorf("publish secret: %w", err)
		}
		if err = unix.Unlinkat(parent, tmp, 0); err != nil {
			return fmt.Errorf("remove temporary link: %w", err)
		}
	}
	keep = true
	if err := syncDirectory(parent); err != nil {
		return fmt.Errorf("new value was published but directory sync failed; durability is uncertain: %w", err)
	}
	return nil
}

func (s *Store) openFile(name string) (*os.File, error) {
	parent, base, err := openParent(s.fd, name, false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	fd, err := unix.Openat(parent, base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, errors.New("secret does not exist")
		}
		return nil, fmt.Errorf("open secret safely: %w", err)
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Size == 0 {
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("secret must be a non-empty regular file with mode 0600")
	}
	return os.NewFile(uintptr(fd), base), nil
}

func (s *Store) ValidateFile(name string) error {
	f, err := s.openFile(name)
	if err == nil {
		err = f.Close()
	}
	return err
}

func (s *Store) Read(name string, max int64) ([]byte, error) {
	f, err := s.openFile(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("secret is too large")
	}
	return b, nil
}

func openImport(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open import safely: %w", err)
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("import source is not a regular file")
	}
	return os.NewFile(uintptr(fd), filepath.Base(path)), nil
}

const envHeaderLine = "# Generated by secret. Contains file paths only."
const envHeader = envHeaderLine + "\n"

func (s *Store) Register(variable, name string) error {
	unlock, err := s.lockRegistrations()
	if err != nil {
		return err
	}
	defer unlock()

	entries, err := s.readRegistrations()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	entries[variable] = name
	var b strings.Builder
	b.WriteString(envHeader)
	for _, key := range sortedKeys(entries) {
		fmt.Fprintf(&b, "export %s=%s # secret:%s\n", key, shellQuote(filepath.Join(s.path, filepath.FromSlash(entries[key]))), entries[key])
	}
	return s.Write("env.zsh", strings.NewReader(b.String()), fileExistsAt(s.fd, "env.zsh"))
}

func (s *Store) lockRegistrations() (func(), error) {
	fd, err := unix.Openat(s.fd, lockName, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, fmt.Errorf("open registration lock: %w", err)
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 {
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("registration lock must be a regular file with mode 0600")
	}
	if err = unix.Flock(fd, unix.LOCK_EX); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("lock environment registrations: %w", err)
	}
	return func() {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = unix.Close(fd)
	}, nil
}

func fileExistsAt(fd int, name string) bool { _, err := statAt(fd, name); return err == nil }

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

func (s *Store) readRegistrations() (map[string]string, error) {
	m := make(map[string]string)
	f, err := s.openMetadata()
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return m, os.ErrNotExist
		}
		return m, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if lineNumber == 1 && line == envHeaderLine {
			continue
		}
		marker := " # secret:"
		i := strings.LastIndex(line, marker)
		if i < 0 || !strings.HasPrefix(line, "export ") {
			return m, errors.New("invalid env.zsh registration")
		}
		left, name := line[len("export "):i], line[i+len(marker):]
		eq := strings.IndexByte(left, '=')
		if eq < 1 || !validVariable(left[:eq]) || validateName(name) != nil {
			return m, errors.New("invalid env.zsh registration")
		}
		variable := left[:eq]
		if _, exists := m[variable]; exists {
			return m, errors.New("duplicate env.zsh registration")
		}
		expected := fmt.Sprintf("export %s=%s # secret:%s", variable, shellQuote(filepath.Join(s.path, filepath.FromSlash(name))), name)
		if line != expected {
			return m, errors.New("invalid env.zsh registration")
		}
		m[variable] = name
	}
	if lineNumber == 0 {
		return m, errors.New("invalid env.zsh header")
	}
	return m, scanner.Err()
}

func (s *Store) openMetadata() (*os.File, error) {
	fd, err := unix.Openat(s.fd, "env.zsh", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 {
		unix.Close(fd)
		return nil, errors.New("env.zsh must be a regular file with mode 0600")
	}
	return os.NewFile(uintptr(fd), "env.zsh"), nil
}

func (s *Store) CheckAll(out io.Writer) error {
	bad := false
	if err := s.checkDir(s.fd, "", out, &bad); err != nil {
		return err
	}
	entries, err := s.readRegistrations()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(out, "ERROR env.zsh")
		bad = true
	} else {
		for _, variable := range sortedKeys(entries) {
			if s.ValidateFile(entries[variable]) != nil {
				fmt.Fprintf(out, "ERROR env %s -> %s\n", variable, entries[variable])
				bad = true
			} else {
				fmt.Fprintf(out, "OK env %s -> %s\n", variable, entries[variable])
			}
		}
	}
	if bad {
		return errors.New("check found problems")
	}
	return nil
}

func (s *Store) checkDir(fd int, prefix string, out io.Writer, bad *bool) error {
	dup, err := unix.Dup(fd)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(dup), prefix)
	defer f.Close()
	entries, err := f.ReadDir(-1)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		name := entry.Name()
		rel := name
		if prefix != "" {
			rel = prefix + "/" + name
		}
		if name == lockName && prefix == "" {
			var lockStat unix.Stat_t
			if err := unix.Fstatat(fd, name, &lockStat, unix.AT_SYMLINK_NOFOLLOW); err != nil || lockStat.Mode&unix.S_IFMT != unix.S_IFREG || lockStat.Mode&0777 != 0600 {
				fmt.Fprintln(out, "ERROR registration lock")
				*bad = true
			}
			continue
		}
		if !(prefix == "" && name == "env.zsh") && validateName(rel) != nil {
			fmt.Fprintln(out, "ERROR unsafe filename")
			*bad = true
			continue
		}
		var st unix.Stat_t
		if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			fmt.Fprintf(out, "ERROR %s\n", rel)
			*bad = true
			continue
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			if st.Mode&0777 != 0700 {
				fmt.Fprintf(out, "ERROR %s\n", rel)
				*bad = true
			}
			next, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if e != nil {
				fmt.Fprintf(out, "ERROR %s\n", rel)
				*bad = true
				continue
			}
			e = s.checkDir(next, rel, out, bad)
			unix.Close(next)
			if e != nil {
				return e
			}
		case unix.S_IFREG:
			if name == "env.zsh" && prefix == "" {
				continue
			}
			if st.Mode&0777 != 0600 || st.Size == 0 {
				fmt.Fprintf(out, "ERROR %s\n", rel)
				*bad = true
			} else {
				fmt.Fprintf(out, "OK %s\n", rel)
			}
		default:
			fmt.Fprintf(out, "ERROR %s\n", rel)
			*bad = true
		}
	}
	return nil
}
