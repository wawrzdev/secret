package secret

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

const (
	defaultLength = 32
	maxSize       = 1 << 20
)

var (
	randomReader = io.Reader(rand.Reader)
	readHidden   = terminalPassword
	clipboard    = copyClipboard
)

const usage = `secret stores credentials as private machine-local files.

Usage:
  secret generate [LENGTH]
  secret generate url [LENGTH]
  secret generate hex [LENGTH]
  secret generate base64 [BYTES]
  secret generate uuid
  secret set NAME [--replace] [--env VARIABLE] [--stdin]
  secret import NAME PATH [--replace] [--env VARIABLE]
  secret import NAME --stdin [--replace] [--env VARIABLE]
  secret path NAME
  secret check [NAME]
  secret exec NAME VARIABLE -- COMMAND [ARG...]

The store is ${XDG_CONFIG_HOME:-$HOME/.config}/secrets. Secret values are
accepted only through hidden terminal input, non-terminal stdin, or an import
file. --env exports the resulting file path, never its contents.
`

func Run(args []string, in *os.File, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(out, usage)
		return 0
	}
	var err error
	switch args[0] {
	case "generate":
		err = runGenerate(args[1:], out, errOut)
	case "set":
		err = runSet(args[1:], in, errOut)
	case "import":
		err = runImport(args[1:], in, errOut)
	case "path":
		err = runPath(args[1:], out)
	case "check":
		err = runCheck(args[1:], out)
	case "exec":
		err = runExec(args[1:], in, out, errOut)
	default:
		err = fmt.Errorf("unknown command %q", args[0])
	}
	if err != nil {
		var childErr *childExitError
		if errors.As(err, &childErr) {
			return childErr.code
		}
		fmt.Fprintf(errOut, "secret: %v\n", err)
		return 1
	}
	return 0
}

func runGenerate(args []string, out, errOut io.Writer) error {
	kind := "url"
	n := defaultLength
	if len(args) > 0 {
		switch args[0] {
		case "url", "hex", "base64", "uuid":
			kind = args[0]
			args = args[1:]
		}
	}
	if kind == "uuid" {
		if len(args) != 0 {
			return errors.New("uuid accepts no length")
		}
	} else {
		if len(args) > 1 {
			return errors.New("too many generation arguments")
		}
		if len(args) == 1 {
			var err error
			n, err = positiveSize(args[0])
			if err != nil {
				return err
			}
		}
	}
	var value string
	var err error
	switch kind {
	case "url":
		value, err = randomURL(n)
	case "hex":
		value, err = randomHex(n)
	case "base64":
		value, err = randomBase64(n)
	case "uuid":
		value, err = randomUUID()
	}
	if err != nil {
		return fmt.Errorf("generate: %w", err)
	}
	if _, err = fmt.Fprintln(out, value); err != nil {
		return err
	}
	if clipboard(value) {
		fmt.Fprintln(errOut, "(copied)")
	}
	return nil
}

func positiveSize(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > maxSize {
		return 0, fmt.Errorf("size must be between 1 and %d", maxSize)
	}
	return n, nil
}

func randomURL(n int) (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	b := make([]byte, n)
	if _, err := io.ReadFull(randomReader, b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[int(b[i])&63]
	}
	return string(b), nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, (n+1)/2)
	if _, err := io.ReadFull(randomReader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b)[:n], nil
}

func randomBase64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(randomReader, b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func randomUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(randomReader, b); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

type writeFlags struct {
	replace, stdin bool
	env            string
}

func parseWriteFlags(command string, args []string, allowPath bool) (string, string, writeFlags, error) {
	if len(args) == 0 {
		return "", "", writeFlags{}, fmt.Errorf("usage: secret %s NAME", command)
	}
	name := args[0]
	var f writeFlags
	path := ""
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--replace":
			f.replace = true
		case "--stdin":
			f.stdin = true
		case "--env":
			i++
			if i == len(args) {
				return "", "", f, errors.New("--env requires a variable name")
			}
			f.env = args[i]
		default:
			if strings.HasPrefix(args[i], "-") || !allowPath || path != "" {
				return "", "", f, fmt.Errorf("unexpected argument %q", args[i])
			}
			path = args[i]
		}
	}
	if allowPath && (f.stdin == (path != "")) {
		return "", "", f, errors.New("provide exactly one import PATH or --stdin")
	}
	if f.env != "" && !validVariable(f.env) {
		return "", "", f, errors.New("invalid environment variable name")
	}
	if err := validateName(name); err != nil {
		return "", "", f, err
	}
	return name, path, f, nil
}

func runSet(args []string, in *os.File, errOut io.Writer) error {
	name, _, flags, err := parseWriteFlags("set", args, false)
	if err != nil {
		return err
	}
	var value []byte
	if flags.stdin {
		if term.IsTerminal(int(in.Fd())) {
			return errors.New("--stdin refuses terminal input")
		}
		value, err = io.ReadAll(io.LimitReader(in, maxSize+2))
		if err == nil {
			value = bytesWithoutOneNewline(value)
		}
	} else {
		value, err = readHidden("Secret: ", errOut)
	}
	if err != nil {
		return fmt.Errorf("read token: %w", err)
	}
	if len(value) == 0 {
		return errors.New("token must not be empty")
	}
	if len(value) > maxSize {
		return errors.New("token is too large")
	}
	if strings.ContainsAny(string(value), "\r\n") {
		return errors.New("token must be a single line")
	}
	return storeValue(name, value, flags, errOut)
}

func bytesWithoutOneNewline(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	if len(b) > 0 && b[len(b)-1] == '\r' {
		b = b[:len(b)-1]
	}
	return b
}

func runImport(args []string, in *os.File, errOut io.Writer) error {
	name, path, flags, err := parseWriteFlags("import", args, true)
	if err != nil {
		return err
	}
	var src *os.File
	if flags.stdin {
		if term.IsTerminal(int(in.Fd())) {
			return errors.New("--stdin refuses terminal input")
		}
		src = in
	} else {
		src, err = openImport(path)
		if err != nil {
			return err
		}
		defer src.Close()
	}
	return storeReader(name, src, flags, errOut)
}

func storeValue(name string, value []byte, flags writeFlags, errOut io.Writer) error {
	return storeReader(name, strings.NewReader(string(value)), flags, errOut)
}

func storeReader(name string, r io.Reader, flags writeFlags, errOut io.Writer) error {
	s, err := openStore(true)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.Write(name, r, flags.replace); err != nil {
		return err
	}
	if flags.env != "" {
		if err := s.Register(flags.env, name); err != nil {
			return fmt.Errorf("secret stored but environment registration failed: %w", err)
		}
	}
	fmt.Fprintf(errOut, "stored %s\n", name)
	return nil
}

func runPath(args []string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: secret path NAME")
	}
	if err := validateName(args[0]); err != nil {
		return err
	}
	s, err := openStore(false)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.ValidateFile(args[0]); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, filepath.Join(s.path, filepath.FromSlash(args[0])))
	return err
}

func runCheck(args []string, out io.Writer) error {
	if len(args) > 1 {
		return errors.New("usage: secret check [NAME]")
	}
	s, err := openStore(false)
	if err != nil {
		if len(args) == 0 && errors.Is(err, errStoreMissing) {
			_, err = fmt.Fprintln(out, "no secrets configured")
			return err
		}
		return err
	}
	defer s.Close()
	if len(args) == 1 {
		if err := validateName(args[0]); err != nil {
			return err
		}
		if err := s.ValidateFile(args[0]); err != nil {
			return err
		}
		fmt.Fprintf(out, "OK %s\n", args[0])
		return nil
	}
	return s.CheckAll(out)
}

func runExec(args []string, in *os.File, out, errOut io.Writer) error {
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep != 2 || len(args) < 4 {
		return errors.New("usage: secret exec NAME VARIABLE -- COMMAND [ARG...]")
	}
	name, variable := args[0], args[1]
	if err := validateName(name); err != nil {
		return err
	}
	if !validVariable(variable) {
		return errors.New("invalid environment variable name")
	}
	s, err := openStore(false)
	if err != nil {
		return err
	}
	defer s.Close()
	value, err := s.Read(name, maxSize)
	if err != nil {
		return err
	}
	if !utf8.Valid(value) || strings.IndexByte(string(value), 0) >= 0 {
		return errors.New("secret is not textual environment data; use path instead")
	}
	cmd := exec.Command(args[3], args[4:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, errOut
	cmd.Env = setEnvironment(os.Environ(), variable, string(value))
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return &childExitError{code: ee.ExitCode()}
		}
		return fmt.Errorf("start child: %w", err)
	}
	return nil
}

type childExitError struct{ code int }

func (e *childExitError) Error() string { return fmt.Sprintf("child exited with status %d", e.code) }

func setEnvironment(env []string, key, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env)+1)
	for _, item := range env {
		if !strings.HasPrefix(item, prefix) {
			out = append(out, item)
		}
	}
	return append(out, prefix+value)
}

func validateName(name string) error {
	if name == "" || filepath.IsAbs(name) || strings.Contains(name, "\\") {
		return errors.New("invalid secret name")
	}
	parts := strings.Split(name, "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || p == "env.zsh" {
			return errors.New("invalid secret name")
		}
		for _, r := range p {
			if r < ' ' || r == 0x7f {
				return errors.New("invalid secret name")
			}
		}
	}
	return nil
}

func validVariable(s string) bool {
	if s == "" || !((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z') || s[0] == '_') {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

func terminalPassword(prompt string, errOut io.Writer) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("interactive input requires a terminal; use --stdin")
	}
	defer tty.Close()
	fmt.Fprint(errOut, prompt)
	b, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(errOut)
	return b, err
}

func copyClipboard(value string) bool {
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" {
		return false
	}
	var candidates [][]string
	if runtime.GOOS == "darwin" {
		candidates = [][]string{{"pbcopy"}}
	} else if os.Getenv("WAYLAND_DISPLAY") != "" {
		candidates = [][]string{{"wl-copy"}}
	} else if os.Getenv("DISPLAY") != "" {
		candidates = [][]string{{"xclip", "-selection", "clipboard"}, {"xsel", "--clipboard", "--input"}}
	}
	for _, argv := range candidates {
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Stdin = strings.NewReader(value)
		if cmd.Run() == nil {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
