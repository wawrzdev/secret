package secret

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

func isolated(t *testing.T) string {
	t.Helper()
	config := filepath.Join(t.TempDir(), "config")
	t.Setenv("XDG_CONFIG_HOME", config)
	t.Setenv("SSH_CONNECTION", "test")
	return filepath.Join(config, "secrets")
}

func inputFile(t *testing.T, b []byte) *os.File {
	t.Helper()
	p := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func invoke(t *testing.T, in []byte, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Run(args, inputFile(t, in), &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestBareHelpDoesNotCreateStore(t *testing.T) {
	root := isolated(t)
	code, out, _ := invoke(t, nil)
	if code != 0 || !strings.Contains(out, "Usage:") {
		t.Fatalf("code=%d output=%q", code, out)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("bare command created store: %v", err)
	}
}

func TestCheckAbsentStoreIsValidAndReadOnly(t *testing.T) {
	root := isolated(t)
	code, out, errOut := invoke(t, nil, "check")
	if code != 0 || out != "no secrets configured\n" || errOut != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("check created store: %v", err)
	}
	code, out, _ = invoke(t, nil, "check", "missing")
	if code == 0 || out != "" {
		t.Fatalf("named missing check: code=%d stdout=%q", code, out)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("named check created store: %v", err)
	}
}

func TestGenerateFormsAndFailures(t *testing.T) {
	isolated(t)
	oldClip := clipboard
	clipboard = func(string) bool { return false }
	defer func() { clipboard = oldClip }()
	tests := []struct {
		args   []string
		length int
		match  string
	}{
		{[]string{"generate"}, 32, `^[A-Za-z0-9_-]+\n$`},
		{[]string{"generate", "url", "47"}, 47, `^[A-Za-z0-9_-]+\n$`},
		{[]string{"generate", "hex", "31"}, 31, `^[0-9a-f]+\n$`},
		{[]string{"generate", "uuid"}, 36, `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\n$`},
	}
	for _, tt := range tests {
		code, out, errOut := invoke(t, nil, tt.args...)
		if code != 0 || len(strings.TrimSuffix(out, "\n")) != tt.length || !regexp.MustCompile(tt.match).MatchString(out) {
			t.Errorf("%v: code=%d out=%q err=%q", tt.args, code, out, errOut)
		}
	}
	code, out, _ := invoke(t, nil, "generate", "base64", "7")
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
	if code != 0 || err != nil || len(decoded) != 7 {
		t.Fatalf("base64: code=%d bytes=%d err=%v", code, len(decoded), err)
	}
	for _, bad := range [][]string{{"generate", "0"}, {"generate", "hex", "-1"}, {"generate", "base64", "1048577"}, {"generate", "uuid", "2"}} {
		code, out, _ := invoke(t, nil, bad...)
		if code == 0 || out != "" {
			t.Errorf("failure %v: code=%d stdout=%q", bad, code, out)
		}
	}
}

func TestSetCreateReplaceAndModes(t *testing.T) {
	root := isolated(t)
	code, out, errOut := invoke(t, []byte("alpha\n"), "set", "api/token", "--stdin")
	if code != 0 || out != "" || strings.Contains(errOut, "alpha") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errOut)
	}
	path := filepath.Join(root, "api", "token")
	assertFile(t, path, []byte("alpha"), 0600)
	assertMode(t, root, 0700)
	assertMode(t, filepath.Join(root, "api"), 0700)
	code, _, _ = invoke(t, []byte("lost\n"), "set", "api/token", "--stdin")
	if code == 0 {
		t.Fatal("existing secret overwritten")
	}
	assertFile(t, path, []byte("alpha"), 0600)
	code, _, _ = invoke(t, []byte("beta\n"), "set", "api/token", "--replace", "--stdin")
	if code != 0 {
		t.Fatal("replace failed")
	}
	assertFile(t, path, []byte("beta"), 0600)
	code, _, _ = invoke(t, []byte("\n"), "set", "empty", "--stdin")
	if code == 0 {
		t.Fatal("accepted empty token")
	}
	code, _, _ = invoke(t, []byte("two\nlines\n"), "set", "multiline", "--stdin")
	if code == 0 {
		t.Fatal("accepted multiline token")
	}
}

func TestInteractiveSetUsesHiddenReader(t *testing.T) {
	isolated(t)
	old := readHidden
	defer func() { readHidden = old }()
	called := false
	readHidden = func(prompt string, w io.Writer, in *os.File) ([]byte, error) {
		called = true
		return []byte("hidden"), nil
	}
	code, _, errOut := invoke(t, nil, "set", "interactive")
	if code != 0 || !called || strings.Contains(errOut, "hidden") {
		t.Fatalf("code=%d called=%v stderr=%q", code, called, errOut)
	}
	assertFile(t, filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "secrets", "interactive"), []byte("hidden"), 0600)
}

func TestImportPreservesBytesAndRejectsSymlinks(t *testing.T) {
	root := isolated(t)
	data := []byte{0, 1, '\n', 0xff, '\n'}
	source := filepath.Join(t.TempDir(), "credential.json")
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	code, _, _ := invoke(t, nil, "import", "files/credential", source, "--env", "CRED_PATH")
	if code != 0 {
		t.Fatal("import failed")
	}
	assertFile(t, filepath.Join(root, "files", "credential"), data, 0600)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	code, _, _ = invoke(t, nil, "import", "linked", link)
	if code == 0 {
		t.Fatal("accepted source symlink")
	}
	code, _, _ = invoke(t, data, "import", "stdin/file", "--stdin")
	if code != 0 {
		t.Fatal("stdin import failed")
	}
	assertFile(t, filepath.Join(root, "stdin", "file"), data, 0600)
}

func TestPathTraversalAndDestinationLinks(t *testing.T) {
	root := isolated(t)
	for _, name := range []string{"", "../x", "/tmp/x", "a//b", "a/./b", "line\nbreak", `a\b`} {
		code, _, _ := invoke(t, []byte("x"), "set", name, "--stdin")
		if code == 0 {
			t.Errorf("accepted %q", name)
		}
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "parent")); err != nil {
		t.Fatal(err)
	}
	code, _, _ := invoke(t, []byte("x"), "set", "parent/value", "--stdin")
	if code == 0 {
		t.Fatal("followed parent symlink")
	}
	target := filepath.Join(outside, "target")
	if err := os.WriteFile(target, []byte("safe"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "dest")); err != nil {
		t.Fatal(err)
	}
	code, _, _ = invoke(t, []byte("evil"), "set", "dest", "--replace", "--stdin")
	if code == 0 {
		t.Fatal("replaced destination symlink")
	}
	assertFile(t, target, []byte("safe"), 0600)
}

func TestReplaceMissingDoesNotCreateStoreOrParents(t *testing.T) {
	root := isolated(t)
	config := filepath.Dir(root)
	code, _, _ := invoke(t, []byte("value\n"), "set", "nested/missing", "--replace", "--stdin")
	if code == 0 {
		t.Fatal("replace of missing secret succeeded")
	}
	if _, err := os.Stat(config); !os.IsNotExist(err) {
		t.Fatalf("failed replace created config tree: %v", err)
	}

	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	code, _, _ = invoke(t, []byte("value\n"), "set", "nested/missing", "--replace", "--stdin")
	if code == 0 {
		t.Fatal("nested replace of missing secret succeeded")
	}
	if _, err := os.Stat(filepath.Join(root, "nested")); !os.IsNotExist(err) {
		t.Fatalf("failed replace created parent: %v", err)
	}
}

func TestEnvironmentRegistrationDeterministicAndIdempotent(t *testing.T) {
	root := isolated(t)
	for _, tc := range []struct{ name, variable string }{{"zeta", "Z_TOKEN"}, {"alpha", "A_TOKEN"}, {"other", "Z_TOKEN"}} {
		args := []string{"set", tc.name, "--stdin", "--env", tc.variable}
		code, _, _ := invoke(t, []byte("value\n"), args...)
		if code != 0 {
			t.Fatalf("register %s", tc.name)
		}
	}
	b, err := os.ReadFile(filepath.Join(root, "env.zsh"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Count(s, "export Z_TOKEN=") != 1 || strings.Index(s, "A_TOKEN") > strings.Index(s, "Z_TOKEN") || !strings.Contains(s, "# secret:other") {
		t.Fatalf("unexpected env file:\n%s", s)
	}
	if strings.Contains(s, "value") {
		t.Fatal("env file contains value")
	}
	assertMode(t, filepath.Join(root, "env.zsh"), 0600)
}

func TestConcurrentCLIRegistrationsAreNotLost(t *testing.T) {
	root := isolated(t)
	const count = 40
	type child struct {
		cmd    *exec.Cmd
		stderr bytes.Buffer
	}
	children := make([]child, count)
	for i := 0; i < count; i++ {
		args, err := json.Marshal([]string{"set", fmt.Sprintf("token-%02d", i), "--stdin", "--env", fmt.Sprintf("TOKEN_%02d", i)})
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestCLIProcessHelper$")
		cmd.Env = append(os.Environ(), "SECRET_CLI_HELPER=1", "SECRET_CLI_ARGS="+string(args), "XDG_CONFIG_HOME="+filepath.Dir(root), "SSH_CONNECTION=test")
		cmd.Stdin = strings.NewReader("value-" + strconv.Itoa(i) + "\n")
		cmd.Stderr = &children[i].stderr
		children[i].cmd = cmd
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
	}
	for i := range children {
		if err := children[i].cmd.Wait(); err != nil {
			t.Fatalf("child %d: %v: %s", i, err, children[i].stderr.String())
		}
	}
	code, _, errOut := invoke(t, nil, "check")
	if code != 0 {
		t.Fatalf("check after concurrent registration: %s", errOut)
	}
	s, err := openStore(false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	entries, err := s.readRegistrations()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != count {
		t.Fatalf("got %d registrations, want %d", len(entries), count)
	}
	for i := 0; i < count; i++ {
		variable, name := fmt.Sprintf("TOKEN_%02d", i), fmt.Sprintf("token-%02d", i)
		if entries[variable] != name {
			t.Errorf("%s=%q, want %q", variable, entries[variable], name)
		}
	}
}

func TestPathCheckAndReadOnlyFailure(t *testing.T) {
	root := isolated(t)
	code, out, _ := invoke(t, nil, "path", "missing")
	if code == 0 || out != "" {
		t.Fatal("missing path succeeded")
	}
	code, _, _ = invoke(t, []byte("value\n"), "set", "token", "--stdin", "--env", "TOKEN_FILE")
	if code != 0 {
		t.Fatal("set")
	}
	code, out, _ = invoke(t, nil, "path", "token")
	if code != 0 || strings.TrimSpace(out) != filepath.Join(root, "token") {
		t.Fatalf("path=%q", out)
	}
	if err := os.Chmod(filepath.Join(root, "token"), 0644); err != nil {
		t.Fatal(err)
	}
	code, out, _ = invoke(t, nil, "check")
	if code == 0 || !strings.Contains(out, "ERROR token") {
		t.Fatalf("code=%d out=%q", code, out)
	}
	assertMode(t, filepath.Join(root, "token"), 0644)
}

func TestCheckRejectsAlteredRegistrationWithoutRewritingIt(t *testing.T) {
	root := isolated(t)
	code, _, _ := invoke(t, []byte("value\n"), "set", "token", "--stdin", "--env", "TOKEN_FILE")
	if code != 0 {
		t.Fatal("set")
	}
	envPath := filepath.Join(root, "env.zsh")
	bad := []byte(envHeader + "export TOKEN_FILE='/tmp/wrong' # secret:token\n")
	if err := os.WriteFile(envPath, bad, 0600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := invoke(t, nil, "check")
	if code == 0 || !strings.Contains(out, "ERROR env.zsh") {
		t.Fatalf("code=%d out=%q", code, out)
	}
	assertFile(t, envPath, bad, 0600)
}

func TestCheckRejectsUnsafeNamesAndEmptyFilesWithoutSpoofing(t *testing.T) {
	root := isolated(t)
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "empty"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	unsafe := "bad\nOK forged"
	if err := os.WriteFile(filepath.Join(root, unsafe), []byte("value"), 0600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := invoke(t, nil, "check")
	if code == 0 || !strings.Contains(out, "ERROR empty") || !strings.Contains(out, "ERROR unsafe filename") {
		t.Fatalf("code=%d out=%q", code, out)
	}
	if strings.Contains(out, "forged") {
		t.Fatalf("unsafe filename reached output: %q", out)
	}
	code, out, _ = invoke(t, nil, "check", "empty")
	if code == 0 || out != "" {
		t.Fatalf("empty named check: code=%d out=%q", code, out)
	}
	assertFile(t, filepath.Join(root, "empty"), nil, 0600)
}

func TestRegistrationMarkerCannotAppearInName(t *testing.T) {
	root := isolated(t)
	code, _, _ := invoke(t, []byte("value\n"), "set", "safe # secret:spoof", "--stdin", "--env", "TOKEN")
	if code == 0 {
		t.Fatal("accepted ambiguous registration marker")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("invalid name created store: %v", err)
	}
}

func TestExecChildOnlyAndBinaryRefusal(t *testing.T) {
	isolated(t)
	t.Setenv("TEST_EXEC_VALUE", "parent")
	code, _, _ := invoke(t, []byte("child\n"), "set", "exec", "--stdin")
	if code != 0 {
		t.Fatal("set")
	}
	code, _, errOut := invoke(t, nil, "exec", "exec", "TEST_EXEC_VALUE", "--", os.Args[0], "-test.run=TestExecHelper")
	if code != 0 {
		t.Fatalf("exec code=%d err=%q", code, errOut)
	}
	if os.Getenv("TEST_EXEC_VALUE") != "parent" {
		t.Fatal("parent environment changed")
	}
	code, _, _ = invoke(t, []byte{0, 1}, "import", "binary", "--stdin")
	if code != 0 {
		t.Fatal("import")
	}
	code, _, _ = invoke(t, nil, "exec", "binary", "BINARY", "--", os.Args[0], "-test.run=TestExecHelper")
	if code == 0 {
		t.Fatal("executed binary secret")
	}
}

func TestExecReturnsConventionalSignalStatus(t *testing.T) {
	isolated(t)
	code, _, _ := invoke(t, []byte("value\n"), "set", "signal", "--stdin")
	if code != 0 {
		t.Fatal("set")
	}
	code, _, errOut := invoke(t, nil, "exec", "signal", "TOKEN", "--", "/bin/sh", "-c", "kill -TERM $$")
	if code != 143 || errOut != "" {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
}

func TestHiddenTerminalInputSuppressesEchoAndRestoresTerminal(t *testing.T) {
	config := filepath.Join(t.TempDir(), "config")
	args, _ := json.Marshal([]string{"set", "pty-secret"})
	cmd := exec.Command(os.Args[0], "-test.run=^TestCLIProcessHelper$")
	cmd.Env = append(os.Environ(), "SECRET_CLI_HELPER=pty", "SECRET_CLI_ARGS="+string(args), "XDG_CONFIG_HOME="+config, "SSH_CONNECTION=test")
	terminal, err := pty.Start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer terminal.Close()
	reader := bufio.NewReader(terminal)
	prefix, err := readPTYUntil(reader, ':', terminal)
	if err != nil || !strings.Contains(prefix, "Secret:") {
		more, _ := readPTYUntil(reader, '\n', terminal)
		t.Fatalf("prompt=%q err=%v", prefix+more, err)
	}
	const hidden = "hidden-pty-value"
	if _, err := terminal.Write([]byte(hidden + "\n")); err != nil {
		t.Fatal(err)
	}
	after, err := readPTYUntil(reader, '>', terminal)
	if err != nil || !strings.Contains(after, "AFTER>") {
		t.Fatalf("after=%q err=%v", after, err)
	}
	if strings.Contains(prefix+after, hidden) {
		t.Fatalf("hidden value was echoed: %q", prefix+after)
	}
	const visible = "echo-restored"
	if _, err := terminal.Write([]byte(visible + "\n")); err != nil {
		t.Fatal(err)
	}
	rest, err := readPTYUntil(reader, '>', terminal)
	if err != nil || !strings.Contains(rest, visible) || !strings.Contains(rest, "DONE>") {
		t.Fatalf("terminal echo was not restored: %q err=%v", rest, err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(config, "secrets", "pty-secret"), []byte(hidden), 0600)
}

func readPTYUntil(reader *bufio.Reader, delimiter byte, terminal *os.File) (string, error) {
	type result struct {
		value string
		err   error
	}
	done := make(chan result, 1)
	go func() { value, err := reader.ReadString(delimiter); done <- result{value, err} }()
	select {
	case got := <-done:
		return got.value, got.err
	case <-time.After(10 * time.Second):
		_ = terminal.Close()
		return "", errors.New("timed out reading pseudo-terminal")
	}
}

func TestStdinModeRefusesTerminal(t *testing.T) {
	config := filepath.Join(t.TempDir(), "config")
	args, _ := json.Marshal([]string{"set", "refused", "--stdin"})
	cmd := exec.Command(os.Args[0], "-test.run=^TestCLIProcessHelper$")
	cmd.Env = append(os.Environ(), "SECRET_CLI_HELPER=1", "SECRET_CLI_ARGS="+string(args), "XDG_CONFIG_HOME="+config)
	terminal, err := pty.Start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	output, _ := io.ReadAll(terminal)
	terminal.Close()
	err = cmd.Wait()
	if err == nil || !strings.Contains(string(output), "refuses terminal input") {
		t.Fatalf("err=%v output=%q", err, output)
	}
	if _, err := os.Stat(filepath.Join(config, "secrets")); !os.IsNotExist(err) {
		t.Fatalf("refusal created store: %v", err)
	}
}

func TestCLIProcessHelper(t *testing.T) {
	mode := os.Getenv("SECRET_CLI_HELPER")
	if mode == "" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv("SECRET_CLI_ARGS")), &args); err != nil {
		os.Exit(97)
	}
	code := Run(args, os.Stdin, os.Stdout, os.Stderr)
	if mode == "pty" && code == 0 {
		fmt.Fprint(os.Stdout, "AFTER>")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		fmt.Fprint(os.Stdout, "DONE>")
	}
	os.Exit(code)
}

func TestExecHelper(t *testing.T) {
	value := os.Getenv("TEST_EXEC_VALUE")
	if value == "" || value == "parent" {
		return
	}
	if value != "child" {
		os.Exit(42)
	}
}

func TestReplacementFailurePreservesOldFile(t *testing.T) {
	root := isolated(t)
	s, err := openStore(true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Write("token", strings.NewReader("old"), false); err != nil {
		t.Fatal(err)
	}
	err = s.Write("token", failingReader{}, true)
	if err == nil {
		t.Fatal("expected failure")
	}
	assertFile(t, filepath.Join(root, "token"), []byte("old"), 0600)
}

func TestDirectorySyncFailureReportsPublishedDurabilityUncertainty(t *testing.T) {
	root := isolated(t)
	s, err := openStore(true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Write("token", strings.NewReader("old"), false); err != nil {
		t.Fatal(err)
	}
	oldSync := syncDirectory
	syncDirectory = func(int) error { return unix.EIO }
	defer func() { syncDirectory = oldSync }()
	err = s.Write("token", strings.NewReader("new"), true)
	if err == nil || !strings.Contains(err.Error(), "published") || !strings.Contains(err.Error(), "durability is uncertain") || !errors.Is(err, unix.EIO) {
		t.Fatalf("error=%v", err)
	}
	assertFile(t, filepath.Join(root, "token"), []byte("new"), 0600)
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, os.ErrInvalid }

func assertFile(t *testing.T, path string, want []byte, mode os.FileMode) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s contents differ", path)
	}
	assertMode(t, path, mode)
}
func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != want {
		t.Fatalf("%s mode %04o, want %04o", path, st.Mode().Perm(), want)
	}
}

func TestBuildTargetsSupportedPlatforms(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("release platforms are macOS and Linux")
	}
}
