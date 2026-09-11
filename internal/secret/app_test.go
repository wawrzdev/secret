package secret

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
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
	readHidden = func(prompt string, w io.Writer) ([]byte, error) { called = true; return []byte("hidden"), nil }
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
