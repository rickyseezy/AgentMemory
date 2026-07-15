// Package rebootlogin owns the platform-specific per-user login continuation
// registration used by the PF-001 reboot-resume flow.
package rebootlogin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/rebootapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/rebootcontinuation"
)

const maximumEntryBytes = 16 * 1024

type entry struct {
	name    string
	content string
}

type entryRenderer func(rebootcontinuation.Record) (entry, error)

// TokenRemover cleans a stale platform entry when its one-use record is
// already absent or corrupt and the operation ID can no longer be trusted.
type TokenRemover interface {
	RemoveToken(context.Context, string) error
}

func renderDarwinEntry(record rebootcontinuation.Record) (entry, error) {
	token, err := rebootcontinuation.TokenFor(record.OperationID())
	if err != nil || record.LauncherPath() == "" {
		return entry{}, rebootapp.ErrIntegrity
	}
	label := "com.rickyseezy.agentmemory.resume." + token
	content := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>` + xmlText(label) +
		`</string><key>ProgramArguments</key><array><string>` + xmlText(record.LauncherPath()) +
		`</string><string>resume</string><string>--continuation</string><string>` + xmlText(token) +
		`</string></array><key>RunAtLoad</key><true/><key>ProcessType</key><string>Background</string></dict></plist>
`
	return entry{name: label, content: content}, nil
}

func renderLinuxEntry(record rebootcontinuation.Record) (entry, error) {
	token, err := rebootcontinuation.TokenFor(record.OperationID())
	if err != nil || record.LauncherPath() == "" {
		return entry{}, rebootapp.ErrIntegrity
	}
	name := "agentmemory-resume-" + token
	content := "[Desktop Entry]\nType=Application\nName=AgentMemory installation continuation\n" +
		"Exec=" + desktopQuote(record.LauncherPath()) + " resume --continuation " + token + "\n" +
		"NoDisplay=true\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
	return entry{name: name, content: content}, nil
}

func renderWindowsEntry(record rebootcontinuation.Record) (entry, error) {
	token, err := rebootcontinuation.TokenFor(record.OperationID())
	if err != nil || record.LauncherPath() == "" || strings.ContainsAny(record.LauncherPath(), "\x00\"") {
		return entry{}, rebootapp.ErrIntegrity
	}
	content := `"` + record.LauncherPath() + `" resume --continuation ` + token
	if len(content) > 260 {
		return entry{}, rebootapp.ErrIntegrity
	}
	return entry{name: "AgentMemory-" + token, content: content}, nil
}

func xmlText(value string) string {
	var encoded bytes.Buffer
	_ = xml.EscapeText(&encoded, []byte(value))
	return encoded.String()
}

func desktopQuote(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`", "$", `\$`)
	return `"` + replacer.Replace(value) + `"`
}

type fileRegistrar struct {
	root   string
	suffix string
	render entryRenderer
	mu     sync.Mutex
}

func newFileRegistrar(root, suffix string, render entryRenderer) (*fileRegistrar, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || strings.IndexByte(root, 0) >= 0 ||
		(suffix != ".plist" && suffix != ".desktop") || render == nil {
		return nil, rebootapp.ErrIntegrity
	}
	if err := platformEnsureLoginDirectory(root); err != nil {
		return nil, rebootapp.ErrIntegrity
	}
	return &fileRegistrar{root: root, suffix: suffix, render: render}, nil
}

func (r *fileRegistrar) Register(ctx context.Context, record rebootcontinuation.Record) error {
	if r == nil || ctx == nil || record.OperationID().IsZero() || record.Nonce().IsZero() {
		return rebootapp.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	value, err := r.render(record)
	if err != nil || value.name == "" || len(value.content) == 0 || len(value.content) > maximumEntryBytes {
		return rebootapp.ErrIntegrity
	}
	target := r.path(record.OperationID())
	existing, readError := readLoginEntry(ctx, target)
	if readError == nil {
		if string(existing) == value.content {
			return nil
		}
		return rebootapp.ErrConflict
	}
	if !errors.Is(readError, os.ErrNotExist) {
		return rebootapp.ErrIntegrity
	}
	if err := publishLoginEntry(ctx, r.root, target, []byte(value.content)); err != nil {
		if errors.Is(err, os.ErrExist) {
			return rebootapp.ErrConflict
		}
		return rebootapp.ErrUnavailable
	}
	return nil
}

func (r *fileRegistrar) Remove(ctx context.Context, operationID install.OperationID) error {
	if r == nil || ctx == nil || operationID.IsZero() {
		return rebootapp.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	token, err := rebootcontinuation.TokenFor(operationID)
	if err != nil {
		return rebootapp.ErrIntegrity
	}
	return r.RemoveToken(ctx, token)
}

func (r *fileRegistrar) RemoveToken(ctx context.Context, token string) error {
	if r == nil || ctx == nil || !validEntryToken(token) {
		return rebootapp.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := os.Remove(r.pathToken(token)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return rebootapp.ErrUnavailable
	}
	return platformSyncLoginDirectory(r.root)
}

func (r *fileRegistrar) path(operationID install.OperationID) string {
	token, _ := rebootcontinuation.TokenFor(operationID)
	return r.pathToken(token)
}

func (r *fileRegistrar) pathToken(token string) string {
	return filepath.Join(r.root, "agentmemory-resume-"+token+r.suffix)
}

func validEntryToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	for _, character := range token {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func readLoginEntry(ctx context.Context, path string) ([]byte, error) {
	file, err := platformOpenLoginEntry(ctx, path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(io.LimitReader(file, maximumEntryBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumEntryBytes {
		return nil, rebootapp.ErrIntegrity
	}
	return raw, nil
}

func publishLoginEntry(ctx context.Context, root, target string, payload []byte) error {
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	temporary := filepath.Join(root, ".agentmemory-login-"+hex.EncodeToString(random[:])+".tmp")
	file, err := platformCreateLoginEntry(ctx, temporary)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(temporary) }()
	if _, err = file.Write(payload); err == nil {
		err = file.Sync()
	}
	if closeError := file.Close(); err == nil {
		err = closeError
	}
	if err != nil {
		return err
	}
	if err = os.Link(temporary, target); err != nil {
		return err
	}
	if err = platformSyncLoginDirectory(root); err != nil {
		return err
	}
	if err = os.Remove(temporary); err != nil {
		return err
	}
	return platformSyncLoginDirectory(root)
}

var _ rebootapp.LoginRegistrar = (*fileRegistrar)(nil)
var _ TokenRemover = (*fileRegistrar)(nil)
