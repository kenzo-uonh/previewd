package orchestrator

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/kenzo-uonh/previewd/internal/textutil"
	"github.com/kenzo-uonh/previewd/internal/validate"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/moby/buildkit/frontend/dockerfile/shell"
)

// The Dockerfile preflight (V1 F2, task E1) runs on the daemon's own parser:
// github.com/moby/buildkit at the version the supported engine embeds
// (Docker 29.8.2: BuildKit v0.33.1, pinned in go.mod). Every refusal happens
// before any request reaches the engine. Anything the preflight does not
// recognize is refused.

// ErrPreflight is a build refused before any request reaches the engine.
var ErrPreflight = errors.New("build refused by preflight")

// ErrContextTooLarge is a build context above PREVIEWD_MAX_BUILD_CONTEXT_MIB.
var ErrContextTooLarge = errors.New("build context exceeds the size cap")

const (
	// dockerfileName is the only Dockerfile previewd builds: the daemon is
	// told this exact name, at the context root.
	dockerfileName = "Dockerfile"
	// maxDockerfileBytes bounds the Dockerfile the preflight parses.
	maxDockerfileBytes = 1 << 20
	// maxPreflightQuoteBytes bounds the PR-controlled text quoted in a
	// refusal (instructions, names, parser errors).
	maxPreflightQuoteBytes = 128
	// scratchImage is the empty base: no image, no pull.
	scratchImage = "scratch"
)

func refusef(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrPreflight}, args...)...)
}

func q(s string) string {
	return strconv.Quote(textutil.Truncate(s, maxPreflightQuoteBytes))
}

// line is the first line of an instruction, for the refusal message.
func line(loc []parser.Range) int {
	if len(loc) == 0 {
		return 0
	}
	return loc[0].Start.Line
}

// Preflight refuses a Dockerfile that could fetch from the network, pull an
// image, escape the forced network mode or share state between builds:
//   - a parser directive selecting a frontend (# syntax=, in every form the
//     frontend detects): the daemon would pull the frontend image;
//   - a FROM whose base, after ARG substitution, is neither an earlier stage,
//     scratch, nor an image of allowedBases (canonical name@sha256:<hex>,
//     validate.BaseImage), and any FROM --platform. A base that depends on a
//     variable previewd cannot evaluate exactly as the daemon does (the
//     builtin platform ARGs, an ARG without a default, an ARG whose default
//     depends on either) is refused;
//   - ADD of a URL or a git source, a source with a variable, and ADD
//     --checksum, --keep-git-dir or --unpack;
//   - every RUN flag: --network, --mount, --security, --device;
//   - COPY --from anything but a stage of this Dockerfile;
//   - ONBUILD, and any instruction it does not recognize.
//
// allowedBases holds canonical references (validate.AllowedBaseImages).
func Preflight(dockerfile []byte, allowedBases map[string]bool) error {
	if len(dockerfile) > maxDockerfileBytes {
		return refusef("Dockerfile is %d bytes, above the %d-byte cap", len(dockerfile), maxDockerfileBytes)
	}
	if ref, _, loc, ok := parser.DetectSyntax(dockerfile); ok {
		return refusef("line %d: syntax directive %s: the daemon would pull a frontend image", line(loc), q(ref))
	}
	res, err := parser.Parse(bytes.NewReader(dockerfile))
	if err != nil {
		return refusef("parse Dockerfile: %s", q(err.Error()))
	}
	stages, metaArgs, err := instructions.Parse(res.AST, nil)
	if err != nil {
		return refusef("parse Dockerfile instructions: %s", q(err.Error()))
	}
	if len(stages) == 0 {
		return refusef("Dockerfile has no FROM")
	}
	lex := shell.NewLex(res.EscapeToken)
	env, err := globalArgs(lex, metaArgs)
	if err != nil {
		return err
	}
	for i, st := range stages {
		if err := checkBase(lex, env, stages[:i], st, allowedBases); err != nil {
			return err
		}
		for _, cmd := range st.Commands {
			if err := checkCommand(cmd, stages); err != nil {
				return err
			}
		}
	}
	return nil
}

// argEnv is the global ARG scope as previewd can evaluate it: the defaults
// of the ARGs declared before the first FROM. A tainted value depends on a
// variable previewd does not set but the daemon may (its builtin platform
// ARGs).
type argEnv struct {
	vals    map[string]string
	tainted map[string]bool
}

func (e argEnv) Get(k string) (string, bool) {
	v, ok := e.vals[k]
	return v, ok
}

func (e argEnv) Keys() []string {
	return slices.Sorted(maps.Keys(e.vals))
}

// globalArgs evaluates the meta ARGs in order, as the daemon's
// buildMetaArgs does with no build argument: a default is expanded in the
// scope built so far; an ARG without a default changes nothing (the daemon
// keeps its builtin value, if any, which previewd does not model).
func globalArgs(lex *shell.Lex, metaArgs []instructions.ArgCommand) (argEnv, error) {
	env := argEnv{vals: map[string]string{}, tainted: map[string]bool{}}
	for _, cmd := range metaArgs {
		for _, kp := range cmd.Args {
			if kp.Value == nil {
				continue
			}
			r, err := lex.ProcessWordWithMatches(*kp.Value, env)
			if err != nil {
				return argEnv{}, refusef("line %d: ARG %s: %s", line(cmd.Location()), q(kp.Key), q(err.Error()))
			}
			env.vals[kp.Key] = r.Result
			env.tainted[kp.Key] = len(r.Unmatched) > 0 || env.anyTainted(r.Matched)
		}
	}
	return env, nil
}

func (e argEnv) anyTainted(names map[string]struct{}) bool {
	for k := range names {
		if e.tainted[k] {
			return true
		}
	}
	return false
}

// checkBase resolves the base of st as the daemon does: ARG substitution in
// the global scope, then an earlier stage of that exact name, scratch, or
// an image, which must be allowlisted by digest.
func checkBase(lex *shell.Lex, env argEnv, earlier []instructions.Stage, st instructions.Stage, allowed map[string]bool) error {
	at := line(st.Location)
	if st.Platform != "" {
		return refusef("line %d: FROM --platform: the daemon would resolve another platform's image", at)
	}
	r, err := lex.ProcessWordWithMatches(st.BaseName, env)
	if err != nil {
		return refusef("line %d: FROM %s: %s", at, q(st.BaseName), q(err.Error()))
	}
	if len(r.Unmatched) > 0 || env.anyTainted(r.Matched) {
		return refusef("line %d: FROM %s depends on a variable without a fixed default", at, q(st.BaseName))
	}
	base := r.Result
	for _, s := range earlier {
		if s.Name != "" && s.Name == base {
			return nil
		}
	}
	if base == scratchImage {
		return nil
	}
	canonical, err := validate.BaseImage(base)
	if err != nil {
		return refusef("line %d: FROM %s: %w", at, q(base), err)
	}
	if !allowed[canonical] {
		return refusef("line %d: FROM %s is not in PREVIEWD_ALLOWED_BASE_IMAGES", at, q(canonical))
	}
	return nil
}

// checkCommand allows the instructions that neither fetch nor change the
// build's network or mounts, with the flags listed below; anything else is
// refused.
func checkCommand(cmd instructions.Command, stages []instructions.Stage) error {
	switch c := cmd.(type) {
	case *instructions.RunCommand:
		if len(c.FlagsUsed) > 0 {
			flags := slices.Sorted(slices.Values(c.FlagsUsed))
			return refusef("line %d: RUN %s: RUN takes no flag (network, mounts and security are fixed by previewd)",
				line(c.Location()), q("--"+strings.Join(flags, " --")))
		}
	case *instructions.AddCommand:
		at := line(c.Location())
		switch {
		case c.Checksum != "":
			return refusef("line %d: ADD --checksum applies to remote sources only", at)
		case c.KeepGitDir != nil:
			return refusef("line %d: ADD --keep-git-dir applies to git sources only", at)
		case c.Unpack != nil:
			return refusef("line %d: ADD --unpack is not allowed", at)
		}
		for _, src := range c.SourcePaths {
			if remoteSource(src) {
				return refusef("line %d: ADD %s: only paths of the build context are allowed (no URL, git source or variable)", at, q(src))
			}
		}
	case *instructions.CopyCommand:
		if c.From != "" && !isStage(c.From, stages) {
			return refusef("line %d: COPY --from=%s is not a stage of this Dockerfile", line(c.Location()), q(c.From))
		}
	case *instructions.OnbuildCommand:
		return refusef("line %d: ONBUILD is not allowed", line(c.Location()))
	case *instructions.ArgCommand, *instructions.EnvCommand, *instructions.LabelCommand,
		*instructions.MaintainerCommand, *instructions.WorkdirCommand, *instructions.UserCommand,
		*instructions.ExposeCommand, *instructions.VolumeCommand, *instructions.CmdCommand,
		*instructions.EntrypointCommand, *instructions.HealthCheckCommand, *instructions.ShellCommand,
		*instructions.StopSignalCommand:
	default:
		return refusef("unrecognized instruction %s", q(fmt.Sprintf("%T", cmd)))
	}
	return nil
}

// remoteSource reports an ADD source that is not plainly a context path. It
// is a superset of what the frontend fetches (dfgitutil.ParseGitRef: a
// scheme://, an scp-style user@host:path, a github.com/ prefix; http(s)://):
// all of them need ':' or that prefix. A variable could expand to any of
// them in the stage's scope, which previewd does not evaluate.
func remoteSource(src string) bool {
	return strings.ContainsAny(src, ":$") || strings.HasPrefix(src, "github.com/")
}

// isStage resolves COPY --from as the daemon does: an index into the stages
// (strconv.Atoi), else a stage name, case-insensitively. Anything else is an
// image the daemon would pull. The daemon refuses variables in --from.
func isStage(from string, stages []instructions.Stage) bool {
	if i, err := strconv.Atoi(from); err == nil {
		return i >= 0 && i < len(stages)
	}
	name := strings.ToLower(from)
	for _, s := range stages {
		if s.Name != "" && s.Name == name {
			return true
		}
	}
	return false
}

// PrepareBuildContext packs srcDir into a new tar file at tarPath, runs the
// preflight on the Dockerfile it packed, and returns the tar rewound, ready
// to stream (the caller closes it). The tar holds directories, regular files
// (permission bits only, owned by root) and symlinks that resolve inside the
// context; it is refused above maxBytes, with a device, socket or pipe, a
// symlink that leaves the context or dangles, or without a regular
// Dockerfile at its root. The Dockerfile checked is the one packed: nothing
// is read twice.
func PrepareBuildContext(srcDir, tarPath string, maxBytes int64, allowedBases map[string]bool) (*os.File, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("build context cap must be positive, got %d", maxBytes)
	}
	f, err := os.OpenFile(tarPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- a path under the job's own build directory
	if err != nil {
		return nil, fmt.Errorf("create build context: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
		}
	}()
	dockerfile, err := packContext(srcDir, maxBytes, f)
	if err != nil {
		return nil, err
	}
	if err := Preflight(dockerfile, allowedBases); err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind build context: %w", err)
	}
	ok = true
	return f, nil
}

// cappedWriter fails, without writing, any write that would take the total
// above max.
type cappedWriter struct {
	w      io.Writer
	n, max int64
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > c.max-c.n {
		return 0, ErrContextTooLarge
	}
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// packContext writes srcDir as a tar to w, at most maxBytes, and returns the
// content of the root Dockerfile.
func packContext(srcDir string, maxBytes int64, w io.Writer) ([]byte, error) {
	root, err := os.OpenRoot(srcDir)
	if err != nil {
		return nil, fmt.Errorf("open build context: %w", err)
	}
	defer func() { _ = root.Close() }()

	cw := &cappedWriter{w: w, max: maxBytes}
	tw := tar.NewWriter(cw)
	var (
		dockerfile []byte
		found      bool
	)
	err = fs.WalkDir(root.FS(), ".", func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", q(name), err)
		}
		hdr := &tar.Header{Name: name, Mode: int64(info.Mode().Perm()), ModTime: info.ModTime()}
		switch info.Mode().Type() {
		case fs.ModeDir:
			hdr.Typeflag, hdr.Name = tar.TypeDir, name+"/"
			return writeHeader(tw, hdr)
		case fs.ModeSymlink:
			target, err := checkSymlink(root, name)
			if err != nil {
				return err
			}
			hdr.Typeflag, hdr.Linkname = tar.TypeSymlink, target
			return writeHeader(tw, hdr)
		case 0:
			if info.Size() > cw.max-cw.n {
				return fmt.Errorf("%w: %s is %d bytes", ErrContextTooLarge, q(name), info.Size())
			}
			hdr.Typeflag, hdr.Size = tar.TypeReg, info.Size()
			content, err := packFile(root, tw, hdr)
			if err != nil {
				return err
			}
			if name == dockerfileName {
				dockerfile, found = content, true
			}
			return nil
		default:
			return refusef("%s is a %s: only files, directories and symlinks are packed", q(name), info.Mode().Type())
		}
	})
	if err != nil {
		return nil, fmt.Errorf("pack build context: %w", err)
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("pack build context: %w", err)
	}
	if !found {
		return nil, refusef("no regular %s at the root of the build context", dockerfileName)
	}
	return dockerfile, nil
}

func writeHeader(tw *tar.Writer, hdr *tar.Header) error {
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("write %s: %w", q(hdr.Name), err)
	}
	return nil
}

// packFile copies exactly hdr.Size bytes of the regular file hdr.Name into
// tw. It returns the content of the root Dockerfile, bounded, and nil for
// any other file.
func packFile(root *os.Root, tw *tar.Writer, hdr *tar.Header) ([]byte, error) {
	isDockerfile := hdr.Name == dockerfileName
	if isDockerfile && hdr.Size > maxDockerfileBytes {
		return nil, refusef("%s is %d bytes, above the %d-byte cap", dockerfileName, hdr.Size, maxDockerfileBytes)
	}
	f, err := root.Open(hdr.Name)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", q(hdr.Name), err)
	}
	defer func() { _ = f.Close() }()
	if err := writeHeader(tw, hdr); err != nil {
		return nil, err
	}
	var content bytes.Buffer
	dst := io.Writer(tw)
	if isDockerfile {
		dst = io.MultiWriter(tw, &content)
	}
	if _, err := io.CopyN(dst, f, hdr.Size); err != nil {
		return nil, fmt.Errorf("pack %s: %w", q(hdr.Name), err)
	}
	if !isDockerfile {
		return nil, nil
	}
	return content.Bytes(), nil
}

// checkSymlink returns the target of the symlink name if it is relative and
// resolves, through every link on its way, to an entry inside root.
// os.Root refuses any resolution that escapes it.
func checkSymlink(root *os.Root, name string) (string, error) {
	target, err := root.Readlink(name)
	if err != nil {
		return "", fmt.Errorf("read symlink %s: %w", q(name), err)
	}
	if path.IsAbs(target) {
		return "", refusef("symlink %s points to the absolute path %s", q(name), q(target))
	}
	if _, err := root.Stat(name); err != nil {
		return "", refusef("symlink %s -> %s leaves the build context or dangles", q(name), q(target))
	}
	return target, nil
}
