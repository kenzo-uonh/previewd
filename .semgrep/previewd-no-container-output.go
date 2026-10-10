// Fixture for `semgrep --test .semgrep/` (rule previewd-no-container-output).
// Never compiled: directories whose name starts with "." are outside the Go
// module's package set.

package fixture

import (
	"context"
	"io"

	"github.com/moby/moby/client"
)

func logs(ctx context.Context, cli *client.Client, id string) (io.ReadCloser, error) {
	// ruleid: previewd-no-container-output
	return cli.ContainerLogs(ctx, id, client.ContainerLogsOptions{ShowStdout: true, Follow: true})
}

func attach(ctx context.Context, cli *client.Client, id string) error {
	// ruleid: previewd-no-container-output
	_, err := cli.ContainerAttach(ctx, id, client.ContainerAttachOptions{Stream: true, Stdout: true})
	return err
}

func execAttach(ctx context.Context, cli *client.Client, execID string) error {
	// ruleid: previewd-no-container-output
	_, err := cli.ContainerExecAttach(ctx, execID, client.ExecAttachOptions{})
	return err
}

type engine struct{ cli *client.Client }

func (e engine) logsFunc() func(context.Context, string, client.ContainerLogsOptions) (client.ContainerLogsResult, error) {
	// ruleid: previewd-no-container-output
	return e.cli.ContainerLogs
}

func inspect(ctx context.Context, cli *client.Client, id string) error {
	// ok: previewd-no-container-output
	_, err := cli.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	return err
}

func list(ctx context.Context, cli *client.Client) error {
	// ok: previewd-no-container-output
	_, err := cli.ContainerList(ctx, client.ContainerListOptions{All: true})
	return err
}
