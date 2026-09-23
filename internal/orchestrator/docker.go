package orchestrator

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/containerd/errdefs"
	"github.com/docker/docker/api/types/build"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
)

// DockerEngine implements Engine using the local Docker API.
type DockerEngine struct {
	client *client.Client
}

// NewDockerEngine initializes a connection to the local host's Docker daemon.
func NewDockerEngine() (*DockerEngine, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize docker client: %w", err)
	}
	return &DockerEngine{client: cli}, nil
}

// Ping verifies daemon reachability.
func (d *DockerEngine) Ping(ctx context.Context) error {
	if _, err := d.client.Ping(ctx); err != nil {
		return fmt.Errorf("docker daemon ping failed: %w", err)
	}
	return nil
}

// Build creates an in-memory tarball of the context directory and streams it to the Docker daemon.
func (d *DockerEngine) Build(ctx context.Context, buildDir, tag string) error {
	tarBuffer := new(bytes.Buffer)
	tw := tar.NewWriter(tarBuffer)
	defer func() {
		_ = tw.Close()
	}()

	root, err := os.OpenRoot(buildDir)
	if err != nil {
		return fmt.Errorf("failed to open secure root for build directory: %w", err)
	}
	defer func() {
		_ = root.Close()
	}()

	err = fs.WalkDir(root.FS(), ".", func(path string, dEntry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == "." {
			return nil
		}

		info, err := dEntry.Info()
		if err != nil {
			return fmt.Errorf("failed to retrieve file info: %w", err)
		}

		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			return fmt.Errorf("failed to create tar header: %w", err)
		}
		header.Name = filepath.ToSlash(path)

		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("failed to write tar header: %w", err)
		}

		if dEntry.IsDir() {
			return nil
		}

		file, err := root.Open(path)
		if err != nil {
			return fmt.Errorf("failed to securely open file for tar: %w", err)
		}
		defer func() {
			_ = file.Close()
		}()

		if _, err := io.Copy(tw, file); err != nil {
			return fmt.Errorf("failed to copy file contents to tar: %w", err)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("tar context creation failed: %w", err)
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("tar writer close failure: %w", err)
	}

	opts := build.ImageBuildOptions{
		Dockerfile: "Dockerfile",
		Tags:       []string{tag},
		Remove:     true,
	}

	res, err := d.client.ImageBuild(ctx, bytes.NewReader(tarBuffer.Bytes()), opts)
	if err != nil {
		return fmt.Errorf("docker image build failed: %w", err)
	}
	defer func() {
		_ = res.Body.Close()
	}()

	if _, err := io.Copy(io.Discard, res.Body); err != nil {
		return fmt.Errorf("failed to drain build output: %w", err)
	}

	return nil
}

// ProvisionNetwork creates a dedicated bridge network for the pull request.
func (d *DockerEngine) ProvisionNetwork(ctx context.Context, envID string) error {
	netName := fmt.Sprintf("%s-net", envID)
	opts := network.CreateOptions{
		Driver: "bridge",
	}
	_, err := d.client.NetworkCreate(ctx, netName, opts)
	if err != nil && !errdefs.IsConflict(err) {
		return fmt.Errorf("failed to provision isolated network %s: %w", netName, err)
	}
	return nil
}

// Deploy provisions a container with dynamic routing labels and in-memory secrets.
func (d *DockerEngine) Deploy(ctx context.Context, env Environment) error {
	envVars := make([]string, 0, len(env.Secrets))
	for k, v := range env.Secrets {
		envVars = append(envVars, fmt.Sprintf("%s=%s", k, v))
	}

	labels := map[string]string{
		"traefik.enable": "true",
		fmt.Sprintf("traefik.http.routers.%s.rule", env.ID):                      fmt.Sprintf("Host(`%s.local`)", env.ID),
		fmt.Sprintf("traefik.http.services.%s.loadbalancer.server.port", env.ID): fmt.Sprintf("%d", env.Port),
	}

	cfg := &container.Config{
		Image:  env.Image,
		Env:    envVars,
		Labels: labels,
	}

	netName := fmt.Sprintf("%s-net", env.ID)
	hostCfg := &container.HostConfig{
		NetworkMode: container.NetworkMode(netName),
		AutoRemove:  false,
	}

	resp, err := d.client.ContainerCreate(ctx, cfg, hostCfg, nil, nil, env.ID)
	if err != nil {
		return fmt.Errorf("failed to create environment container %s: %w", env.ID, err)
	}

	if err := d.client.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return fmt.Errorf("failed to start environment container %s: %w", env.ID, err)
	}

	return nil
}

// Destroy aggressively terminates the container, purges the image, and removes the network.
func (d *DockerEngine) Destroy(ctx context.Context, id string) error {
	opts := container.RemoveOptions{
		Force:         true,
		RemoveVolumes: true,
	}
	if err := d.client.ContainerRemove(ctx, id, opts); err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("container teardown failed: %w", err)
	}

	netName := fmt.Sprintf("%s-net", id)
	if err := d.client.NetworkRemove(ctx, netName); err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("network teardown failed: %w", err)
	}

	imgName := fmt.Sprintf("%s:latest", id)
	if _, err := d.client.ImageRemove(ctx, imgName, image.RemoveOptions{Force: true}); err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("image teardown failed: %w", err)
	}

	return nil
}

// Logs returns the standard output and error streams.
func (d *DockerEngine) Logs(ctx context.Context, id string) (io.ReadCloser, error) {
	opts := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
	}
	logs, err := d.client.ContainerLogs(ctx, id, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to stream logs for environment %s: %w", id, err)
	}
	return logs, nil
}

// Close gracefully terminates the SDK connection.
func (d *DockerEngine) Close() error {
	return d.client.Close()
}
