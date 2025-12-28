package containers

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	build "github.com/docker/docker/api/types/build"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	defaultJunocashVersion = "0.9.7"
	defaultRPCUser         = "rpcuser"
	defaultRPCPassword     = "rpcpass"
)

type Junocashd struct {
	ContainerID string
	RPCURL      string
	RPCUser     string
	RPCPassword string

	c testcontainers.Container
}

func StartJunocashd(ctx context.Context) (*Junocashd, error) {
	version := defaultJunocashVersion
	rpcUser := defaultRPCUser
	rpcPass := defaultRPCPassword

	req := testcontainers.ContainerRequest{
		ImagePlatform: "linux/amd64",
		FromDockerfile: testcontainers.FromDockerfile{
			Context:    repoRoot(),
			Dockerfile: "docker/junocashd/Dockerfile",
			BuildArgs: map[string]*string{
				"JUNOCASH_VERSION": &version,
			},
			BuildOptionsModifier: func(opts *build.ImageBuildOptions) {
				opts.Platform = "linux/amd64"
				opts.Version = build.BuilderBuildKit
			},
		},
		ExposedPorts: []string{"8232/tcp"},
		Cmd: []string{
			"-regtest",
			"-server=1",
			"-daemon=0",
			"-listen=0",
			"-printtoconsole=1",
			"-datadir=/data",
			"-rpcbind=0.0.0.0",
			"-rpcallowip=0.0.0.0/0",
			"-rpcport=8232",
			"-rpcuser=" + rpcUser,
			"-rpcpassword=" + rpcPass,
		},
		WaitingFor: wait.ForListeningPort(nat.Port("8232/tcp")).WithStartupTimeout(60 * time.Second),
	}

	if os.Getenv("JUNO_TEST_LOG") != "" {
		req.FromDockerfile.BuildLogWriter = os.Stdout
		req.LogConsumerCfg = &testcontainers.LogConsumerConfig{
			Consumers: []testcontainers.LogConsumer{&testcontainers.StdoutLogConsumer{}},
		}
	}

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	host, err := c.Host(ctx)
	if err != nil {
		_ = c.Terminate(ctx)
		return nil, err
	}

	rpcPort, err := c.MappedPort(ctx, nat.Port("8232/tcp"))
	if err != nil {
		_ = c.Terminate(ctx)
		return nil, err
	}

	j := &Junocashd{
		ContainerID: c.GetContainerID(),
		RPCURL:      fmt.Sprintf("http://%s:%s", host, rpcPort.Port()),
		RPCUser:     rpcUser,
		RPCPassword: rpcPass,
		c:           c,
	}

	if err := waitForRPCReady(ctx, j); err != nil {
		_ = c.Terminate(ctx)
		return nil, err
	}

	return j, nil
}

func (j *Junocashd) Terminate(ctx context.Context) error {
	if j == nil || j.c == nil {
		return nil
	}
	return j.c.Terminate(ctx)
}

func (j *Junocashd) ExecCLI(ctx context.Context, args ...string) ([]byte, error) {
	if j == nil || j.c == nil {
		return nil, fmt.Errorf("junocashd: container is nil")
	}

	cmd := append([]string{
		"junocash-cli",
		"-regtest",
		"-datadir=/data",
		"-rpcuser=" + j.RPCUser,
		"-rpcpassword=" + j.RPCPassword,
		"-rpcport=8232",
	}, args...)

	exitCode, reader, err := j.c.Exec(ctx, cmd)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	var stdout, stderr bytes.Buffer
	if _, err := stdcopy.StdCopy(&stdout, &stderr, bytes.NewReader(raw)); err != nil {
		stdout.Write(raw)
	}
	if exitCode != 0 {
		msg := bytes.TrimSpace(stderr.Bytes())
		if len(msg) == 0 {
			msg = bytes.TrimSpace(stdout.Bytes())
		}
		return nil, fmt.Errorf("junocash-cli exit %d: %s", exitCode, msg)
	}
	return stdout.Bytes(), nil
}

func repoRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func waitForRPCReady(ctx context.Context, jd *Junocashd) error {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		_, err := jd.ExecCLI(ctx, "getblockcount")
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
