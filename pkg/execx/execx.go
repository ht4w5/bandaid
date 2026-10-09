package execx

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/google/shlex"
)

func Run(ctx context.Context, cmd string) error {
	parts, err := shlex.Split(cmd)
	if err != nil {
		return fmt.Errorf("split cmd: %w", err)
	}
	if len(parts) == 0 {
		return fmt.Errorf("empty cmd")
	}

	c := exec.CommandContext(ctx, parts[0], parts[1:]...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin

	if err := c.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("run %q: %w", cmd, ctxErr)
		}
		return fmt.Errorf("run %q: %w", cmd, err)
	}

	return nil
}
