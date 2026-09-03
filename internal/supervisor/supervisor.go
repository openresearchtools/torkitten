package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Phase string

const (
	PhaseStopped  Phase = "stopped"
	PhaseStarting Phase = "starting"
	PhaseRunning  Phase = "running"
	PhaseBackoff  Phase = "backoff"
)

type Spec struct {
	Name string
	Path string
	Args []string
	Dir  string
}

func (spec Spec) validate() error {
	if spec.Name == "" {
		return errors.New("component name is required")
	}
	if strings.ContainsAny(spec.Name, "\r\n\t ") {
		return fmt.Errorf("component name %q contains whitespace", spec.Name)
	}
	if !filepath.IsAbs(spec.Path) {
		return fmt.Errorf("component %q executable path must be absolute", spec.Name)
	}
	if spec.Dir != "" && !filepath.IsAbs(spec.Dir) {
		return fmt.Errorf("component %q working directory must be absolute", spec.Name)
	}
	for _, argument := range spec.Args {
		if strings.ContainsAny(argument, "\x00\r\n") {
			return fmt.Errorf("component %q has an invalid argument", spec.Name)
		}
	}
	return nil
}

type Status struct {
	Name       string    `json:"name"`
	Phase      Phase     `json:"phase"`
	PID        int       `json:"pid,omitempty"`
	Restarts   uint64    `json:"restarts"`
	LastError  string    `json:"last_error,omitempty"`
	LastChange time.Time `json:"last_change"`
}

type Options struct {
	InitialBackoff time.Duration
	MaximumBackoff time.Duration
	StopTimeout    time.Duration
	Output         io.Writer
	Factory        Factory
}

type Process interface {
	Start() error
	Wait() error
	Signal(os.Signal) error
	Kill() error
	PID() int
}

type Factory interface {
	New(Spec, io.Writer) Process
}

type Supervisor struct {
	specs          []Spec
	factory        Factory
	output         io.Writer
	initialBackoff time.Duration
	maximumBackoff time.Duration
	stopTimeout    time.Duration

	mutex  sync.RWMutex
	status map[string]Status
}

func New(specs []Spec, options Options) (*Supervisor, error) {
	if len(specs) == 0 {
		return nil, errors.New("at least one component is required")
	}
	seen := make(map[string]struct{}, len(specs))
	cloned := make([]Spec, len(specs))
	for index, spec := range specs {
		if err := spec.validate(); err != nil {
			return nil, err
		}
		if _, exists := seen[spec.Name]; exists {
			return nil, fmt.Errorf("duplicate component name %q", spec.Name)
		}
		seen[spec.Name] = struct{}{}
		cloned[index] = spec
		cloned[index].Args = append([]string(nil), spec.Args...)
	}
	sort.Slice(cloned, func(left, right int) bool {
		return cloned[left].Name < cloned[right].Name
	})

	if options.InitialBackoff <= 0 {
		options.InitialBackoff = 250 * time.Millisecond
	}
	if options.MaximumBackoff <= 0 {
		options.MaximumBackoff = 30 * time.Second
	}
	if options.MaximumBackoff < options.InitialBackoff {
		return nil, errors.New("maximum backoff must not be less than initial backoff")
	}
	if options.StopTimeout <= 0 {
		options.StopTimeout = 10 * time.Second
	}
	if options.Output == nil {
		options.Output = io.Discard
	}
	if options.Factory == nil {
		options.Factory = commandFactory{}
	}

	statuses := make(map[string]Status, len(cloned))
	for _, spec := range cloned {
		statuses[spec.Name] = Status{Name: spec.Name, Phase: PhaseStopped, LastChange: time.Now().UTC()}
	}
	return &Supervisor{
		specs:          cloned,
		factory:        options.Factory,
		output:         options.Output,
		initialBackoff: options.InitialBackoff,
		maximumBackoff: options.MaximumBackoff,
		stopTimeout:    options.StopTimeout,
		status:         statuses,
	}, nil
}

func (supervisor *Supervisor) Run(ctx context.Context) {
	var workers sync.WaitGroup
	workers.Add(len(supervisor.specs))
	for _, spec := range supervisor.specs {
		spec := spec
		go func() {
			defer workers.Done()
			supervisor.runComponent(ctx, spec)
		}()
	}
	workers.Wait()
}

func (supervisor *Supervisor) Status() []Status {
	supervisor.mutex.RLock()
	defer supervisor.mutex.RUnlock()
	result := make([]Status, 0, len(supervisor.status))
	for _, component := range supervisor.status {
		result = append(result, component)
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].Name < result[right].Name
	})
	return result
}

func (supervisor *Supervisor) runComponent(ctx context.Context, spec Spec) {
	backoff := supervisor.initialBackoff
	var restarts uint64
	for ctx.Err() == nil {
		process := supervisor.factory.New(spec, supervisor.output)
		supervisor.update(spec.Name, PhaseStarting, 0, restarts, "")
		if err := process.Start(); err != nil {
			supervisor.update(spec.Name, PhaseBackoff, 0, restarts, boundedError(err))
			if !waitContext(ctx, backoff) {
				break
			}
			restarts++
			backoff = nextBackoff(backoff, supervisor.maximumBackoff)
			continue
		}

		supervisor.update(spec.Name, PhaseRunning, process.PID(), restarts, "")
		waited := make(chan error, 1)
		go func() {
			waited <- process.Wait()
		}()

		select {
		case <-ctx.Done():
			supervisor.stop(process, waited)
			supervisor.update(spec.Name, PhaseStopped, 0, restarts, "")
			return
		case err := <-waited:
			if ctx.Err() != nil {
				supervisor.update(spec.Name, PhaseStopped, 0, restarts, "")
				return
			}
			supervisor.update(spec.Name, PhaseBackoff, 0, restarts, boundedError(err))
		}

		if !waitContext(ctx, backoff) {
			break
		}
		restarts++
		backoff = nextBackoff(backoff, supervisor.maximumBackoff)
	}
	supervisor.update(spec.Name, PhaseStopped, 0, restarts, "")
}

func (supervisor *Supervisor) stop(process Process, waited <-chan error) {
	_ = process.Signal(syscall.SIGTERM)
	timer := time.NewTimer(supervisor.stopTimeout)
	defer timer.Stop()
	select {
	case <-waited:
		return
	case <-timer.C:
		_ = process.Kill()
		<-waited
	}
}

func (supervisor *Supervisor) update(name string, phase Phase, pid int, restarts uint64, lastError string) {
	supervisor.mutex.Lock()
	defer supervisor.mutex.Unlock()
	supervisor.status[name] = Status{
		Name:       name,
		Phase:      phase,
		PID:        pid,
		Restarts:   restarts,
		LastError:  lastError,
		LastChange: time.Now().UTC(),
	}
}

func nextBackoff(current, maximum time.Duration) time.Duration {
	if current >= maximum/2 {
		return maximum
	}
	return current * 2
}

func waitContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func boundedError(err error) string {
	if err == nil {
		return "component exited"
	}
	message := strings.ReplaceAll(err.Error(), "\n", " ")
	message = strings.ReplaceAll(message, "\r", " ")
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}

type commandFactory struct{}

func (commandFactory) New(spec Spec, output io.Writer) Process {
	command := exec.Command(spec.Path, spec.Args...)
	command.Dir = spec.Dir
	command.Stdout = output
	command.Stderr = output
	command.Stdin = nil
	command.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
		Setpgid:   true,
	}
	return &commandProcess{command: command}
}

type commandProcess struct {
	command *exec.Cmd
}

func (process *commandProcess) Start() error {
	return process.command.Start()
}

func (process *commandProcess) Wait() error {
	return process.command.Wait()
}

func (process *commandProcess) Signal(signal os.Signal) error {
	if process.command.Process == nil {
		return os.ErrProcessDone
	}
	nativeSignal, ok := signal.(syscall.Signal)
	if !ok {
		return fmt.Errorf("unsupported signal %T", signal)
	}
	return syscall.Kill(-process.command.Process.Pid, nativeSignal)
}

func (process *commandProcess) Kill() error {
	if process.command.Process == nil {
		return os.ErrProcessDone
	}
	return syscall.Kill(-process.command.Process.Pid, syscall.SIGKILL)
}

func (process *commandProcess) PID() int {
	if process.command.Process == nil {
		return 0
	}
	return process.command.Process.Pid
}
