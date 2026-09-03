package supervisor

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestSupervisorRestartsOnlyFailedComponent(t *testing.T) {
	factory := newFakeFactory()
	torFirst := factory.queue("tor")
	torSecond := factory.queue("tor")
	caddy := factory.queue("caddy")

	supervisor, err := New([]Spec{
		{Name: "tor", Path: "/opt/torkitten/bin/tor"},
		{Name: "caddy", Path: "/opt/torkitten/bin/caddy"},
	}, Options{Factory: factory, InitialBackoff: time.Millisecond, MaximumBackoff: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		supervisor.Run(ctx)
		close(done)
	}()
	waitFor(t, func() bool { return torFirst.started() && caddy.started() })
	torFirst.exit(errors.New("tor crashed"))
	waitFor(t, torSecond.started)
	if caddy.startCount() != 1 {
		t.Fatalf("Caddy was restarted after only Tor failed: starts=%d", caddy.startCount())
	}

	cancel()
	waitForDone(t, done)
	if torSecond.signal() != syscall.SIGTERM || caddy.signal() != syscall.SIGTERM {
		t.Fatal("running components did not receive SIGTERM")
	}
}

func TestSupervisorRetriesStartFailure(t *testing.T) {
	factory := newFakeFactory()
	failed := factory.queue("tor")
	failed.startErr = errors.New("not executable")
	running := factory.queue("tor")

	supervisor, err := New(
		[]Spec{{Name: "tor", Path: "/opt/torkitten/bin/tor"}},
		Options{Factory: factory, InitialBackoff: time.Millisecond, MaximumBackoff: time.Millisecond},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		supervisor.Run(ctx)
		close(done)
	}()
	waitFor(t, running.started)
	statuses := supervisor.Status()
	if len(statuses) != 1 || statuses[0].Phase != PhaseRunning || statuses[0].Restarts != 1 {
		t.Fatalf("unexpected status: %#v", statuses)
	}
	cancel()
	waitForDone(t, done)
}

func TestSupervisorKillsComponentAfterGracePeriod(t *testing.T) {
	factory := newFakeFactory()
	process := factory.queue("tor")
	process.ignoreTerm = true
	supervisor, err := New(
		[]Spec{{Name: "tor", Path: "/opt/torkitten/bin/tor"}},
		Options{Factory: factory, StopTimeout: time.Millisecond},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		supervisor.Run(ctx)
		close(done)
	}()
	waitFor(t, process.started)
	cancel()
	waitForDone(t, done)
	if !process.killed() {
		t.Fatal("component was not killed after its graceful shutdown deadline")
	}
}

func TestSpecRejectsRelativeExecutable(t *testing.T) {
	_, err := New([]Spec{{Name: "tor", Path: "bin/tor"}}, Options{})
	if err == nil {
		t.Fatal("relative executable path was accepted")
	}
}

type fakeFactory struct {
	mutex  sync.Mutex
	queued map[string][]*fakeProcess
}

func newFakeFactory() *fakeFactory {
	return &fakeFactory{queued: make(map[string][]*fakeProcess)}
}

func (factory *fakeFactory) queue(name string) *fakeProcess {
	factory.mutex.Lock()
	defer factory.mutex.Unlock()
	process := &fakeProcess{waited: make(chan error, 1), pid: len(factory.queued[name]) + 100}
	factory.queued[name] = append(factory.queued[name], process)
	return process
}

func (factory *fakeFactory) New(spec Spec, _ io.Writer) Process {
	factory.mutex.Lock()
	defer factory.mutex.Unlock()
	queued := factory.queued[spec.Name]
	if len(queued) == 0 {
		panic("unexpected process creation for " + spec.Name)
	}
	process := queued[0]
	factory.queued[spec.Name] = queued[1:]
	return process
}

type fakeProcess struct {
	mutex      sync.Mutex
	waited     chan error
	pid        int
	starts     int
	startErr   error
	lastSignal os.Signal
	wasKilled  bool
	ignoreTerm bool
	exited     bool
}

func (process *fakeProcess) Start() error {
	process.mutex.Lock()
	defer process.mutex.Unlock()
	process.starts++
	return process.startErr
}

func (process *fakeProcess) Wait() error {
	return <-process.waited
}

func (process *fakeProcess) Signal(signal os.Signal) error {
	process.mutex.Lock()
	process.lastSignal = signal
	ignore := process.ignoreTerm
	exited := process.exited
	if !ignore && !exited {
		process.exited = true
	}
	process.mutex.Unlock()
	if !ignore && !exited {
		process.waited <- nil
	}
	return nil
}

func (process *fakeProcess) Kill() error {
	process.mutex.Lock()
	process.wasKilled = true
	exited := process.exited
	if !exited {
		process.exited = true
	}
	process.mutex.Unlock()
	if !exited {
		process.waited <- errors.New("killed")
	}
	return nil
}

func (process *fakeProcess) PID() int {
	return process.pid
}

func (process *fakeProcess) exit(err error) {
	process.mutex.Lock()
	if process.exited {
		process.mutex.Unlock()
		return
	}
	process.exited = true
	process.mutex.Unlock()
	process.waited <- err
}

func (process *fakeProcess) started() bool {
	return process.startCount() > 0
}

func (process *fakeProcess) startCount() int {
	process.mutex.Lock()
	defer process.mutex.Unlock()
	return process.starts
}

func (process *fakeProcess) signal() os.Signal {
	process.mutex.Lock()
	defer process.mutex.Unlock()
	return process.lastSignal
}

func (process *fakeProcess) killed() bool {
	process.mutex.Lock()
	defer process.mutex.Unlock()
	return process.wasKilled
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not satisfied")
}

func waitForDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("supervisor did not stop")
	}
}
