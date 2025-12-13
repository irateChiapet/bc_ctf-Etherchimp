package daemon

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	pidFile = "/var/run/etherchimp/etherchimp.pid"
	logFile = "/var/log/etherchimp/etherchimp.log"
)

// Daemonize runs the current process as a daemon
func Daemonize() error {
	// Check if already running
	if IsRunning() {
		return fmt.Errorf("daemon is already running (PID file exists: %s)", pidFile)
	}

	// Get the executable path
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	// Prepare command with original arguments, but replace daemon command
	args := os.Args[1:]
	newArgs := []string{}
	skipNext := false
	for i, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}
		// Skip daemon command and its value
		if arg == "-daemon" || arg == "--daemon" {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				skipNext = true
			}
			continue
		}
		// Add --background flag to indicate we're running in background
		newArgs = append(newArgs, arg)
	}
	newArgs = append(newArgs, "--background")

	// Create the command
	cmd := exec.Command(executable, newArgs...)

	// Create log directory and file
	if err := os.MkdirAll(filepath.Dir(logFile), 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %v", err)
	}

	logFd, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to create log file: %v", err)
	}
	cmd.Stdout = logFd
	cmd.Stderr = logFd
	cmd.Stdin = nil

	// Start the process
	if err := cmd.Start(); err != nil {
		logFd.Close()
		return fmt.Errorf("failed to start daemon: %v", err)
	}

	// Write PID file
	if err := writePIDFile(cmd.Process.Pid); err != nil {
		cmd.Process.Kill()
		logFd.Close()
		return fmt.Errorf("failed to write PID file: %v", err)
	}

	fmt.Printf("Daemon started successfully with PID %d\n", cmd.Process.Pid)
	fmt.Printf("PID file: %s\n", pidFile)
	fmt.Printf("Log file: %s\n", logFile)

	// Don't close logFd here - let the child process inherit it
	return nil
}

// IsRunning checks if the daemon is currently running
func IsRunning() bool {
	pid, err := readPIDFile()
	if err != nil {
		return false
	}

	// Check if process exists
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// Send signal 0 to check if process is alive (doesn't actually send a signal)
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

// GetPID returns the PID of the running daemon, or 0 if not running
func GetPID() int {
	if !IsRunning() {
		return 0
	}
	pid, _ := readPIDFile()
	return pid
}

// Stop stops the running daemon
func Stop() error {
	pid, err := readPIDFile()
	if err != nil {
		return fmt.Errorf("daemon is not running")
	}

	// Send SIGTERM for graceful shutdown
	process, err := os.FindProcess(pid)
	if err != nil {
		removePIDFile()
		return fmt.Errorf("failed to find process: %v", err)
	}

	fmt.Printf("Stopping daemon (PID %d)...\n", pid)
	if err := process.Signal(syscall.SIGTERM); err != nil {
		removePIDFile()
		return fmt.Errorf("failed to stop daemon: %v", err)
	}

	// Wait for process to exit (with timeout)
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		if !IsRunning() {
			removePIDFile()
			fmt.Println("Daemon stopped successfully")
			return nil
		}
	}

	// Force kill if graceful shutdown failed
	fmt.Println("Graceful shutdown timed out, forcing kill...")
	process.Signal(syscall.SIGKILL)
	time.Sleep(500 * time.Millisecond)
	removePIDFile()
	fmt.Println("Daemon killed")
	return nil
}

// Pause pauses the running daemon
func Pause() error {
	pid, err := readPIDFile()
	if err != nil {
		return fmt.Errorf("daemon is not running")
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process: %v", err)
	}

	fmt.Printf("Pausing daemon (PID %d)...\n", pid)
	// Send SIGUSR1 to pause
	if err := process.Signal(syscall.SIGUSR1); err != nil {
		return fmt.Errorf("failed to pause daemon: %v", err)
	}

	fmt.Println("Daemon paused successfully")
	return nil
}

// Resume resumes the paused daemon
func Resume() error {
	pid, err := readPIDFile()
	if err != nil {
		return fmt.Errorf("daemon is not running")
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process: %v", err)
	}

	fmt.Printf("Resuming daemon (PID %d)...\n", pid)
	// Send SIGUSR2 to resume
	if err := process.Signal(syscall.SIGUSR2); err != nil {
		return fmt.Errorf("failed to resume daemon: %v", err)
	}

	fmt.Println("Daemon resumed successfully")
	return nil
}

// Status displays the current status of the daemon
func Status() {
	if !IsRunning() {
		fmt.Println("Daemon is not running")
		return
	}

	pid, _ := readPIDFile()
	fmt.Printf("Daemon is running (PID %d)\n", pid)
	fmt.Printf("PID file: %s\n", pidFile)
	fmt.Printf("Log file: %s\n", logFile)

	// Try to read process info
	if procInfo, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		// Replace null bytes with spaces for readability
		cmdline := strings.ReplaceAll(string(procInfo), "\x00", " ")
		fmt.Printf("Command: %s\n", strings.TrimSpace(cmdline))
	}

	// Get process start time
	if stat, err := os.Stat(pidFile); err == nil {
		fmt.Printf("Started: %s\n", stat.ModTime().Format("2006-01-02 15:04:05"))
	}

	// Check log file size
	if stat, err := os.Stat(logFile); err == nil {
		fmt.Printf("Log size: %d bytes\n", stat.Size())
	}
}

// writePIDFile writes the process ID to the PID file
func writePIDFile(pid int) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(pidFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create PID directory: %v", err)
	}

	return os.WriteFile(pidFile, []byte(strconv.Itoa(pid)), 0644)
}

// readPIDFile reads the process ID from the PID file
func readPIDFile() (int, error) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, err
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, err
	}

	return pid, nil
}

// removePIDFile removes the PID file
func removePIDFile() {
	os.Remove(pidFile)
}

// RemovePIDFileOnExit removes the PID file when the process exits
func RemovePIDFileOnExit() {
	removePIDFile()
}

// SetupLogging redirects logging to a file when running in background
func SetupLogging(background bool) error {
	if !background {
		return nil
	}

	// Create log directory
	if err := os.MkdirAll(filepath.Dir(logFile), 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %v", err)
	}

	// Open log file
	logFd, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}

	// Redirect standard logger
	log.SetOutput(logFd)

	// Also redirect stdout/stderr
	syscall.Dup2(int(logFd.Fd()), int(os.Stdout.Fd()))
	syscall.Dup2(int(logFd.Fd()), int(os.Stderr.Fd()))

	return nil
}

// DiscardOutput redirects stdout/stderr to /dev/null
func DiscardOutput() {
	devNull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if devNull != nil {
		os.Stdout = devNull
		os.Stderr = devNull
		log.SetOutput(io.Discard)
	}
}
