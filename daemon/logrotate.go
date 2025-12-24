package daemon

import (
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LogRotateConfig holds configuration for log rotation
type LogRotateConfig struct {
	MaxSizeBytes  int64         // Maximum size before rotation (default: 10MB)
	MaxBackups    int           // Maximum number of backup files to keep (default: 5)
	MaxAgeDays    int           // Maximum age of backup files in days (default: 30, 0 = no limit)
	Compress      bool          // Whether to compress rotated files (default: true)
	CheckInterval time.Duration // How often to check for rotation (default: 1 minute)
}

// DefaultLogRotateConfig returns sensible defaults
func DefaultLogRotateConfig() LogRotateConfig {
	return LogRotateConfig{
		MaxSizeBytes:  10 * 1024 * 1024, // 10MB
		MaxBackups:    5,
		MaxAgeDays:    30,
		Compress:      true,
		CheckInterval: 1 * time.Minute,
	}
}

// LogRotator manages log file rotation
type LogRotator struct {
	config   LogRotateConfig
	logPath  string
	mu       sync.Mutex
	stopChan chan struct{}
	doneChan chan struct{}
	running  bool
	logFile  *os.File
}

// NewLogRotator creates a new log rotator for the specified log file
func NewLogRotator(logPath string, config LogRotateConfig) *LogRotator {
	return &LogRotator{
		config:   config,
		logPath:  logPath,
		stopChan: make(chan struct{}),
		doneChan: make(chan struct{}),
	}
}

// Start begins the log rotation background process
func (lr *LogRotator) Start() error {
	lr.mu.Lock()
	if lr.running {
		lr.mu.Unlock()
		return fmt.Errorf("log rotator already running")
	}
	lr.running = true
	lr.mu.Unlock()

	go lr.rotationLoop()
	log.Printf("Log rotation started for %s (max size: %d bytes, max backups: %d)",
		lr.logPath, lr.config.MaxSizeBytes, lr.config.MaxBackups)
	return nil
}

// Stop stops the log rotation background process
func (lr *LogRotator) Stop() {
	lr.mu.Lock()
	if !lr.running {
		lr.mu.Unlock()
		return
	}
	lr.mu.Unlock()

	close(lr.stopChan)
	<-lr.doneChan

	lr.mu.Lock()
	lr.running = false
	lr.mu.Unlock()
}

// rotationLoop periodically checks if rotation is needed
func (lr *LogRotator) rotationLoop() {
	defer close(lr.doneChan)

	ticker := time.NewTicker(lr.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-lr.stopChan:
			return
		case <-ticker.C:
			if err := lr.checkAndRotate(); err != nil {
				log.Printf("Log rotation error: %v", err)
			}
		}
	}
}

// checkAndRotate checks if rotation is needed and performs it
func (lr *LogRotator) checkAndRotate() error {
	lr.mu.Lock()
	defer lr.mu.Unlock()

	// Check if log file exists
	info, err := os.Stat(lr.logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist yet
		}
		return fmt.Errorf("failed to stat log file: %v", err)
	}

	// Check if rotation is needed based on size
	if info.Size() < lr.config.MaxSizeBytes {
		return nil
	}

	return lr.rotate()
}

// rotate performs the actual log rotation
func (lr *LogRotator) rotate() error {
	log.Printf("Rotating log file %s (size: %d bytes)", lr.logPath, lr.getFileSize())

	// Generate new backup filename with timestamp
	timestamp := time.Now().Format("20060102-150405")
	backupPath := fmt.Sprintf("%s.%s", lr.logPath, timestamp)

	// Close current log file if we have it open
	if lr.logFile != nil {
		lr.logFile.Close()
		lr.logFile = nil
	}

	// Rename current log to backup
	if err := os.Rename(lr.logPath, backupPath); err != nil {
		return fmt.Errorf("failed to rename log file: %v", err)
	}

	// Compress if enabled
	if lr.config.Compress {
		if err := lr.compressFile(backupPath); err != nil {
			log.Printf("Warning: failed to compress %s: %v", backupPath, err)
		}
	}

	// Clean up old backups
	if err := lr.cleanupOldBackups(); err != nil {
		log.Printf("Warning: failed to cleanup old backups: %v", err)
	}

	// Create new log file
	newFile, err := os.OpenFile(lr.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to create new log file: %v", err)
	}
	lr.logFile = newFile

	// Update log output to new file
	log.SetOutput(newFile)

	log.Printf("Log rotation complete. New log file created.")
	return nil
}

// compressFile compresses a file using gzip
func (lr *LogRotator) compressFile(path string) error {
	// Open source file
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()

	// Create destination file
	dstPath := path + ".gz"
	dst, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	// Create gzip writer
	gzWriter := gzip.NewWriter(dst)
	defer gzWriter.Close()

	// Copy data
	if _, err := io.Copy(gzWriter, src); err != nil {
		os.Remove(dstPath) // Clean up on error
		return err
	}

	// Close gzip writer to flush
	if err := gzWriter.Close(); err != nil {
		os.Remove(dstPath)
		return err
	}

	// Remove original file
	return os.Remove(path)
}

// cleanupOldBackups removes old backup files exceeding MaxBackups or MaxAgeDays
func (lr *LogRotator) cleanupOldBackups() error {
	dir := filepath.Dir(lr.logPath)
	baseName := filepath.Base(lr.logPath)

	// Find all backup files
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	var backups []string
	for _, entry := range entries {
		name := entry.Name()
		// Match backup files (logfile.timestamp or logfile.timestamp.gz)
		if strings.HasPrefix(name, baseName+".") && name != baseName {
			backups = append(backups, filepath.Join(dir, name))
		}
	}

	// Sort by modification time (newest first)
	sort.Slice(backups, func(i, j int) bool {
		infoI, _ := os.Stat(backups[i])
		infoJ, _ := os.Stat(backups[j])
		if infoI == nil || infoJ == nil {
			return false
		}
		return infoI.ModTime().After(infoJ.ModTime())
	})

	// Remove excess backups
	for i, backup := range backups {
		shouldRemove := false

		// Check count limit
		if i >= lr.config.MaxBackups {
			shouldRemove = true
		}

		// Check age limit
		if lr.config.MaxAgeDays > 0 {
			info, err := os.Stat(backup)
			if err == nil {
				age := time.Since(info.ModTime())
				if age > time.Duration(lr.config.MaxAgeDays)*24*time.Hour {
					shouldRemove = true
				}
			}
		}

		if shouldRemove {
			if err := os.Remove(backup); err != nil {
				log.Printf("Warning: failed to remove old backup %s: %v", backup, err)
			} else {
				log.Printf("Removed old backup: %s", backup)
			}
		}
	}

	return nil
}

// getFileSize returns the current log file size
func (lr *LogRotator) getFileSize() int64 {
	info, err := os.Stat(lr.logPath)
	if err != nil {
		return 0
	}
	return info.Size()
}

// ForceRotate forces an immediate log rotation regardless of size
func (lr *LogRotator) ForceRotate() error {
	lr.mu.Lock()
	defer lr.mu.Unlock()

	// Check if log file exists
	if _, err := os.Stat(lr.logPath); os.IsNotExist(err) {
		return fmt.Errorf("log file does not exist: %s", lr.logPath)
	}

	return lr.rotate()
}

// RotateLogs is a CLI-callable function to manually rotate logs
func RotateLogs(config LogRotateConfig) error {
	rotator := NewLogRotator(logFile, config)
	return rotator.ForceRotate()
}

// RotateLogsWithPath rotates a specific log file
func RotateLogsWithPath(logPath string, config LogRotateConfig) error {
	rotator := NewLogRotator(logPath, config)
	return rotator.ForceRotate()
}

// ParseLogRotateConfig parses CLI flags into a LogRotateConfig
func ParseLogRotateConfig(maxSizeMB int, maxBackups int, maxAgeDays int, compress bool, checkIntervalSec int) LogRotateConfig {
	config := DefaultLogRotateConfig()

	if maxSizeMB > 0 {
		config.MaxSizeBytes = int64(maxSizeMB) * 1024 * 1024
	}
	if maxBackups >= 0 {
		config.MaxBackups = maxBackups
	}
	if maxAgeDays >= 0 {
		config.MaxAgeDays = maxAgeDays
	}
	config.Compress = compress
	if checkIntervalSec > 0 {
		config.CheckInterval = time.Duration(checkIntervalSec) * time.Second
	}

	return config
}

// GetLogRotateStatus returns the current status of log files
func GetLogRotateStatus() {
	info, err := os.Stat(logFile)
	if err != nil {
		fmt.Printf("Log file: %s (not found)\n", logFile)
		return
	}

	fmt.Printf("Log file: %s\n", logFile)
	fmt.Printf("  Size: %s\n", formatBytes(info.Size()))
	fmt.Printf("  Modified: %s\n", info.ModTime().Format("2006-01-02 15:04:05"))

	// Find backups
	dir := filepath.Dir(logFile)
	baseName := filepath.Base(logFile)
	entries, _ := os.ReadDir(dir)

	var backups []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, baseName+".") && name != baseName {
			backups = append(backups, name)
		}
	}

	if len(backups) > 0 {
		fmt.Printf("  Backups: %d\n", len(backups))
		for _, backup := range backups {
			backupPath := filepath.Join(dir, backup)
			if bInfo, err := os.Stat(backupPath); err == nil {
				fmt.Printf("    - %s (%s)\n", backup, formatBytes(bInfo.Size()))
			}
		}
	} else {
		fmt.Printf("  Backups: none\n")
	}
}

// formatBytes formats bytes into human readable string
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// CleanupAllLogs removes all log files (use with caution)
func CleanupAllLogs() error {
	dir := filepath.Dir(logFile)
	baseName := filepath.Base(logFile)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, baseName) {
			path := filepath.Join(dir, name)
			if err := os.Remove(path); err != nil {
				fmt.Printf("Failed to remove %s: %v\n", path, err)
			} else {
				fmt.Printf("Removed: %s\n", path)
			}
		}
	}

	return nil
}

// Global log rotator instance for use by the daemon
var globalLogRotator *LogRotator

// StartLogRotation starts the global log rotator
func StartLogRotation(config LogRotateConfig) error {
	if globalLogRotator != nil {
		return fmt.Errorf("log rotation already started")
	}
	globalLogRotator = NewLogRotator(logFile, config)
	return globalLogRotator.Start()
}

// StopLogRotation stops the global log rotator
func StopLogRotation() {
	if globalLogRotator != nil {
		globalLogRotator.Stop()
		globalLogRotator = nil
	}
}

// ParseSizeString parses a size string like "10MB" or "1GB" into bytes
func ParseSizeString(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0, fmt.Errorf("empty size string")
	}

	// Find where the number ends
	numEnd := 0
	for i, c := range s {
		if c < '0' || c > '9' {
			if c != '.' {
				numEnd = i
				break
			}
		}
	}

	if numEnd == 0 {
		// No suffix, assume bytes
		return strconv.ParseInt(s, 10, 64)
	}

	numStr := s[:numEnd]
	suffix := strings.TrimSpace(s[numEnd:])

	num, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number: %s", numStr)
	}

	multiplier := int64(1)
	switch suffix {
	case "B", "":
		multiplier = 1
	case "K", "KB":
		multiplier = 1024
	case "M", "MB":
		multiplier = 1024 * 1024
	case "G", "GB":
		multiplier = 1024 * 1024 * 1024
	default:
		return 0, fmt.Errorf("unknown size suffix: %s", suffix)
	}

	return int64(num * float64(multiplier)), nil
}
