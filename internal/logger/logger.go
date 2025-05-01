package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// LogLevel represents the severity of a log message
type LogLevel int

const (
	// Debug level for detailed troubleshooting
	Debug LogLevel = iota
	// Info level for general operational entries
	Info
	// Warn level for non-critical issues
	Warn
	// Error level for errors that need attention
	Error
)

var levelNames = map[LogLevel]string{
	Debug: "DEBUG",
	Info:  "INFO",
	Warn:  "WARN",
	Error: "ERROR",
}

// FileMode defines platform-specific file permissions
var FileMode os.FileMode

// DirMode defines platform-specific directory permissions
var DirMode os.FileMode

func init() {
	if runtime.GOOS == "windows" {
		FileMode = 0666
		DirMode = 0666
	} else {
		FileMode = 0600
		DirMode = 0755
	}
}

// Logger represents our custom logger
type Logger struct {
	debugLogger *log.Logger
	infoLogger  *log.Logger
	warnLogger  *log.Logger
	errorLogger *log.Logger
	level       LogLevel
	mu          sync.Mutex
	file        *os.File // Keep track of open file
}

var (
	defaultLogger *Logger
	once          sync.Once
)

// Config holds logger configuration
type Config struct {
	// LogLevel sets the minimum level to log
	LogLevel LogLevel
	// LogFile is the path to the log file. If empty, logs to stdout
	LogFile string
	// MaxSize is the maximum size in MB before log rotation
	MaxSize int64
}

// Initialize sets up the default logger with configuration
func Initialize(config Config) error {
	var err error
	once.Do(func() {
		defaultLogger, err = NewLogger(config)
	})
	return err
}

// NewLogger creates a new logger instance
func NewLogger(config Config) (*Logger, error) {
	var writers []io.Writer
	writers = append(writers, os.Stdout)

	var logFile *os.File
	if config.LogFile != "" {
		// Ensure path separators are correct for the platform
		config.LogFile = filepath.Clean(config.LogFile)

		// Create log directory with platform-appropriate permissions
		logDir := filepath.Dir(config.LogFile)
		if err := os.MkdirAll(logDir, DirMode); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %v", err)
		}

		// Open log file with platform-appropriate permissions
		file, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, FileMode)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %v", err)
		}
		logFile = file
		writers = append(writers, file)
	}

	multiWriter := io.MultiWriter(writers...)

	return &Logger{
		debugLogger: log.New(multiWriter, "DEBUG: ", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile),
		infoLogger:  log.New(multiWriter, "INFO: ", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile),
		warnLogger:  log.New(multiWriter, "WARN: ", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile),
		errorLogger: log.New(multiWriter, "ERROR: ", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile),
		level:       config.LogLevel,
		file:        logFile,
	}, nil
}

// Close properly closes the logger's file handle if one exists
func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Debug logs a debug message
func (l *Logger) Debug(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.level <= Debug {
		l.debugLogger.Printf(format, v...)
	}
}

// Info logs an info message
func (l *Logger) Info(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.level <= Info {
		l.infoLogger.Printf(format, v...)
	}
}

// Warn logs a warning message
func (l *Logger) Warn(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.level <= Warn {
		l.warnLogger.Printf(format, v...)
	}
}

// Error logs an error message
func (l *Logger) Error(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.level <= Error {
		l.errorLogger.Printf(format, v...)
	}
}

// GetLogger returns the default logger instance
func GetLogger() *Logger {
	if defaultLogger == nil {
		panic("logger not initialized")
	}
	return defaultLogger
}

// ParseLogLevel converts a string level to LogLevel
func ParseLogLevel(level string) (LogLevel, error) {
	switch level {
	case "debug", "DEBUG":
		return Debug, nil
	case "info", "INFO":
		return Info, nil
	case "warn", "WARN":
		return Warn, nil
	case "error", "ERROR":
		return Error, nil
	default:
		return Info, fmt.Errorf("unknown log level: %s", level)
	}
}
