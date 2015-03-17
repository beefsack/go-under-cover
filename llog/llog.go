package llog

import (
	"fmt"
	"log"
	"os"
)

const (
	LevelError = iota + 1
	LevelWarn
	LevelInfo
	LevelDebug
	LevelTrace
)

var levelStrs = map[int]string{
	LevelError: "[ERROR]",
	LevelWarn:  "[WARN] ",
	LevelInfo:  "[INFO] ",
	LevelDebug: "[DEBUG]",
	LevelTrace: "[TRACE]",
}

var Default = New(LevelError, log.New(os.Stderr, "", log.LstdFlags))

type Logger struct {
	Level  int
	logger *log.Logger
}

func New(level int, logger *log.Logger) *Logger {
	return &Logger{
		Level:  level,
		logger: logger,
	}
}

func (l *Logger) Print(level int, format string, v ...interface{}) {
	if l.Level >= level {
		l.logger.Printf("%s %s", levelStrs[level], fmt.Sprintf(format, v...))
	}
}

func (l *Logger) Fatal(format string, v ...interface{}) {
	l.Error(format, v...)
	os.Exit(1)
}

func (l *Logger) Error(format string, v ...interface{}) {
	l.Print(LevelError, format, v...)
}

func (l *Logger) Warn(format string, v ...interface{}) {
	l.Print(LevelWarn, format, v...)
}

func (l *Logger) Info(format string, v ...interface{}) {
	l.Print(LevelInfo, format, v...)
}

func (l *Logger) Debug(format string, v ...interface{}) {
	l.Print(LevelDebug, format, v...)
}

func (l *Logger) Trace(format string, v ...interface{}) {
	l.Print(LevelTrace, format, v...)
}

func Print(level int, format string, v ...interface{}) {
	Default.Print(level, format, v...)
}

func Fatal(format string, v ...interface{}) {
	Default.Fatal(format, v...)
}

func Error(format string, v ...interface{}) {
	Default.Error(format, v...)
}

func Warn(format string, v ...interface{}) {
	Default.Warn(format, v...)
}

func Info(format string, v ...interface{}) {
	Default.Info(format, v...)
}

func Debug(format string, v ...interface{}) {
	Default.Debug(format, v...)
}

func Trace(format string, v ...interface{}) {
	Default.Trace(format, v...)
}
