package vpn

import (
	"context"
	"fmt"
)

type sessionLogger struct{ s *Session }

func (l sessionLogger) write(args ...any)                           { l.s.addLog(fmt.Sprint(args...)) }
func (l sessionLogger) Trace(args ...any)                           { l.write(args...) }
func (l sessionLogger) Debug(args ...any)                           { l.write(args...) }
func (l sessionLogger) Info(args ...any)                            { l.write(args...) }
func (l sessionLogger) Warn(args ...any)                            { l.write(args...) }
func (l sessionLogger) Error(args ...any)                           { l.write(args...) }
func (l sessionLogger) Fatal(args ...any)                           { l.write(args...) }
func (l sessionLogger) Panic(args ...any)                           { l.write(args...) }
func (l sessionLogger) TraceContext(_ context.Context, args ...any) { l.write(args...) }
func (l sessionLogger) DebugContext(_ context.Context, args ...any) { l.write(args...) }
func (l sessionLogger) InfoContext(_ context.Context, args ...any)  { l.write(args...) }
func (l sessionLogger) WarnContext(_ context.Context, args ...any)  { l.write(args...) }
func (l sessionLogger) ErrorContext(_ context.Context, args ...any) { l.write(args...) }
func (l sessionLogger) FatalContext(_ context.Context, args ...any) { l.write(args...) }
func (l sessionLogger) PanicContext(_ context.Context, args ...any) { l.write(args...) }
