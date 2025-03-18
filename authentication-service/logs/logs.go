package logs

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var log *zap.Logger

func init() {

	config := zap.NewProductionConfig()
	config.EncoderConfig.TimeKey = "Timestamp"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.DisableStacktrace = true
	// config.EncoderConfig.StacktraceKey = ""

	var err error
	log, err = config.Build(zap.AddCallerSkip(1))
	defer log.Sync()

	if err != nil {
		panic(err)
	}

}

func Info(msg string, fields ...zap.Field) {
	log.Info(msg, fields...)
}

func Debug(msg string, fields ...zap.Field) {
	log.Debug(msg, fields...)
}

func Error(msg interface{}, fields ...zap.Field) {

	switch val := msg.(type) {
	case error:
		log.Error(val.Error(), fields...)
	case string:
		log.Error(val, fields...)
	}

}
