// Command worker runs the ingestion/normalization worker as a standalone process
// (production). In development the api process can run it inline instead.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/detection"
	"github.com/ArowuTest/nirvet/internal/ingestion"
	"github.com/ArowuTest/nirvet/internal/threatintel"
	"github.com/ArowuTest/nirvet/internal/platform/config"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/platform/logger"
	"github.com/ArowuTest/nirvet/internal/platform/queue"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}
	log := logger.New(cfg.Env)
	log.Info("nirvet worker starting", "env", cfg.Env)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := database.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("database connect failed", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	events := eventstore.NewPostgres(db)
	jobs := queue.NewPostgres(db.Pool)
	alertSvc := alert.NewService(alert.NewRepository(db))
	detEngine := detection.NewEngine(detection.NewRepository(db))
	enricher := threatintel.NewEnricher(threatintel.NewRepository(db))
	wk := ingestion.NewWorker(jobs, events, enricher, detEngine, alertSvc, log)

	log.Info("nirvet worker running")
	wk.Start(ctx, time.Second)
	log.Info("nirvet worker stopped")
}
