package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"capability-broker/internal/audit"
	"capability-broker/internal/broker"
	"capability-broker/internal/capability"
	"capability-broker/internal/server"
	"capability-broker/internal/store"
)

func main() {
	addr := env("BROKER_ADDR", ":8080")
	dbPath := env("DB_PATH", "data/broker.db")
	keyPath := env("SIGNING_KEY_PATH", "data/signing.key")
	_ = os.MkdirAll("data", 0o755)

	svc, err := broker.New(broker.Config{
		TTL:     capability.DefaultTTL,
		KeyPath: keyPath,
	})
	if err != nil {
		log.Fatal(err)
	}
	if db, err := store.Open(dbPath); err == nil {
		svc.SetPersist(func(e audit.Entry) { _ = db.PersistAudit(e) })
		defer db.Close()
		log.Printf("audit sqlite %s (WAL)", dbPath)
	} else {
		log.Printf("sqlite unavailable (%v); audit is in-memory only", err)
	}

	h := server.New(svc).Handler()
	log.Printf("capability broker listening on %s (credential TTL %s)", addr, capability.DefaultTTL)
	log.Printf("local signing key at %s — this is not a KMS; the minting pattern is the same", keyPath)
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
