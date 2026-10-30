package middle

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/open4go/log"
	"github.com/open4go/log/model/operation"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/mongo"
)

const (
	DefaultAuditTopic   = "audit.operation"
	DefaultAuditBrokers = "localhost:19092"
	defaultAuditQueue   = 4096
)

// AuditPublisher sends compressed operation logs off-process.
type AuditPublisher interface {
	Publish(ctx context.Context, m *operation.Model) error
}

var (
	auditOnce     sync.Once
	auditCh       chan *operation.Model
	auditPub      AuditPublisher
	auditDropTotal atomic.Uint64
)

// AuditEnqueueDropTotal is the number of audit events dropped because the local queue was full.
func AuditEnqueueDropTotal() uint64 { return auditDropTotal.Load() }

// InitAuditFromViper starts the Kafka publisher used by OperateLogMiddleware.
// Brokers: audit.kafka.brokers, then kafka.brokers, then localhost:19092.
// Topic: audit.kafka.topic (default audit.operation).
// Disable with audit.async=false to keep synchronous InsertOne.
func InitAuditFromViper() {
	ctx := context.Background()
	if viper.IsSet("audit.async") && !viper.GetBool("audit.async") {
		log.Log(ctx).Info("audit async disabled; OperateLog stays synchronous")
		return
	}
	brokers := viper.GetStringSlice("audit.kafka.brokers")
	if len(brokers) == 0 {
		brokers = viper.GetStringSlice("kafka.brokers")
	}
	if len(brokers) == 0 {
		brokers = []string{DefaultAuditBrokers}
		log.Log(ctx).WithField("brokers", brokers).Warning("audit kafka: no brokers in config, using default")
	}
	topic := strings.TrimSpace(viper.GetString("audit.kafka.topic"))
	if topic == "" {
		topic = DefaultAuditTopic
	}
	StartAuditPublisher(&kafkaAuditPublisher{brokers: brokers, topic: topic})
	log.Log(ctx).WithField("brokers", brokers).WithField("topic", topic).Info("audit kafka publisher started")
}

// StartAuditPublisher begins a non-blocking queue that forwards models to pub.
func StartAuditPublisher(pub AuditPublisher) {
	if pub == nil {
		return
	}
	auditOnce.Do(func() {
		auditPub = pub
		auditCh = make(chan *operation.Model, defaultAuditQueue)
		go auditLoop()
	})
}

func auditLoop() {
	for m := range auditCh {
		if auditPub == nil || m == nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := auditPub.Publish(ctx, m); err != nil {
			log.Log(ctx).WithError(err).
				WithField("merchant_id", m.MerchantID).
				WithField("resource", m.Resource).
				WithField("action", m.Action).
				Warning("audit publish failed")
		}
		cancel()
	}
}

// AuditAsyncReady reports whether the async publisher queue is running.
func AuditAsyncReady() bool { return auditCh != nil }

// EnqueueAudit never blocks the caller. Returns false when the publisher is
// not started or the queue is full (caller should sync-insert critical rows).
func EnqueueAudit(m *operation.Model) bool {
	if m == nil {
		return false
	}
	ch := auditCh
	if ch == nil {
		return false
	}
	select {
	case ch <- m:
		return true
	default:
		auditDropTotal.Add(1)
		log.Log(context.Background()).
			WithField("merchant_id", m.MerchantID).
			WithField("resource", m.Resource).
			WithField("action", m.Action).
			WithField("drop_total", auditDropTotal.Load()).
			Warning("audit kafka queue full, drop event")
		return false
	}
}

// IsCriticalAudit marks resources that should not silently lose an audit row
// when the async queue is full (sync InsertOne fallback).
func IsCriticalAudit(resource, action string) bool {
	if strings.EqualFold(action, "delete") {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(resource)) {
	case "member", "member_level", "admin_account", "role", "tenant",
		"pay", "billing", "password", "plan", "partner":
		return true
	default:
		return false
	}
}

func insertOperationSync(ctx context.Context, db *mongo.Database, m *operation.Model) {
	if db == nil || m == nil {
		return
	}
	handler := m.Init(ctx, db, m.CollectionName())
	// Meta already filled by caller when possible; Init may refresh handler side.
	if _, err := handler.Context.Handler.Collection(handler.Context.Collection).InsertOne(ctx, m); err != nil {
		log.Log(ctx).WithError(err).
			WithField("path", m.FullPath).
			WithField("method", m.Method).
			Warning("write operation log failed")
	}
}
