package middle

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/open4go/log"
	"github.com/spf13/viper"
)

const (
	KindImage   = "image"
	KindProduct = "product"
	KindOrder   = "order"
	KindMember  = "member"
	KindStore   = "store"
	KindBytes   = "storage_bytes"

	DefaultUsageTopic   = "tenant.usage"
	DefaultUsageBrokers = "localhost:19092"
)

// UsageEvent is a single occupancy delta for a tenant. Positive on create, negative on delete.
type UsageEvent struct {
	MerchantID string `json:"merchant_id"`
	Kind       string `json:"kind"`
	Delta      int64  `json:"delta"`
	Bytes      int64  `json:"bytes,omitempty"`
	Path       string `json:"path,omitempty"`
	At         int64  `json:"at"`
}

// UsagePublisher sends events off-process. Kafka is the production implementation.
type UsagePublisher interface {
	Publish(ctx context.Context, ev UsageEvent) error
}

var (
	usageOnce sync.Once
	usageCh   chan UsageEvent
	usagePub  UsagePublisher
)

// InitUsageFromViper starts the Kafka publisher used by OperateLogMiddleware.
// Brokers: usage.kafka.brokers, then kafka.brokers, then localhost:19092.
func InitUsageFromViper() {
	ctx := context.Background()
	brokers := viper.GetStringSlice("usage.kafka.brokers")
	if len(brokers) == 0 {
		brokers = viper.GetStringSlice("kafka.brokers")
	}
	if len(brokers) == 0 {
		brokers = []string{DefaultUsageBrokers}
		log.Log(ctx).WithField("brokers", brokers).Warning("usage kafka: no brokers in config, using default")
	}
	topic := strings.TrimSpace(viper.GetString("usage.kafka.topic"))
	if topic == "" {
		topic = DefaultUsageTopic
	}
	StartUsagePublisher(&kafkaUsagePublisher{brokers: brokers, topic: topic})
	log.Log(ctx).WithField("brokers", brokers).WithField("topic", topic).Info("usage kafka publisher started")
}

// StartUsagePublisher begins a non-blocking queue that forwards events to pub.
func StartUsagePublisher(pub UsagePublisher) {
	if pub == nil {
		return
	}
	usageOnce.Do(func() {
		usagePub = pub
		usageCh = make(chan UsageEvent, 4096)
		go usageLoop()
	})
}

func usageLoop() {
	for ev := range usageCh {
		if usagePub == nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := usagePub.Publish(ctx, ev); err != nil {
			log.Log(ctx).WithError(err).
				WithField("merchant_id", ev.MerchantID).
				WithField("kind", ev.Kind).
				Warning("usage publish failed")
		}
		cancel()
	}
}

// EnqueueUsage never blocks the caller. Full queue drops the event.
func EnqueueUsage(ev UsageEvent) {
	if ev.MerchantID == "" || ev.Kind == "" || (ev.Delta == 0 && ev.Bytes == 0) {
		return
	}
	if skipUsageMerchant(ev.MerchantID) {
		return
	}
	if ev.At == 0 {
		ev.At = time.Now().Unix()
	}
	ch := usageCh
	if ch == nil {
		log.Log(context.Background()).
			WithField("merchant_id", ev.MerchantID).
			WithField("kind", ev.Kind).
			Warning("usage kafka not started; call middle.InitUsageFromViper() at process boot")
		return
	}
	select {
	case ch <- ev:
	default:
		log.Log(context.Background()).
			WithField("merchant_id", ev.MerchantID).
			WithField("kind", ev.Kind).
			Warning("usage kafka queue full, drop event")
	}
}

func skipUsageMerchant(id string) bool {
	switch strings.TrimSpace(id) {
	case "", "*", "share", "st":
		return true
	default:
		return false
	}
}

// UsageFromOperation maps an oplog row onto a usage delta. Updates and failed
// requests are ignored so occupancy only moves on successful create/delete.
func UsageFromOperation(resource, action string, respCode int, contentLength int64) (UsageEvent, bool) {
	if respCode >= 400 {
		return UsageEvent{}, false
	}
	var delta int64
	switch action {
	case "create":
		delta = 1
	case "delete":
		delta = -1
	default:
		return UsageEvent{}, false
	}
	kind := usageKindOf(resource)
	if kind == "" {
		return UsageEvent{}, false
	}
	ev := UsageEvent{Kind: kind, Delta: delta}
	if kind == KindImage && delta > 0 && contentLength > 0 {
		ev.Bytes = contentLength
	}
	return ev, true
}

func usageKindOf(resource string) string {
	switch resource {
	case "image":
		return KindImage
	case "product":
		return KindProduct
	case "order":
		return KindOrder
	case "member":
		return KindMember
	case "store":
		return KindStore
	default:
		return ""
	}
}
