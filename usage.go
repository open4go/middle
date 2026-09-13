package middle

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/open4go/log"
	"github.com/spf13/viper"
)

// UsageBytesContextKey is set by handlers that already know the object size
// (image upload/delete) so occupancy can move storage_bytes, not just count.
const UsageBytesContextKey = "UsageBytes"

const (
	KindImage    = "image"
	KindProduct  = "product"
	KindOrder    = "order"
	KindMember   = "member"
	KindStore    = "store"
	KindScm      = "scm"
	KindCampaign = "campaign"
	KindDevice   = "device"
	KindFeedback = "feedback"
	KindClient   = "client"
	KindFinance  = "finance"
	KindBytes    = "storage_bytes"
	KindAI       = "ai"
	KindAiCalls  = "ai_calls"
	KindAiTokens = "ai_tokens"

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
	if kind == KindImage {
		if n := absInt64(contentLength); n > 0 {
			ev.Bytes = n
		}
	}
	return ev, true
}

// SetUsageBytes records the object size on the request so delete/upload
// occupancy can adjust storage, not only the image counter.
func SetUsageBytes(c *gin.Context, n int64) {
	if c == nil {
		return
	}
	if n = absInt64(n); n == 0 {
		return
	}
	c.Set(UsageBytesContextKey, n)
}

func usageBytes(c *gin.Context, before string, contentLength int64) int64 {
	if n := contextInt64(c, UsageBytesContextKey); n > 0 {
		return n
	}
	if n := sizeFromJSON(before); n > 0 {
		return n
	}
	return absInt64(contentLength)
}

func sizeFromJSON(raw string) int64 {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw[0] != '{' {
		return 0
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return 0
	}
	for _, key := range []string{"size", "Size", "bytes", "storage_bytes"} {
		if n := absInt64(asInt64(m[key])); n > 0 {
			return n
		}
	}
	return 0
}

func contextInt64(c *gin.Context, key string) int64 {
	if c == nil {
		return 0
	}
	v, ok := c.Get(key)
	if !ok {
		return 0
	}
	return absInt64(asInt64(v))
}

func asInt64(v any) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int32:
		return int64(n)
	case int64:
		return n
	case uint:
		return int64(n)
	case uint32:
		return int64(n)
	case uint64:
		return int64(n)
	case float32:
		return int64(n)
	case float64:
		return int64(n)
	case json.Number:
		i, err := n.Int64()
		if err == nil {
			return i
		}
		f, err := n.Float64()
		if err == nil {
			return int64(f)
		}
	case string:
		i, err := strconv.ParseInt(strings.TrimSpace(n), 10, 64)
		if err == nil {
			return i
		}
	}
	return 0
}

func absInt64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
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
	case "scm":
		return KindScm
	case "campaign":
		return KindCampaign
	case "device":
		return KindDevice
	case "feedback":
		return KindFeedback
	case "client":
		return KindClient
	case "finance":
		return KindFinance
	default:
		return ""
	}
}
