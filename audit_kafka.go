package middle

import (
	"context"
	"encoding/json"
	"time"

	"github.com/open4go/log/model/operation"
	"github.com/segmentio/kafka-go"
)

type kafkaAuditPublisher struct {
	brokers []string
	topic   string
	writer  *kafka.Writer
}

func (p *kafkaAuditPublisher) getWriter() *kafka.Writer {
	if p.writer != nil {
		return p.writer
	}
	p.writer = &kafka.Writer{
		Addr:                   kafka.TCP(p.brokers...),
		Topic:                  p.topic,
		Balancer:               &kafka.Hash{},
		RequiredAcks:           kafka.RequireOne,
		Async:                  false,
		AllowAutoTopicCreation: true,
		BatchTimeout:           10 * time.Millisecond,
	}
	return p.writer
}

func (p *kafkaAuditPublisher) Publish(ctx context.Context, m *operation.Model) error {
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	key := m.MerchantID
	if key == "" {
		key = m.AccountID
	}
	return p.getWriter().WriteMessages(ctx, kafka.Message{
		Key:   []byte(key),
		Value: body,
	})
}
