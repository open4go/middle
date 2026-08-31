package middle

import (
	"context"
	"encoding/json"
	"time"

	"github.com/segmentio/kafka-go"
)

type kafkaUsagePublisher struct {
	brokers []string
	topic   string
	writer  *kafka.Writer
}

func (p *kafkaUsagePublisher) getWriter() *kafka.Writer {
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

func (p *kafkaUsagePublisher) Publish(ctx context.Context, ev UsageEvent) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return p.getWriter().WriteMessages(ctx, kafka.Message{
		Key:   []byte(ev.MerchantID),
		Value: body,
	})
}
