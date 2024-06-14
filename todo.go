package middle

import (
	"context"
	r2redis "github.com/open4go/db/redis"
	"github.com/open4go/log"
	v9 "github.com/redis/go-redis/v9"
)

// GetRedisMiddleHandler 获取数据库handler 这里定义一个方法
func GetRedisMiddleHandler(ctx context.Context) *v9.Client {
	handler, err := r2redis.DBPool.GetHandler("middle")
	if err != nil {
		log.Log(ctx).Fatal(err)
	}
	return handler
}
