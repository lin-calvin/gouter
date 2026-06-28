# 阶段1：构建阶段
FROM golang:1.26.4-alpine AS builder

# 安装构建依赖
RUN apk add --no-cache git

WORKDIR /app

# 先复制依赖文件，利用缓存
COPY go.mod go.sum ./
RUN go mod download

# 复制源码并构建
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# 阶段2：运行阶段（更小的镜像）
FROM alpine:latest

# 安装 CA 证书（如果需要 HTTPS 请求）
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# 从构建阶段复制二进制文件
COPY --from=builder /app/main .

EXPOSE 8080
CMD ["./main","/config/config.yaml"]
