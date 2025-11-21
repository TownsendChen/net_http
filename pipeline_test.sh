#!/bin/bash
echo "Testing HTTP/1.1 Pipelining..."

# 发送多个请求在一个连接中
(
    printf "GET / HTTP/1.1\r\nHost: localhost:8080\r\nConnection: keep-alive\r\n\r\n"
    printf "GET /about.html HTTP/1.1\r\nHost: localhost:8080\r\nConnection: keep-alive\r\n\r\n"
    printf "GET / HTTP/1.1\r\nHost: localhost:8080\r\nConnection: close\r\n\r\n"
    sleep 1
) | nc localhost 8080

echo "Pipelining test completed."
