FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY example/example.go .
COPY example/page.html  .

RUN CGO_ENABLED=0 go build -ldflags="-s -w"  -o ./app ./example.go

FROM scratch

COPY --from=builder /app/app /app

ENTRYPOINT ["./app"]
