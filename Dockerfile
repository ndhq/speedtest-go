FROM golang:alpine AS build_base
#ENV GOARCH arm64
#ENV GOARCH amd64

WORKDIR /build

RUN apk add --no-cache git gcc ca-certificates libc-dev

COPY . ./

RUN go get ./ && go build -ldflags "-w -s" -trimpath -o nyaspeed main.go

FROM alpine AS RUNNER

RUN apk add ca-certificates
WORKDIR /app
COPY --from=build_base /build/nyaspeed .
COPY --from=build_base /build/web/assets ./assets
COPY --from=build_base /build/settings.toml .

EXPOSE 8989

CMD ["./nyaspeed"]
