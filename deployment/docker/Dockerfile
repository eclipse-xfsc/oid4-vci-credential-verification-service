FROM golang:1.22-alpine3.18 as build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /server

FROM scratch as run
COPY --from=build /server .
COPY --from=build app/config.yaml .
CMD ["/server"]
