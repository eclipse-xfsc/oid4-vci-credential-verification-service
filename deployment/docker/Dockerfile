FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/verification .
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/verification /app/verification
COPY --from=build /src/config.yaml /app/config.yaml
EXPOSE 8080
ENTRYPOINT ["/app/verification"]
