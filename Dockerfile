FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /impersonate-serve ./cmd/serve

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /impersonate-serve /impersonate-serve
EXPOSE 8080
ENTRYPOINT ["/impersonate-serve"]
CMD ["-addr", ":8080"]
