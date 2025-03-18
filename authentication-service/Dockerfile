FROM golang:1.24.0 AS build

WORKDIR /go-app

COPY go.mod go.sum ./
RUN go mod download

COPY . ./

RUN go build -o ./app

# =================================================
# FROM gcr.io/distroless/base-debian12 AS production
FROM golang:1.24.0 AS production

WORKDIR /go-app

COPY --from=build /go-app/app ./
COPY --from=build /go-app/config.yaml ./

# RUN chmod +x ./app

EXPOSE 3000

USER 1000

# RUN chown -R 1000 ./app

ENTRYPOINT ["./app"]
# CMD ["tail", "-f", "/dev/null"]