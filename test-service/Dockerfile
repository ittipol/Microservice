FROM golang:1.24.0 AS build

WORKDIR /go-app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . ./

RUN go build -o ./app

# =================================================
# FROM gcr.io/distroless/base-debian12 AS production
# FROM gcr.io/distroless/base-debian12:debug AS production
# FROM gcr.io/distroless/base-debian12:debug-nonroot AS production
FROM golang:1.24.0

WORKDIR /go-app

COPY --from=build /go-app/app ./
COPY --from=build /go-app/config.yaml ./

# RUN chmod +x ./app

EXPOSE 5055

USER 1000

# RUN chown -R 1000 ./app

ENTRYPOINT ["./app"]
# CMD ["tail", "-f", "/dev/null"]