FROM golang:1.24.0 AS build

WORKDIR /go-app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . ./

RUN go build -o ./app

# =================================================
# FROM gcr.io/distroless/base-debian12 AS production
FROM gcr.io/distroless/base-debian12:debug AS production
# FROM gcr.io/distroless/base-debian12:debug-nonroot AS production

WORKDIR /go-app

COPY --from=build /go-app/app ./
COPY --from=build /go-app/config.yaml ./

# RUN mkdir -p /usr/local/script && \
#     echo '#!/bin/bash' > /usr/local/script/run.sh && \
#     echo 'pwd && echo "$(env)"' >> /usr/local/script/run.sh && \
#     chmod +x /usr/local/script/run.sh

EXPOSE 5055

USER 1000

ENTRYPOINT ["./app"]