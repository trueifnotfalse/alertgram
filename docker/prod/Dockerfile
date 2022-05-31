FROM golang:1.18.2-alpine3.15 as build-stage

ARG VERSION
ENV VERSION=${VERSION}
ARG ostype=Linux

WORKDIR /src
COPY . .
RUN ./scripts/build/build.sh

# Final image.
FROM alpine:3.15
RUN apk --no-cache add \
    ca-certificates
COPY --from=build-stage /src/bin/alertgram-linux-amd64 /usr/local/bin/alertgram
ENTRYPOINT ["/usr/local/bin/alertgram"]
