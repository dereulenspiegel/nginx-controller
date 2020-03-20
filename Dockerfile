FROM golang:1.14-alpine  as builder

RUN apk update && apk add make git gcc musl-dev

RUN mkdir -p ${GOPATH}/src/github.com/dereulenspiegel/nginx-controller
COPY ./ ${GOPATH}/src/github.com/dereulenspiegel/nginx-controller/
RUN cd ${GOPATH}/src/github.com/dereulenspiegel/nginx-controller/ && make clean && make build

FROM nginx:1.17.9-alpine

RUN apk update && apk add ca-certificates

COPY --from=builder /go/src/github.com/dereulenspiegel/nginx-controller/controller /controller

WORKDIR /

EXPOSE 80
EXPOSE 443

VOLUME /var/lib/nginx-controller

ENTRYPOINT ["/controller"]