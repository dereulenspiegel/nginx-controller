# nginx-controller

This little project is inspired by the concept of kubernetes ingress controller. But running
kubernetes just to host a few little tools is sometimes overkill. Sometimes you just want
to have a few containers running, a reverse proxy in front of them and don't care much about it.
This is where nginx-controller might help you. It inspects your running containers and looks for
specific labels, and then generates an appropriate nginx configuration and requests certificates
at [letsencrypt](https://letsencrypt.org/). The configuration necessary should be minimal.

## Configuration

### docker-compose example

```
version: '3'
services:
  nginx-controller:
    image: dereulenspiegel/nginx-controller:v0.1.3
    restart: always
    ports:
    - "80:80"
    - "443:443"
    volumes:
    - "/var/run/docker.sock:/var/run/docker.sock"
    - "/var/lib/nginx-controller"
    command: -email <your-email>
```

The important parts here are, that nginx-controller has access to the file `/var/run/docker.sock?`
so it can connect to your docker daemon and listen for events. Also nginx-controller needs a place
to store certificates and account specific data, which in this example is `/var/lib/nginx-controller`.
Lastly you need to specify the email address you want to register with at letsencrypt.

### container labels

nginx-controller will only proxy traffic to containers which have specific labels. These labels
are also used to configure how traffic is directed to containers. Right now nginx-controller only
supports one container per (sub)domain. Also containers should only expose a single TCP port, because
nginx-controller will send all HTTP traffic to the first TCP port it can find on a container.

| Label | Description |
|-------|-------------|
| `nginx-controller.akuz.de/host` | Controls under which domain the container will be available |
| `nginx-controller.akuz.de/path` | nginx location which should be used |
| `nginx-controller.akuz.de/port` | Overwrite the discovered TCP port |
