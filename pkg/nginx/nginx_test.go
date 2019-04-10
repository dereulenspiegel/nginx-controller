package nginx

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToByteUnit(t *testing.T) {
	for _, data := range []struct {
		val      uint64
		expected string
	}{
		{
			val:      867,
			expected: "867",
		},
		{
			val:      12 * 1024,
			expected: "12K",
		},
		{
			val:      8 * 1024 * 1024,
			expected: "8M",
		},
		{
			val:      8*1024*1024 + 867,
			expected: "8M",
		},
	} {
		assert.Equal(t, data.expected, TmplToByteUnit(data.val))
	}
}

var expectedConfig = `
user nginx;
worker_processes  2;
worker_rlimit_nofile 100000;

error_log  stderr;
pid        /var/run/nginx.pid;

events {
    worker_connections  4096;
    use epoll;
    multi_accept on;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    access_log  off;
    server_names_hash_bucket_size  64;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;
    tcp_nodelay        on;

    gzip  on;
    gzip_proxied any;
    gzip_types text/plain text/css application/json application/x-javascript text/xml application/xml text/javascript;
    gzip_min_length 10240;
    gzip_comp_level 1;
    gzip_vary on;
    gzip_disable msie6;

    client_max_body_size 25M;

    reset_timedout_connection on;


    server {
      listen          443 ssl http2;
      listen          [::]:443 ssl http2;
      server_name     foo.bar;

      ssl_protocols TLSv1.2 TLSv1.3;
      ssl_prefer_server_ciphers on;
      ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
      ssl_ecdh_curve auto;
      ssl_session_cache shared:SSL:10m;
      ssl_session_timeout 1h;
      ssl_session_tickets off; # Requires nginx >= 1.5.9
      ssl_stapling on; # Requires nginx >= 1.3.7
      ssl_stapling_verify on; # Requires nginx => 1.3.7
      ssl_buffer_size 4k;
      resolver 8.8.8.8 8.8.4.4 valid=300s;
      resolver_timeout 5s;
      add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
      # add_header X-Frame-Options DENY;
      add_header X-Content-Type-Options nosniff;

      ssl_certificate ;
      ssl_certificate_key ;

      access_log off;
      error_log stderr;



      location / {
        add_header              Access-Control-Allow-Origin *;

        proxy_set_header        Host $host;
        proxy_set_header        X-Real-IP $remote_addr;
        proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header        X-Forwarded-Proto $scheme;
        proxy_set_header        Connection "";
        proxy_http_version      1.1;


        proxy_pass              http://172.16.0.1:8080;
        proxy_read_timeout      90;

        proxy_redirect          off;

        http2_push_preload      on;
      }

    }


    server {
      listen          [::]:80 default_server;
      listen          80 default_server;
      server_name     _;

      access_log off;

      location / {
        return 301 https://$host$request_uri;
      }

      location /.well-known/acme-challenge/ {
        proxy_set_header        Host $host;
        proxy_set_header        X-Real-IP $remote_addr;
        proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header        X-Forwarded-Proto $scheme;
        proxy_pass              http://127.0.0.1:8402;
      }
    }
}
`

func TestRenderConfig(t *testing.T) {
	tmplCfg := DefaultTemplateConfig()
	tmplCfg.HTTP.Servers["foo.bar"] = DefaultServerTemplateConfig("foo.bar", "http://172.16.0.1:8080")

	buf := &bytes.Buffer{}

	require.NoError(t, RenderConfig(DefaultTemplate, tmplCfg, buf))
	assert.Equal(t, expectedConfig, buf.String())
}
