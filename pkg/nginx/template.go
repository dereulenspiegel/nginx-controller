package nginx

var DefaultTemplate = `
user {{ .User }};
worker_processes  {{ .WorkProcesses }};

error_log  {{ .ErrorLog }};
pid        {{ .Pid }};

events {
    worker_connections  {{ .Events.WorkerConnections }};
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    access_log  {{ .HTTP.AccessLog }};
    server_names_hash_bucket_size  {{ .HTTP.ServerNamesHashBucketSize }};

    sendfile        {{ nginxBool .HTTP.SendFile }};
    #tcp_nopush     {{ nginxBool .HTTP.TCPNoPush }};

    #keepalive_timeout  0;
    keepalive_timeout  {{ .HTTP.KeepAliveTimeout }};
    tcp_nodelay        {{ nginxBool .HTTP.TCPNoDelay }};

    gzip  {{ nginxBool .HTTP.GZIP }};
    gzip_proxied {{ .HTTP.GZIPProxied }};
    gzip_types {{ spaceList .HTTP.GZIPTypes }};

    client_max_body_size {{ hrBytes .HTTP.ClientMaxBodySize }};

{{ range .HTTP.Servers }}
    server {
      listen          443 ssl http2;
      listen          [::]:443 ssl http2;
      server_name     {{ .ServerName }};

      ssl_protocols TLSv1.2 TLSv1.3;
      ssl_prefer_server_ciphers on;
      ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
      ssl_ecdh_curve auto;
      ssl_session_cache shared:SSL:{{ hrBytes .SSLSessionCacheSize | toLower }};
      ssl_session_timeout 1h;
      ssl_session_tickets off; # Requires nginx >= 1.5.9
      ssl_stapling on; # Requires nginx >= 1.3.7
      ssl_stapling_verify on; # Requires nginx => 1.3.7
      ssl_buffer_size 4k;
      resolver {{ spaceList .Resolver }} valid=300s;
      resolver_timeout {{ .ResolverTimeout }};
      add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
      # add_header X-Frame-Options DENY;
      add_header X-Content-Type-Options nosniff;

      ssl_certificate {{ .SSLCertificate }};
      ssl_certificate_key {{ .SSLKey }};

      access_log {{ .AccessLog }};
      error_log {{ .ErrorLog }};

{{ range $dest, $location := .Locations }}

      location {{ $dest }} {
        add_header              Access-Control-Allow-Origin *;

        proxy_set_header        Host $host;
        proxy_set_header        X-Real-IP $remote_addr;
        proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header        X-Forwarded-Proto $scheme;


        proxy_pass              {{ $location.Upstream }};
        proxy_read_timeout      90;

        proxy_redirect off;
      }
{{ end }}
    }
{{ end }}

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
