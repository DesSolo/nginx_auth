# nginx_auth
Python backend based service for proxy_pass authorisation requests

### Run service
podman: `podman run nginx_auth`  
docker: `docker run nginx_auth`

## Example nginx config
```
server {
        listen       80;
        server_name  _;

        location /private {
                auth_request /login;
                auth_request_set $saved_set_cookie $upstream_http_set_cookie;
                auth_request_set $saved_auth_user $upstream_http_x_auth_user;
                add_header Set-Cookie $saved_set_cookie;
                empty_gif;

        }

        location ~ /(login|logout)$ {
                internal;
                proxy_pass http://nginx_auth:8000;

                proxy_pass_request_headers off;
                proxy_pass_request_body off;
                proxy_set_header Content-Length "";
                proxy_set_header Cookie $http_cookie;
                proxy_set_header Authorization $http_authorization;
                proxy_set_header User-Agent $http_user_agent;
                proxy_set_header Referer $scheme://$host$request_uri;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Radius-Realm TEST_REALM;
        }
}
```

### Image environ params  
`COOKIE_KEY` cookie name default session_id  
`LISTEN_PORT` listen port application default 8000  
`SECRET_KEY` cookie secret key default random generic value  

### Headers
`X-Real-IP` source request user ip address default `127.0.0.1`  
`X-Radius-Realm` realm name default `Restricted area`