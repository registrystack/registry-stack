FROM nginx:1.27.3@sha256:bc2f6a7c8ddbccf55bdb19659ce3b0a92ca6559e86d42677a5a02ef6bda2fcef

RUN openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/ssl/private/nginx-selfsigned.key \
        -out /etc/ssl/certs/nginx-selfsigned.crt \
        -subj "/CN=localhost.emobix.co.uk" \
        -addext "subjectAltName=DNS:localhost.emobix.co.uk,DNS:localhost,IP:127.0.0.1,IP:::1" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign" \
        -addext "extendedKeyUsage=serverAuth"
COPY nginx.conf /etc/nginx/nginx.conf
