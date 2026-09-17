# Integration environment: a real nginx, as root, isolated from the host.
#
#   docker build -f tests/Dockerfile -t nginx-ratelimit-test .
#   docker run --rm nginx-ratelimit-test
#
FROM nginx:stable

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 curl bc procps ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY nginx-ratelimit /src/nginx-ratelimit
COPY tests /src/tests
RUN chmod +x /src/nginx-ratelimit /src/tests/*.sh

# The suite drives its own private nginx prefix, so the image's default
# server is never started.
CMD ["/src/tests/run-all.sh"]
