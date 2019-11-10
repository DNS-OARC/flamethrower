FROM ubuntu:disco AS build

ENV BUILD_DEPS "g++ cmake make libldns-dev libnghttp2-dev libuv1-dev libgnutls28-dev pkgconf"

RUN \
    apt-get update && \
    apt-get install --yes --no-install-recommends ${BUILD_DEPS}

COPY . /src

RUN \
    mkdir /tmp/build && \
    cd /tmp/build && \
    cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo /src && \
    make all tests && \
    ./tests

FROM ubuntu:disco AS runtime

ENV RUNTIME_DEPS "libldns2 libuv1 nghttp2"

RUN \
    apt-get update && \
    apt-get install --yes --no-install-recommends ${RUNTIME_DEPS} && \
    rm -rf /var/lib/apt

COPY --from=build /tmp/build/flame /usr/local/bin/flame

ENTRYPOINT [ "/usr/local/bin/flame" ]
