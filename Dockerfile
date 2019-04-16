FROM ubuntu:18.04

ENV BUILD_DEPS "cmake make g++ wget ca-certificates libgetopt-complete-perl automake libtool pkg-config clang"
ENV RUNTIME_DEPS "libssl-dev libgnutls28-dev"

# Install build and runtime dependencies.
RUN apt-get update \
    && apt-get install -yqq --no-install-recommends \
    ${BUILD_DEPS} \
    ${RUNTIME_DEPS} \
    && rm -rf /var/lib/apt

ENV FLAME_HOME "/opt/flame"

RUN mkdir -p ${FLAME_HOME} /usr/local/bin

COPY . ${FLAME_HOME}

# Setup some more deps
RUN /bin/bash ${FLAME_HOME}/ci/install-ldns.sh "container" && rm -rf /tmp/*
RUN /bin/bash ${FLAME_HOME}/ci/install-libuv.sh "container" && rm -rf /tmp/*

# Build flamethrower
RUN cd ${FLAME_HOME} \
    && mkdir build \
    && cd build \
    && cmake .. \
    && make \
    && mv flame /usr/local/bin/flame

ENTRYPOINT [ "/usr/local/bin/flame" ]
