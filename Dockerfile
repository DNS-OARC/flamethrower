FROM registry.fedoraproject.org/fedora-minimal:43 AS build

RUN \
  dnf --setopt=install_weak_deps=False --no-docs --assumeyes install \
    gcc g++ meson pkgconf ninja-build redhat-rpm-config \
    ldns-devel libuv-devel gnutls-devel libnghttp2-devel \
  && dnf clean all

COPY . /mnt/src

RUN \
  mkdir /mnt/build \
  && cd /mnt/build \
  && meson setup /mnt/src \
  && ninja

FROM registry.fedoraproject.org/fedora-minimal:43 AS runtime

RUN \
  dnf --setopt=install_weak_deps=False --no-docs --assumeyes install \
    ldns libuv gnutls libnghttp2 \
  && dnf clean all

COPY --from=build /mnt/build/flame /usr/local/bin/flame

ENTRYPOINT ["/usr/local/bin/flame"]
