# Build image for nt-responder: produces a static (musl) binary at /out/nt-responder. Used by build.sh.
FROM alpine:3.20

RUN apk add --no-cache g++ make cmake linux-headers

WORKDIR /src
COPY CMakeLists.txt ./
COPY src ./src

RUN cmake -S . -B /build -DCMAKE_BUILD_TYPE=Release -DNT_STATIC=ON \
    && cmake --build /build -j"$(nproc)" \
    && mkdir -p /out \
    && strip -o /out/nt-responder /build/nt-responder
