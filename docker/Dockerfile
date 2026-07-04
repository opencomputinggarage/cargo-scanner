FROM anchore/grype:latest AS grype
FROM anchore/syft:latest AS syft
FROM aquasec/trivy:latest AS trivy

FROM alpine:3.23

RUN apk add --no-cache ca-certificates

COPY --from=grype /grype /usr/local/bin/grype
COPY --from=syft /syft /usr/local/bin/syft
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

WORKDIR /cargo

ENTRYPOINT ["grype"]
