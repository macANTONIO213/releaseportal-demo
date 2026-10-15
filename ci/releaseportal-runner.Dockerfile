# Trusted scanner recipe. Build only this reviewed context; never a repository Dockerfile.
FROM node:22-alpine3.23@sha256:baf676f7d0e552f3231945c2f979055ca121bce128c152f7a34e6bd1728b1c5a AS node
FROM python:3.12-alpine3.23@sha256:9ce5a4e59b833c002e1c4196c60ec0b38977e3235d626298ba7ffe2e64f5a30c
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/work/home \
    PIP_DISABLE_PIP_VERSION_CHECK=1 NPM_CONFIG_UPDATE_NOTIFIER=false
RUN sed -i 's|http://|https://|g' /etc/apk/repositories \
    && apk upgrade --no-cache \
    && apk add --no-cache 'zlib>=1.3.2-r1' 'musl>=1.2.5-r23' libgcc libstdc++ git \
    && addgroup -g 10001 runner && adduser -D -u 10001 -G runner runner \
    && mkdir /tools /input /output /work
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
COPY runtime/pnpm-11.25.0.tgz /tools/pnpm.tgz
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
    && npm install --global --offline --ignore-scripts --no-audit --no-fund /tools/pnpm.tgz
COPY ci/releaseportal-tools.lock.txt /tools/tools.lock.txt
COPY runner-wheels /tools/wheels
RUN pip install --no-cache-dir --no-index --find-links=/tools/wheels --require-hashes --only-binary=:all: -r /tools/tools.lock.txt
COPY ci/releaseportal_pipeline.py ci/releaseportal_test_runner.py ci/releaseportal_run_tests.py /tools/
COPY ci/releaseportal-profile.example.json /tools/releaseportal-profile.json
COPY ci/bandit.ini /tools/bandit.ini
USER 10001:10001
WORKDIR /work
ENTRYPOINT ["python", "/tools/releaseportal_pipeline.py"]
