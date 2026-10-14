# Build on the approved Linux build host, review, then configure its immutable digest.
FROM python:3.12-slim
RUN useradd --uid 10001 --create-home runner
COPY ci/tools.lock.txt /tools/tools.lock.txt
RUN pip install --no-cache-dir -r /tools/tools.lock.txt
COPY ci/run_pipeline.py /tools/run_pipeline.py
USER runner
ENTRYPOINT ["python", "/tools/run_pipeline.py"]
