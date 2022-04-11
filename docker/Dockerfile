FROM python:3.9-slim-buster
COPY ./dist/netfoundry-*.whl /tmp/
RUN pip install --upgrade pip
RUN pip install /tmp/netfoundry-*.whl
RUN rm -f /tmp/netfoundry-*.whl
CMD ["nfctl --version"]
