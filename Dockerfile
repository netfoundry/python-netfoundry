FROM python:3.9-slim-buster
COPY ./dist/netfoundry-*.tar.gz /tmp/
RUN pip install --upgrade pip
RUN pip install /tmp/netfoundry-*.tar.gz
RUN rm -f /tmp/netfoundry-*.tar.gz
CMD ["nfctl --version"]
