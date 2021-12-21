FROM python:3.9-slim-buster
ARG netfoundry_version
RUN pip install --upgrade pip
RUN pip install netfoundry==${netfoundry_version}
CMD ["bash"]
