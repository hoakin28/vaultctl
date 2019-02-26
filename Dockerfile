FROM debian:jessie-slim

MAINTAINER Operaciones MX "ops-mx@datiobd.com"

RUN apt-get update -y && \
    apt-get install python3 python3-dev python3-pip vim curl jq -y && \
    apt-get clean && \
    apt-get autoclean

RUN pip3 install ete3 && \
    pip3 install requests

WORKDIR crawler

ADD . /crawler
RUN chmod +x vault_crawler.py
CMD ["/bin/bash"]
