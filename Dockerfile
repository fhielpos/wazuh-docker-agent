FROM centos:7

ARG WAZUH_VERSION=4.1.4-1

COPY config/wazuh.repo /etc/yum.repos.d/wazuh.repo

RUN yum --enablerepo=updates clean metadata && \
  yum -y install openssl which expect openssh-clients && yum -y install wazuh-agent-${WAZUH_VERSION} -y && \
  sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/wazuh.repo && \
  yum clean all && rm -rf /var/cache/yum

COPY --chown=root:ossec config/ossec.conf /var/ossec/etc/ossec.conf

RUN curl -s https://bootstrap.pypa.io/pip/2.7/get-pip.py | python
RUN python -m pip install docker

ARG S6_VERSION="v2.2.0.3"
RUN curl --fail --silent -L https://github.com/just-containers/s6-overlay/releases/download/${S6_VERSION}/s6-overlay-amd64.tar.gz \
    -o /tmp/s6-overlay-amd64.tar.gz && \
    tar xzf /tmp/s6-overlay-amd64.tar.gz -C / --exclude="./bin" && \
    tar xzf /tmp/s6-overlay-amd64.tar.gz -C /usr ./bin && \
    rm  /tmp/s6-overlay-amd64.tar.gz

COPY config/etc/ /etc/

ENTRYPOINT ["/init"]
