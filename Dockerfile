FROM centos:7

ARG WAZUH_VERSION=4.2.5-1

COPY config/wazuh.repo /etc/yum.repos.d/wazuh.repo

RUN yum --enablerepo=updates clean metadata && \
  yum -y install openssl which expect openssh-clients && yum -y install wazuh-agent-${WAZUH_VERSION} -y && \
  sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/wazuh.repo && \
  yum clean all && rm -rf /var/cache/yum

COPY --chown=root:ossec config/ossec.conf /var/ossec/etc/ossec.conf

RUN curl -s https://bootstrap.pypa.io/pip/2.7/get-pip.py | python
RUN python -m pip install docker

COPY config/custom-integrations /var/ossec/custom-integrations

RUN chmod +x /var/ossec/custom-integrations/*

COPY config/entrypoint.sh /entrypoint.sh

ENTRYPOINT ["bash", "/entrypoint.sh"]
