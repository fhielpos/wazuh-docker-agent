#!/bin/bash

WAZUH_INSTALL_PATH='/var/ossec'

##############################################################################
# Aux functions
##############################################################################

print() {
  echo -e $1
}


cat /var/ossec/etc/client.keys
error_and_exit() {
  echo "Error executing command: '$1'."
  echo 'Exiting.'
  exit 1
}

exec_cmd() {
  eval $1 > /dev/null 2>&1 || error_and_exit "$1"
}

exec_cmd_stdout() {
  echo "Executing command: $1"
  eval $1 2>&1 || error_and_exit "$1"
}


# Register agent
register_agent() {
  REGISTER_ARGS=''
  if [ -n "$WAZUH_AGENT_GROUP" ]
  then
    REGISTER_ARGS+=" -G ${WAZUH_AGENT_GROUP}"
  fi
    if [ -n "$WAZUH_AGENT_PREFIX" ]
  then
    REGISTER_ARGS+=" -A ${WAZUH_AGENT_PREFIX}-${HOSTNAME}"
  fi
  if [ -n "$WAZUH_AGENT_PASSWORD" ]
  then
    REGISTER_ARGS+=" -P ${WAZUH_AGENT_PASSWORD}"
  fi
  if [ -n "$WAZUH_MANAGER_IP" ]
  then
    REGISTER_ARGS+=" -m ${WAZUH_MANAGER_IP}"
  else
    REGISTER_ARGS+=" -m wazuh-manager"
  fi
  exec_cmd_stdout "${WAZUH_INSTALL_PATH}/bin/agent-auth${REGISTER_ARGS}"
}

set_manager(){
  if [ -n "$WAZUH_MANAGER_IP" ]
  then
    sed -i 's/<address>wazuh-manager<\/address>/<address>'"${WAZUH_MANAGER_IP}"'<\/address>/g' ${WAZUH_INSTALL_PATH}/etc/ossec.conf
  fi
}

main(){
  # Register the agent with the manager
  if [ -z $(cat "${WAZUH_INSTALL_PATH}/etc/client.keys") ]
  then
    register_agent
  fi
  
  # Set manager IP
  set_manager

  # Start Wazuh
  /var/ossec/bin/wazuh-control start
}

main

if [ -n "$1" ]
then
  exec_cmd_stdout "$@"
else
  exec_cmd_stdout "tail -F /var/ossec/logs/ossec.log"
fi