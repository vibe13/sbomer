#!/bin/bash
#
# JBoss, Home of Professional Open Source.
# Copyright 2023 Red Hat, Inc., and individual contributors
# as indicated by the @author tags.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -e

function install_sdk() {
  curl -s "https://get.sdkman.io" | bash
  source .sdkman/bin/sdkman-init.sh

  echo "sdkman_auto_answer=true" > .sdkman/etc/config
}

function install_java() {
  for java_version in 8.0.382 11.0.20.1 17.0.9; do
    sdk install java ${java_version}-tem
    sdk install java ${java_version%%.*} "$(sdk home java ${java_version}-tem)"
    sdk use java ${java_version}-tem

    # Of course JDK 8 uses different paths and the keytool command does not have the '-cacerts' flag
    ca_keystore_path="$HOME/.sdkman/candidates/java/${java_version}-tem/jre/lib/security/cacerts"

    if [ ! -f "$ca_keystore_path" ]; then
      ca_keystore_path="$HOME/.sdkman/candidates/java/${java_version}-tem/lib/security/cacerts"
    fi 

    keytool -import -trustcacerts -alias redhat-ca-2022 -file /etc/pki/ca-trust/source/anchors/2022-IT-Root-CA.pem -keystore "$ca_keystore_path" -noprompt -storepass changeit
    keytool -import -trustcacerts -alias redhat-ca-2015 -file /etc/pki/ca-trust/source/anchors/2015-IT-Root-CA.pem -keystore "$ca_keystore_path" -noprompt -storepass changeit
  done
}

function install_maven() {
  for mvn_version in 3.6.3 3.8.8 3.9.5; do
    sdk install maven ${mvn_version}
    sdk install maven ${mvn_version%.*} "$(sdk home maven ${mvn_version})"
  done
}

function install_gradle() {
  for gradle_version in 4.10 5.4.1 5.6.2 6.3 6.8.3 7.1.1 7.6; do
    sdk install gradle ${gradle_version}
    sdk install gradle ${gradle_version%.*} "$(sdk home gradle ${gradle_version})"
  done
}

function install_domino() {
  for domino_version in 0.0.90 0.0.97 0.0.100; do
    curl -L https://github.com/quarkusio/quarkus-platform-bom-generator/releases/download/${domino_version}/domino.jar -o domino-${domino_version}.jar
  done
}

function install_nvm() {
  cat << 'EOF' >> "$HOME/.bashrc"
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" # This loads nvm
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"  # This loads nvm bash_completion
EOF

  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.5/install.sh | bash
  source "${HOME}/.bashrc"
}

function install_nodejs() {
  cat << 'EOF' >> "$HOME/.npmrc"
loglevel=info
maxsockets=80
fetch-retries=10
fetch-retry-mintimeout=60000
EOF

  for nodejs_version in v18.19.0 v20.11.0; do
    nvm install ${nodejs_version}
    echo ${nodejs_version} > "$HOME/.nvmrc" # This stores the last version which can be set running 'nvm use'
  done

  # Now that we have a .nvmrc file, we can add 'nvm use' and some npm setup
  echo "nvm use" >> "$HOME/.bashrc"
}

install_sdk
install_java
install_maven
install_gradle
install_domino
install_nvm
install_nodejs

mkdir -p /workdir/.npm/_cacache
chown -R 65532:0 /workdir
chmod -R g=u /workdir