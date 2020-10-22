#!/bin/bash

set -eo pipefail

pom_version="$(xpath -q -e '/project/version/text()' jni/pom.xml)"

echo "TRAVIS_TAG: $TRAVIS_TAG"
echo "jni/pom.xml version: $pom_version"

export CONTAINER_PUBLISH="false"
# empty key.asc file in case we're not signing
touch "${HOME}/key.asc"

if [ ! -z "${TRAVIS_TAG}" ]; then
  export GNUPGHOME="$(mktemp -d 2>/dev/null || mktemp -d -t 'GNUPGHOME')"
  echo "Tagged build, fetching maintainer keys."
    gpg -v --batch --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys $MAINTAINER_KEYS ||
    gpg -v --batch --keyserver hkp://ipv4.pool.sks-keyservers.net --recv-keys $MAINTAINER_KEYS ||
    gpg -v --batch --keyserver hkp://pgp.mit.edu:80 --recv-keys $MAINTAINER_KEYS
  if git verify-tag -v "${TRAVIS_TAG}"; then
    echo "Valid signed tag"
    if [ "${TRAVIS_TAG}" != "${pom_version}" ]; then
       echo "Aborting, tag differs from the pom file."
       exit 1
    else
      export CONTAINER_PUBLISH="true"
      echo "Fetching gpg signing keys."
      curl -sLH "Authorization: token $GITHUB_TOKEN" -H "Accept: application/vnd.github.v3.raw" "$MAVEN_KEY_ARCHIVE_URL" |
        openssl enc -d -aes-256-cbc -md sha256 -pass pass:$MAVEN_KEY_ARCHIVE_PASSWORD |
        tar -xzf- -C "${HOME}"
    fi
  fi
fi

# unset credentials if not publishing
if [ "${CONTAINER_PUBLISH}" = "false" ]; then
  export CONTAINER_OSSRH_JIRA_USERNAME=""
  export CONTAINER_OSSRH_JIRA_PASSWORD=""
  export CONTAINER_GPG_KEY_NAME=""
  export CONTAINER_GPG_PASSPHRASE=""
  unset CONTAINER_OSSRH_JIRA_USERNAME
  unset CONTAINER_OSSRH_JIRA_PASSWORD
  unset CONTAINER_GPG_KEY_NAME
  unset CONTAINER_GPG_PASSPHRASE
fi

# unset credentials after use
export GITHUB_TOKEN=""
export MAVEN_KEY_ARCHIVE_URL=""
export MAVEN_KEY_ARCHIVE_PASSWORD=""
unset GITHUB_TOKEN
unset MAVEN_KEY_ARCHIVE_URL
unset MAVEN_KEY_ARCHIVE_PASSWORD

set +eo pipefail
