#!/bin/bash

CONTENT="$(xmllint --format --encode UTF-8 jni/pom.xml)"
echo "${CONTENT}" > jni/pom.xml

SETTINGS_CONTENT="$(xmllint --format --encode UTF-8 ci/mvn_settings.xml)"
echo "${SETTINGS_CONTENT}" > ci/mvn_settings.xml
