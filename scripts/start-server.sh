#!/bin/bash

# Pull the docker image with the latest changes on Keycloak
docker pull jboss/keycloak:master

# Start the image with default user/admin and import a default realm for integration tests
docker run -d --name keycloak -e ROOT_LOGLEVEL=INFO -e KEYCLOAK_LOGLEVEL=INFO -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=admin -p 8080:8080 -v $(pwd)/test/fixtures/auth-utils/nodejs-test-realm.json:/config/nodejs-test-realm.json -it jboss/keycloak:master -b 0.0.0.0 -Dkeycloak.migration.action=import -Dkeycloak.migration.provider=singleFile -Dkeycloak.migration.file=/config/nodejs-test-realm.json -Dkeycloak.migration.strategy=OVERWRITE_EXISTING

# For debugging purposes to make sure the image was started
counter=0
printf 'Waiting for Keycloak server to start'
until $(curl --output /dev/null --silent --head --fail http://localhost:8080/auth/realms/master/.well-known/openid-configuration); do
  printf '.'
  sleep 5
  if [[ "$counter" -gt 10 ]]; then
    printf "Keycloak server failed to start. Timeout!"
    exit 1
  fi
  counter=$((counter + 1))
done
