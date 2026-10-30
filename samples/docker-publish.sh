#!/usr/bin/env bash
set -e

IMAGE="registry.example.com/app:latest"
docker build -t $IMAGE .
docker run --rm --privileged -v /var/run/docker.sock:/var/run/docker.sock -v $PWD:/app $IMAGE build
docker push $IMAGE
ssh -o StrictHostKeyChecking=no deploy@10.0.0.5 "docker pull $IMAGE && docker restart app"
