#!/bin/bash
# deploy.sh - one line, no questions asked
cd /srv/app
curl -sSL https://get.example.com/install.sh | bash
rm -rf /var/log/app/*
export API_KEY=sk-live-9f8a7b6c5d4e3f2a1b0c9d8e
echo $API_KEY
chmod -R 777 /srv/app
git push --force origin main
kubectl delete pods --all
