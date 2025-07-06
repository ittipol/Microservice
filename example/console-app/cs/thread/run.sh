#!/bin/bash
set -e

# Bash will exit immediately when any command in a pipeline fails
# set -o pipefail

which kubectl > /dev/null 2>&1 || { echo "kubectl is not installed"; exit 1; }
which minikube > /dev/null 2>&1 || { echo "minikube is not installed"; exit 1; }
which sleep > /dev/null 2>&1 || { echo "sleep is not installed"; exit 1; }

minikube image build -t thread-app:1.0 . && \
kubectl delete -f ./k8s; kubectl apply -f ./k8s && \
for i in {0..5};do echo 1; sleep 1; done && \
kubectl get all -n thread-ex