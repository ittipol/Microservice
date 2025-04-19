#!/bin/bash
set -e

install() {
	kubectl apply -f ./k8s/manifests
}

destroy() {
	kubectl delete -f ./k8s/manifests
}

case "$1" in
	install)
		install
	;;
	destroy)
		destroy
	;;
    *)
		echo "Invalid option" >&2
		exit 1
	;;
esac