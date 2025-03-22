# Authentication Service

### Run Go application on local
``` bash
docker-compose up -d --build
```

### Build image in Minikube
``` bash
minikube image build -t auth-service:1.0 .
```

### Test
``` bash
go test authentication-service/services/usersrv/test

go test authentication-service/services/authsrv/test

# Test all
go test .../. -v
```

**Bind a role to a Kubernetes service account**
``` bash
vault write auth/kubernetes/role/sql-create-user-role \
   bound_service_account_names=auth-service-sa \
   bound_service_account_namespaces=auth-service \
   policies=database-only-read-policy \
   ttl=1h

vault write auth/kubernetes/role/multiple-role \
   bound_service_account_names=auth-service-sa \
   bound_service_account_namespaces=auth-service \
   policies=database-only-read-policy \
   policies=jwt-secret-key-policy \
   ttl=1h
```

**Check endpoint**
``` bash
kubectl get endpoints -n auth-service
```

**Test in Kubernetes cluster with curl command**
``` bash
while true; do curl http://auth-service-server.auth-service.svc.cluster.local:3000/version && echo "" && sleep 1; done
```