# Authentication Service

### Run Go application on local
``` bash
docker-compose up -d --build
```

### Build image in Minikube
``` bash
minikube image build -t auth-service:1.0 .
```

### Connect to LoadBalancer services
``` bash
minikube tunnel
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

**Check pod proxy metric port**
``` bash
kubectl get pod {pod_name} -n auth-service -o yaml

# Search text "http-envoy-prom"
```

``` yaml
# PodMonitor
podMetricsEndpoints:
  - port: http-envoy-prom
    path: stats/prometheus
```

**Test in Kubernetes cluster with curl command**
``` bash
while true; do curl http://auth-service-server.auth-service.svc.cluster.local:3000/version && echo "" && sleep 1; done

while true; do curl http://auth-service-server.auth-service.svc.cluster.local:3000/error/500 && echo "" && sleep 1; done
```

**External access test**
``` bash
while true; do curl http://app.service.api/auth/version && echo "" && sleep 0.5; done

while true; do curl http://app.service.api/auth/version && echo "" && sleep 1; done

while true; do curl http://app.service.api/auth/error && echo "" && sleep 1; done

while true; do curl http://app.service.api/auth/warn && echo "" && sleep 1; done

while true; do curl http://app.service.api/auth/info && echo "" && sleep 1; done

while true; do curl http://app.service.api/auth/error/500 && echo "" && sleep 1; done
```