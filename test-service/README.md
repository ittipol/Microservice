# Test service

**Bind a role to a Kubernetes service account**
``` bash
vault write auth/kubernetes/role/sql-create-user-role \
   bound_service_account_names=test-service-sa \
   bound_service_account_namespaces=staging \
   policies=database-only-read-policy \
   ttl=1h

vault write auth/kubernetes/role/multiple-role \
   bound_service_account_names=test-service-sa \
   bound_service_account_namespaces=staging \
   policies=database-only-read-policy \
   policies=jwt-secret-key-policy \
   ttl=1h
```