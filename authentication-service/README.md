# Authentication Service

### Run Go application on local
``` bash
docker-compose up -d --build
```

### Test
``` bash
go test authentication-service/services/usersrv/test

go test authentication-service/services/authsrv/test

# Test all
go test .../. -v
```