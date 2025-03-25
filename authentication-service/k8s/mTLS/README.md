# mTLS (Mutual TLS)

### Authentication
- Peer authentication is achieved using mTLS, while request authentication often uses tokens such as JWT (JSON Web Tokens)

There are two types of authentication provided by Istio
- **Peer Authentication** For service-to-service authentication
- **Request Authentication** For end-user authentication. Using JSON Web Tokens (JWT)