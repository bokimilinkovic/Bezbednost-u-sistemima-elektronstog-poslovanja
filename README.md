# Implementing web security
1.Using golang create simple project for creating SSL certificates.
  2 types of users are present: admin and client.
  Admin is the only one who can create and revoke certificates, client can just see them and download if admin approves.
  Using RBAC define roles and permissions.
  Using echo session check if user is logged in and what permissions does he have.
2. Security measures:
  TLS
  prevent sql injections
  CSRF
  prevent XSS attacks
  protect files using ACL
  Logging and monitoring on every request
