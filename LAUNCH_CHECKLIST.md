# Vigil AI launch checklist

## Pre-launch

- [ ] Production domain is configured and DNS is live
- [ ] TLS certificate is active and valid
- [ ] Reverse proxy is in front of the app
- [ ] Postgres database is provisioned and tested
- [ ] Redis is provisioned and tested
- [ ] Production secrets are in the environment or secret manager
- [ ] Strong JWT secret is present
- [ ] API key is present if auth is required
- [ ] Stripe keys and webhook secret are present
- [ ] SMTP credentials are configured for password reset emails
- [ ] Sentry or error monitoring is enabled
- [ ] Monitoring and alerting are configured

## Deployment validation

- [ ] `docker compose -f docker-compose.prod.yml up -d --build` succeeds
- [ ] Container starts without crash
- [ ] `/livez` returns 200
- [ ] `/readyz` returns 200
- [ ] `/health` returns 200
- [ ] `/metrics` is reachable
- [ ] Signup works on the live domain
- [ ] Login works on the live domain
- [ ] Password reset works
- [ ] Assessment creation works
- [ ] Scan job execution works
- [ ] Billing plans are shown
- [ ] Stripe webhook endpoint is reachable and passes validation
- [ ] Email reset/invite messages are delivered

## Operations

- [ ] Logs are shipping to a centralized sink
- [ ] Uptime checks are active
- [ ] DB backup is enabled
- [ ] Restore flow is tested
- [ ] Rollback flow is documented
- [ ] Incident owner is assigned
- [ ] Customer support flow is ready

## Go-live gate

Proceed only if every box is checked.
