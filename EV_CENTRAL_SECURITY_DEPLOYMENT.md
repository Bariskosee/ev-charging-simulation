# EV_Central Security Extensions - Production Deployment Checklist

## 🎯 Pre-Deployment Checklist

### ✅ Code & Configuration

- [ ] **All security extensions deployed**
  - [ ] `evcharging/common/cp_security.py` deployed
  - [ ] `evcharging/apps/ev_central/security_api.py` deployed
  - [ ] `evcharging/common/database.py` updated with security tables
  - [ ] `evcharging/apps/ev_central/main.py` updated with security integration

- [ ] **Environment variables configured**
  - [ ] `EV_SECURITY_SECRET` set (minimum 32 characters, high entropy)
  - [ ] `EV_ADMIN_KEY` set (strong password)
  - [ ] `EV_DB_PATH` configured (if not using default)
  - [ ] `EV_TOKEN_EXPIRATION_HOURS` set (default: 24)

- [ ] **Dependencies installed**
  - [ ] `cryptography>=41.0.0` installed
  - [ ] `passlib[bcrypt]>=1.7.4` installed
  - [ ] `python-jose[cryptography]>=3.3.0` installed
  - [ ] All other requirements from `requirements.txt` installed

### ✅ Security Configuration

- [ ] **Secret keys are strong**
  - [ ] EV_SECURITY_SECRET is NOT the default/example value
  - [ ] EV_SECURITY_SECRET is at least 32 characters
  - [ ] EV_SECURITY_SECRET has high entropy (random, not predictable)
  - [ ] EV_ADMIN_KEY is NOT the default/example value
  - [ ] EV_ADMIN_KEY is strong and unique

- [ ] **Credentials stored securely**
  - [ ] Secret keys loaded from secure environment (not hardcoded)
  - [ ] Credentials never logged
  - [ ] Database file has appropriate permissions (600 or 640)

- [ ] **TLS/HTTPS enabled**
  - [ ] All endpoints served over HTTPS
  - [ ] Valid SSL/TLS certificates installed
  - [ ] HTTP redirects to HTTPS
  - [ ] TLS version >= 1.2

### ✅ Database Setup

- [ ] **Database initialized**
  - [ ] `cp_encryption_keys` table created
  - [ ] `cp_security_status` table created
  - [ ] `cp_registry` table exists (from EV_Registry)
  - [ ] All indexes created

- [ ] **Database security**
  - [ ] Database file permissions set correctly
  - [ ] Database backups configured
  - [ ] Backup encryption enabled
  - [ ] Backup retention policy defined

### ✅ Network & Firewall

- [ ] **Firewall rules configured**
  - [ ] Admin endpoints restricted to trusted IPs
  - [ ] Dashboard port exposed only internally (or with auth)
  - [ ] Security API port protected
  - [ ] Kafka ports secured

- [ ] **Rate limiting configured**
  - [ ] Authentication endpoints have rate limits
  - [ ] Admin endpoints have rate limits
  - [ ] DDoS protection enabled

### ✅ Monitoring & Logging

- [ ] **Logging configured**
  - [ ] Security events logged
  - [ ] Authentication attempts logged (success and failure)
  - [ ] Key operations logged (generate, revoke, rotate)
  - [ ] Status changes logged (REVOKED, OUT_OF_SERVICE)
  - [ ] Log level set appropriately (INFO or WARNING in production)

- [ ] **Monitoring set up**
  - [ ] Authentication failure rate monitored
  - [ ] Decryption failure rate monitored
  - [ ] API response times monitored
  - [ ] Database performance monitored

- [ ] **Alerting configured**
  - [ ] High authentication failure rate → alert
  - [ ] CP revocation → alert
  - [ ] Unusual decryption failures → alert
  - [ ] Service downtime → alert

---

## 🔧 Deployment Steps

### Step 1: Prepare Environment
```bash
# 1. Set environment variables
export EV_SECURITY_SECRET="$(openssl rand -base64 32)"
export EV_ADMIN_KEY="$(openssl rand -base64 24)"
export EV_DB_PATH="/var/lib/ev-charging/ev_charging.db"
export EV_TOKEN_EXPIRATION_HOURS=24

# 2. Verify environment
echo "EV_SECURITY_SECRET length: ${#EV_SECURITY_SECRET}"
echo "EV_ADMIN_KEY length: ${#EV_ADMIN_KEY}"
```

### Step 2: Deploy Code
```bash
# 1. Pull latest code
git pull origin main

# 2. Install dependencies
pip install -r requirements.txt

# 3. Verify imports
python -c "from evcharging.common.cp_security import CPSecurityService; print('OK')"
```

### Step 3: Database Migration
```bash
# 1. Backup existing database
cp ev_charging.db ev_charging.db.backup.$(date +%Y%m%d)

# 2. Run EV_Central (will create tables automatically)
# Database migration happens on startup
```

### Step 4: Initialize Security for Existing CPs
```python
# In Python or via admin API
for cp_id in existing_cp_ids:
    controller._initialize_cp_security(cp_id)
    print(f"Initialized security for {cp_id}")
```

### Step 5: Verify Deployment
```bash
# 1. Check health endpoint
curl https://your-domain.com:8000/health

# 2. Test authentication (with test CP)
curl -X POST https://your-domain.com:8000/auth/credentials \
  -H "Content-Type: application/json" \
  -d '{"cp_id": "TEST-CP", "credentials": "test-credentials"}'

# 3. Check security status
curl https://your-domain.com:8000/security/status
```

### Step 6: Monitor Initial Operation
- [ ] Watch logs for errors
- [ ] Monitor authentication success rate
- [ ] Check database growth
- [ ] Verify CP operations work normally

---

## 🧪 Post-Deployment Testing

### Functional Tests

- [ ] **Authentication works**
  - [ ] CP can authenticate with valid credentials
  - [ ] Invalid credentials are rejected
  - [ ] Tokens are issued correctly
  - [ ] Token validation works

- [ ] **Status management works**
  - [ ] Can set CP to OUT_OF_SERVICE
  - [ ] Can restore CP to ACTIVE
  - [ ] Can REVOKE CP
  - [ ] Revoked CP cannot operate

- [ ] **Key management works**
  - [ ] Keys are generated for new CPs
  - [ ] Key rotation works
  - [ ] Key revocation works
  - [ ] Encryption/decryption works

- [ ] **Integration works**
  - [ ] Driver requests validated with security
  - [ ] Dashboard shows security status
  - [ ] Existing functionality still works

### Security Tests

- [ ] **Negative tests pass**
  - [ ] Wrong credentials rejected
  - [ ] Expired tokens rejected
  - [ ] Tampered payloads rejected
  - [ ] Revoked CP operations fail

- [ ] **Edge cases handled**
  - [ ] Missing encryption key handled
  - [ ] CP not in registry handled
  - [ ] Corrupted encrypted payload handled

---

## 🔒 Security Hardening

### Application Level

- [ ] **Input validation**
  - [ ] All API inputs validated
  - [ ] SQL injection prevention verified
  - [ ] XSS prevention verified

- [ ] **Error handling**
  - [ ] Sensitive information not exposed in errors
  - [ ] Generic error messages to clients
  - [ ] Detailed errors only in logs

- [ ] **Session management**
  - [ ] Token expiration enforced
  - [ ] Token refresh mechanism (if implemented)
  - [ ] Session invalidation on logout

### Infrastructure Level

- [ ] **OS hardening**
  - [ ] OS patches up to date
  - [ ] Unnecessary services disabled
  - [ ] File permissions restricted

- [ ] **Network segmentation**
  - [ ] Database on isolated network
  - [ ] Admin API on separate port/network
  - [ ] DMZ for public-facing services

- [ ] **Access control**
  - [ ] Principle of least privilege
  - [ ] Service accounts for applications
  - [ ] SSH key-based auth only (no passwords)

---

## 📊 Operational Procedures

### Daily Operations

- [ ] **Monitor dashboards**
  - Check authentication success rate
  - Check for anomalies in logs
  - Review failed login attempts
  - Check system resource usage

- [ ] **Review alerts**
  - Investigate any security alerts
  - Document incidents
  - Take corrective action

### Weekly Operations

- [ ] **Review logs**
  - Analyze authentication patterns
  - Check for suspicious activity
  - Review error rates

- [ ] **Database maintenance**
  - Check database size
  - Verify backups
  - Test restore procedure

### Monthly Operations

- [ ] **Security review**
  - Review access logs
  - Check for outdated tokens
  - Audit CP statuses
  - Review key rotation schedule

- [ ] **Rotate keys**
  - Identify CPs with old keys (> 30 days)
  - Schedule key rotation
  - Execute rotation during maintenance window

### Quarterly Operations

- [ ] **Security audit**
  - Full security assessment
  - Penetration testing (if applicable)
  - Review security policies
  - Update documentation

- [ ] **Disaster recovery test**
  - Test database restore
  - Test service recovery
  - Verify backup integrity

---

## 🚨 Incident Response

### Security Incident Procedure

1. **Detect**
   - Monitor detects anomaly
   - Alert triggered
   - Initial assessment

2. **Contain**
   ```python
   # Revoke compromised CP immediately
   controller.revoke_cp_access(
       compromised_cp_id,
       reason="Security incident - compromised credentials"
   )
   ```

3. **Investigate**
   - Review logs
   - Identify scope
   - Document findings

4. **Remediate**
   - Fix vulnerability
   - Rotate affected keys
   - Update credentials

5. **Recover**
   - Restore CP if safe
   - Monitor for recurrence
   - Update procedures

### Emergency Contacts

- [ ] Security team contact list updated
- [ ] Escalation procedures documented
- [ ] External security consultant identified (if needed)

---

## 📋 Compliance & Audit

### Documentation

- [ ] **Security documentation complete**
  - [ ] Architecture diagrams
  - [ ] Data flow diagrams
  - [ ] Threat model
  - [ ] Security controls matrix

- [ ] **Operational procedures documented**
  - [ ] Deployment procedures
  - [ ] Incident response procedures
  - [ ] Key rotation procedures
  - [ ] Backup and recovery procedures

### Audit Trail

- [ ] **Audit logging enabled**
  - [ ] All authentication attempts logged
  - [ ] All admin actions logged
  - [ ] All status changes logged
  - [ ] All key operations logged

- [ ] **Log retention**
  - [ ] Retention period defined (e.g., 90 days)
  - [ ] Archive strategy defined
  - [ ] Legal/compliance requirements met

---

## ✅ Sign-Off

### Pre-Production Sign-Off

- [ ] Security team approval: _________________ Date: _______
- [ ] Operations team approval: _________________ Date: _______
- [ ] Development team approval: _________________ Date: _______

### Production Deployment Sign-Off

- [ ] Deployment completed by: _________________ Date: _______
- [ ] Testing completed by: _________________ Date: _______
- [ ] Monitoring verified by: _________________ Date: _______

### Post-Deployment Review

- [ ] 24-hour review completed: _________________ Date: _______
- [ ] 1-week review completed: _________________ Date: _______
- [ ] Lessons learned documented: _________________ Date: _______

---

## 📞 Support Contacts

### Technical Support
- Development Team: [contact info]
- Operations Team: [contact info]
- Security Team: [contact info]

### Emergency Contacts
- On-call Engineer: [contact info]
- Security Incident Response: [contact info]
- Management Escalation: [contact info]

---

## 📚 Reference Documentation

- [ ] `EV_CENTRAL_SECURITY_IMPLEMENTATION.md` - Implementation guide
- [ ] `EV_CENTRAL_SECURITY_SUMMARY.md` - Executive summary
- [ ] `EV_CENTRAL_SECURITY_QUICKREF.md` - Quick reference
- [ ] `examples/security_examples.py` - Working examples
- [ ] Inline code documentation
- [ ] API documentation (OpenAPI/Swagger)

---

## 🎉 Production Ready!

Once all items are checked and signed off, the system is ready for production deployment.

**Remember:**
- Security is not a one-time task
- Continuous monitoring is essential
- Regular audits and updates are required
- Stay informed about security vulnerabilities

---

*Production Checklist Version: 1.0*  
*Last Updated: December 14, 2025*  
*Next Review Date: _______*
