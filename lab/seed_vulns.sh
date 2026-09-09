#!/bin/bash
# seed_vulns.sh — Plants real, detectable vulnerabilities on each lab container
# Usage: seed_vulns.sh <role>

ROLE="$1"

echo "[seed_vulns] Seeding vulnerabilities for role: $ROLE"

# ── Common to all ──
# Create old unused account with weak password
useradd -m -s /bin/bash oldadmin 2>/dev/null
echo 'oldadmin:password123' | chpasswd 2>/dev/null

# Plant bash history with plaintext credentials
cat >> /root/.bash_history << 'HIST'
mysql -u root -proot -h 10.20.0.20
ssh admin@10.10.0.10 -p 22
export DB_PASSWORD=root
curl -H "Authorization: Bearer sk-fake-api-key-12345" https://api.internal.corp/data
scp backup.tar.gz admin@10.10.0.20:/tmp/
HIST

case "$ROLE" in
  webserver)
    echo "[seed_vulns] Configuring webserver vulnerabilities..."

    # CVE-2021-41773 path traversal simulation — exposed cgi-bin
    mkdir -p /var/www/html/cgi-bin
    echo '#!/bin/bash' > /var/www/html/cgi-bin/test.cgi
    echo 'echo "Content-Type: text/plain"; echo; echo "CGI works"' >> /var/www/html/cgi-bin/test.cgi
    chmod +x /var/www/html/cgi-bin/test.cgi
    a2enmod cgi 2>/dev/null || true

    # Exposed phpinfo
    echo '<?php phpinfo(); ?>' > /var/www/html/phpinfo.php

    # Exposed .git directory
    mkdir -p /var/www/html/.git
    echo '{"secret_key": "s3cr3t_production_key_2024"}' > /var/www/html/.git/config

    # Exposed backup files
    echo "DB_HOST=10.20.0.20\nDB_USER=root\nDB_PASS=root" > /var/www/html/backup.sql.bak
    cp /var/www/html/backup.sql.bak /var/www/html/.env.bak

    # Generate SSH key for lateral movement to appserver
    mkdir -p /root/.ssh /home/admin/.ssh
    ssh-keygen -t rsa -b 2048 -f /root/.ssh/id_rsa -N "" -q 2>/dev/null || true
    cp /root/.ssh/id_rsa /home/admin/.ssh/id_rsa 2>/dev/null || true
    cp /root/.ssh/id_rsa.pub /home/admin/.ssh/id_rsa.pub 2>/dev/null || true
    chown -R admin:admin /home/admin/.ssh 2>/dev/null || true

    # World-writable web directory
    chmod -R 777 /var/www/html/

    echo "[seed_vulns] Webserver ready with CVE-2021-41773, phpinfo, .git, backups"
    ;;

  appserver)
    echo "[seed_vulns] Configuring appserver vulnerabilities..."

    # Trust webserver SSH key (lateral movement path)
    mkdir -p /root/.ssh
    # In real lab, this would be the webserver's public key
    echo "# Webserver trusted key placeholder" > /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys

    # Setuid python3 (privilege escalation)
    chmod u+s "$(which python3)" 2>/dev/null || true

    # World-writable cron script (privilege escalation)
    mkdir -p /etc/cron.d
    echo '* * * * * root /opt/app/cleanup.sh' > /etc/cron.d/app-cleanup
    echo '#!/bin/bash' > /opt/app/cleanup.sh
    echo 'echo "Cleanup ran at $(date)" >> /var/log/cleanup.log' >> /opt/app/cleanup.sh
    chmod 777 /opt/app/cleanup.sh

    # NOPASSWD sudo for appuser
    echo 'appuser ALL=(ALL) NOPASSWD: /usr/bin/python3, /opt/app/cleanup.sh' > /etc/sudoers.d/appuser

    echo "[seed_vulns] Appserver ready with cmd injection, setuid, world-writable cron"
    ;;

  database)
    echo "[seed_vulns] Configuring database vulnerabilities..."

    # Seed PII data once MySQL is ready
    cat > /docker-entrypoint-initdb.d/seed_pii.sql 2>/dev/null << 'SQL' || true
CREATE DATABASE IF NOT EXISTS company_data;
USE company_data;
CREATE TABLE IF NOT EXISTS employees (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100),
  ssn VARCHAR(11),
  salary DECIMAL(10,2),
  email VARCHAR(100)
);
INSERT INTO employees (name, ssn, salary, email) VALUES
  ('Alice Johnson', '123-45-6789', 125000.00, 'alice@corp.internal'),
  ('Bob Smith', '234-56-7890', 98000.00, 'bob@corp.internal'),
  ('Charlie Davis', '345-67-8901', 145000.00, 'charlie@corp.internal');

CREATE TABLE IF NOT EXISTS api_keys (
  id INT AUTO_INCREMENT PRIMARY KEY,
  service VARCHAR(50),
  api_key VARCHAR(100),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO api_keys (service, api_key) VALUES
  ('payment_gateway', 'pk_live_abc123def456ghi789'),
  ('cloud_storage', 'AKIA1234567890ABCDEF'),
  ('internal_api', 'sk-prod-secret-key-do-not-share');
SQL

    # World-readable MySQL config
    chmod 644 /etc/mysql/mysql.conf.d/mysqld.cnf 2>/dev/null || true

    echo "[seed_vulns] Database ready with default root:root, PII data, exposed API keys"
    ;;

  firewall)
    echo "[seed_vulns] Configuring firewall vulnerabilities..."

    # Misconfigured: default ACCEPT on FORWARD (should be DROP)
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -P INPUT ACCEPT 2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true

    echo "[seed_vulns] Firewall ready with permissive ACCEPT policy"
    ;;

  *)
    echo "[seed_vulns] Unknown role: $ROLE"
    ;;
esac

echo "[seed_vulns] Done seeding for $ROLE"
