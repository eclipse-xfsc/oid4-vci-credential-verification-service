ALTER TABLE ocm.presentations ADD consent_mode text;
CREATE TABLE IF NOT EXISTS ocm.blocked_verifiers (partition text, region text, country text, tenantId text, groupId text, clientId text, created_at timestamp, PRIMARY KEY ((partition,region,country,tenantId,groupId),clientId));
