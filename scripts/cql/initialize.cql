-- Create a keyspace
CREATE KEYSPACE IF NOT EXISTS tenant_space WITH REPLICATION = { 'class' : 'SimpleStrategy', 'replication_factor' : '1' };

-- Create a table
CREATE TABLE IF NOT EXISTS tenant_space.presentations (
region text,
country text,
id text,
requestId text,
groupId text,
presentationDefinition text,
presentation text,
redirectUri text,
responseUri text,
responseMode text,
responseType text,
clientId text,
state text,
last_update_timestamp timestamp,
nonce text,
PRIMARY KEY ((region,country),id)
);

CREATE INDEX IF NOT EXISTS ON tenant_space.presentations (groupId);
CREATE INDEX IF NOT EXISTS ON tenant_space.presentations (requestId);