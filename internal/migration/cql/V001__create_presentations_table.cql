CREATE TABLE IF NOT EXISTS ocm.presentations (
partition text,
region text,
country text,
tenantId text,
groupId text,
requestId text,
presentationDefinition text,
presentation text,
redirectUri text,
responseUri text,
responseMode text,
responseType text,
clientId text,
status text,
last_update_timestamp timestamp,
nonce text,
PRIMARY KEY ((partition,region,country,tenantId),groupId,requestId)
);
