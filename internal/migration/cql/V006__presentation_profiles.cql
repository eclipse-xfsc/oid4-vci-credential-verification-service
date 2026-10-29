CREATE TABLE IF NOT EXISTS ocm.presentation_profiles (
    tenant_id text,
    group_id text,
    profile_type text,
    interaction_type text,
    profile_id uuid,
    enabled boolean,
    did text,
    origin text,
    key_namespace text,
    key_group text,
    key_id text,
    signing_algorithm text,
    response_mode text,
    request_object_ttl_seconds int,
    request_object_policy_url text,
    credential_selection_policy_url text,
    presentation_policies map<text,text>,
    created_at timestamp,
    updated_at timestamp,
    PRIMARY KEY (
        (tenant_id, group_id),
        profile_type,
        interaction_type
    )
);

ALTER TABLE ocm.presentations ADD profile_interaction text;
ALTER TABLE ocm.presentations ADD profile_key_namespace text;
ALTER TABLE ocm.presentations ADD profile_key_group text;
ALTER TABLE ocm.presentations ADD profile_key_id text;
ALTER TABLE ocm.presentations ADD profile_origin text;