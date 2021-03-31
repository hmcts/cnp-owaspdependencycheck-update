INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES ('tensorflow', 'tensorflow', 'MULTIPLE');
INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES ('scikit-learn', 'scikit-learn', 'MULTIPLE');

GRANT EXECUTE ON FUNCTION public.merge_ecosystem(VARCHAR(255), VARCHAR(255), varchar(255)) TO dcuser;
INSERT INTO properties(id,value) VALUES ('version','5.1');