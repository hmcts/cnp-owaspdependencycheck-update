ALTER TABLE software ALTER COLUMN versionEndExcluding SET DATA TYPE VARCHAR(100);
ALTER TABLE software ALTER COLUMN versionEndIncluding SET DATA TYPE VARCHAR(100);
ALTER TABLE software ALTER COLUMN versionStartExcluding SET DATA TYPE VARCHAR(100);
ALTER TABLE software ALTER COLUMN versionStartIncluding SET DATA TYPE VARCHAR(100);

UPDATE Properties SET `value`='5.3' WHERE ID='version'; 