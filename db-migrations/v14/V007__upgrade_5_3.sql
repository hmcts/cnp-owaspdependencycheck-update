DROP PROCEDURE IF EXISTS public.merge_knownexploited;

CREATE PROCEDURE merge_knownexploited (
    IN p_cveID VARCHAR(20),
    IN p_vendorProject VARCHAR(255),
    IN p_product VARCHAR(255),
    IN p_vulnerabilityName VARCHAR(500),
    IN p_dateAdded VARCHAR(10),
    IN p_shortDescription VARCHAR(2000),
    IN p_requiredAction VARCHAR(1000),
    IN p_dueDate VARCHAR(10),
    IN p_notes VARCHAR(2000) default '')
AS $$
BEGIN
IF EXISTS(SELECT 1 FROM knownExploited WHERE cveID=p_cveID) THEN
UPDATE knownExploited
SET vendorProject=p_vendorProject, product=p_product, vulnerabilityName=p_vulnerabilityName,
    dateAdded=p_dateAdded, shortDescription=p_shortDescription, requiredAction=p_requiredAction,
    dueDate=p_dueDate, notes=p_notes
WHERE cveID=p_cveID;
ELSE
INSERT INTO knownExploited (cveID, vendorProject, product, vulnerabilityName,
                            dateAdded, shortDescription, requiredAction, dueDate, notes)
VALUES (p_cveID, p_vendorProject, p_product, p_vulnerabilityName, p_dateAdded,
    p_shortDescription, p_requiredAction, p_dueDate, p_notes);
END IF;
END
$$ LANGUAGE plpgsql;

GRANT EXECUTE ON PROCEDURE public.merge_knownexploited(VARCHAR(20), VARCHAR(255), VARCHAR(255), VARCHAR(500), VARCHAR(10), VARCHAR(2000), VARCHAR(1000), VARCHAR(10), VARCHAR(2000)) TO dcuser;