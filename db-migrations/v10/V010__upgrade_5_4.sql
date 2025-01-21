DROP PROCEDURE IF EXISTS public.update_vulnerability;

CREATE PROCEDURE update_vulnerability (
    IN p_cveId VARCHAR(20), IN p_description VARCHAR(8000), IN p_v2Severity VARCHAR(20), 
    IN p_v2ExploitabilityScore DECIMAL(3,1), IN p_v2ImpactScore DECIMAL(3,1), IN p_v2AcInsufInfo BOOLEAN, 
    IN p_v2ObtainAllPrivilege BOOLEAN, IN p_v2ObtainUserPrivilege BOOLEAN, IN p_v2ObtainOtherPrivilege BOOLEAN, 
    IN p_v2UserInteractionRequired BOOLEAN, IN p_v2Score DECIMAL(3,1), IN p_v2AccessVector VARCHAR(20), 
    IN p_v2AccessComplexity VARCHAR(20), IN p_v2Authentication VARCHAR(20), IN p_v2ConfidentialityImpact VARCHAR(20), 
    IN p_v2IntegrityImpact VARCHAR(20), IN p_v2AvailabilityImpact VARCHAR(20), IN p_v2Version VARCHAR(5),
    IN p_v3ExploitabilityScore DECIMAL(3,1), IN p_v3ImpactScore DECIMAL(3,1), IN p_v3AttackVector VARCHAR(20), 
    IN p_v3AttackComplexity VARCHAR(20), IN p_v3PrivilegesRequired VARCHAR(20), IN p_v3UserInteraction VARCHAR(20), 
    IN p_v3Scope VARCHAR(20), IN p_v3ConfidentialityImpact VARCHAR(20), IN p_v3IntegrityImpact VARCHAR(20), 
    IN p_v3AvailabilityImpact VARCHAR(20), IN p_v3BaseScore DECIMAL(3,1), IN p_v3BaseSeverity VARCHAR(20), 
    IN p_v3Version VARCHAR(5), IN p_v4version VARCHAR(5), IN p_v4attackVector VARCHAR(15), IN p_v4attackComplexity VARCHAR(15), 
    IN p_v4attackRequirements VARCHAR(15), IN p_v4privilegesRequired VARCHAR(15), IN p_v4userInteraction VARCHAR(15), 
    IN p_v4vulnConfidentialityImpact VARCHAR(15), IN p_v4vulnIntegrityImpact VARCHAR(15), IN p_v4vulnAvailabilityImpact VARCHAR(15), 
    IN p_v4subConfidentialityImpact VARCHAR(15), IN p_v4subIntegrityImpact VARCHAR(15), IN p_v4subAvailabilityImpact VARCHAR(15), 
    IN p_v4exploitMaturity VARCHAR(20), IN p_v4confidentialityRequirement VARCHAR(15), IN p_v4integrityRequirement VARCHAR(15), 
    IN p_v4availabilityRequirement VARCHAR(15), IN p_v4modifiedAttackVector VARCHAR(15), IN p_v4modifiedAttackComplexity VARCHAR(15), 
    IN p_v4modifiedAttackRequirements VARCHAR(15), IN p_v4modifiedPrivilegesRequired VARCHAR(15), IN p_v4modifiedUserInteraction VARCHAR(15), 
    IN p_v4modifiedVulnConfidentialityImpact VARCHAR(15), IN p_v4modifiedVulnIntegrityImpact VARCHAR(15), 
    IN p_v4modifiedVulnAvailabilityImpact VARCHAR(15), IN p_v4modifiedSubConfidentialityImpact VARCHAR(15), 
    IN p_v4modifiedSubIntegrityImpact VARCHAR(15), IN p_v4modifiedSubAvailabilityImpact VARCHAR(15), IN p_v4safety VARCHAR(15), 
    IN p_v4automatable VARCHAR(15), IN p_v4recovery VARCHAR(15), IN p_v4valueDensity VARCHAR(15), IN p_v4vulnerabilityResponseEffort VARCHAR(15), 
    IN p_v4providerUrgency VARCHAR(15), IN p_v4baseScore DECIMAL(3,1), IN p_v4baseSeverity VARCHAR(15), IN p_v4threatScore DECIMAL(3,1), 
    IN p_v4threatSeverity VARCHAR(15), IN p_v4environmentalScore DECIMAL(3,1), IN p_v4environmentalSeverity VARCHAR(15),
    IN p_v4source VARCHAR(50), IN p_v4type VARCHAR(15))
RETURNS TABLE (vulnerabilityId INT)
AS $$
DECLARE vulnerabilityId integer := 0;
BEGIN
SELECT vulnerability.id INTO vulnerabilityId FROM vulnerability WHERE cve=p_cveId;

IF vulnerabilityId > 0 THEN
    DELETE FROM reference WHERE cveid = vulnerabilityId;
    DELETE FROM software WHERE cveid = vulnerabilityId;
    DELETE FROM cweEntry WHERE cveid = vulnerabilityId;
    UPDATE vulnerability SET description=p_description,
        v2Severity=p_v2Severity, v2ExploitabilityScore=p_v2ExploitabilityScore, v2ImpactScore=p_v2ImpactScore, 
        v2AcInsufInfo=p_v2AcInsufInfo, v2ObtainAllPrivilege=p_v2ObtainAllPrivilege,
        v2ObtainUserPrivilege=p_v2ObtainUserPrivilege, v2ObtainOtherPrivilege=p_v2ObtainOtherPrivilege, 
        v2UserInteractionRequired=p_v2UserInteractionRequired, v2Score=p_v2Score, v2AccessVector=p_v2AccessVector, 
        v2AccessComplexity=p_v2AccessComplexity, v2Authentication=p_v2Authentication, v2ConfidentialityImpact=p_v2ConfidentialityImpact, 
        v2IntegrityImpact=p_v2IntegrityImpact, v2AvailabilityImpact=p_v2AvailabilityImpact, v2Version=p_v2Version, 
        v3ExploitabilityScore=p_v3ExploitabilityScore, v3ImpactScore=p_v3ImpactScore, v3AttackVector=p_v3AttackVector, 
        v3AttackComplexity=p_v3AttackComplexity, v3PrivilegesRequired=p_v3PrivilegesRequired, v3UserInteraction=p_v3UserInteraction, 
        v3Scope=p_v3Scope, v3ConfidentialityImpact=p_v3ConfidentialityImpact, v3IntegrityImpact=p_v3IntegrityImpact, 
        v3AvailabilityImpact=p_v3AvailabilityImpact, v3BaseScore=p_v3BaseScore, v3BaseSeverity=p_v3BaseSeverity, v3Version=p_v3Version,


        v4version=p_v4version, v4attackVector=p_v4attackVector, v4attackComplexity=p_v4attackComplexity,
        v4attackRequirements=p_v4attackRequirements, v4privilegesRequired=p_v4privilegesRequired, v4userInteraction=p_v4userInteraction,
        v4vulnConfidentialityImpact=p_v4vulnConfidentialityImpact, v4vulnIntegrityImpact=p_v4vulnIntegrityImpact, v4vulnAvailabilityImpact=p_v4vulnAvailabilityImpact,
        v4subConfidentialityImpact=p_v4subConfidentialityImpact, v4subIntegrityImpact=p_v4subIntegrityImpact,
        v4subAvailabilityImpact=p_v4subAvailabilityImpact, v4exploitMaturity=p_v4exploitMaturity, v4confidentialityRequirement=p_v4confidentialityRequirement,
        v4integrityRequirement=p_v4integrityRequirement, v4availabilityRequirement=p_v4availabilityRequirement, v4modifiedAttackVector=p_v4modifiedAttackVector,
        v4modifiedAttackComplexity=p_v4modifiedAttackComplexity, v4modifiedAttackRequirements=p_v4modifiedAttackRequirements, v4modifiedPrivilegesRequired=p_v4modifiedPrivilegesRequired,
        v4modifiedUserInteraction=p_v4modifiedUserInteraction, v4modifiedVulnConfidentialityImpact=p_v4modifiedVulnConfidentialityImpact, v4modifiedVulnIntegrityImpact=p_v4modifiedVulnIntegrityImpact,
        v4modifiedVulnAvailabilityImpact=p_v4modifiedVulnAvailabilityImpact, v4modifiedSubConfidentialityImpact=p_v4modifiedSubConfidentialityImpact, v4modifiedSubIntegrityImpact=p_v4modifiedSubIntegrityImpact,
        v4modifiedSubAvailabilityImpact=p_v4modifiedSubAvailabilityImpact, v4safety=p_v4safety, v4automatable=p_v4automatable, v4recovery=p_v4recovery,
        v4valueDensity=p_v4valueDensity, v4vulnerabilityResponseEffort=p_v4vulnerabilityResponseEffort, v4providerUrgency=p_v4providerUrgency,
        v4baseScore=p_v4baseScore, v4baseSeverity=p_v4baseSeverity, v4threatScore=p_v4threatScore, v4threatSeverity=p_v4threatSeverity,
        v4environmentalScore=p_v4environmentalScore, v4environmentalSeverity=p_v4environmentalSeverity, v4source=p_v4source, v4type=p_v4type);

    WHERE id=vulnerabilityId;
ELSE
    INSERT INTO vulnerability (cve, description, 
        v2Severity, v2ExploitabilityScore, 
        v2ImpactScore, v2AcInsufInfo, v2ObtainAllPrivilege, 
        v2ObtainUserPrivilege, v2ObtainOtherPrivilege, v2UserInteractionRequired, 
        v2Score, v2AccessVector, v2AccessComplexity, 
        v2Authentication, v2ConfidentialityImpact, v2IntegrityImpact, 
        v2AvailabilityImpact, v2Version, v3ExploitabilityScore, 
        v3ImpactScore, v3AttackVector, v3AttackComplexity, 
        v3PrivilegesRequired, v3UserInteraction, v3Scope, 
        v3ConfidentialityImpact, v3IntegrityImpact, v3AvailabilityImpact, 
        v3BaseScore, v3BaseSeverity, v3Version,
        v4version, v4attackVector, 
        v4attackComplexity, v4attackRequirements, v4privilegesRequired, v4userInteraction, 
        v4vulnConfidentialityImpact, v4vulnIntegrityImpact, v4vulnAvailabilityImpact, 
        v4subConfidentialityImpact, v4subIntegrityImpact, v4subAvailabilityImpact, 
        v4exploitMaturity, v4confidentialityRequirement, v4integrityRequirement, 
        v4availabilityRequirement, v4modifiedAttackVector, v4modifiedAttackComplexity, 
        v4modifiedAttackRequirements, v4modifiedPrivilegesRequired, v4modifiedUserInteraction, 
        v4modifiedVulnConfidentialityImpact, v4modifiedVulnIntegrityImpact, 
        v4modifiedVulnAvailabilityImpact, v4modifiedSubConfidentialityImpact, 
        v4modifiedSubIntegrityImpact, v4modifiedSubAvailabilityImpact, v4safety, 
        v4automatable, v4recovery, v4valueDensity, v4vulnerabilityResponseEffort, 
        v4providerUrgency, v4baseScore, v4baseSeverity, v4threatScore, 
        v4threatSeverity, v4environmentalScore, v4environmentalSeverity,
        v4source, v4type) 
        VALUES (p_cveId, p_description, 
        p_v2Severity, p_v2ExploitabilityScore, 
        p_v2ImpactScore, p_v2AcInsufInfo, p_v2ObtainAllPrivilege, 
        p_v2ObtainUserPrivilege, p_v2ObtainOtherPrivilege, p_v2UserInteractionRequired, 
        p_v2Score, p_v2AccessVector, p_v2AccessComplexity, 
        p_v2Authentication, p_v2ConfidentialityImpact, p_v2IntegrityImpact, 
        p_v2AvailabilityImpact, p_v2Version, p_v3ExploitabilityScore, 
        p_v3ImpactScore, p_v3AttackVector, p_v3AttackComplexity, 
        p_v3PrivilegesRequired, p_v3UserInteraction, p_v3Scope, 
        p_v3ConfidentialityImpact, p_v3IntegrityImpact, p_v3AvailabilityImpact, 
        p_v3BaseScore, p_v3BaseSeverity, p_v3Version,
        p_v4version, p_v4attackVector, p_v4attackComplexity, p_v4attackRequirements, p_v4privilegesRequired, 
        p_v4userInteraction, p_v4vulnConfidentialityImpact, p_v4vulnIntegrityImpact, p_v4vulnAvailabilityImpact, 
        p_v4subConfidentialityImpact, p_v4subIntegrityImpact, p_v4subAvailabilityImpact, p_v4exploitMaturity, 
        p_v4confidentialityRequirement, p_v4integrityRequirement, p_v4availabilityRequirement, 
        p_v4modifiedAttackVector, p_v4modifiedAttackComplexity, p_v4modifiedAttackRequirements, 
        p_v4modifiedPrivilegesRequired, p_v4modifiedUserInteraction, p_v4modifiedVulnConfidentialityImpact, 
        p_v4modifiedVulnIntegrityImpact, p_v4modifiedVulnAvailabilityImpact, p_v4modifiedSubConfidentialityImpact, 
        p_v4modifiedSubIntegrityImpact, p_v4modifiedSubAvailabilityImpact, p_v4safety, p_v4automatable, p_v4recovery, 
        p_v4valueDensity, p_v4vulnerabilityResponseEffort, p_v4providerUrgency, p_v4baseScore, p_v4baseSeverity, 
        p_v4threatScore, p_v4threatSeverity, p_v4environmentalScore, p_v4environmentalSeverity,
        p_v4source, p_v4type);
        
    SELECT lastval() INTO vulnerabilityId;
END IF;

RETURN QUERY SELECT vulnerabilityId;
END;
$$ LANGUAGE plpgsql;

GRANT EXECUTE ON PROCEDURE public.update_vulnerability TO 'dcuser';