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

GRANT EXECUTE ON PROCEDURE public.update_vulnerability TO 'dcuser';