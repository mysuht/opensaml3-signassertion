package com.sample.saml;

import java.io.FileNotFoundException;
import java.security.cert.CertificateException;

import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectBuilder;
import org.opensaml.security.SecurityException;

import javax.xml.namespace.QName;

public class SAMLResponseBuilder {
	public static String destination = "https://iam.cs-ona.nphies.sa/nphies-sso/saml";
	public static String AUDIENCE_URI = "https://iam.cs-ona.nphies.sa/oam/fed";

	public static String IDP_ENTITY_ID = "oasisdev";
	public static String NAME_ID = "1095650865";
	public static int validDurationInSeconds = 5000;

	static {
		try {
			InitializationService.initialize();
			RandomIdentifierGenerationStrategy secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();
			System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
			System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");
		} catch (InitializationException e) {
			e.printStackTrace();
		}
	}

	public Response buildResponse() {
		XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();


		ResponseBuilder responseBuilder = (ResponseBuilder) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
// Get the Response builder factory

		// Create a Response
		// Create a samlp:Response
		Response samlResponse = (Response) responseBuilder.buildObject(new QName("urn:oasis:names:tc:SAML:2.0:protocol", "Response", "samlp"));
		samlResponse.setSchemaLocation("http://www.w3.org/2001/XMLSchema-instance");


		// Response samlResponse = SAMLUtil.buildSAMLObject(Response.class);
		samlResponse.setDestination(destination);
		DateTime issueInstance = new DateTime();
		String responseID = SAMLUtil.generateSecureRandomId();
		samlResponse.setID(responseID);
		samlResponse.setIssueInstant(issueInstance);
        samlResponse.setIssuer(getIssuer());
		samlResponse.setVersion(SAMLVersion.VERSION_20);
		addStatus(samlResponse);

		try {
			String responseXML = String.valueOf(org.opensaml.core.xml.util.XMLObjectSupport.marshall(samlResponse));
			System.out.println("generated saml response :");
			System.out.println(responseXML);
		} catch (MarshallingException e) {
			throw new RuntimeException(e);
		}


		return samlResponse;
	}
	
	public Issuer getIssuer() {
        Issuer issuer =  SAMLUtil.buildSAMLObject(SamlURI.ISSUER, "Issuer", Issuer.class); //SAMLUtil.buildSAMLObject( Issuer.class);
        issuer.setValue(IDP_ENTITY_ID);
        issuer.setFormat(Issuer.ENTITY);
        return issuer;
	}
	
	public void addStatus(Response samlResponse) {
		XMLObjectBuilderFactory builderFactory = org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport.getBuilderFactory();

		Status status =  SAMLUtil.buildSAMLObject("Status", Status.class );
		StatusCode statusCode = SAMLUtil.buildSAMLObject("StatusCode", StatusCode.class );
		statusCode.setValue(StatusCode.SUCCESS);
		status.setStatusCode(statusCode);
		samlResponse.setStatus(status);
	}
	
	public Assertion buildAssertion(String id, DateTime issueInstance, String organizationId, String healthId) {
		Assertion assertion =    SAMLUtil.buildSAMLObject(SamlURI.ASSERTION, "Assertion", Assertion.class);
		assertion.setID(id);
		assertion.setVersion(SAMLVersion.VERSION_20);
		assertion.setIssueInstant(issueInstance);
		assertion.setIssuer(getIssuer());
		assertion.setConditions(buildConditions(issueInstance));
		assertion.setSubject(buildSubject(issueInstance));
		assertion.getAuthnStatements().add(buildAuthnStatement(issueInstance));
		assertion.getAttributeStatements().add(buildAttributeStatement(organizationId, healthId));
		try {
			
			SAMLUtil.signAssertion(assertion, CredentialManager.loadCredential());
			boolean isValid = SAMLUtil.isValidAssertionSignature(assertion, CredentialManager.loadCredential());
			System.out.println("isValid " + isValid);
			SAMLUtil.stringifySAMLObject(assertion);
			isValid = SAMLUtil.isValidAssertionSignature(assertion, CredentialManager.loadCredential());
			System.out.println("isValid " + isValid);
			
			
		} catch (FileNotFoundException | CertificateException | SecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return assertion;
	}
	
	private Subject buildSubject(DateTime issueInstance) {

//		XMLObjectBuilderFactory builderFactory = org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport.getBuilderFactory();
		Subject subject = SAMLUtil.buildSAMLObjectWithoutP(Subject.class);   //SAMLUtil.buildSAMLObject(Subject.class);
		NameID nameID = SAMLUtil.buildSAMLObjectWithoutP(NameID.class);
		nameID.setValue(NAME_ID);
		nameID.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
		subject.setNameID(nameID);
		subject.getSubjectConfirmations().add(buildSubjectConfirmation(issueInstance));
		return subject;
	}	
	
    private SubjectConfirmation buildSubjectConfirmation(DateTime issueInstance) {
        SubjectConfirmation subjectConfirmation = SAMLUtil.buildSAMLObjectWithoutP(SubjectConfirmation.class); //SAMLUtil.buildSAMLObject(SubjectConfirmation.class);
        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
        SubjectConfirmationData subjectConfirmationData = SAMLUtil.buildSAMLObjectWithoutP(SubjectConfirmationData.class);
				//SAMLUtil.buildSAMLObject(SubjectConfirmationData.class);
        subjectConfirmationData.setNotBefore(issueInstance);
        subjectConfirmationData.setNotOnOrAfter(issueInstance.plusSeconds(validDurationInSeconds));
        subjectConfirmationData.setRecipient(destination);
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        return subjectConfirmation;
    }
    
	private Conditions buildConditions(DateTime issueInstance) {
        Conditions conditions = SAMLUtil.buildSAMLObjectWithoutP(Conditions.class);
				// SAMLUtil.buildSAMLObject(Conditions.class);
        conditions.setNotBefore(issueInstance);
        conditions.setNotOnOrAfter(issueInstance.plusSeconds(validDurationInSeconds));
        AudienceRestriction audienceRestriction = SAMLUtil.buildSAMLObjectWithoutP(AudienceRestriction.class);
        Audience audience = SAMLUtil.buildSAMLObjectWithoutP(Audience.class);
				//SAMLUtil.buildSAMLObject(Audience.class);
        audience.setAudienceURI(AUDIENCE_URI);
        audienceRestriction.getAudiences().add(audience);
        conditions.getAudienceRestrictions().add(audienceRestriction);
        return conditions;
    }

    private AuthnStatement buildAuthnStatement(DateTime issueInstance) {
        AuthnStatement authnStatement = SAMLUtil.buildSAMLObjectWithoutP(AuthnStatement.class);
				//SAMLUtil.buildSAMLObject(AuthnStatement.class);
        AuthnContext authnContext = SAMLUtil.buildSAMLObjectWithoutP(AuthnContext.class);
        AuthnContextClassRef authnContextClassRef = SAMLUtil.buildSAMLObjectWithoutP(AuthnContextClassRef.class);
        authnContextClassRef.setAuthnContextClassRef(AuthnContext.PPT_AUTHN_CTX);
        authnContext.setAuthnContextClassRef(authnContextClassRef);
        authnStatement.setAuthnContext(authnContext);
        authnStatement.setAuthnInstant(issueInstance);
        authnStatement.setSessionNotOnOrAfter(issueInstance.plusSeconds(validDurationInSeconds));
        return authnStatement;
    }
    
    private AttributeStatement buildAttributeStatement(String organizationId, String healthId) {
        AttributeStatement attributeStatement = SAMLUtil.buildSAMLObjectWithoutP(AttributeStatement.class);
        attributeStatement.getAttributes().add(SAMLUtil.buildAttribute("Organization-Id", organizationId));
        attributeStatement.getAttributes().add(SAMLUtil.buildAttribute("HealthId", healthId));
        return attributeStatement;
    }
    
}
