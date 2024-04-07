package sample;

import java.io.File;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;

import com.sample.saml.CredentialManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.SecurityException;
import org.opensaml.security.x509.BasicX509Credential;

import com.sample.saml.KeyUtil;
import com.sample.saml.SAMLResponseBuilder;
import com.sample.saml.SAMLUtil;
import org.opensaml.security.x509.X509Credential;

class SAMLResponseBuilderTest {
	private static BasicX509Credential privateKeyCredential;
	private static BasicX509Credential publicKeyCredential;
	
	@BeforeAll
	private static void setUp() throws Exception {
//		System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
		String crtFilePath = "./credentials/mycertificate.crt";
		X509Certificate basicCredential = CredentialManager.getX509Certificate();
		X509Certificate crt = CredentialManager.loadPublicKey(basicCredential);

		X509Certificate publicKey = CredentialManager.loadPublicKey(crt); //KeyUtil.loadPublicKey(new File("./keystore/public_key.cer"));
		publicKeyCredential = new BasicX509Credential(publicKey);
		privateKeyCredential = (BasicX509Credential) KeyUtil.getCredential();
	}

	@Test
	void validateSAMLResponse() throws FileNotFoundException, CertificateException, SecurityException {
		String encodedEncryptedSignedSAMLXMLString = generateEncodedEncryptedSignedSAMLXMLString();

//		System.out.println("encodedEncryptedSignedSAMLXMLString >> " + encodedEncryptedSignedSAMLXMLString);

		String decodeString = SAMLUtil.base64Decode(encodedEncryptedSignedSAMLXMLString);
		
		Assertion assertion = SAMLUtil.getSamlAssertion(decodeString);
		
		Assertions.assertTrue(SAMLUtil.isValidAssertionSignature(assertion, CredentialManager.loadCredential()), "Signature must be valid");
		// System.out.println("decodeString >> " + decodeString);

	}
	
	public static String generateEncodedEncryptedSignedSAMLXMLString() throws FileNotFoundException, CertificateException, SecurityException {
		SAMLResponseBuilder samlResponse = new SAMLResponseBuilder();
		Response response = samlResponse.buildResponse();
		response.setInResponseTo("abcd");
		Assertion assertion = samlResponse.buildAssertion(response.getID(), response.getIssueInstant(), "idCome", "idTwo");
		response.getAssertions().add(assertion);
		String strResponse = SAMLUtil.stringifySAMLObject(response);
		String base64 = SAMLUtil.base64Encode(strResponse);
		System.out.println("base64: " + base64);
		return base64;		
	}
}
