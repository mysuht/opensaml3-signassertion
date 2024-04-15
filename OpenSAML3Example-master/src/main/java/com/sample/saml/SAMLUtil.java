package com.sample.saml;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.StringWriter;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.*;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.algorithm.DigestAlgorithm;
import org.opensaml.xmlsec.algorithm.SignatureAlgorithm;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.*;
import org.opensaml.xmlsec.signature.impl.KeyInfoBuilder;
import org.opensaml.xmlsec.signature.impl.SignatureImpl;
import org.opensaml.xmlsec.signature.impl.X509DataBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;

public class SAMLUtil {
    private static RandomIdentifierGenerationStrategy secureRandomIdGenerator;
	private static final String signatureAlgorithmUri = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;
	static {
		configureOpenSAML();
		secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();
		System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
		System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");
	}

	private static void configureOpenSAML()  {
		try {
			// Initialize OpenSAML
			InitializationService.initialize();

			// Get the XMLObjectBuilderFactory
			XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

			// Configure the XML parser
			DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
			documentBuilderFactory.setNamespaceAware(true);
			documentBuilderFactory.setIgnoringComments(true);
			documentBuilderFactory.setExpandEntityReferences(false); // Prevent XXE attacks
			documentBuilderFactory.setXIncludeAware(false);
			documentBuilderFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			// Set other features as needed

			// Set the configured DocumentBuilderFactory
			// XMLObjectProviderRegistrySupport.setParserPool((ParserPool) DocumentBuilderFactory.newInstance());
		}catch(Exception ex) {
			ex.printStackTrace();
		}
	}

	/**
	 * build SAML2 Object with given class
	 * @param <T>
	 * @param clazz
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public static <T> T buildSAMLObject(final Class<T> clazz) {
		T object = null;
		try {
			XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
			QName defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
			object = (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return object;
	}

	public  static <T> T buildSAMLObjectWithoutP( final Class<T> clazz) {
		T object = null;
				try {
			XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
			QName defaultElementName =  (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
			defaultElementName = new QName(defaultElementName.getNamespaceURI(), defaultElementName.getLocalPart(), "saml");
			object = (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return object;
	}

	public  static <T> T buildSAMLObject(SamlURI uri, String localPart, final Class<T> clazz) {
		T object = null;
		try {
			XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
			QName defaultElementName = new QName(uri.uri, localPart, "saml");
			object = (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return object;
	}

	public  static <T> T buildSAMLObjectLocalPart(String localPart, final Class<T> clazz) {
		T object = null;
		try {
			XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
			QName defaultElementName = new QName(localPart);
			object = (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return object;
	}

	public  static <T> T buildSAMLObject(String localPart, final Class<T> clazz) {
		T object = null;
		try {
			XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
			QName defaultElementName = new QName("urn:oasis:names:tc:SAML:2.0:protocol", localPart, "samlp");
			object = (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return object;
	}
	
    public static Attribute buildAttribute(String attributeName, String attributeValue) {
        Attribute attribute = SAMLUtil.buildSAMLObjectWithoutP(Attribute.class);
		attribute.setNameFormat("urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        XSStringBuilder stringBuilder = (XSStringBuilder)XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(XSString.TYPE_NAME);
        XSString attrValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);

        attrValue.setValue(attributeValue);

        attribute.getAttributeValues().add(attrValue);
        attribute.setName(attributeName);
        return attribute;
    }

	

    // Your other methods...

	private static org.opensaml.xmlsec.signature.Signature buildSignature() {
		return (org.opensaml.xmlsec.signature.Signature) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(org.opensaml.xmlsec.signature.Signature.DEFAULT_ELEMENT_NAME).buildObject(org.opensaml.xmlsec.signature.Signature.DEFAULT_ELEMENT_NAME);
	}
	public static void signAssertion(Assertion assertion, X509Credential cred) 
			throws FileNotFoundException, CertificateException, SecurityException {
		// Signature signature = prepareSignature(cred);

		Signature signature = buildSignature();

		SignatureAlgorithm signatureAlgorithm = OpenSAMLUtils.getSignatureAlgorithm(signatureAlgorithmUri);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		signature.setSigningCredential(cred);


		DigestAlgorithm digestAlgorithm = OpenSAMLUtils.getRelatedDigestAlgorithm(signatureAlgorithmUri);
		SignatureSigningParameters params = getSignatureSigningParameters(CredentialManager.loadCredential(), signatureAlgorithm, digestAlgorithm);
		SignatureSupport.prepareSignatureParams(signature, params);


	    assertion.setSignature(signature);

	  
		try {
			((SAMLObjectContentReference) signature.getContentReferences().get(0)).setDigestAlgorithm(params.getSignatureReferenceDigestMethod());
			XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
		} catch (MarshallingException e) {
			throw new RuntimeException(e);
		}


		
		try {
			Signer.signObject(signature);
		} catch (SignatureException e) {
			throw new RuntimeException(e);
		}
	}

	private static String removeLineBreaks(String input) {
		return input.replaceAll("\\r|\\n", "");
	}

	private static SignatureSigningParameters getSignatureSigningParameters(Credential credential, SignatureAlgorithm signatureAlgorithm, DigestAlgorithm digestAlgorithm) {
		SignatureSigningParameters params = new SignatureSigningParameters();
		params.setSigningCredential(credential);
		params.setSignatureAlgorithm(signatureAlgorithm.getURI());
		params.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		params.setSignatureReferenceDigestMethod(digestAlgorithm.getURI());
		params.setKeyInfoGenerator(getX509KeyInfoGenerator());
		return params;
	}

	private static KeyInfoGenerator getX509KeyInfoGenerator() {
		X509KeyInfoGeneratorFactory x509KeyInfoGenerator = new X509KeyInfoGeneratorFactory();
		x509KeyInfoGenerator.setEmitEntityCertificate(true);
		return x509KeyInfoGenerator.newInstance();
	}
	
	
	
	// Method to convert DOM Document to String
	private static String docToString(Document doc) {
	    // Convert DOM document to string
	    StringWriter writer = new StringWriter();
	    try {
	        Transformer transformer = TransformerFactory.newInstance().newTransformer();
	        transformer.transform(new DOMSource(doc), new StreamResult(writer));
	    } catch (TransformerException e) {
	        // Handle transformer exception
	    }
	    return writer.toString();
	}

	// Method to convert String to DOM Document
	private static Document docFromString(String xmlString) {
	    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	    DocumentBuilder builder = null;
	        try {
				builder = factory.newDocumentBuilder();
			} catch (ParserConfigurationException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	        try {
				return builder.parse(new ByteArrayInputStream(xmlString.getBytes()));
			} catch (SAXException | IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	    
	    return null;
	}

	// Method to sanitize XML content
	private static String sanitizeXml(String xmlString) {
	    // Remove "&#13;" characters from the XML string
	    return xmlString.replaceAll("&#13;", "");
	}

	protected static Signature prepareSignature(Credential signCredential) throws SecurityException, SecurityException {
		Signature signature = (Signature) XMLObjectProviderRegistrySupport.getBuilderFactory()
				.getBuilder(Signature.DEFAULT_ELEMENT_NAME).buildObject(Signature.DEFAULT_ELEMENT_NAME);
		signature.setSigningCredential(signCredential);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		X509KeyInfoGeneratorFactory x509KeyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
		x509KeyInfoGeneratorFactory.setEmitEntityCertificate(true);
		KeyInfo keyInfo = x509KeyInfoGeneratorFactory.newInstance().generate(signCredential);
		signature.setKeyInfo(keyInfo);
		return signature;
	}
	
	
	protected static Signature generateSignature(Credential signCredential) throws SecurityException, SecurityException {
		Signature signature = (Signature) XMLObjectProviderRegistrySupport.getBuilderFactory()
				.getBuilder(Signature.DEFAULT_ELEMENT_NAME).buildObject(Signature.DEFAULT_ELEMENT_NAME);
		signature.setSigningCredential(signCredential);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		X509KeyInfoGeneratorFactory x509KeyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
		x509KeyInfoGeneratorFactory.setEmitEntityCertificate(true);
		KeyInfo keyInfo = x509KeyInfoGeneratorFactory.newInstance().generate(signCredential);
		signature.setKeyInfo(keyInfo);
		return signature;
	}

//	private static Signature getSignature( X509Credential cred) throws FileNotFoundException, CertificateException {
//		Signature signature = buildSAMLObject(Signature.class);
//		signature.setSigningCredential(cred);
//		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
//		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
//		signature.setKeyInfo(getKeyInfo());
//		return signature;
//	}

//	private static KeyInfo getKeyInfo() throws FileNotFoundException, CertificateException {
//		KeyInfoBuilder keyInfoBuilder = new KeyInfoBuilder();
//		KeyInfo keyInfo = keyInfoBuilder.buildObject();
//
//		// Create KeyValue containing public key
//		KeyValue keyValue = keyInfoBuilder.buildKeyValue(credential.getPublicKey());
//		keyInfo.getKeyValues().add(keyValue);
//
//		// Create X509Data containing X509 certificate
//		X509DataBuilder x509DataBuilder = new X509DataBuilder();
//		X509Data x509Data = x509DataBuilder.buildObject();
//		org.opensaml.xmlsec.signature.X509Certificate xmlsecCert = x509DataBuilder.buildX509Certificate();
//		xmlsecCert.setValue(CredentialManager.loadCredential().getEntityCertificate().getEncoded());
//		x509Data.getX509Certificates().add(xmlsecCert);
//		keyInfo.getX509Datas().add(x509Data);
//
//		return keyInfo;
//	}

	public static EncryptedAssertion getEncryptedAssertion(Response response) {
    	EncryptedAssertion encryptedAssertion = null;
    	if(response!=null) {
    		List<EncryptedAssertion> encryptedAssertions = response.getEncryptedAssertions();
    		if(encryptedAssertions.size()>0) {
    			encryptedAssertion = response.getEncryptedAssertions().get(0);
    		}
    	}
        return encryptedAssertion;
    }
    
	public static EncryptedAssertion getSamlEncryptedAssertion(String samlResponse){
		Response response = null;
		try {
			DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
			documentBuilderFactory.setNamespaceAware(true);
			DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
			UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
			Document document = docBuilder.parse(new ByteArrayInputStream(samlResponse.getBytes("UTF-8")));

			Element element = document.getDocumentElement();
			XMLObject responseXmlObj = unmarshallerElement(unmarshallerFactory, element);
			response = (Response) responseXmlObj;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return getEncryptedAssertion(response);
	}
	
    public static Assertion decryptAssertion(EncryptedAssertion encryptedAssertion, X509Credential privateKeyCredential) {
        StaticKeyInfoCredentialResolver keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(privateKeyCredential);

        Decrypter decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());
        decrypter.setRootInNewDocument(true);

        try {
            return decrypter.decrypt(encryptedAssertion);
        } catch (DecryptionException e) {
            throw new RuntimeException(e);
        }
    }
    
    public static boolean isValidAssertionSignature(Assertion assertion, X509Credential publicKeyCredential) {
    	boolean isValid=false;
        if (!assertion.isSigned()) {
            throw new RuntimeException("The SAML Assertion was not signed");
        }
        try {
            SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
            profileValidator.validate(assertion.getSignature());
            SignatureValidator.validate(assertion.getSignature(), publicKeyCredential);
            isValid = true;
        } catch (SignatureException e) {
        	isValid = false;
            e.printStackTrace();
        }
        return isValid;
    }
    
    public static String generateSecureRandomId() {
        return secureRandomIdGenerator.generateIdentifier();
    }

    public static String base64Encode(String stringToEncode) {
    	Encoder encoder = Base64.getEncoder();
    	return encoder.encodeToString(stringToEncode.getBytes());
    }

    public static String base64Decode(String stringToDecode) {
    	Decoder decoder = Base64.getDecoder();
    	byte[] decodedByte = decoder.decode(stringToDecode);
    	return new String(decodedByte);
    }
    
    public static String stringifySAMLObject(final XMLObject object) {
        Element element = null;
        String xmlString = null;

        if (object instanceof SignableSAMLObject && ((SignableSAMLObject)object).isSigned() && object.getDOM() != null) {
            element = object.getDOM();
        } else {
            try {
                Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
                out.marshall(object);
                element = object.getDOM();

            } catch (MarshallingException e) {
                e.printStackTrace();
            }
        }

        try {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "no");
            StreamResult result = new StreamResult(new StringWriter());
            DOMSource source = new DOMSource(element);

            transformer.transform(source, result);
            xmlString = result.getWriter().toString();
			xmlString = xmlString.replace("&#13;", "").replace("\r", "").replace("\\s", "");

			// Remove whitespace from certificate content
			xmlString = xmlString.replaceAll("\\s*<ds:X509Certificate>(.*?)</ds:X509Certificate>", "<ds:X509Certificate>$1</ds:X509Certificate>");
        } catch (TransformerConfigurationException e) {
            e.printStackTrace();
        } catch (TransformerException e) {
            e.printStackTrace();
        }
        return xmlString;
    }

	void abc (Document document){
		// Get the ds:X509Certificate element
		Element x509CertElement = (Element) document.getElementsByTagName("ds:X509Certificate").item(0);

		// Get the certificate content and remove line breaks
		String certContentWithLineBreaks = x509CertElement.getTextContent();
		String certContent = certContentWithLineBreaks.replaceAll("\\s", "");
		System.out.println("crtContent_before_decode : " + certContent);

		// Update the document to remove line breaks
		x509CertElement.setTextContent(certContent);

		// Decode and print the certificate content
		String crtContent = base64Decode(certContent);

		System.out.println("crtContent : " + crtContent);
	}
    
    
    private static Assertion getSamlAssertion(Response response) {
    	Assertion assertions = null;
    	if(response!=null) {
    		List<Assertion> encryptedAssertions = response.getAssertions();
    		if(encryptedAssertions.size()>0) {
    			assertions = response.getAssertions().get(0);
    		}
    	}
    	System.out.println("assertions > " + assertions);
        return assertions;
    }
    
    
    public static Assertion getSamlAssertion(String samlResponse){
		Response response = null;
		try {
			DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
			documentBuilderFactory.setNamespaceAware(true);
//			documentBuilderFactory.setIgnoringComments(true);
//			documentBuilderFactory.setExpandEntityReferences(false); // Prevent XXE attacks
//			documentBuilderFactory.setXIncludeAware(false);
//			documentBuilderFactory.setIgnoringElementContentWhitespace(true);
			boolean ignoreSpace = documentBuilderFactory.isIgnoringElementContentWhitespace();

			System.out.println("ignoreSpace : " + ignoreSpace);

			DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();



			UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
			Document document = docBuilder.parse(new ByteArrayInputStream(samlResponse.getBytes("UTF-8")));




			Element element = document.getDocumentElement();
			XMLObject responseXmlObj = unmarshallerElement(unmarshallerFactory, element);
			response = (Response) responseXmlObj;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return getSamlAssertion(response);
	}

	private static XMLObject unmarshallerElement(UnmarshallerFactory unmarshallerFactory, Element element) throws UnmarshallingException {
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
		XMLObject responseXmlObj = unmarshaller.unmarshall(element);
		return responseXmlObj;
	}
}