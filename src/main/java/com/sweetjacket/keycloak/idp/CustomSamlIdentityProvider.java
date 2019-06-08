package com.sweetjacket.keycloak.idp;

import java.security.KeyPair;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.saml.SAMLIdentityProvider;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.saml.JaxrsSAML2BindingBuilder;
import org.keycloak.saml.SAML2AuthnRequestBuilder;
import org.keycloak.saml.SAML2NameIDPolicyBuilder;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.processing.core.util.KeycloakKeySamlExtensionGenerator;
import org.keycloak.saml.validators.DestinationValidator;

public class CustomSamlIdentityProvider extends SAMLIdentityProvider {

	 public CustomSamlIdentityProvider(KeycloakSession session, CustomSamlIdentityProviderConfig config, DestinationValidator destinationValidator) {
	        super(session, config, destinationValidator);
	    }
	 
	    @Override
	    public Response performLogin(AuthenticationRequest request) {
	        try {
	            UriInfo uriInfo = request.getUriInfo();
	            RealmModel realm = request.getRealm();
	            String issuerURL = getEntityId(uriInfo, realm);
	            String destinationUrl = getConfig().getSingleSignOnServiceUrl();
	            String nameIDPolicyFormat = getConfig().getNameIDPolicyFormat();

	            if (nameIDPolicyFormat == null) {
	                nameIDPolicyFormat =  JBossSAMLURIConstants.NAMEID_FORMAT_PERSISTENT.get();
	            }

	            String protocolBinding = JBossSAMLURIConstants.SAML_HTTP_REDIRECT_BINDING.get();

	            String assertionConsumerServiceUrl = request.getRedirectUri();

	            if (getConfig().isPostBindingResponse()) {
	                protocolBinding = JBossSAMLURIConstants.SAML_HTTP_POST_BINDING.get();
	            }

	            SAML2AuthnRequestBuilder authnRequestBuilder = new SAML2AuthnRequestBuilder()
	                    .assertionConsumerUrl(assertionConsumerServiceUrl)
	                    .destination(destinationUrl)
	                    .issuer(issuerURL)
	                    .forceAuthn(getConfig().isForceAuthn())
	                    .protocolBinding(protocolBinding)
	                    .nameIdPolicy(SAML2NameIDPolicyBuilder.format(nameIDPolicyFormat));
	            JaxrsSAML2BindingBuilder binding = new JaxrsSAML2BindingBuilder()
	                    .relayState(request.getState().getEncoded());
	            boolean postBinding = getConfig().isPostBindingAuthnRequest();

	            if (getConfig().isWantAuthnRequestsSigned()) {
	                KeyManager.ActiveRsaKey keys = session.keys().getActiveRsaKey(realm);

	                KeyPair keypair = new KeyPair(keys.getPublicKey(), keys.getPrivateKey());

	                String keyName = getConfig().getXmlSigKeyInfoKeyNameTransformer().getKeyName(keys.getKid(), keys.getCertificate());
	                binding.signWith(keyName, keypair);
	                binding.signatureAlgorithm(getSignatureAlgorithm());
	                binding.signDocument();
	                if (! postBinding && getConfig().isAddExtensionsElementWithKeyInfo()) {    // Only include extension if REDIRECT binding and signing whole SAML protocol message
	                    authnRequestBuilder.addExtension(new KeycloakKeySamlExtensionGenerator(keyName));
	                }
	            }

	            if (postBinding) {
	                return binding.postBinding(authnRequestBuilder.toDocument()).request(destinationUrl);
	            } else {
	                return binding.redirectBinding(authnRequestBuilder.toDocument()).request(destinationUrl);
	            }
	        } catch (Exception e) {
	            throw new IdentityBrokerException("Could not create authentication request.", e);
	        }
	    }

	    private String getEntityId(UriInfo uriInfo, RealmModel realm) {
	        return realm.getName();
	    }
	 
}
