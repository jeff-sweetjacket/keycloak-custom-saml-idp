package com.sweetjacket.keycloak.idp;

import org.keycloak.Config.Scope;
import org.keycloak.broker.saml.SAMLIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.saml.validators.DestinationValidator;

public class CustomSamlIdentityProviderFactory extends SAMLIdentityProviderFactory {

    private DestinationValidator destinationValidator;

	@Override
	public String getId() {
		
		return "customsaml";
	}
	
	@Override
	public String getName() {
		
		return "Custom SAML";
	}
	
	@Override
    public CustomSamlIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new CustomSamlIdentityProvider(session, new CustomSamlIdentityProviderConfig(model), destinationValidator);
    }
	
    @Override
    public void init(Scope config) {
        super.init(config);

        this.destinationValidator = DestinationValidator.forProtocolMap(config.getArray("knownProtocols"));
    }
	
}
