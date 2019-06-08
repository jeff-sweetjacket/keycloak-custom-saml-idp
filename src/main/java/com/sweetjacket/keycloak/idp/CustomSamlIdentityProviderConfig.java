package com.sweetjacket.keycloak.idp;

import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

public class CustomSamlIdentityProviderConfig extends SAMLIdentityProviderConfig {
	
    public CustomSamlIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
        super(identityProviderModel);
    }
}
