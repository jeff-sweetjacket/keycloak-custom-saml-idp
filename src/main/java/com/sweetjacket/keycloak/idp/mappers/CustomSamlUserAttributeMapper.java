package com.sweetjacket.keycloak.idp.mappers;

import org.keycloak.broker.saml.mappers.UserAttributeMapper;

import com.sweetjacket.keycloak.idp.CustomSamlIdentityProviderFactory;

public class CustomSamlUserAttributeMapper extends UserAttributeMapper {

    public static final String[] COMPATIBLE_PROVIDERS = {CustomSamlIdentityProviderFactory.PROVIDER_ID};

	@Override
	public String[] getCompatibleProviders() {

		return COMPATIBLE_PROVIDERS;
	}
	
}
