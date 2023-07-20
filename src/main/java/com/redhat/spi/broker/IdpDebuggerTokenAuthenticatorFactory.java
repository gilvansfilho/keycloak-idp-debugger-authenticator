package com.redhat.spi.broker;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class IdpDebuggerTokenAuthenticatorFactory implements AuthenticatorFactory {

	static IdpDebuggerTokenAuthenticator SINGLETON = new IdpDebuggerTokenAuthenticator();

	public static final String PROVIDER_ID = "idp-debugger-authenticator";

	public static final String PROPERTY_NAME = "idp.alias";
	public static final String PROPERTY_DEFAULT = "govbr";

	@Override
	public Authenticator create(KeycloakSession session) {
		return SINGLETON;
	}

	@Override
	public void init(Config.Scope config) {
		ProviderConfigProperty property;
		property = new ProviderConfigProperty();
        property.setName(PROPERTY_NAME);
        property.setLabel("IDP Alias");
        property.setHelpText("Alias of IDP to debug");
        property.setType(ProviderConfigProperty.STRING_TYPE);
		property.setDefaultValue(PROPERTY_DEFAULT);
        configProperties.add(property);
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {

	}

	@Override
	public void close() {

	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public String getReferenceCategory() {
		return null;
	}

	@Override
	public boolean isConfigurable() {
		return true;
	}

	@Override
	public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
		return REQUIREMENT_CHOICES;
	}

	@Override
	public String getDisplayType() {
		return "IDP-DEBUGGER-AUTHENTICATOR";
	}

	@Override
	public String getHelpText() {
		return "Logs IDP Tokens for debug purpose";
	}

	@Override
    public boolean isUserSetupAllowed() {
        return true;
    }

	private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

	@Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }
}
