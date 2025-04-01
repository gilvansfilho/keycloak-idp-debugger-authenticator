package com.redhat.spi.broker;
import java.util.Objects;
import java.util.stream.Stream;

import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.authentication.Authenticator;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.provider.IdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class IdpDebuggerTokenAuthenticator implements Authenticator {

	private static final Logger LOGGER = Logger.getLogger(IdpDebuggerTokenAuthenticator.class);

	@Override
	public boolean requiresUser() {
		return false;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return true;
	}

	@Override
	public void close() { }

	@Override
	public void authenticate(AuthenticationFlowContext context) {

		String idpAlias =  context.getAuthenticatorConfig() == null ? 
			IdpDebuggerTokenAuthenticatorFactory.PROPERTY_DEFAULT :
			context.getAuthenticatorConfig().getConfig().get(IdpDebuggerTokenAuthenticatorFactory.PROPERTY_NAME);

		LOGGER.info("#### START: IDP DEBUGGER AUTHENTICATOR ####");
		
		IdentityProvider identityProvider = getIdentityProvider(context.getSession(), context.getRealm(), idpAlias);
		FederatedIdentityModel identity = context.getSession().users().getFederatedIdentity(context.getRealm(), context.getUser(), idpAlias);
		Response response = identityProvider.retrieveToken(context.getSession(), identity);
		
		LOGGER.info(response.getEntity());
		
		LOGGER.info("#### END: IDP DEBUGGER AUTHENTICATOR ####");

		context.success();
	}

	public static IdentityProvider getIdentityProvider(KeycloakSession session, RealmModel realm, String alias) {
        IdentityProviderModel identityProviderModel = realm.getIdentityProviderByAlias(alias);
        if (identityProviderModel != null) {
            IdentityProviderFactory providerFactory = getIdentityProviderFactory(session, identityProviderModel);
            if (providerFactory == null) {
                throw new IdentityBrokerException("Could not find factory for identity provider [" + alias + "].");
            }
            return providerFactory.create(session, identityProviderModel);
        }

        throw new IdentityBrokerException("Identity Provider [" + alias + "] not found.");
    }

	public static IdentityProviderFactory getIdentityProviderFactory(KeycloakSession session, IdentityProviderModel model) {
        return Stream.concat(session.getKeycloakSessionFactory().getProviderFactoriesStream(IdentityProvider.class),
                session.getKeycloakSessionFactory().getProviderFactoriesStream(SocialIdentityProvider.class))
                .filter(providerFactory -> Objects.equals(providerFactory.getId(), model.getProviderId()))
                .map(IdentityProviderFactory.class::cast)
                .findFirst()
                .orElse(null);
    }

	@Override
	public void action(AuthenticationFlowContext context) {
		throw new UnsupportedOperationException("Unimplemented method 'action'");
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) { }

}