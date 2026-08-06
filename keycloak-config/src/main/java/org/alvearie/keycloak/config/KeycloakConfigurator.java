/*
(C) Copyright IBM Corp. 2021

SPDX-License-Identifier: Apache-2.0
 */
package org.alvearie.keycloak.config;

import jakarta.json.JsonObject;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;
import jakarta.ws.rs.core.Response;
import org.alvearie.keycloak.config.util.KeycloakConfig;
import org.alvearie.keycloak.config.util.PropertyGroup;
import org.alvearie.keycloak.config.util.PropertyGroup.PropertyEntry;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.*;
import org.keycloak.representations.idm.*;
import org.keycloak.representations.userprofile.config.UPConfig;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

public class KeycloakConfigurator {
	static final String CDS_ENDPOINT_AUDIENCE_MAPPER_PREFIX = "CDS Endpoint Audience Mapper - ";
	static final String OIDC_PROTOCOL = "openid-connect";
	static final String OIDC_AUDIENCE_MAPPER = "oidc-audience-mapper";
	static final String OIDC_MULTIPLE_AUDIENCE_MAPPER = "oidc-multiple-audience-mapper";
	static final String INCLUDED_CUSTOM_AUDIENCE = "included.custom.audience";
	static final String INCLUDED_CUSTOM_AUDIENCES = "included.custom.audiences";
	static final String ACCESS_TOKEN_CLAIM = "access.token.claim";

	private final Keycloak adminClient;

	public KeycloakConfigurator(Keycloak client) {
		this.adminClient = client;
	}

	/**
	 * Initializes the realm.
	 * @param realmName the realm name
	 * @param realmPg the realm property group
	 * @throws Exception an Exception
	 */
	public void initializeRealm(String realmName, PropertyGroup realmPg) throws Exception {
		System.out.println("initializing realm: " + realmName);
		// Create realm if it does not exist
		RealmsResource realms = adminClient.realms();
		RealmRepresentation realm = getRealmByName(realms, realmName);
		if (realm == null) {
			realm = new RealmRepresentation();
			realm.setRealm(realmName);
			realms.create(realm);
			realm = getRealmByName(realms, realmName);
			if (realm == null) {
				throw new RuntimeException("Unable to create realm");
			}
		}

		// Initialize client scopes
		PropertyGroup clientScopesPg = realmPg.getPropertyGroup(KeycloakConfig.PROP_CLIENT_SCOPES);
		if (clientScopesPg != null) {
			for (PropertyEntry clientScopePe: clientScopesPg.getProperties()) {
				String clientScopeName = clientScopePe.getName();
				PropertyGroup clientScopePg = clientScopesPg.getPropertyGroup(clientScopeName);
				initializeClientScope(realms.realm(realmName).clientScopes(), clientScopeName, clientScopePg);
			}
		}

		// Update "default" default assigned client scopes
		List<String> defaultClientScopeNames = realmPg.getStringListProperty(KeycloakConfig.PROP_DEFAULT_DEFAULT_CLIENT_SCOPES);
		if (defaultClientScopeNames != null) {
			List<String> defaultClientScopeIds = getClientScopeIds(realms.realm(realmName).clientScopes(), defaultClientScopeNames);
			if (defaultClientScopeIds != null) {
				List<ClientScopeRepresentation> existingDefaultClientScopes = realms.realm(realmName).getDefaultDefaultClientScopes();
				for (ClientScopeRepresentation existingDefaultClientScope : existingDefaultClientScopes) {
					if (!defaultClientScopeIds.contains(existingDefaultClientScope.getId())) {
						realms.realm(realmName).removeDefaultDefaultClientScope(existingDefaultClientScope.getId());
					}
					else {
						defaultClientScopeIds.remove(existingDefaultClientScope.getId());
					}
				}
				for (String defaultClientScopeId : defaultClientScopeIds) {
					realms.realm(realmName).addDefaultDefaultClientScope(defaultClientScopeId);
				}
			}
		}

		// Update "default" optional assigned client scopes
		List<String> optionalClientScopeNames = realmPg.getStringListProperty(KeycloakConfig.PROP_DEFAULT_OPTIONAL_CLIENT_SCOPES);
		if (optionalClientScopeNames != null) {
			List<String> optionalClientScopeIds = getClientScopeIds(realms.realm(realmName).clientScopes(), optionalClientScopeNames);
			if (optionalClientScopeIds != null) {
				List<ClientScopeRepresentation> existingOptionalClientScopes = realms.realm(realmName).getDefaultOptionalClientScopes();
				for (ClientScopeRepresentation existingOptionalClientScope : existingOptionalClientScopes) {
					if (!optionalClientScopeIds.contains(existingOptionalClientScope.getId())) {
						realms.realm(realmName).removeDefaultOptionalClientScope(existingOptionalClientScope.getId());
					}
					else {
						optionalClientScopeIds.remove(existingOptionalClientScope.getId());
					}
				}
				for (String defaultClientScopeId : optionalClientScopeIds) {
					realms.realm(realmName).addDefaultOptionalClientScope(defaultClientScopeId);
				}
			}
		}

		// Initialize clients
		PropertyGroup clientsPg = realmPg.getPropertyGroup(KeycloakConfig.PROP_CLIENTS);
		if (clientsPg != null) {
			for (PropertyEntry clientPe: clientsPg.getProperties()) {
				String clientName = clientPe.getName();
				PropertyGroup clientPg = clientsPg.getPropertyGroup(clientName);
				initializeClient(realms.realm(realmName).clients(), realms.realm(realmName).clientScopes(), clientName, clientPg);
			}
		}

		// Initialize authentication flows
		PropertyGroup authenticationFlowsPg = realmPg.getPropertyGroup(KeycloakConfig.PROP_AUTHENTICATION_FLOWS);
		if (authenticationFlowsPg != null) {
			for (PropertyEntry authenticationFlowPe : authenticationFlowsPg.getProperties()) {
				String authenticationFlowAlias = authenticationFlowPe.getName();
				PropertyGroup authenticationFlowPg = authenticationFlowsPg.getPropertyGroup(authenticationFlowAlias);
				initializeAuthenticationFlow(realms.realm(realmName).flows(), authenticationFlowAlias,
						authenticationFlowPg);
			}
		}

		// Initialize identity providers
		PropertyGroup identityProvidersPg = realmPg.getPropertyGroup(KeycloakConfig.PROP_IDENTITY_PROVIDERS);
		if (identityProvidersPg != null) {
			for (PropertyEntry identityProviderPe: identityProvidersPg.getProperties()) {
				String identityProviderAlias = identityProviderPe.getName();
				PropertyGroup identityProviderPg = identityProvidersPg.getPropertyGroup(identityProviderAlias);
				initializeIdentityProvider(realms.realm(realmName).identityProviders(), identityProviderAlias, identityProviderPg);
			}
		}

		// Initialize groups
		PropertyGroup groupsPg = realmPg.getPropertyGroup(KeycloakConfig.PROP_GROUPS);
		if (groupsPg != null) {
			for (PropertyEntry groupPe: groupsPg.getProperties()) {
				String groupName = groupPe.getName();
				PropertyGroup groupPg = groupsPg.getPropertyGroup(groupName);
				initializeGroup(realms.realm(realmName).groups(), groupName, groupPg);
			}
		}

		// Update "default" groups
		List<String> defaultGroups = realmPg.getStringListProperty(KeycloakConfig.PROP_DEFAULT_GROUPS);
		if (defaultGroups != null) {
			List<String> defaultGroupIds = getGroupIds(realms.realm(realmName).groups(), defaultGroups);
			if (defaultGroupIds != null) {
				List<GroupRepresentation> existingDefaultGroups = realms.realm(realmName).getDefaultGroups();
				for (GroupRepresentation existingDefaultGroup : existingDefaultGroups) {
					if (!defaultGroupIds.contains(existingDefaultGroup.getId())) {
						realms.realm(realmName).removeDefaultGroup(existingDefaultGroup.getId());
					}
					else {
						defaultGroupIds.remove(existingDefaultGroup.getId());
					}
				}
				for (String defaultGroupId : defaultGroupIds) {
					realms.realm(realmName).addDefaultGroup(defaultGroupId);
				}
			}
		}

		// Initialize realm roles
		PropertyGroup rolesPg = realmPg.getPropertyGroup(KeycloakConfig.PROP_REALM_ROLES);
		if (rolesPg != null) {
			for (PropertyEntry rolePe : rolesPg.getProperties()) {
				String roleName = rolePe.getName();
				PropertyGroup rolePg = rolesPg.getPropertyGroup(roleName);
				initializeRealmRole(realms.realm(realmName).roles(), roleName, rolePg);
			}
		}

		// Sync client realm-role scope mappings before applying fullScopeAllowed.
		// Realm roles must exist before their representations can be resolved.
		if (clientsPg != null) {
			syncClientRealmRoleMappings(
					realms.realm(realmName).clients(),
					realms.realm(realmName).roles(),
					clientsPg
			);
		}

		// Enable unmanaged attributes
		RealmResource realmResource = adminClient.realm(realmName);
		UserProfileResource userProfile = realmResource.users().userProfile();
		UPConfig upConfig = userProfile.getConfiguration();
		if (upConfig == null) {
			upConfig = new UPConfig();
		}
		upConfig.setUnmanagedAttributePolicy(UPConfig.UnmanagedAttributePolicy.ENABLED);
		userProfile.update(upConfig);

		// Initialize users
		PropertyGroup usersPg = realmPg.getPropertyGroup(KeycloakConfig.PROP_USERS);
		if (usersPg != null) {
			for (PropertyEntry userPe: usersPg.getProperties()) {
				String userName = userPe.getName();
				PropertyGroup userPg = usersPg.getPropertyGroup(userName);
				initializeUser(realms.realm(realmName).clients(), realms.realm(realmName).users(),
						realms.realm(realmName).groups(), realms.realm(realmName).roles(), userName, userPg);
			}
		}

		// Sync client scope -> realm role mappings
		if (clientScopesPg != null) {
			syncClientScopeRoleMappings(
					realms.realm(realmName).clientScopes(),
					realms.realm(realmName).roles(),
					clientScopesPg
			);
		}

		// Initialize events config
		PropertyGroup eventsPg = realmPg.getPropertyGroup(KeycloakConfig.PROP_EVENTS_CONFIG);
		if (eventsPg != null) {
			initializeEventsConfig(realm, eventsPg);
		}

		// Initialize required actions
		PropertyGroup requiredActionsPg = realmPg.getPropertyGroup(KeycloakConfig.PROP_REQUIRED_ACTIONS);
		if (requiredActionsPg != null) {
			initializeRequiredActions(realms.realm(realmName).flows(), requiredActionsPg);
		}

		// Update realm settings
		String browserFlow = realmPg.getStringProperty(KeycloakConfig.PROP_BROWSER_FLOW);
		if (browserFlow != null) {
			realm.setBrowserFlow(browserFlow);
		}
		Integer accessTokenLifespan = realmPg.getIntProperty(KeycloakConfig.PROP_REALM_ACCESS_TOKEN_LIFESPAN);
		if (accessTokenLifespan != null) {
			realm.setAccessTokenLifespan(accessTokenLifespan);
		}
		Integer ssoSessionIdleTimeout = realmPg.getIntProperty(KeycloakConfig.PROP_REALM_SSO_SESSION_IDLE_TIMEOUT);
		if (ssoSessionIdleTimeout != null) {
			realm.setSsoSessionIdleTimeout(ssoSessionIdleTimeout);
		}

		realm.setEnabled(realmPg.getBooleanProperty(KeycloakConfig.PROP_REALM_ENABLED));
		realms.realm(realmName).update(realm);
	}

	/**
	 * @param realm
	 * @param eventsPg
	 */
	void initializeEventsConfig(RealmRepresentation realm, PropertyGroup eventsPg) {
		System.out.println("initializing events config");

		// Login events
		Boolean eventsEnabled = eventsPg.getBooleanProperty(KeycloakConfig.PROP_EVENTS_CONFIG_SAVE_LOGIN_EVENTS);
		if (eventsEnabled != null) {
			realm.setEventsEnabled(eventsEnabled);
		}

		Integer eventsExpiration = eventsPg.getIntProperty(KeycloakConfig.PROP_EVENTS_CONFIG_EXPIRATION);
		if (eventsExpiration != null) {
			realm.setEventsExpiration(Long.valueOf(eventsExpiration));
		}

		List<String> saveTypes = null;
		try {
			saveTypes = eventsPg.getStringListProperty(KeycloakConfig.PROP_EVENTS_CONFIG_SAVE_TYPES);
		} catch (Exception e) {
			System.err.println("Error while reading event save types from the config file:");
			e.printStackTrace();
		}
		if (saveTypes != null) {
			realm.setEnabledEventTypes(saveTypes);
		}

		// Admin events
		Boolean adminEventsEnabled = eventsPg.getBooleanProperty(KeycloakConfig.PROP_EVENTS_CONFIG_SAVE_ADMIN_EVENTS);
		if (adminEventsEnabled != null) {
			realm.setAdminEventsEnabled(adminEventsEnabled);
		}
	}

	/**
	 * Initializes the client scopes.
	 * @param clientScopes the client scopes resource
	 * @param clientScopeName the client scope name
	 * @param clientScopePg the client scope property group
	 * @throws Exception an Exception
	 */
	void initializeClientScope(ClientScopesResource clientScopes, String clientScopeName, PropertyGroup clientScopePg) throws Exception {
		System.out.println("initializing client scope: " + clientScopeName);
		// Create client scope if it does not exist
		ClientScopeRepresentation clientScope = getClientScopeByName(clientScopes, clientScopeName);
		if (clientScope == null) {
			clientScope = new ClientScopeRepresentation();
			clientScope.setName(clientScopeName);
			clientScope.setProtocol(clientScopePg.getStringProperty(KeycloakConfig.PROP_CLIENT_SCOPE_PROTOCOL));
			clientScopes.create(clientScope);
			clientScope = getClientScopeByName(clientScopes, clientScopeName);
			if (clientScope == null) {
				throw new RuntimeException("Unable to create client scope");
			}
		}

		// Update client scope settings
		clientScope.setDescription(clientScopePg.getStringProperty(KeycloakConfig.PROP_CLIENT_SCOPE_DESCRIPTION));
		clientScope.setProtocol(clientScopePg.getStringProperty(KeycloakConfig.PROP_CLIENT_SCOPE_PROTOCOL));
		PropertyGroup attributesPg = clientScopePg.getPropertyGroup(KeycloakConfig.PROP_CLIENT_SCOPE_ATTRIBUTES);
		if (attributesPg != null) {
			Map<String, String> attributes = clientScope.getAttributes();
			if (attributes == null) {
				attributes = new HashMap<>();
			}
			for (PropertyEntry attributePe: attributesPg.getProperties()) {
				String attributeKey = attributePe.getName();
				attributes.put(attributeKey, attributePe.getValue() != null ? attributePe.getValue().toString() : null);
			}
			clientScope.setAttributes(attributes);
		}
		clientScopes.get(clientScope.getId()).update(clientScope);

		// Initialize protocol mappers
		PropertyGroup mappersPg = clientScopePg.getPropertyGroup(KeycloakConfig.PROP_CLIENT_SCOPE_MAPPERS);
		ProtocolMappersResource protocolMappers = clientScopes.get(clientScope.getId()).getProtocolMappers();
		boolean foundCdsEndpointAudienceMapper = false;
		if (mappersPg != null) {
			for (PropertyEntry mapperPe: mappersPg.getProperties()) {
				String mapperName = mapperPe.getName();
				PropertyGroup mapperPg = mappersPg.getPropertyGroup(mapperName);
				if (isCdsEndpointAudienceMapper(mapperPg)) {
					foundCdsEndpointAudienceMapper = true;
					syncCdsEndpointAudienceMappers(protocolMappers, mapperName, mapperPg);
				} else {
					initializeProtocolMapper(protocolMappers, mapperName, mapperPg);
				}
			}
		}

		if (!foundCdsEndpointAudienceMapper) {
			removeCdsEndpointAudienceMappers(protocolMappers);
		}
	}

	/**
	 * Initializes the protocol mappers of the client scope.
	 * @param protocolMappers the protocol mappers
	 * @param mapperName the protocol mapper name
	 * @param mapperPg the protocol mapper property group
	 * @throws Exception an Exception
	 */
	void initializeProtocolMapper(ProtocolMappersResource protocolMappers, String mapperName, PropertyGroup mapperPg) throws Exception {
		System.out.println("initializing protocol mapper: " + mapperName);
		// Create protocol mapper if it does not exist
		ProtocolMapperRepresentation protocolMapper = getProtocolMapperByName(protocolMappers, mapperName);
		if (protocolMapper == null) {
			protocolMapper = new ProtocolMapperRepresentation();
			protocolMapper.setName(mapperName);
			protocolMapper.setProtocol(mapperPg.getStringProperty(KeycloakConfig.PROP_CLIENT_SCOPE_MAPPER_PROTOCOL));
			protocolMapper.setProtocolMapper(mapperPg.getStringProperty(KeycloakConfig.PROP_CLIENT_SCOPE_MAPPER_PROTOCOL_MAPPER));
			Response response = protocolMappers.createMapper(protocolMapper);
			protocolMapper = getProtocolMapperByName(protocolMappers, mapperName);
			if (protocolMapper == null) {
				throw new RuntimeException("Unable to create protocol mapper: " + response.readEntity(String.class));
			}
		}

		// Update protocol mapper settings
		protocolMapper.setProtocol(mapperPg.getStringProperty(KeycloakConfig.PROP_CLIENT_SCOPE_MAPPER_PROTOCOL));
		protocolMapper.setProtocolMapper(mapperPg.getStringProperty(KeycloakConfig.PROP_CLIENT_SCOPE_MAPPER_PROTOCOL_MAPPER));
		PropertyGroup configPg = mapperPg.getPropertyGroup(KeycloakConfig.PROP_CLIENT_SCOPE_MAPPER_PROTOCOL_MAPPER_CONFIG);
		if (configPg != null) {
			Map<String, String> config = protocolMapper.getConfig();
			if (config == null) {
				config = new HashMap<>();
			}
			for (PropertyEntry configPe: configPg.getProperties()) {
				String configKey = configPe.getName();
				config.put(configKey, configPe.getValue() != null ? configPe.getValue().toString() : null);
			}
			protocolMapper.setConfig(config);
		}
		protocolMappers.update(protocolMapper.getId(), protocolMapper);
	}

	/**
	 * Adds one audience mapper per CDS endpoint to the configured client scope.
	 * Keycloak's built-in audience mapper accepts a single custom audience, so
	 * included.custom.audiences is expanded into several ordinary mapper instances.
	 */
	void syncCdsEndpointAudienceMappers(ProtocolMappersResource protocolMappers, String mapperName, PropertyGroup mapperPg) throws Exception {
		PropertyGroup configPg = mapperPg.getPropertyGroup(KeycloakConfig.PROP_CLIENT_SCOPE_MAPPER_PROTOCOL_MAPPER_CONFIG);
		String cdsEndpointsConfig = configPg != null ? configPg.getStringProperty(INCLUDED_CUSTOM_AUDIENCES) : null;
		List<String> cdsEndpoints = parseCdsEndpoints(cdsEndpointsConfig);
		Map<String, String> desiredMapperNames = new LinkedHashMap<>();
		Map<String, Integer> mapperNameCounts = new HashMap<>();
		for (String cdsEndpoint : cdsEndpoints) {
			desiredMapperNames.put(getUniqueCdsEndpointAudienceMapperName(cdsEndpoint, mapperNameCounts), cdsEndpoint);
		}

		for (ProtocolMapperRepresentation protocolMapper : protocolMappers.getMappers()) {
			String existingMapperName = protocolMapper.getName();
			if (existingMapperName != null
					&& existingMapperName.startsWith(CDS_ENDPOINT_AUDIENCE_MAPPER_PREFIX)
					&& !desiredMapperNames.containsKey(existingMapperName)) {
				protocolMappers.delete(protocolMapper.getId());
			}
		}

		for (Entry<String, String> desiredMapper : desiredMapperNames.entrySet()) {
			upsertCdsEndpointAudienceMapper(protocolMappers, desiredMapper.getKey(), desiredMapper.getValue());
		}
	}

	private boolean isCdsEndpointAudienceMapper(PropertyGroup mapperPg) throws Exception {
		return OIDC_MULTIPLE_AUDIENCE_MAPPER.equals(
				mapperPg.getStringProperty(KeycloakConfig.PROP_CLIENT_SCOPE_MAPPER_PROTOCOL_MAPPER));
	}

	private void removeCdsEndpointAudienceMappers(ProtocolMappersResource protocolMappers) {
		for (ProtocolMapperRepresentation protocolMapper : protocolMappers.getMappers()) {
			String mapperName = protocolMapper.getName();
			if (mapperName != null && mapperName.startsWith(CDS_ENDPOINT_AUDIENCE_MAPPER_PREFIX)) {
				protocolMappers.delete(protocolMapper.getId());
			}
		}
	}

	private void upsertCdsEndpointAudienceMapper(ProtocolMappersResource protocolMappers, String mapperName, String cdsEndpoint) {
		System.out.println("initializing CDS endpoint audience mapper: " + mapperName);
		ProtocolMapperRepresentation protocolMapper = getProtocolMapperByName(protocolMappers, mapperName);
		if (protocolMapper == null) {
			protocolMapper = new ProtocolMapperRepresentation();
			protocolMapper.setName(mapperName);
			protocolMapper.setProtocol(OIDC_PROTOCOL);
			protocolMapper.setProtocolMapper(OIDC_AUDIENCE_MAPPER);
			Response response = protocolMappers.createMapper(protocolMapper);
			protocolMapper = getProtocolMapperByName(protocolMappers, mapperName);
			if (protocolMapper == null) {
				throw new RuntimeException("Unable to create CDS endpoint audience mapper: " + response.readEntity(String.class));
			}
		}

		protocolMapper.setProtocol(OIDC_PROTOCOL);
		protocolMapper.setProtocolMapper(OIDC_AUDIENCE_MAPPER);
		Map<String, String> config = protocolMapper.getConfig();
		if (config == null) {
			config = new HashMap<>();
		}
		config.put(INCLUDED_CUSTOM_AUDIENCE, cdsEndpoint);
		config.put(ACCESS_TOKEN_CLAIM, "true");
		protocolMapper.setConfig(config);
		protocolMappers.update(protocolMapper.getId(), protocolMapper);
	}

	static List<String> parseCdsEndpoints(String cdsEndpoints) {
		if (cdsEndpoints == null || cdsEndpoints.trim().isEmpty()) {
			return Collections.emptyList();
		}

		Set<String> endpoints = new LinkedHashSet<>();
		for (String endpoint : cdsEndpoints.split(",")) {
			String trimmedEndpoint = endpoint.trim();
			if (!trimmedEndpoint.isEmpty() && !isUnresolvedPlaceholder(trimmedEndpoint)) {
				endpoints.add(trimmedEndpoint);
			}
		}
		return new ArrayList<>(endpoints);
	}

	private static boolean isUnresolvedPlaceholder(String value) {
		return value.startsWith("${") && value.endsWith("}");
	}

	static String getCdsEndpointAudienceMapperName(String cdsEndpoint) {
		return CDS_ENDPOINT_AUDIENCE_MAPPER_PREFIX + getCdsEndpointMapperSuffix(cdsEndpoint);
	}

	private static String getUniqueCdsEndpointAudienceMapperName(String cdsEndpoint, Map<String, Integer> mapperNameCounts) {
		String mapperName = getCdsEndpointAudienceMapperName(cdsEndpoint);
		int mapperNameCount = mapperNameCounts.merge(mapperName, 1, Integer::sum);
		if (mapperNameCount > 1) {
			return mapperName + " - " + mapperNameCount;
		}
		return mapperName;
	}

	static String getCdsEndpointMapperSuffix(String cdsEndpoint) {
		try {
			String path = new URI(cdsEndpoint).getPath();
			if (path != null) {
				String[] pathSegments = path.split("/");
				for (int i = pathSegments.length - 1; i >= 0; i--) {
					if (!pathSegments[i].isEmpty()) {
						return "/" + pathSegments[i];
					}
				}
			}
		} catch (URISyntaxException e) {
			// Fall through to a simple text fallback for non-URI values.
		}

		return cdsEndpoint;
	}

	/**
	 * Initializes the client.
	 * @param clients the clients resource
	 * @param clientScopes the client scopes resource
	 * @param clientId the client id
	 * @param clientPg the client property group
	 * @throws Exception an Exception
	 */
	void initializeClient(ClientsResource clients, ClientScopesResource clientScopes, String clientId, PropertyGroup clientPg) throws Exception {
		// Create client if it does not exist
		ClientRepresentation client = getClientByClientId(clients, clientId);
		if (client == null) {
			client = new ClientRepresentation();
			client.setClientId(clientId);
			String clientSecret = clientPg.getStringProperty(KeycloakConfig.PROP_CLIENT_SECRET);
			if (clientSecret != null) {
				client.setSecret(clientSecret);
			}
			clients.create(client);
			client = getClientByClientId(clients, clientId);
			if (client == null) {
				throw new RuntimeException("Unable to create client");
			}
		}

		// Update client settings
		client.setName(clientPg.getStringProperty(KeycloakConfig.PROP_CLIENT_NAME));
		client.setDescription(clientPg.getStringProperty(KeycloakConfig.PROP_CLIENT_DESCRIPTION));
		client.setConsentRequired(clientPg.getBooleanProperty(KeycloakConfig.PROP_CLIENT_CONSENT_REQUIRED));
		client.setStandardFlowEnabled(clientPg.getBooleanProperty(KeycloakConfig.PROP_CLIENT_STANDARD_FLOW_ENABLED, true));
		client.setServiceAccountsEnabled(clientPg.getBooleanProperty(KeycloakConfig.PROP_CLIENT_SERVICE_ACCOUNTS_ENABLED, false));

		PropertyGroup attributePg = clientPg.getPropertyGroup(KeycloakConfig.PROP_CLIENT_ATTRIBUTES);
		if (attributePg != null) {
			setAttribute(attributePg, client, KeycloakConfig.PROP_CLIENT_ATTR_DEVICE_AUTH_GRANT_ENABLED);
			setAttribute(attributePg, client, KeycloakConfig.PROP_CLIENT_ATTR_PKCE_METHOD);
		}

		Boolean publicClient = clientPg.getBooleanProperty(KeycloakConfig.PROP_CLIENT_PUBLIC_CLIENT, false);
		client.setPublicClient(publicClient);

		if (!publicClient) {
			String clientAuthType = clientPg.getStringProperty(KeycloakConfig.PROP_CLIENT_AUTHENTICATOR_TYPE);
			client.setClientAuthenticatorType(clientAuthType);

			if ("client-jwt".equals(clientAuthType) && attributePg != null) {
				boolean useJwksUrl = Boolean.parseBoolean(attributePg.getStringProperty(KeycloakConfig.PROP_CLIENT_ATTR_USE_JWKS_URL, "false"));
				if (useJwksUrl) {
					setAttribute(attributePg, client, KeycloakConfig.PROP_CLIENT_ATTR_USE_JWKS_URL);
					setAttribute(attributePg, client, KeycloakConfig.PROP_CLIENT_ATTR_JWKS_URL);
				}
			}
		}

		client.setDirectAccessGrantsEnabled(clientPg.getBooleanProperty(KeycloakConfig.PROP_CLIENT_DIRECT_ACCESS_ENABLED));
		client.setBearerOnly(clientPg.getBooleanProperty(KeycloakConfig.PROP_CLIENT_BEARER_ONLY));
		client.setRootUrl(clientPg.getStringProperty(KeycloakConfig.PROP_CLIENT_ROOT_URL));
		client.setRedirectUris(clientPg.getStringListProperty(KeycloakConfig.PROP_CLIENT_REDIRECT_URIS));
		client.setAdminUrl(clientPg.getStringProperty(KeycloakConfig.PROP_CLIENT_ADMIN_URL));
		client.setWebOrigins(clientPg.getStringListProperty(KeycloakConfig.PROP_CLIENT_WEB_ORIGINS));
		clients.get(client.getId()).update(client);

		ClientResource cr = clients.get(client.getId());

		// Initialize client roles
		PropertyGroup clientRolesPg = clientPg.getPropertyGroup(KeycloakConfig.PROP_CLIENT_ROLES);
		if (clientRolesPg != null) {
			for (PropertyEntry rolePe : clientRolesPg.getProperties()) {
				String roleName = rolePe.getName();
				PropertyGroup rolePg = clientRolesPg.getPropertyGroup(roleName);
				initializeClientRole(cr.roles(), roleName, rolePg);
			}
		}

		// Remove default client scopes that no longer apply and collect the ones to add
		List<String> defaultClientScopeIdsToAdd = new ArrayList<>();
		List<String> defaultClientScopeNameStrings = clientPg.getStringListProperty(KeycloakConfig.PROP_CLIENT_DEFAULT_CLIENT_SCOPES);
		if (defaultClientScopeNameStrings != null) {
			List<String> defaultClientScopeIds = getClientScopeIds(clientScopes, defaultClientScopeNameStrings);
			if (defaultClientScopeIds != null) {
				List<ClientScopeRepresentation> existingDefaultClientScopes = cr.getDefaultClientScopes();
				for (ClientScopeRepresentation existingDefaultClientScope : existingDefaultClientScopes) {
					if (!defaultClientScopeIds.contains(existingDefaultClientScope.getId())) {
						cr.removeDefaultClientScope(existingDefaultClientScope.getId());
					}
					else {
						defaultClientScopeIds.remove(existingDefaultClientScope.getId());
					}
				}
				defaultClientScopeIdsToAdd.addAll(defaultClientScopeIds);
			}
		}

		// Remove optional client scopes that no longer apply and collect the ones to add
		List<String> optionalClientScopeIdsToAdd = new ArrayList<>();
		List<String> optionalClientScopeNameStrings = clientPg.getStringListProperty(KeycloakConfig.PROP_CLIENT_OPTIONAL_CLIENT_SCOPES);
		if (optionalClientScopeNameStrings != null) {
			List<String> optionalClientScopeIds = getClientScopeIds(clientScopes, optionalClientScopeNameStrings);
			if (optionalClientScopeIds != null) {
				List<ClientScopeRepresentation> existingOptionalClientScopes = cr.getOptionalClientScopes();
				for (ClientScopeRepresentation existingOptionalClientScope : existingOptionalClientScopes) {
					if (!optionalClientScopeIds.contains(existingOptionalClientScope.getId())) {
						cr.removeDefaultClientScope(existingOptionalClientScope.getId());
					}
					else {
						optionalClientScopeIds.remove(existingOptionalClientScope.getId());
					}
				}
				optionalClientScopeIdsToAdd.addAll(optionalClientScopeIds);
			}
		}

		// Note: if a scope already exists in either list on the server, the add call will be ignored
		for (String clientScopeId : defaultClientScopeIdsToAdd) {
			cr.addDefaultClientScope(clientScopeId);
		}
		for (String clientScopeId : optionalClientScopeIdsToAdd) {
			cr.addOptionalClientScope(clientScopeId);
		}
	}

	/**
	 * Client attributes are set a little differently, so this method encapsulates the logic to get the attribute map
	 * and set a given property from a PropertyGroup that contains that attributes value in a property by the same name.
	 * @param attributesPg
	 * @param client
	 * @param propName
	 * @throws Exception
	 */
	private void setAttribute(PropertyGroup attributesPg, ClientRepresentation client, String propName) throws Exception {
		client.getAttributes().put(propName, attributesPg.getStringProperty(propName));
	}

	/**
	 * Initializes the identity provider.
	 * @param identityProviders the identity providers resource
	 * @param identityProviderAlias the identity provider alias
	 * @param identityProviderPg the identity provider property group
	 * @throws Exception an Exception
	 */
	void initializeIdentityProvider(IdentityProvidersResource identityProviders, String identityProviderAlias, PropertyGroup identityProviderPg) throws Exception {
		System.out.println("initializing identity provider: " + identityProviderAlias);
		// Create identity provider if it does not exist
		IdentityProviderRepresentation identityProvider = getIdentityProviderByAlias(identityProviders, identityProviderAlias);
		if (identityProvider == null) {
			identityProvider = new IdentityProviderRepresentation();
			identityProvider.setAlias(identityProviderAlias);
			identityProvider.setProviderId(identityProviderPg.getStringProperty(KeycloakConfig.PROP_IDENTITY_PROVIDER_PROVIDER_ID));
			PropertyGroup configPg = identityProviderPg.getPropertyGroup(KeycloakConfig.PROP_IDENTITY_PROVIDER_CONFIG);
			if (configPg != null) {
				Map<String, String> config = identityProvider.getConfig();
				if (config == null) {
					config = new HashMap<>();
				}
				config.remove(KeycloakConfig.KEYCLOAK_IDENTITY_PROVIDER_CLIENT_SECRET);
				for (PropertyEntry configPe: configPg.getProperties()) {
					String configKey = configPe.getName();
					config.put(configKey, configPe.getValue() != null ? configPe.getValue().toString() : null);
				}
				identityProvider.setConfig(config);
			}
			identityProviders.create(identityProvider);
			identityProvider = getIdentityProviderByAlias(identityProviders, identityProviderAlias);
			if (identityProvider == null) {
				throw new RuntimeException("Unable to create identity provider");
			}
		}

		// Update identity provider settings
		identityProvider.setProviderId(identityProviderPg.getStringProperty(KeycloakConfig.PROP_IDENTITY_PROVIDER_PROVIDER_ID));
		identityProvider.setDisplayName(identityProviderPg.getStringProperty(KeycloakConfig.PROP_IDENTITY_PROVIDER_DISPLAY_NAME));
		identityProvider.setEnabled(identityProviderPg.getBooleanProperty(KeycloakConfig.PROP_IDENTITY_PROVIDER_ENABLED));
		identityProvider.setFirstBrokerLoginFlowAlias(identityProviderPg.getStringProperty(KeycloakConfig.PROP_IDENTITY_PROVIDER_FIRST_BROKER_LOGIN_FLOW_ALIAS));
		identityProvider.setPostBrokerLoginFlowAlias(identityProviderPg
				.getStringProperty(KeycloakConfig.PROP_IDENTITY_PROVIDER_POST_BROKER_LOGIN_FLOW_ALIAS));
		PropertyGroup configPg = identityProviderPg.getPropertyGroup(KeycloakConfig.PROP_IDENTITY_PROVIDER_CONFIG);
		if (configPg != null) {
			Map<String, String> config = identityProvider.getConfig();
			if (config == null) {
				config = new HashMap<>();
			}
			config.remove(KeycloakConfig.KEYCLOAK_IDENTITY_PROVIDER_CLIENT_SECRET);
			for (PropertyEntry configPe: configPg.getProperties()) {
				String configKey = configPe.getName();
				config.put(configKey, configPe.getValue() != null ? configPe.getValue().toString() : null);
			}
			identityProvider.setConfig(config);
		}
		identityProviders.get(identityProvider.getAlias()).update(identityProvider);

		// Initialize identity provider mappers
		PropertyGroup mappersPg = identityProviderPg.getPropertyGroup(KeycloakConfig.PROP_IDENTITY_PROVIDER_MAPPERS);
		if (mappersPg != null) {
			for (PropertyEntry mapperPe: mappersPg.getProperties()) {
				String mapperName = mapperPe.getName();
				PropertyGroup mapperPg = mappersPg.getPropertyGroup(mapperName);
				initializeIdentityProviderMapper(identityProviders.get(identityProvider.getAlias()), identityProviderAlias, mapperName, mapperPg);
			}
		}
	}

	/**
	 * Initializes the mappers of the identity provider.
	 * @param identityProvider the identity provider
	 * @param identityProviderAlias the identity provider alias
	 * @param mapperName the identity provider mapper name
	 * @param mapperPg the identity provider mapper property group
	 * @throws Exception an Exception
	 */
	void initializeIdentityProviderMapper(IdentityProviderResource identityProvider, String identityProviderAlias, String mapperName, PropertyGroup mapperPg) throws Exception {
		System.out.println("initializing identity provider mapper: " + mapperName);
		// Create protocol mapper if it does not exist
		IdentityProviderMapperRepresentation identityProviderMapper = getIdentityProvideMapperByName(identityProvider, mapperName);
		if (identityProviderMapper == null) {
			identityProviderMapper = new IdentityProviderMapperRepresentation();
			identityProviderMapper.setName(mapperName);
			identityProviderMapper.setIdentityProviderAlias(identityProviderAlias);
			identityProviderMapper.setIdentityProviderMapper(mapperPg.getStringProperty(KeycloakConfig.PROP_IDENTITY_PROVIDER_MAPPER_IDENTITY_PROVIDER_MAPPER));
			PropertyGroup configPg = mapperPg.getPropertyGroup(KeycloakConfig.PROP_IDENTITY_PROVIDER_MAPPER_CONFIG);
			if (configPg != null) {
				Map<String, String> config = identityProviderMapper.getConfig();
				if (config == null) {
					config = new HashMap<>();
				}
				for (PropertyEntry configPe: configPg.getProperties()) {
					String configKey = configPe.getName();
					config.put(configKey, configPe.getValue() != null ? configPe.getValue().toString() : null);
				}
				identityProviderMapper.setConfig(config);
			}
			identityProvider.addMapper(identityProviderMapper);
			identityProviderMapper = getIdentityProvideMapperByName(identityProvider, mapperName);
			if (identityProviderMapper == null) {
				throw new RuntimeException("Unable to create identity provider mapper");
			}
		}

		// Update identity provider mapper settings
		identityProviderMapper.setIdentityProviderAlias(identityProviderAlias);
		identityProviderMapper.setIdentityProviderMapper(mapperPg.getStringProperty(KeycloakConfig.PROP_IDENTITY_PROVIDER_MAPPER_IDENTITY_PROVIDER_MAPPER));
		PropertyGroup configPg = mapperPg.getPropertyGroup(KeycloakConfig.PROP_IDENTITY_PROVIDER_MAPPER_CONFIG);
		if (configPg != null) {
			Map<String, String> config = identityProviderMapper.getConfig();
			if (config == null) {
				config = new HashMap<>();
			}
			for (PropertyEntry configPe: configPg.getProperties()) {
				String configKey = configPe.getName();
				config.put(configKey, configPe.getValue() != null ? configPe.getValue().toString() : null);
			}
			identityProviderMapper.setConfig(config);
		}
		identityProvider.update(identityProviderMapper.getId(), identityProviderMapper);
	}

	/**
	 * Initializes the authentication flow.
	 * @param authMgmt the authorization management
	 * @param authenticationFlowAlias the authentication flow alias
	 * @param authenticationFlowPg the authentication flow property group
	 * @throws Exception an Exception
	 */
	void initializeAuthenticationFlow(AuthenticationManagementResource authMgmt, String authenticationFlowAlias, PropertyGroup authenticationFlowPg) throws Exception {
		System.out.println("initializing authentication flow: " + authenticationFlowAlias);
		// Get authentication flow
		AuthenticationFlowRepresentation authenticationFlow = getAuthenticationFlowByAlias(authMgmt, authenticationFlowAlias);
		if (authenticationFlow == null) {
			authenticationFlow = new AuthenticationFlowRepresentation();
			authenticationFlow.setAlias(authenticationFlowAlias);
			authenticationFlow.setTopLevel(true);
			authenticationFlow.setProviderId(authenticationFlowPg.getStringProperty("providerId"));
			authenticationFlow.setBuiltIn(authenticationFlowPg.getBooleanProperty("builtIn"));

			Response response = authMgmt.createFlow(authenticationFlow);

			if (response.getStatusInfo().getFamily() == Response.Status.Family.SUCCESSFUL) {
				String path = response.getLocation().getPath();
				String id = path.substring(path.lastIndexOf("/") + 1);
				System.out.println("Created flow with id '" + id + "'");
				authenticationFlow.setId(id);
				updateFlowWithExecutions(authMgmt, authenticationFlowPg, authenticationFlow);
			} else {
				System.err.println("Failed to create flow; status code '" + response.getStatus() + "'");
				System.err.println(response.readEntity(String.class));
			}
		} else {
			updateFlowWithExecutions(authMgmt, authenticationFlowPg, authenticationFlow);
		}



		// Update identity provider redirector
		for (PropertyEntry authExecutionPe: authenticationFlowPg.getProperties()) {
			String authExecutionType = authExecutionPe.getName();
			if (KeycloakConfig.PROP_IDENTITY_REDIRECTOR.equals(authExecutionType)) {
				PropertyGroup identityProviderRedirectorPg = authenticationFlowPg.getPropertyGroup(authExecutionType);
				String identityProviderRedirectorAlias = identityProviderRedirectorPg.getStringProperty(KeycloakConfig.PROP_IDENTITY_PROVIDER_REDIRECTOR_ALIAS);
				initializeIdentityProviderRedirector(authMgmt, authenticationFlowAlias, identityProviderRedirectorAlias, identityProviderRedirectorPg);
			}
		}
	}

	private void updateFlowWithExecutions(AuthenticationManagementResource authMgmt, PropertyGroup authenticationFlowPg,
										  AuthenticationFlowRepresentation authenticationFlow) throws Exception {
		PropertyGroup authenticationExecutionsPg = authenticationFlowPg.getPropertyGroup("authenticationExecutions");
		JsonObject jsonObject = authenticationFlowPg.getJsonValue("authenticationExecutions").asJsonObject();
		for (String entry : jsonObject.keySet()) {

			System.out.println("adding auth execution: " + entry);

			PropertyGroup entryProps = authenticationExecutionsPg.getPropertyGroup(entry);

			HashMap<String, Object> executionParams = new HashMap<String, Object>();

			String description = entryProps.getStringProperty("description");
			executionParams.put("description", description);

			Boolean isFlow = entryProps.getBooleanProperty("authenticatorFlow", false);
			if (isFlow) {
				executionParams.put("alias", entry);
				executionParams.put("type", "basic-flow");

				AuthenticationExecutionInfoRepresentation executionFlow = getOrCreateExecution(authMgmt,
						authenticationFlow.getAlias(), entry, isFlow, executionParams);

				// the above "alias" actually gets saved as the display name for some reason, but the alias is what we need to add subflow executions
				executionFlow.setAlias(entry);
				executionFlow.setRequirement(entryProps.getStringProperty("requirement"));
				authMgmt.updateExecutions(authenticationFlow.getAlias(), executionFlow);

				PropertyGroup childExecutions = entryProps.getPropertyGroup("authenticationExecutions");
				for (PropertyEntry childEntry : childExecutions.getProperties()) {
					// TODO: see if we can get the display name from the authenticator provider_id somehow, instead of requiring it in our config
					String displayName = childEntry.getName();
					PropertyGroup childEntryPg = childExecutions.getPropertyGroup(displayName);

					configExecution(childEntryPg, authMgmt, entry, displayName, authenticationFlow);
				}
			} else {
				configExecution(entryProps, authMgmt, authenticationFlow.getAlias(), entry, authenticationFlow);
			}
		}
	}

	void initializeRequiredActions(AuthenticationManagementResource authMgmt, PropertyGroup requiredActionsPg) throws Exception {
		System.out.println("initializing required actions");

		List<RequiredActionProviderRepresentation> existing = authMgmt.getRequiredActions();

		for (PropertyEntry actionPe : requiredActionsPg.getProperties()) {
			String alias = actionPe.getName();
			PropertyGroup actionPg = requiredActionsPg.getPropertyGroup(alias);

			RequiredActionProviderRepresentation match = null;
			for (RequiredActionProviderRepresentation ra : existing) {
				if (alias.equals(ra.getAlias())) {
					match = ra;
					break;
				}
			}

			if (match == null) {
				System.err.println("Required action not found: " + alias);
				continue;
			}

			Boolean enabled = actionPg.getBooleanProperty(KeycloakConfig.PROP_REQUIRED_ACTION_ENABLED);
			Boolean defaultAction = actionPg.getBooleanProperty(KeycloakConfig.PROP_REQUIRED_ACTION_DEFAULT);

			if (enabled != null) {
				match.setEnabled(enabled);
			}
			if (defaultAction != null) {
				match.setDefaultAction(defaultAction);
			}

			authMgmt.updateRequiredAction(alias, match);
		}
	}

	private void configExecution(PropertyGroup propGroup, AuthenticationManagementResource authMgmt, String entry,
								 String displayName, AuthenticationFlowRepresentation authenticationFlow) throws Exception {
		String authenticator = propGroup.getStringProperty("authenticator");

		Boolean childIsFlow = propGroup.getBooleanProperty("authenticatorFlow", false);
		if (childIsFlow) {
			System.out.println("Adding nested flow: " + displayName);

			HashMap<String, Object> executionParams = new HashMap<>();

			// String alias = propGroup.getStringProperty("alias");
			String parentFlowAlias = entry;
			String flowAlias = displayName;
			String type = propGroup.getStringProperty("providerId");
			// String provider = propGroup.getStringProperty("provider");
			String description = propGroup.getStringProperty("description");

			executionParams.put("alias", flowAlias);
			executionParams.put("type", type);
			// executionParams.put("provider", "xx");
			executionParams.put("description", description);

			authMgmt.addExecutionFlow(parentFlowAlias, executionParams);

			// there doesn't seem to be a way to query for this, but the last added item
			// should be the correct one
			AuthenticationExecutionInfoRepresentation lastAdded = null;
			for (AuthenticationExecutionInfoRepresentation flow : authMgmt.getExecutions(parentFlowAlias)) {
				lastAdded = flow;
			}

			// have to update the requirement separately, and also the flowAlias doesn't get
			// set for some reason
			lastAdded.setAlias(flowAlias);
			lastAdded.setRequirement(propGroup.getStringProperty("requirement"));
			authMgmt.updateExecutions(parentFlowAlias, lastAdded);

			// now fetch the nested flow so we can recursively add the executions to it
			authenticationFlow = authMgmt.getFlow(lastAdded.getFlowId());
			updateFlowWithExecutions(authMgmt, propGroup, authenticationFlow);
		} else {
			HashMap<String, Object> childExecutionParams = new HashMap<>();
			childExecutionParams.put("provider", authenticator);
			AuthenticationExecutionInfoRepresentation childExecution = getOrCreateExecution(authMgmt, entry, displayName,
					childIsFlow, childExecutionParams);

			String configAlias = propGroup.getStringProperty("configAlias");
			JsonValue configJson = propGroup.getJsonValue("config");
			if (configJson != null) {
				Map<String, String> config = buildConfigMap(configJson, configAlias);

				AuthenticatorConfigRepresentation authenticatorConfig = getOrCreateAuthenticatorConfig(authMgmt,
						childExecution, configAlias, config);
				authenticatorConfig.setConfig(config);
				authMgmt.updateAuthenticatorConfig(authenticatorConfig.getId(), authenticatorConfig);
				childExecution.setAuthenticationConfig(configAlias);
			}

			childExecution.setRequirement(propGroup.getStringProperty("requirement"));
			authMgmt.updateExecutions(authenticationFlow.getAlias(), childExecution);
		}
	}

	private AuthenticatorConfigRepresentation getOrCreateAuthenticatorConfig(AuthenticationManagementResource authMgmt,
																			 AuthenticationExecutionInfoRepresentation execution, String configAlias, Map<String, String> config) {

		AuthenticatorConfigRepresentation authenticatorConfig = null;

		String configId = execution.getAuthenticationConfig();
		if (configId != null) {
			authenticatorConfig = authMgmt.getAuthenticatorConfig(configId);
		} else {
			authenticatorConfig = new AuthenticatorConfigRepresentation();
			authenticatorConfig.setAlias(configAlias);
			Response response = authMgmt.newExecutionConfig(execution.getId(), authenticatorConfig);

			if (response.getStatusInfo().getFamily() == Response.Status.Family.SUCCESSFUL) {
				String path = response.getLocation().getPath();
				String id = path.substring(path.lastIndexOf("/") + 1);
				System.out.println("Created authenticator config with id '" + id + "'");
				authenticatorConfig.setId(id);
			} else {
				System.err.println("Failed to create authenticator config; status code '" + response.getStatus() + "'");
				System.err.println(response.readEntity(String.class));
			}
		}

		return authenticatorConfig;
	}

	private Map<String, String> buildConfigMap(JsonValue configJson, String configAlias) {
		Map<String, String> config = new HashMap<String, String>();
		Set<Entry<String,JsonValue>> entrySet = configJson.asJsonObject().entrySet();
		for (Entry<String, JsonValue> configEntry : entrySet) {
			JsonValue value = configEntry.getValue();
			if (value instanceof JsonString) {
				config.put(configEntry.getKey(), ((JsonString) value).getString());
			} else {
				System.err.println("Expected config of type String, but found " + value.getValueType());
			}
		}
		return config;
	}

	private AuthenticationExecutionInfoRepresentation getOrCreateExecution(AuthenticationManagementResource authMgmt,
																		   String flowAlias, String displayName, boolean isFlow, HashMap<String, Object> executionParams) {
		AuthenticationExecutionInfoRepresentation savedExecution = getExecutionByDisplayName(authMgmt, flowAlias, displayName);

		// System.out.println("savedExecution1: " + savedExecution);

		if (savedExecution == null) {
			if (isFlow) {
				authMgmt.addExecutionFlow(flowAlias, executionParams);
			} else {
				// System.out.println("calling addExecution for flowAlias: " + flowAlias);
				// for (Map.Entry<String, String> entry : executionParams.entrySet()) {
				// System.out.println("addExecution param: " + entry.getKey() + " : " +
				// entry.getValue());
				// }
				authMgmt.addExecution(flowAlias, executionParams);
			}
			savedExecution = getExecutionByDisplayName(authMgmt, flowAlias, displayName);
			// System.out.println("savedExecution2: " + savedExecution);
		}
		if (savedExecution == null) {
			throw new RuntimeException("Unable to create execution '" + displayName + "'");
		}
		return savedExecution;
	}

	/**
	 * Initializes the identity provider redirector.
	 * @param authMgmt the authorization management
	 * @param authenticationFlowAlias the authentication flow alias
	 * @param identityProviderRedirectorAlias the identity provider redirector alias
	 * @param identityProviderRedirectorPg the identity provider redirector property group
	 * @throws Exception an Exception
	 */
	void initializeIdentityProviderRedirector(AuthenticationManagementResource authMgmt, String authenticationFlowAlias, String identityProviderRedirectorAlias, PropertyGroup identityProviderRedirectorPg) throws Exception {
		System.out.println("initializing identity provider redirector: " + identityProviderRedirectorAlias);
		// Get identity provider redirector
		AuthenticationExecutionInfoRepresentation identityProviderRedirector = getIdentityProviderRedirector(authMgmt, authenticationFlowAlias);
		if (identityProviderRedirector == null) {
			throw new RuntimeException("Identity provider redirector does not exist");
		}

		// Update identity provider redirector
		identityProviderRedirector.setRequirement(identityProviderRedirectorPg.getStringProperty(KeycloakConfig.PROP_IDENTITY_PROVIDER_REDIRECTOR_REQUIREMENT));
		authMgmt.updateExecutions(authenticationFlowAlias, identityProviderRedirector);
		identityProviderRedirector = getIdentityProviderRedirector(authMgmt, authenticationFlowAlias);
		if (identityProviderRedirector == null) {
			throw new RuntimeException("Identity provider redirector does not exist");
		}

		// Create config representation if it does not exist
		AuthenticatorConfigRepresentation configRepresentation = identityProviderRedirector.getAuthenticationConfig() != null ? authMgmt.getAuthenticatorConfig(identityProviderRedirector.getAuthenticationConfig()) : null;
		if (configRepresentation == null) {
			configRepresentation = new AuthenticatorConfigRepresentation();
			configRepresentation.setAlias(identityProviderRedirectorAlias);
			PropertyGroup configPg = identityProviderRedirectorPg.getPropertyGroup(KeycloakConfig.PROP_IDENTITY_PROVIDER_MAPPER_CONFIG);
			if (configPg != null) {
				Map<String, String> config = configRepresentation.getConfig();
				if (config == null) {
					config = new HashMap<>();
				}
				for (PropertyEntry configPe: configPg.getProperties()) {
					String configKey = configPe.getName();
					config.put(configKey, configPe.getValue() != null ? configPe.getValue().toString() : null);
				}
				configRepresentation.setConfig(config);
			}
			authMgmt.newExecutionConfig(identityProviderRedirector.getId(), configRepresentation);
			identityProviderRedirector = getIdentityProviderRedirector(authMgmt, authenticationFlowAlias);
			if (identityProviderRedirector == null) {
				throw new RuntimeException("Identity provider redirector does not exist");
			}
			configRepresentation = identityProviderRedirector.getAuthenticationConfig() != null ? authMgmt.getAuthenticatorConfig(identityProviderRedirector.getAuthenticationConfig()) : null;
			if (configRepresentation == null) {
				throw new RuntimeException("Unable to create identity provider redirector");
			}
		}

		// Update config representation
		configRepresentation.setAlias(identityProviderRedirectorAlias);
		PropertyGroup configPg = identityProviderRedirectorPg.getPropertyGroup(KeycloakConfig.PROP_IDENTITY_PROVIDER_MAPPER_CONFIG);
		if (configPg != null) {
			Map<String, String> config = configRepresentation.getConfig();
			if (config == null) {
				config = new HashMap<>();
			}
			for (PropertyEntry configPe: configPg.getProperties()) {
				String configKey = configPe.getName();
				config.put(configKey, configPe.getValue() != null ? configPe.getValue().toString() : null);
			}
			configRepresentation.setConfig(config);
		}
		authMgmt.updateAuthenticatorConfig(configRepresentation.getId(), configRepresentation);
	}

	/**
	 * Initializes the group.
	 * @param groups the groups resource
	 * @param groupName the group name
	 * @param groupPg the group property group
	 * @throws Exception an Exception
	 */
	void initializeGroup(GroupsResource groups, String groupName, PropertyGroup groupPg) throws Exception {
		System.out.println("initializing group: " + groupName);
		// Create group if it does not exist
		GroupRepresentation group = getGroupByName(groups, groupName);
		if (group == null) {
			group = new GroupRepresentation();
			group.setName(groupName);
			groups.add(group);
			group = getGroupByName(groups, groupName);
			if (group == null) {
				throw new RuntimeException("Unable to create group");
			}
		}

		// Update group settings
		PropertyGroup attributesPg = groupPg.getPropertyGroup(KeycloakConfig.PROP_GROUP_ATTRIBUTES);
		if (attributesPg != null) {
			Map<String, List<String>> attributes = group.getAttributes();
			if (attributes == null) {
				attributes = new HashMap<>();
			}
			for (PropertyEntry attributePe: attributesPg.getProperties()) {
				String attributeKey = attributePe.getName();
				List<String> attributeValue = PropertyGroup.convertToStringList(attributePe.getValue());
				attributes.put(attributeKey, attributeValue);
			}
			group.setAttributes(attributes);
		}
		groups.group(group.getId()).update(group);
	}

	/**
	 * Initializes realm role
	 * @param roles the roles resource
	 * @param roleName the role name
	 * @param rolePg the role property group
	 * @throws Exception
	 */
	void initializeRealmRole(RolesResource roles, String roleName, PropertyGroup rolePg) throws Exception {
		System.out.println("initializing realm role: " + roleName);

		RoleRepresentation role;
		try {
			role = roles.get(roleName).toRepresentation();
		} catch (Exception e) {
			role = null;
		}

		if (role == null) {
			role = new RoleRepresentation();
			role.setName(roleName);
			role.setDescription(rolePg != null
					? rolePg.getStringProperty(KeycloakConfig.PROP_ROLE_DESCRIPTION)
					: null);
			roles.create(role);

			try {
				role = roles.get(roleName).toRepresentation();
			} catch (Exception e) {
				role = null;
			}

			if (role == null) {
				throw new RuntimeException("Unable to create realm role: " + roleName);
			}
		}

		// Update role settings
		if (rolePg != null) {
			role.setDescription(rolePg.getStringProperty(KeycloakConfig.PROP_ROLE_DESCRIPTION));
			roles.get(roleName).update(role);
		}
	}

	/**
	 * Initializes a client role.
	 * @param roles the client roles resource
	 * @param roleName the role name
	 * @param rolePg the role property group
	 * @throws Exception
	 */
	void initializeClientRole(RolesResource roles, String roleName, PropertyGroup rolePg) throws Exception {
		System.out.println("initializing client role: " + roleName);

		RoleRepresentation role;
		try {
			role = roles.get(roleName).toRepresentation();
		} catch (Exception e) {
			role = null;
		}

		if (role == null) {
			role = new RoleRepresentation();
			role.setName(roleName);
			role.setDescription(rolePg != null
					? rolePg.getStringProperty(KeycloakConfig.PROP_ROLE_DESCRIPTION)
					: null);
			roles.create(role);

			try {
				role = roles.get(roleName).toRepresentation();
			} catch (Exception e) {
				role = null;
			}

			if (role == null) {
				throw new RuntimeException("Unable to create client role: " + roleName);
			}
		}

		// Update role settings
		if (rolePg != null) {
			role.setDescription(rolePg.getStringProperty(KeycloakConfig.PROP_ROLE_DESCRIPTION));
			roles.get(roleName).update(role);
		}
	}

	/**
	 * Initializes the user.
	 * @param clients the clients resource
	 * @param users the users resource
	 * @param groups the groups resource
	 * @param roles the roles resource
	 * @param userName the configured user name
	 * @param userPg the user property group
	 * @throws Exception an Exception
	 */
	void initializeUser(ClientsResource clients, UsersResource users, GroupsResource groups, RolesResource roles,
			String userName, PropertyGroup userPg) throws Exception {
		System.out.println("initializing user: " + userName);
		String serviceAccountClientId = userPg.getStringProperty(KeycloakConfig.PROP_USER_SERVICE_ACCOUNT_CLIENT_ID);
		boolean serviceAccount = serviceAccountClientId != null && !serviceAccountClientId.trim().isEmpty();

		UserRepresentation user;
		if (serviceAccount) {
			ClientRepresentation client = getClientByClientId(clients, serviceAccountClientId);
			if (client == null) {
				throw new IllegalArgumentException("Unable to initialize service account user '" + userName
						+ "': client '" + serviceAccountClientId + "' does not exist");
			}
			if (!Boolean.TRUE.equals(client.isServiceAccountsEnabled())) {
				throw new IllegalArgumentException("Unable to initialize service account user '" + userName
						+ "': service accounts are not enabled for client '" + serviceAccountClientId + "'");
			}

			user = clients.get(client.getId()).getServiceAccountUser();
			if (user == null || user.getId() == null) {
				throw new RuntimeException("Unable to resolve service account user for client '"
						+ serviceAccountClientId + "'");
			}
		}
		else {
			// Create user if it does not exist
			user = getUserByName(users, userName);
			if (user == null) {
				user = new UserRepresentation();
				user.setUsername(userName);
				users.create(user);
				user = getUserByName(users, userName);
				if (user == null) {
					throw new RuntimeException("Unable to create user");
				}
			}
		}

		// Update user data
		String email = userPg.getStringProperty(KeycloakConfig.PROP_USER_EMAIL);
		if (email != null) {
			user.setEmail(email);
		}
		Boolean emailVerified = userPg.getBooleanProperty(KeycloakConfig.PROP_USER_EMAIL_VERIFIED);
		if (emailVerified != null) {
			user.setEmailVerified(emailVerified.booleanValue());
		}
		String firstName = userPg.getStringProperty(KeycloakConfig.PROP_USER_FIRST_NAME);
		if (firstName != null) {
			user.setFirstName(firstName);
		}
		String lastName = userPg.getStringProperty(KeycloakConfig.PROP_USER_LAST_NAME);
		if (lastName != null) {
			user.setLastName(lastName);
		}

		// Update user settings
		user.setEnabled(userPg.getBooleanProperty(KeycloakConfig.PROP_USER_ENABLED));
		PropertyGroup attributesPg = userPg.getPropertyGroup(KeycloakConfig.PROP_USER_ATTRIBUTES);
		if (attributesPg != null) {
			Map<String, List<String>> attributes = user.getAttributes();
			if (attributes == null) {
				attributes = new HashMap<>();
			}
			for (PropertyEntry attributePe: attributesPg.getProperties()) {
				String attributeKey = attributePe.getName();
				List<String> attributeValue = PropertyGroup.convertToStringList(attributePe.getValue());
				attributes.put(attributeKey, attributeValue);
			}
			user.setAttributes(attributes);
		}
		// Service-account users are managed by Keycloak and authenticate through their client,
		// so they must not be assigned a user password from this configuration.
		if (!serviceAccount) {
			CredentialRepresentation credential = new CredentialRepresentation();
			credential.setType(KeycloakConfig.KEYCLOAK_USER_PASSWORD_TYPE);
			credential.setTemporary(userPg.getBooleanProperty(KeycloakConfig.PROP_USER_PASSWORD_TEMPORARY));
			credential.setValue(userPg.getStringProperty(KeycloakConfig.PROP_USER_PASSWORD));
			user.setCredentials(Arrays.asList(credential));
		}
		users.get(user.getId()).update(user);

		// Update user group memberships
		List<String> groupIds = getGroupIds(groups, userPg.getStringListProperty(KeycloakConfig.PROP_USER_GROUPS));
		if (groupIds != null) {
			List<String> existingGroupIds = getGroupIds(groups, user.getGroups());
			for (String existingGroupId : existingGroupIds) {
				if (!groupIds.contains(existingGroupId)) {
					users.get(user.getId()).leaveGroup(existingGroupId);
				}
				else {
					groupIds.remove(existingGroupId);
				}
			}
			for (String groupId : groupIds) {
				users.get(user.getId()).joinGroup(groupId);
			}
		}

		// Update user realm role mappings
		List<String> desiredRealmRoleNames = userPg.getStringListProperty(KeycloakConfig.PROP_USER_REALM_ROLES);
		if (desiredRealmRoleNames != null) {
			List<RoleRepresentation> desiredRealmRoles = getRealmRolesByName(roles, desiredRealmRoleNames);
			RoleScopeResource userRealmRoleScope = users.get(user.getId()).roles().realmLevel();
			syncRoleMappings(userRealmRoleScope, desiredRealmRoles);
		}

		// Update user client role mappings. The property is a map from client ID to role names.
		PropertyGroup userClientRolesPg = userPg.getPropertyGroup(KeycloakConfig.PROP_USER_CLIENT_ROLES);
		if (userClientRolesPg != null) {
			for (PropertyEntry clientRolePe : userClientRolesPg.getProperties()) {
				String clientId = clientRolePe.getName();
				List<String> desiredRoleNames = PropertyGroup.convertToStringList(clientRolePe.getValue());
				ClientRepresentation client = getClientByClientId(clients, clientId);
				if (client == null) {
					throw new IllegalArgumentException("Unable to assign client roles for user '" + userName
							+ "': client '" + clientId + "' does not exist");
				}

				List<RoleRepresentation> desiredClientRoles =
						getClientRolesByName(clients.get(client.getId()).roles(), desiredRoleNames);
				RoleScopeResource userClientRoleScope = users.get(user.getId()).roles().clientLevel(client.getId());
				syncRoleMappings(userClientRoleScope, desiredClientRoles);
			}
		}

	}

	private void syncRoleMappings(RoleScopeResource roleScope, List<RoleRepresentation> desiredRoles) {
		List<RoleRepresentation> existingRoles = roleScope.listAll();

		Map<String, RoleRepresentation> desiredByName = desiredRoles.stream()
				.collect(Collectors.toMap(RoleRepresentation::getName, r -> r, (a, b) -> a));
		Map<String, RoleRepresentation> existingByName = existingRoles.stream()
				.collect(Collectors.toMap(RoleRepresentation::getName, r -> r, (a, b) -> a));

		List<RoleRepresentation> toRemove = new ArrayList<>();
		for (RoleRepresentation existing : existingRoles) {
			if (!desiredByName.containsKey(existing.getName())) {
				toRemove.add(existing);
			}
		}

		List<RoleRepresentation> toAdd = new ArrayList<>();
		for (RoleRepresentation desired : desiredRoles) {
			if (!existingByName.containsKey(desired.getName())) {
				toAdd.add(desired);
			}
		}

		if (!toRemove.isEmpty()) {
			roleScope.remove(toRemove);
		}
		if (!toAdd.isEmpty()) {
			roleScope.add(toAdd);
		}
	}

	/**
	 * Gets the realm by name.
	 * @param realmsResource the realms resource
	 * @param realmName the realm name
	 * @return the realm, or null if not found
	 */
	private RealmRepresentation getRealmByName(RealmsResource realmsResource, String realmName) {
		for (RealmRepresentation realm : realmsResource.findAll()) {
			if (realmName.equals(realm.getRealm())) {
				return realm;
			}
		}
		return null;
	}

	/**
	 * Gets the client scope by name.
	 * @param clientScopes the client scopes
	 * @param clientScopeName the client scope name
	 * @return the client scope, or null if not found
	 */
	private ClientScopeRepresentation getClientScopeByName(ClientScopesResource clientScopes, String clientScopeName) {
		for (ClientScopeRepresentation clientScope : clientScopes.findAll()) {
			if (clientScopeName.equals(clientScope.getName())) {
				return clientScope;
			}
		}
		return null;
	}

	/**
	 * Gets the client scope IDs by name.
	 * @param clientScopes the client scopes
	 * @param clientScopeNames the client scope names
	 * @return the client scope IDs
	 */
	private List<String> getClientScopeIds(ClientScopesResource clientScopes, List<String> clientScopeNames) {
		List<String> clientScopeIds = new ArrayList<>();
		Map<String, String> nameToIdMap = clientScopes.findAll().stream().collect(Collectors.toMap(c -> c.getName(), c -> c.getId()));

		for (String clientScopeName : clientScopeNames) {
			if (nameToIdMap.containsKey(clientScopeName)) {
				clientScopeIds.add(nameToIdMap.get(clientScopeName));
			} else {
				System.err.println("Skipping client scope '" + clientScopeName + "'; unable to find id for client scope with this name");
			}
		}
		return clientScopeIds;
	}

	/**
	 * Gets the client by client ID.
	 * @param adminClient the clients
	 * @param clientName the client name
	 * @return the client, or null if not found
	 */
	private ClientRepresentation getClientByClientId(ClientsResource clients, String clientId) {
		for (ClientRepresentation client : clients.findAll()) {
			if (clientId.equals(client.getClientId())) {
				return client;
			}
		}
		return null;
	}

	/**
	 *
	 * @param clientScopes
	 * @param roles
	 * @param clientScopesPg
	 * @throws Exception
	 */
	void syncClientScopeRoleMappings(ClientScopesResource clientScopes,
									 RolesResource roles,
									 PropertyGroup clientScopesPg) throws Exception {
		for (PropertyEntry clientScopePe : clientScopesPg.getProperties()) {
			String clientScopeName = clientScopePe.getName();
			PropertyGroup clientScopePg = clientScopesPg.getPropertyGroup(clientScopeName);

			List<String> desiredRoleNames = clientScopePg.getStringListProperty(KeycloakConfig.PROP_REALM_ROLES);
			if (desiredRoleNames == null) {
				continue;
			}

			ClientScopeRepresentation clientScope = getClientScopeByName(clientScopes, clientScopeName);
			if (clientScope == null) {
				throw new RuntimeException("Client scope not found: " + clientScopeName);
			}

			RoleScopeResource realmLevelScope =
					clientScopes.get(clientScope.getId()).getScopeMappings().realmLevel();

			List<RoleRepresentation> desiredRoles = getRealmRolesByName(roles, desiredRoleNames);

			syncRoleMappings(realmLevelScope, desiredRoles);
		}
	}

	/**
	 * Syncs client realm-role scope mappings and applies the optional full-scope setting.
	 * Scope mappings are reconciled first so a client does not briefly have full scope
	 * disabled without its configured realm roles.
	 *
	 * @param clients the clients resource
	 * @param roles the realm roles resource
	 * @param clientsPg the clients property group
	 * @throws Exception an Exception
	 */
	void syncClientRealmRoleMappings(ClientsResource clients, RolesResource roles,
									PropertyGroup clientsPg) throws Exception {
		for (PropertyEntry clientPe : clientsPg.getProperties()) {
			String clientId = clientPe.getName();
			PropertyGroup clientPg = clientsPg.getPropertyGroup(clientId);
			ClientRepresentation client = getClientByClientId(clients, clientId);
			if (client == null) {
				throw new IllegalArgumentException("Unable to configure client scope mappings for client '"
						+ clientId + "': client does not exist");
			}

			ClientResource clientResource = clients.get(client.getId());
			PropertyGroup scopeMappingsPg = clientPg.getPropertyGroup(KeycloakConfig.PROP_CLIENT_SCOPE_MAPPINGS);
			if (scopeMappingsPg != null) {
				List<String> desiredRoleNames =
						scopeMappingsPg.getStringListProperty(KeycloakConfig.PROP_REALM_ROLES);
				if (desiredRoleNames != null) {
					RoleScopeResource realmLevelScope = clientResource.getScopeMappings().realmLevel();
					List<RoleRepresentation> desiredRoles = getRealmRolesByName(roles, desiredRoleNames);
					syncRoleMappings(realmLevelScope, desiredRoles);
				}
			}

			Boolean fullScopeAllowed =
					clientPg.getBooleanProperty(KeycloakConfig.PROP_CLIENT_FULL_SCOPE_ALLOWED);
			if (fullScopeAllowed != null) {
				client.setFullScopeAllowed(fullScopeAllowed);
				clientResource.update(client);
			}
		}
	}

	/**
	 * Gets the protocol mapper by name.
	 * @param protocolMappers the protocol mappers
	 * @param mapperName the mapper name
	 * @return the protocol mapper, or null if not found
	 */
	private ProtocolMapperRepresentation getProtocolMapperByName(ProtocolMappersResource protocolMappers, String mapperName) {
		for (ProtocolMapperRepresentation protocolMapper : protocolMappers.getMappers()) {
			if (mapperName.equals(protocolMapper.getName())) {
				return protocolMapper;
			}
		}
		return null;
	}

	/**
	 * Gets the identity provider by provider alias.
	 * @param identityProviders the identity providers
	 * @param identityProviderAlias the identity provider alias
	 * @return the identity provider, or null if not found
	 */
	private IdentityProviderRepresentation getIdentityProviderByAlias(IdentityProvidersResource identityProviders, String identityProviderAlias) {
		for (IdentityProviderRepresentation identityProvider : identityProviders.findAll()) {
			if (identityProviderAlias.equals(identityProvider.getAlias())) {
				return identityProvider;
			}
		}
		return null;
	}

	/**
	 * Gets the identity provider mapper by name.
	 * @param identity provider the identity provider
	 * @param mapperName the mapper name
	 * @return the identity provider mapper, or null if not found
	 */
	private IdentityProviderMapperRepresentation getIdentityProvideMapperByName(IdentityProviderResource identityProvider, String mapperName) {
		for (IdentityProviderMapperRepresentation identityProviderMapper : identityProvider.getMappers()) {
			if (mapperName.equals(identityProviderMapper.getName())) {
				return identityProviderMapper;
			}
		}
		return null;
	}


	/**
	 * Gets the authentication flow by alias.
	 * @param authMgmt the authorization management
	 * @param authenticationFlowAlias the authentication flow alias
	 * @return the authorization flow, or null if not found
	 */
	private AuthenticationFlowRepresentation getAuthenticationFlowByAlias(AuthenticationManagementResource authMgmt, String authenticationFlowAlias) {
		for (AuthenticationFlowRepresentation flow : authMgmt.getFlows()) {
			if (authenticationFlowAlias.equals(flow.getAlias())) {
				return flow;
			}
		}
		return null;
	}

	/**
	 * Gets the authentication execution by alias.
	 * @param authMgmt the authorization management
	 * @param authenticationFlowAlias the authentication flow alias
	 * @return the execution info, or null if not found
	 */
	private AuthenticationExecutionInfoRepresentation getExecutionByDisplayName(AuthenticationManagementResource authMgmt, String authenticationFlowAlias,
																				String executionDisplayName) {
		for (AuthenticationExecutionInfoRepresentation execution : authMgmt.getExecutions(authenticationFlowAlias)) {
			if (executionDisplayName.equals(execution.getDisplayName())) {
				return execution;
			}
		}
		return null;
	}

	/**
	 * Gets the identity provider redirector by alias.
	 * @param authMgmt the authorization management
	 * @param authenticationFlowAlias the authentication flow alias
	 * @return the authorization flow, or null if not found
	 */
	private AuthenticationExecutionInfoRepresentation getIdentityProviderRedirector(AuthenticationManagementResource authMgmt, String authenticationFlowAlias) {
		for (AuthenticationExecutionInfoRepresentation execution : authMgmt.getExecutions(authenticationFlowAlias)) {
			if (KeycloakConfig.KEYCLOAK_IDENTITY_PROVIDER_REDIRECTOR.equals(execution.getProviderId())) {
				return execution;
			}
		}
		return null;
	}


	/**
	 * Gets the group by name.
	 * @param groups the groups
	 * @param groupName the group name
	 * @return the group, or null if not found
	 */
	private GroupRepresentation getGroupByName(GroupsResource groups, String groupName) {
		for (GroupRepresentation group : groups.groups()) {
			if (groupName.equals(group.getName())) {
				return group;
			}
		}
		return null;
	}

	/**
	 * Gets the group IDs by name.
	 * @param groups the groups
	 * @param groupNames the group names
	 * @return the group IDs
	 */
	private List<String> getGroupIds(GroupsResource groups, List<String> groupNames) {
		List<String> groupIds = new ArrayList<>();
		for (GroupRepresentation group : groups.groups()) {
			if (groupNames != null && groupNames.contains(group.getName())) {
				groupIds.add(group.getId());
			}
		}
		return groupIds;
	}

	/**
	 * Gets the realm role by name.
	 * @param roles the roles
	 * @param roleNames the role names
	 * @return the roles
	 */
	private List<RoleRepresentation> getRealmRolesByName(RolesResource roles, List<String> roleNames) {
		List<RoleRepresentation> result = new ArrayList<>();
		if (roleNames == null) {
			return result;
		}
		for (String roleName : roleNames) {
			try {
				RoleRepresentation role = roles.get(roleName).toRepresentation();
				if (role != null) {
					result.add(role);
				}
			} catch (Exception e) {
				System.err.println("Skipping realm role '" + roleName + "'; role not found");
			}
		}
		return result;
	}

	/**
	 * Gets client roles by name.
	 * @param roles the client roles
	 * @param roleNames the role names
	 * @return the roles
	 */
	private List<RoleRepresentation> getClientRolesByName(RolesResource roles, List<String> roleNames) {
		List<RoleRepresentation> result = new ArrayList<>();
		if (roleNames == null) {
			return result;
		}

		for (String roleName : roleNames) {
			try {
				RoleRepresentation role = roles.get(roleName).toRepresentation();
				if (role != null) {
					result.add(role);
				}
			} catch (Exception e) {
				System.err.println("Skipping client role '" + roleName + "'; role not found");
			}
		}
		return result;
	}

	/**
	 * Gets the user by name.
	 * @param users the users
	 * @param userName the user name
	 * @return the user, or null if not found
	 */
	private UserRepresentation getUserByName(UsersResource users, String userName) {
		for (UserRepresentation user : users.list()) {
			if (userName.equals(user.getUsername())) {
				return user;
			}
		}
		return null;
	}
}
