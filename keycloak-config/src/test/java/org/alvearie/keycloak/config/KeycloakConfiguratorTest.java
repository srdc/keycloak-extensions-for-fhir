/*
 * (C) Copyright IBM Corp. 2026
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.alvearie.keycloak.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Collections;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.RoleMappingResource;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.admin.client.resource.RoleScopeResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.alvearie.keycloak.config.util.PropertyGroup;

public class KeycloakConfiguratorTest {

	@Test
	public void testParseCdsEndpointsReturnsEmptyListForMissingValue() {
		assertEquals(Collections.emptyList(), KeycloakConfigurator.parseCdsEndpoints(null));
		assertEquals(Collections.emptyList(), KeycloakConfigurator.parseCdsEndpoints("  "));
	}

	@Test
	public void testParseCdsEndpointsTrimsAndDeduplicatesEndpoints() {
		List<String> endpoints = KeycloakConfigurator.parseCdsEndpoints(
				" https://cds.example/a ,https://cds.example/b,, https://cds.example/a ");

		assertEquals(2, endpoints.size());
		assertEquals("https://cds.example/a", endpoints.get(0));
		assertEquals("https://cds.example/b", endpoints.get(1));
	}

	@Test
	public void testParseCdsEndpointsIgnoresUnresolvedPlaceholder() {
		assertEquals(Collections.emptyList(), KeycloakConfigurator.parseCdsEndpoints("${CDS_ENDPOINTS}"));
		assertEquals(Collections.emptyList(), KeycloakConfigurator.parseCdsEndpoints("${CDS_ENDPOINTS:-}"));
	}

	@Test
	public void testCdsEndpointAudienceMapperNameIsStable() {
		String mapperName = KeycloakConfigurator.getCdsEndpointAudienceMapperName(
				"http://repofyr:8000/cds/cds-services/smart2");

		assertEquals(mapperName, KeycloakConfigurator.getCdsEndpointAudienceMapperName(
				"http://repofyr:8000/cds/cds-services/smart2"));
		assertEquals("CDS Endpoint Audience Mapper - /smart2", mapperName);
		assertTrue(mapperName.startsWith(KeycloakConfigurator.CDS_ENDPOINT_AUDIENCE_MAPPER_PREFIX));
	}

	@Test
	public void testCdsEndpointMapperSuffixFallsBackToRawEndpoint() {
		assertEquals("not a url", KeycloakConfigurator.getCdsEndpointMapperSuffix("not a url"));
	}

	@Test
	public void testClientScopeMappingsAreSyncedBeforeFullScopeAllowed() throws Exception {
		ClientsResource clients = mock(ClientsResource.class);
		ClientResource clientResource = mock(ClientResource.class);
		RoleMappingResource scopeMappings = mock(RoleMappingResource.class);
		RoleScopeResource realmLevelScope = mock(RoleScopeResource.class);
		RolesResource roles = mock(RolesResource.class);
		RoleResource patientRoleResource = mock(RoleResource.class);

		ClientRepresentation client = new ClientRepresentation();
		client.setId("client-id");
		client.setClientId("esc-mobile");
		RoleRepresentation existingRole = new RoleRepresentation();
		existingRole.setName("out-of-band");
		RoleRepresentation patientRole = new RoleRepresentation();
		patientRole.setName("patient");

		when(clients.findAll()).thenReturn(List.of(client));
		when(clients.get("client-id")).thenReturn(clientResource);
		when(clientResource.getScopeMappings()).thenReturn(scopeMappings);
		when(scopeMappings.realmLevel()).thenReturn(realmLevelScope);
		when(realmLevelScope.listAll()).thenReturn(List.of(existingRole));
		when(roles.get("patient")).thenReturn(patientRoleResource);
		when(patientRoleResource.toRepresentation()).thenReturn(patientRole);

		JsonObject clientsJson = Json.createObjectBuilder()
				.add("esc-mobile", Json.createObjectBuilder()
						.add("fullScopeAllowed", false)
						.add("scopeMappings", Json.createObjectBuilder()
								.add("realmRoles", Json.createArrayBuilder().add("patient"))))
				.build();
		PropertyGroup clientsPg = new PropertyGroup(clientsJson);

		new KeycloakConfigurator(null).syncClientRealmRoleMappings(clients, roles, clientsPg);

		InOrder order = inOrder(realmLevelScope, clientResource);
		order.verify(realmLevelScope).remove(List.of(existingRole));
		order.verify(realmLevelScope).add(List.of(patientRole));
		order.verify(clientResource).update(client);
		assertFalse(client.isFullScopeAllowed());
	}

	@Test
	public void testClientFullScopeAllowedIsNotWrittenWhenUnset() throws Exception {
		ClientsResource clients = mock(ClientsResource.class);
		ClientResource clientResource = mock(ClientResource.class);
		ClientRepresentation client = new ClientRepresentation();
		client.setId("client-id");
		client.setClientId("esc-mobile");

		when(clients.findAll()).thenReturn(List.of(client));
		when(clients.get("client-id")).thenReturn(clientResource);

		JsonObject clientsJson = Json.createObjectBuilder()
				.add("esc-mobile", Json.createObjectBuilder())
				.build();

		new KeycloakConfigurator(null).syncClientRealmRoleMappings(
				clients, mock(RolesResource.class), new PropertyGroup(clientsJson));

		verify(clientResource, never()).update(client);
	}
}
