/*
 * (C) Copyright IBM Corp. 2026
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.alvearie.keycloak.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;

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
}
