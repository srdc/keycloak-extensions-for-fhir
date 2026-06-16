package org.alvearie.keycloak;

import org.keycloak.models.*;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class TenantClaimsMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    public static final String PROVIDER_ID = "oidc-tenant-claims-mapper";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(CONFIG_PROPERTIES, TenantClaimsMapper.class);

        ProviderConfigProperty tenantRoot = new ProviderConfigProperty();
        tenantRoot.setName("tenantRootPath");
        tenantRoot.setLabel("Tenant Root Path");
        tenantRoot.setType(ProviderConfigProperty.STRING_TYPE);
        tenantRoot.setDefaultValue("/tenants");
        tenantRoot.setHelpText("Only groups under this path are considered tenant groups.");
        CONFIG_PROPERTIES.add(tenantRoot);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Tenant Claims Mapper";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Adds tenant_id and tenant from the user's tenant group attributes.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    protected void setClaim(
            IDToken token,
            ProtocolMapperModel mappingModel,
            UserSessionModel userSession,
            KeycloakSession keycloakSession,
            ClientSessionContext clientSessionContext
    ) {
        String tenantRootPath = mappingModel.getConfig().getOrDefault("tenantRootPath", "/tenants");

        GroupModel tenantGroup = findTenantGroup(userSession, tenantRootPath);
        if (tenantGroup == null) {
            return;
        }

        String tenantId = tenantGroup.getFirstAttribute("tenant_id");
        String tenantSlug = tenantGroup.getFirstAttribute("slug");

        if (tenantId != null && !tenantId.isBlank()) {
            token.getOtherClaims().put("tenant_id", tenantId);
        }

        if (tenantSlug != null && !tenantSlug.isBlank()) {
            token.getOtherClaims().put("tenant", tenantSlug);
        }
    }

    private GroupModel findTenantGroup(UserSessionModel userSession, String tenantRootName) {

        List<GroupModel> tenantGroups = userSession.getUser()
                .getGroupsStream()
                .filter(group -> isUnderTenantRoot(group, tenantRootName))
                .toList();

        if (tenantGroups.size() != 1) {
            return null;
        }

        return tenantGroups.get(0);
    }

    private boolean isUnderTenantRoot(GroupModel group, String tenantRootName) {
        GroupModel current = group;

        while (current != null) {
            if (tenantRootName.equals("/" + current.getName())) {
                return true;
            }
            current = current.getParent();
        }

        return false;
    }

    public static ProtocolMapperModel create(
            String name,
            boolean accessToken,
            boolean idToken,
            boolean userInfo
    ) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol("openid-connect");

        Map<String, String> config = mapper.getConfig();
        config.put("tenantRootPath", "/tenants/");
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, String.valueOf(accessToken));
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, String.valueOf(idToken));
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, String.valueOf(userInfo));

        return mapper;
    }
}
