/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.trino.plugin.base.security;

import com.google.common.collect.ImmutableList;
import io.trino.spi.security.SystemAccessControl;

import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import static io.trino.plugin.base.security.CatalogAccessControlRule.AccessMode.ALL;
import static java.util.Objects.requireNonNull;

public class SystemAccessControlFactory
{
    private final SystemAccessControlRules rules;

    public SystemAccessControlFactory(final SystemAccessControlRules rules)
    {
        this.rules = requireNonNull(rules);
    }

    public SystemAccessControl create()
    {
        List<CatalogAccessControlRule> catalogAccessControlRules;
        if (rules.getCatalogRules().isPresent()) {
            ImmutableList.Builder<CatalogAccessControlRule> catalogRulesBuilder = ImmutableList.builder();
            catalogRulesBuilder.addAll(rules.getCatalogRules().get());

            // Hack to allow Trino Admin to access the "system" catalog for retrieving server status.
            // todo Change userRegex from ".*" to one particular user that Trino Admin will be restricted to run as
            catalogRulesBuilder.add(new CatalogAccessControlRule(
                    ALL,
                    Optional.of(Pattern.compile(".*")),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.of(Pattern.compile("system"))));
            catalogAccessControlRules = catalogRulesBuilder.build();
        }
        else {
            // if no rules are defined then all access is allowed
            catalogAccessControlRules = ImmutableList.of(CatalogAccessControlRule.ALLOW_ALL);
        }
        return RuleBasedSystemAccessControl.builder()
                .setCatalogRules(catalogAccessControlRules)
                .setQueryAccessRules(rules.getQueryAccessRules())
                .setImpersonationRules(rules.getImpersonationRules())
                .setPrincipalUserMatchRules(rules.getPrincipalUserMatchRules())
                .setSystemInformationRules(rules.getSystemInformationRules())
                .setSchemaRules(rules.getSchemaRules().orElse(ImmutableList.of(CatalogSchemaAccessControlRule.ALLOW_ALL)))
                .setTableRules(rules.getTableRules().orElse(ImmutableList.of(CatalogTableAccessControlRule.ALLOW_ALL)))
                .setSessionPropertyRules(rules.getSessionPropertyRules().orElse(ImmutableList.of(SessionPropertyAccessControlRule.ALLOW_ALL)))
                .setCatalogSessionPropertyRules(rules.getCatalogSessionPropertyRules().orElse(ImmutableList.of(CatalogSessionPropertyAccessControlRule.ALLOW_ALL)))
                .setFunctionRules(rules.getFunctionRules().orElse(ImmutableList.of(CatalogFunctionAccessControlRule.ALLOW_ALL)))
                .build();
    }
}
