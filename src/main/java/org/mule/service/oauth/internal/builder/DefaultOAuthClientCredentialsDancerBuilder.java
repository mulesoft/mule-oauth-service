/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.service.oauth.internal.builder;

import static java.util.Objects.requireNonNull;
import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.mule.runtime.api.util.Preconditions.checkArgument;

import org.mule.runtime.api.el.MuleExpressionLanguage;
import org.mule.runtime.api.lock.LockFactory;
import org.mule.runtime.api.scheduler.SchedulerService;
import org.mule.runtime.api.tls.TlsContextFactory;
import org.mule.runtime.api.util.MultiMap;
import org.mule.runtime.api.util.Pair;
import org.mule.runtime.http.api.client.HttpClient;
import org.mule.runtime.http.api.client.proxy.ProxyConfig;
import org.mule.runtime.oauth.api.ClientCredentialsOAuthDancer;
import org.mule.runtime.oauth.api.listener.ClientCredentialsListener;
import org.mule.runtime.oauth.api.builder.OAuthClientCredentialsDancerBuilder;
import org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext;
import org.mule.service.oauth.internal.DefaultClientCredentialsOAuthDancer;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.github.benmanes.caffeine.cache.LoadingCache;


public class DefaultOAuthClientCredentialsDancerBuilder extends AbstractOAuthDancerBuilder<ClientCredentialsOAuthDancer>
    implements OAuthClientCredentialsDancerBuilder {

  private final List<ClientCredentialsListener> listeners = new LinkedList<>();
  private final MultiMap<String, String> customParameters = new MultiMap<>();
  private final MultiMap<String, String> customHeaders = new MultiMap<>();
  private String audience;


  public DefaultOAuthClientCredentialsDancerBuilder(SchedulerService schedulerService, LockFactory lockProvider,
                                                    Map<String, ResourceOwnerOAuthContext> tokensStore,
                                                    LoadingCache<Pair<TlsContextFactory, ProxyConfig>, HttpClient> httpClientCache,
                                                    MuleExpressionLanguage expressionEvaluator) {
    super(schedulerService, lockProvider, tokensStore, httpClientCache, expressionEvaluator);
  }

  @Override
  public OAuthClientCredentialsDancerBuilder encodeClientCredentialsInBody(boolean encodeClientCredentialsInBody) {
    return (OAuthClientCredentialsDancerBuilder) super.encodeClientCredentialsInBody(encodeClientCredentialsInBody);
  }

  @Override
  public OAuthClientCredentialsDancerBuilder customParameters(Map<String, String> customParameters) {
    requireNonNull(customParameters, "customParameters cannot be null");
    putAll(customParameters, this.customParameters);

    return this;
  }

  private void putAll(Map<String, String> source, MultiMap<String, String> target) {
    if (source instanceof MultiMap) {
      target.putAll((MultiMap<String, String>) source);
    } else {
      target.putAll(source);
    }
  }

  @Override
  public OAuthClientCredentialsDancerBuilder customHeaders(Map<String, String> customHeaders) {
    requireNonNull(customHeaders, "customHeaders cannot be null");
    putAll(customHeaders, this.customHeaders);

    return this;
  }

  @Override
  public OAuthClientCredentialsDancerBuilder audience(String audience) {
    this.audience = audience;
    return this;
  }

  @Override
  public OAuthClientCredentialsDancerBuilder addListener(ClientCredentialsListener listener) {
    requireNonNull(listener, "Cannot add a null listener");
    listeners.add(listener);

    return this;
  }

  @Override
  public ClientCredentialsOAuthDancer build() {
    checkArgument(isNotBlank(clientId), "clientId cannot be blank");
    checkArgument(isNotBlank(clientSecret), "clientSecret cannot be blank");
    checkArgument(isNotBlank(tokenUrl), "tokenUrl cannot be blank");

    return new DefaultClientCredentialsOAuthDancer(name, clientId, clientSecret, tokenUrl, scopes, clientCredentialsLocation,
                                                   encoding, responseAccessTokenExpr, responseRefreshTokenExpr,
                                                   responseExpiresInExpr, customParametersExtractorsExprs,
                                                   resourceOwnerIdTransformer, schedulerService, lockProvider, tokensStore,
                                                   httpClientFactory.get(), expressionEvaluator, customParameters,
                                                   customHeaders, listeners, audience);
  }

}
