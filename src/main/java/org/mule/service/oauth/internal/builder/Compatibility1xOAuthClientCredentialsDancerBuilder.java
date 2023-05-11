/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.service.oauth.internal.builder;

import org.mule.oauth.client.api.builder.ClientCredentialsLocation;
import org.mule.oauth.client.api.http.HttpClientFactory;
import org.mule.oauth.client.api.listener.ClientCredentialsListener;
import org.mule.oauth.client.api.state.ResourceOwnerOAuthContext;
import org.mule.oauth.client.internal.builder.DefaultOAuthClientCredentialsDancerBuilder;
import org.mule.runtime.api.el.MuleExpressionLanguage;
import org.mule.runtime.api.lock.LockFactory;
import org.mule.runtime.api.scheduler.SchedulerService;
import org.mule.runtime.api.tls.TlsContextFactory;
import org.mule.runtime.http.api.client.HttpClient;
import org.mule.runtime.http.api.client.proxy.ProxyConfig;
import org.mule.runtime.oauth.api.builder.OAuthClientCredentialsDancerBuilder;
import org.mule.service.oauth.internal.dancer.Compatibility1xClientCredentialsOAuthDancer;

import java.nio.charset.Charset;
import java.util.Map;
import java.util.function.Function;

/**
 * Provides compatibility with version 1.x of the mule-oauth-client, which was a transitive api of the service api.
 * 
 * @since 2.3
 */
public class Compatibility1xOAuthClientCredentialsDancerBuilder extends DefaultOAuthClientCredentialsDancerBuilder
    implements OAuthClientCredentialsDancerBuilder {

  public Compatibility1xOAuthClientCredentialsDancerBuilder(SchedulerService schedulerService, LockFactory lockProvider,
                                                            Map<String, ResourceOwnerOAuthContext> tokensStore,
                                                            HttpClientFactory httpClientFactory,
                                                            MuleExpressionLanguage expressionEvaluator) {
    super(schedulerService, lockProvider, tokensStore, httpClientFactory, expressionEvaluator);
  }

  ///////////////////////////////////////////////////
  // From OAuthDancerBuilder
  ///////////////////////////////////////////////////

  @Override
  public OAuthClientCredentialsDancerBuilder name(String name) {
    return (OAuthClientCredentialsDancerBuilder) super.name(name);
  }

  @Override
  public OAuthClientCredentialsDancerBuilder clientCredentials(String clientId, String clientSecret) {
    return (OAuthClientCredentialsDancerBuilder) super.clientCredentials(clientId, clientSecret);
  }

  @Override
  public OAuthClientCredentialsDancerBuilder withClientCredentialsIn(ClientCredentialsLocation clientCredentialsLocation) {
    return (OAuthClientCredentialsDancerBuilder) super.withClientCredentialsIn(clientCredentialsLocation);
  }

  @Override
  public OAuthClientCredentialsDancerBuilder tokenUrl(String tokenUrl) {
    return (OAuthClientCredentialsDancerBuilder) super.tokenUrl(tokenUrl);
  }

  @Override
  public OAuthClientCredentialsDancerBuilder tokenUrl(HttpClient httpClient, String tokenUrl) {
    return (OAuthClientCredentialsDancerBuilder) super.tokenUrl(httpClient, tokenUrl);
  }

  @Override
  public OAuthClientCredentialsDancerBuilder tokenUrl(String tokenUrl, TlsContextFactory tlsContextFactory) {
    return (OAuthClientCredentialsDancerBuilder) super.tokenUrl(tokenUrl, tlsContextFactory);
  }

  @Override
  public OAuthClientCredentialsDancerBuilder tokenUrl(String tokenUrl, ProxyConfig proxyConfig) {
    return (OAuthClientCredentialsDancerBuilder) super.tokenUrl(tokenUrl, proxyConfig);
  }

  @Override
  public OAuthClientCredentialsDancerBuilder tokenUrl(String tokenUrl, TlsContextFactory tlsContextFactory,
                                                      ProxyConfig proxyConfig) {
    return (OAuthClientCredentialsDancerBuilder) super.tokenUrl(tokenUrl, tlsContextFactory, proxyConfig);
  }

  @Override
  public OAuthClientCredentialsDancerBuilder scopes(String scopes) {
    return (OAuthClientCredentialsDancerBuilder) super.scopes(scopes);
  }

  @Override
  public OAuthClientCredentialsDancerBuilder encoding(Charset encoding) {
    return (OAuthClientCredentialsDancerBuilder) super.encoding(encoding);
  }

  @Override
  public OAuthClientCredentialsDancerBuilder responseAccessTokenExpr(String responseAccessTokenExpr) {
    return (OAuthClientCredentialsDancerBuilder) super.responseAccessTokenExpr(responseAccessTokenExpr);
  }

  @Override
  public OAuthClientCredentialsDancerBuilder responseRefreshTokenExpr(String responseRefreshTokenExpr) {
    return (OAuthClientCredentialsDancerBuilder) super.responseRefreshTokenExpr(responseRefreshTokenExpr);
  }

  @Override
  public OAuthClientCredentialsDancerBuilder responseExpiresInExpr(String responseExpiresInExpr) {
    return (OAuthClientCredentialsDancerBuilder) super.responseExpiresInExpr(responseExpiresInExpr);
  }

  @Override
  public OAuthClientCredentialsDancerBuilder customParametersExtractorsExprs(Map<String, String> customParamsExtractorsExprs) {
    return (OAuthClientCredentialsDancerBuilder) super.customParametersExtractorsExprs(customParamsExtractorsExprs);
  }

  @Override
  public OAuthClientCredentialsDancerBuilder resourceOwnerIdTransformer(Function<String, String> resourceOwnerIdTransformer) {
    return (OAuthClientCredentialsDancerBuilder) super.resourceOwnerIdTransformer(resourceOwnerIdTransformer);
  }

  @Override
  public org.mule.oauth.client.api.ClientCredentialsOAuthDancer build() {
    org.mule.oauth.client.api.ClientCredentialsOAuthDancer build = super.build();
    return new Compatibility1xClientCredentialsOAuthDancer(build);
  }

  ///////////////////////////////////////////////////
  // From OAuthClientCredentialsDancerBuilder
  ///////////////////////////////////////////////////

  @Override
  public OAuthClientCredentialsDancerBuilder customParameters(Map<String, String> customParameters) {
    return (OAuthClientCredentialsDancerBuilder) super.customParameters(customParameters);
  }

  @Override
  public OAuthClientCredentialsDancerBuilder customHeaders(Map<String, String> customHeaders) {
    return (OAuthClientCredentialsDancerBuilder) super.customHeaders(customHeaders);
  }

  @Override
  public OAuthClientCredentialsDancerBuilder addListener(ClientCredentialsListener listener) {
    return (OAuthClientCredentialsDancerBuilder) super.addListener(listener);
  }

  @Override
  public OAuthClientCredentialsDancerBuilder addListener(org.mule.runtime.oauth.api.listener.ClientCredentialsListener listener) {
    return (OAuthClientCredentialsDancerBuilder) super.addListener(listener);
  }

  @Override
  @Deprecated
  public OAuthClientCredentialsDancerBuilder encodeClientCredentialsInBody(boolean encodeClientCredentialsInBody) {
    return (OAuthClientCredentialsDancerBuilder) super.encodeClientCredentialsInBody(encodeClientCredentialsInBody);
  }

}
