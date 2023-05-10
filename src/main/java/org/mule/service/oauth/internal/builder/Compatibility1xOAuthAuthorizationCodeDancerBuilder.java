/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.service.oauth.internal.builder;

import org.mule.oauth.client.api.AuthorizationCodeRequest;
import org.mule.oauth.client.api.builder.AuthorizationCodeDanceCallbackContext;
import org.mule.oauth.client.api.builder.ClientCredentialsLocation;
import org.mule.oauth.client.api.http.HttpClientFactory;
import org.mule.oauth.client.api.listener.AuthorizationCodeListener;
import org.mule.oauth.client.api.state.ResourceOwnerOAuthContext;
import org.mule.oauth.client.internal.builder.DefaultOAuthAuthorizationCodeDancerBuilder;
import org.mule.runtime.api.el.MuleExpressionLanguage;
import org.mule.runtime.api.lock.LockFactory;
import org.mule.runtime.api.scheduler.SchedulerService;
import org.mule.runtime.api.tls.TlsContextFactory;
import org.mule.runtime.api.util.MultiMap;
import org.mule.runtime.http.api.HttpService;
import org.mule.runtime.http.api.client.HttpClient;
import org.mule.runtime.http.api.client.proxy.ProxyConfig;
import org.mule.runtime.http.api.server.HttpServer;
import org.mule.runtime.oauth.api.builder.OAuthAuthorizationCodeDancerBuilder;
import org.mule.service.oauth.internal.dancer.Compatibility1xAuthorizationCodeOAuthDancer;

import java.net.URL;
import java.nio.charset.Charset;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Provides compatibility with version 1.x of the mule-oauth-client, which was a transitive api of the service api.
 * 
 * @since 2.3
 */
public class Compatibility1xOAuthAuthorizationCodeDancerBuilder extends DefaultOAuthAuthorizationCodeDancerBuilder
    implements OAuthAuthorizationCodeDancerBuilder {

  public Compatibility1xOAuthAuthorizationCodeDancerBuilder(SchedulerService schedulerService, LockFactory lockProvider,
                                                            Map<String, ResourceOwnerOAuthContext> tokensStore,
                                                            HttpService httpService, HttpClientFactory httpClientFactory,
                                                            MuleExpressionLanguage expressionEvaluator) {
    super(schedulerService, lockProvider, tokensStore, httpService, httpClientFactory, expressionEvaluator);
  }

  ///////////////////////////////////////////////////
  // From OAuthDancerBuilder
  ///////////////////////////////////////////////////

  @Override
  public OAuthAuthorizationCodeDancerBuilder name(String name) {
    return (OAuthAuthorizationCodeDancerBuilder) super.name(name);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder clientCredentials(String clientId, String clientSecret) {
    return (OAuthAuthorizationCodeDancerBuilder) super.clientCredentials(clientId, clientSecret);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder withClientCredentialsIn(ClientCredentialsLocation clientCredentialsLocation) {
    return (OAuthAuthorizationCodeDancerBuilder) super.withClientCredentialsIn(clientCredentialsLocation);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder tokenUrl(String tokenUrl) {
    return (OAuthAuthorizationCodeDancerBuilder) super.tokenUrl(tokenUrl);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder tokenUrl(HttpClient httpClient, String tokenUrl) {
    return (OAuthAuthorizationCodeDancerBuilder) super.tokenUrl(httpClient, tokenUrl);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder tokenUrl(String tokenUrl, TlsContextFactory tlsContextFactory) {
    return (OAuthAuthorizationCodeDancerBuilder) super.tokenUrl(tokenUrl, tlsContextFactory);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder tokenUrl(String tokenUrl, ProxyConfig proxyConfig) {
    return (OAuthAuthorizationCodeDancerBuilder) super.tokenUrl(tokenUrl, proxyConfig);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder tokenUrl(String tokenUrl, TlsContextFactory tlsContextFactory,
                                                      ProxyConfig proxyConfig) {
    return (OAuthAuthorizationCodeDancerBuilder) super.tokenUrl(tokenUrl, tlsContextFactory, proxyConfig);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder scopes(String scopes) {
    return (OAuthAuthorizationCodeDancerBuilder) super.scopes(scopes);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder encoding(Charset encoding) {
    return (OAuthAuthorizationCodeDancerBuilder) super.encoding(encoding);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder responseAccessTokenExpr(String responseAccessTokenExpr) {
    return (OAuthAuthorizationCodeDancerBuilder) super.responseAccessTokenExpr(responseAccessTokenExpr);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder responseRefreshTokenExpr(String responseRefreshTokenExpr) {
    return (OAuthAuthorizationCodeDancerBuilder) super.responseRefreshTokenExpr(responseRefreshTokenExpr);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder responseExpiresInExpr(String responseExpiresInExpr) {
    return (OAuthAuthorizationCodeDancerBuilder) super.responseExpiresInExpr(responseExpiresInExpr);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder customParametersExtractorsExprs(Map<String, String> customParamsExtractorsExprs) {
    return (OAuthAuthorizationCodeDancerBuilder) super.customParametersExtractorsExprs(customParamsExtractorsExprs);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder resourceOwnerIdTransformer(Function<String, String> resourceOwnerIdTransformer) {
    return (OAuthAuthorizationCodeDancerBuilder) super.resourceOwnerIdTransformer(resourceOwnerIdTransformer);
  }

  @Override
  public org.mule.oauth.client.api.AuthorizationCodeOAuthDancer build() {
    org.mule.oauth.client.api.AuthorizationCodeOAuthDancer build = super.build();

    return new Compatibility1xAuthorizationCodeOAuthDancer(build);
  }

  ///////////////////////////////////////////////////
  // From OAuthAuthorizationCodeDancerBuilder
  ///////////////////////////////////////////////////

  @Override
  @Deprecated
  public OAuthAuthorizationCodeDancerBuilder encodeClientCredentialsInBody(boolean encodeClientCredentialsInBody) {
    return (OAuthAuthorizationCodeDancerBuilder) super.encodeClientCredentialsInBody(encodeClientCredentialsInBody);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder localCallback(URL localCallbackUrl) {
    return (OAuthAuthorizationCodeDancerBuilder) super.localCallback(localCallbackUrl);
  }

  public OAuthAuthorizationCodeDancerBuilder localCallback(URL localCallbackUrl,
                                                           TlsContextFactory tlsContextFactory) {
    return (OAuthAuthorizationCodeDancerBuilder) super.localCallback(localCallbackUrl, tlsContextFactory);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder localCallback(HttpServer server,
                                                           String localCallbackConfigPath) {
    return (OAuthAuthorizationCodeDancerBuilder) super.localCallback(server, localCallbackConfigPath);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder localAuthorizationUrlPath(String path) {
    return (OAuthAuthorizationCodeDancerBuilder) super.localAuthorizationUrlPath(path);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder localAuthorizationUrlResourceOwnerId(String localAuthorizationUrlResourceOwnerIdExpr) {
    return (OAuthAuthorizationCodeDancerBuilder) super.localAuthorizationUrlResourceOwnerId(localAuthorizationUrlResourceOwnerIdExpr);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder customParameters(Map<String, String> customParameters) {
    return (OAuthAuthorizationCodeDancerBuilder) super.customParameters(customParameters);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder customParameters(Supplier<Map<String, String>> customParameters) {
    return (OAuthAuthorizationCodeDancerBuilder) super.customParameters(customParameters);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder customHeaders(Map<String, String> customHeaders) {
    return (OAuthAuthorizationCodeDancerBuilder) super.customHeaders(customHeaders);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder customHeaders(Supplier<Map<String, String>> customHeaders) {
    return (OAuthAuthorizationCodeDancerBuilder) super.customHeaders(customHeaders);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder state(String stateExpr) {
    return (OAuthAuthorizationCodeDancerBuilder) super.state(stateExpr);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder authorizationUrl(String authorizationUrl) {
    return (OAuthAuthorizationCodeDancerBuilder) super.authorizationUrl(authorizationUrl);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder externalCallbackUrl(String externalCallbackUrl) {
    return (OAuthAuthorizationCodeDancerBuilder) super.externalCallbackUrl(externalCallbackUrl);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder beforeDanceCallback(Function<AuthorizationCodeRequest, AuthorizationCodeDanceCallbackContext> callback) {
    return (OAuthAuthorizationCodeDancerBuilder) super.beforeDanceCallback(callback);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder afterDanceCallback(BiConsumer<AuthorizationCodeDanceCallbackContext, ResourceOwnerOAuthContext> callback) {
    return (OAuthAuthorizationCodeDancerBuilder) super.afterDanceCallback(callback);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder addListener(AuthorizationCodeListener listener) {
    return (OAuthAuthorizationCodeDancerBuilder) super.addListener(listener);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder addAdditionalRefreshTokenRequestParameters(MultiMap<String, String> additionalParameters) {
    return (OAuthAuthorizationCodeDancerBuilder) super.addAdditionalRefreshTokenRequestParameters(additionalParameters);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder addAdditionalRefreshTokenRequestHeaders(MultiMap<String, String> additionalHeaders) {
    return (OAuthAuthorizationCodeDancerBuilder) super.addAdditionalRefreshTokenRequestHeaders(additionalHeaders);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder includeRedirectUriInRefreshTokenRequest(boolean includeRedirectUriInRefreshTokenRequest) {
    return (OAuthAuthorizationCodeDancerBuilder) super.includeRedirectUriInRefreshTokenRequest(includeRedirectUriInRefreshTokenRequest);
  }

}
