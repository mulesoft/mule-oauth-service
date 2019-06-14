/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.test.oauth2.internal.authorizationcode;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.singleton;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.hamcrest.text.IsEqualIgnoringCase.equalToIgnoringCase;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mule.runtime.http.api.HttpConstants.Method.GET;
import static org.mule.runtime.http.api.HttpHeaders.Names.AUTHORIZATION;
import static org.mule.runtime.oauth.api.builder.ClientCredentialsLocation.BASIC_AUTH_HEADER;
import static org.mule.runtime.oauth.api.builder.ClientCredentialsLocation.BODY;
import static org.mule.runtime.oauth.api.builder.ClientCredentialsLocation.QUERY_PARAMS;
import static org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext.DEFAULT_RESOURCE_OWNER_ID;
import static org.mule.service.oauth.internal.OAuthConstants.CODE_PARAMETER;

import org.mule.runtime.api.el.MuleExpressionLanguage;
import org.mule.runtime.api.util.MultiMap;
import org.mule.runtime.http.api.client.HttpRequestOptions;
import org.mule.runtime.http.api.domain.message.request.HttpRequest;
import org.mule.runtime.http.api.domain.request.HttpRequestContext;
import org.mule.runtime.http.api.server.RequestHandler;
import org.mule.runtime.http.api.server.RequestHandlerManager;
import org.mule.runtime.http.api.server.async.HttpResponseReadyCallback;
import org.mule.runtime.oauth.api.AuthorizationCodeOAuthDancer;
import org.mule.runtime.oauth.api.builder.OAuthAuthorizationCodeDancerBuilder;
import org.mule.runtime.oauth.api.state.DefaultResourceOwnerOAuthContext;
import org.mule.test.oauth.AbstractOAuthTestCase;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import io.qameta.allure.Feature;

@Feature("OAuth Service")
public class AuthorizationCodeTokenTestCase extends AbstractOAuthTestCase {

  private final ArgumentCaptor<RequestHandler> localCallbackCaptor = forClass(RequestHandler.class);

  @Before
  public void before() {
    when(httpServer.addRequestHandler(eq(singleton(GET.name())), eq("/localCallback"), localCallbackCaptor.capture()))
        .thenReturn(mock(RequestHandlerManager.class));
    when(httpServer.addRequestHandler(eq(singleton(GET.name())), eq("/auth"), any(RequestHandler.class)))
        .thenReturn(mock(RequestHandlerManager.class));
  }

  private void assertAuthCodeCredentialsEncodedInHeader(boolean useDeprecatedMethod) throws Exception {
    final OAuthAuthorizationCodeDancerBuilder builder = baseAuthCodeDancerbuilder();
    builder.tokenUrl("http://host/token");
    builder.authorizationUrl("http://host/auth");
    builder.localCallback(httpServer, "/localCallback");
    builder.localAuthorizationUrlPath("/auth");
    builder.clientCredentials("Aladdin", "open sesame");
    if (useDeprecatedMethod) {
      builder.encodeClientCredentialsInBody(false);
    } else {
      builder.withClientCredentialsIn(BASIC_AUTH_HEADER);
    }

    AuthorizationCodeOAuthDancer minimalDancer = startDancer(builder);
    localCallbackCaptor.getValue().handleRequest(buildLocalCallbackRequestContext(), mock(HttpResponseReadyCallback.class));

    ArgumentCaptor<HttpRequest> requestCaptor = forClass(HttpRequest.class);
    verify(httpClient).sendAsync(requestCaptor.capture(), any(HttpRequestOptions.class));

    assertThat(requestCaptor.getValue().getHeaderValue(AUTHORIZATION), is("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="));

    assertThat(requestCaptor.getValue().getQueryParams(), not(hasKey("client_id")));
    assertThat(requestCaptor.getValue().getQueryParams(), not(hasKey("client_secret")));

    String requestBody = IOUtils.toString(requestCaptor.getValue().getEntity().getContent(), UTF_8);
    assertThat(requestBody, containsString("code=authCode"));
    assertThat(requestBody, containsString("grant_type=authorization_code"));
    assertThat(requestBody, not(containsString("client_secret=open+sesame")));
    assertThat(requestBody, not(containsString("client_id=Aladdin")));
  }

  @Test
  public void authCodeCredentialsEncodedInHeader() throws Exception {
    assertAuthCodeCredentialsEncodedInHeader(false);
  }

  @Test
  public void authCodeCredentialsEncodedInHeaderCompatibility() throws Exception {
    assertAuthCodeCredentialsEncodedInHeader(true);
  }

  @Test
  public void authCodeCredentialsInBodyByDefault() throws Exception {
    final OAuthAuthorizationCodeDancerBuilder builder = baseAuthCodeDancerbuilder();
    builder.tokenUrl("http://host/token");
    builder.authorizationUrl("http://host/auth");
    builder.localCallback(httpServer, "/localCallback");
    builder.localAuthorizationUrlPath("/auth");
    builder.clientCredentials("Aladdin", "open sesame");

    AuthorizationCodeOAuthDancer minimalDancer = startDancer(builder);
    localCallbackCaptor.getValue().handleRequest(buildLocalCallbackRequestContext(), mock(HttpResponseReadyCallback.class));

    ArgumentCaptor<HttpRequest> requestCaptor = forClass(HttpRequest.class);
    verify(httpClient).sendAsync(requestCaptor.capture(), any(HttpRequestOptions.class));

    assertThat(requestCaptor.getValue().getHeaderNames(), not(hasItem(equalToIgnoringCase(AUTHORIZATION))));

    assertThat(requestCaptor.getValue().getQueryParams(), not(hasKey("client_id")));
    assertThat(requestCaptor.getValue().getQueryParams(), not(hasKey("client_secret")));

    String requestBody = IOUtils.toString(requestCaptor.getValue().getEntity().getContent(), UTF_8);
    assertThat(requestBody, containsString("grant_type=authorization_code"));
    assertThat(requestBody, containsString("client_secret=open+sesame"));
    assertThat(requestBody, containsString("client_id=Aladdin"));
    assertThat(requestBody, containsString("code=authCode"));
  }

  private void assertAuthCodeCredentialsInBody(boolean useDeprecatedMethod) throws Exception {
    final OAuthAuthorizationCodeDancerBuilder builder = baseAuthCodeDancerbuilder();
    builder.tokenUrl("http://host/token");
    builder.authorizationUrl("http://host/auth");
    builder.localCallback(httpServer, "/localCallback");
    builder.localAuthorizationUrlPath("/auth");
    builder.clientCredentials("Aladdin", "open sesame");
    if (useDeprecatedMethod) {
      builder.encodeClientCredentialsInBody(true);
    } else {
      builder.withClientCredentialsIn(BODY);
    }

    AuthorizationCodeOAuthDancer minimalDancer = startDancer(builder);
    localCallbackCaptor.getValue().handleRequest(buildLocalCallbackRequestContext(), mock(HttpResponseReadyCallback.class));

    ArgumentCaptor<HttpRequest> requestCaptor = forClass(HttpRequest.class);
    verify(httpClient).sendAsync(requestCaptor.capture(), any(HttpRequestOptions.class));

    assertThat(requestCaptor.getValue().getHeaderNames(), not(hasItem(equalToIgnoringCase(AUTHORIZATION))));

    assertThat(requestCaptor.getValue().getQueryParams(), not(hasKey("client_id")));
    assertThat(requestCaptor.getValue().getQueryParams(), not(hasKey("client_secret")));

    String requestBody = IOUtils.toString(requestCaptor.getValue().getEntity().getContent(), UTF_8);
    assertThat(requestBody, containsString("grant_type=authorization_code"));
    assertThat(requestBody, containsString("client_secret=open+sesame"));
    assertThat(requestBody, containsString("client_id=Aladdin"));
    assertThat(requestBody, containsString("code=authCode"));
  }

  @Test
  public void authCodeCredentialsInBodyCompatibility() throws Exception {
    assertAuthCodeCredentialsInBody(true);
  }

  @Test
  public void authCodeCredentialsInBody() throws Exception {
    assertAuthCodeCredentialsInBody(false);
  }

  protected HttpRequestContext buildLocalCallbackRequestContext() {
    HttpRequest request = mock(HttpRequest.class);
    MultiMap<String, String> queryParams = new MultiMap<>();
    queryParams.put(CODE_PARAMETER, "authCode");
    when(request.getQueryParams()).thenReturn(queryParams);

    HttpRequestContext requestContext = mock(HttpRequestContext.class);
    when(requestContext.getRequest()).thenReturn(request);
    return requestContext;
  }

  private void assertAuthCodeCredentialsEncodedInHeaderRefresh(boolean useDeprecatedMethod) throws Exception {
    final OAuthAuthorizationCodeDancerBuilder builder = baseAuthCodeDancerbuilder();
    builder.tokenUrl("http://host/token");
    builder.authorizationUrl("http://host/auth");
    builder.clientCredentials("Aladdin", "open sesame");
    if (useDeprecatedMethod) {
      builder.encodeClientCredentialsInBody(false);
    } else {
      builder.withClientCredentialsIn(BASIC_AUTH_HEADER);
    }

    AuthorizationCodeOAuthDancer minimalDancer = startDancer(builder);
    minimalDancer.refreshToken(null);

    ArgumentCaptor<HttpRequest> requestCaptor = forClass(HttpRequest.class);
    verify(httpClient).sendAsync(requestCaptor.capture(), any(HttpRequestOptions.class));

    assertThat(requestCaptor.getValue().getHeaderValue(AUTHORIZATION), is("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="));

    assertThat(requestCaptor.getValue().getQueryParams(), not(hasKey("client_id")));
    assertThat(requestCaptor.getValue().getQueryParams(), not(hasKey("client_secret")));

    String requestBody = IOUtils.toString(requestCaptor.getValue().getEntity().getContent(), UTF_8);
    assertThat(requestBody, containsString("grant_type=refresh_token"));
    assertThat(requestBody, not(containsString("client_secret=open+sesame")));
    assertThat(requestBody, not(containsString("client_id=Aladdin")));
  }

  @Test
  public void authCodeCredentialsEncodedInHeaderRefreshCompatibility() throws Exception {
    assertAuthCodeCredentialsEncodedInHeaderRefresh(true);
  }

  @Test
  public void authCodeCredentialsEncodedInHeaderRefresh() throws Exception {
    assertAuthCodeCredentialsEncodedInHeaderRefresh(false);
  }

  @Test
  public void authCodeCredentialsInBodyRefreshByDefault() throws Exception {
    final OAuthAuthorizationCodeDancerBuilder builder = baseAuthCodeDancerbuilder();
    builder.tokenUrl("http://host/token");
    builder.authorizationUrl("http://host/auth");
    builder.clientCredentials("Aladdin", "open sesame");

    AuthorizationCodeOAuthDancer minimalDancer = startDancer(builder);
    minimalDancer.refreshToken(null);

    ArgumentCaptor<HttpRequest> requestCaptor = forClass(HttpRequest.class);
    verify(httpClient).sendAsync(requestCaptor.capture(), any(HttpRequestOptions.class));

    assertThat(requestCaptor.getValue().getHeaderNames(), not(hasItem(equalToIgnoringCase(AUTHORIZATION))));

    assertThat(requestCaptor.getValue().getQueryParams(), not(hasKey("client_id")));
    assertThat(requestCaptor.getValue().getQueryParams(), not(hasKey("client_secret")));

    String requestBody = IOUtils.toString(requestCaptor.getValue().getEntity().getContent(), UTF_8);
    assertThat(requestBody, containsString("grant_type=refresh_token"));
    assertThat(requestBody, containsString("client_secret=open+sesame"));
    assertThat(requestBody, containsString("client_id=Aladdin"));
  }

  private void assertAuthCodeCredentialsInBodyRefresh(boolean useDeprecatedMethod) throws Exception {
    final OAuthAuthorizationCodeDancerBuilder builder = baseAuthCodeDancerbuilder();
    builder.tokenUrl("http://host/token");
    builder.authorizationUrl("http://host/auth");
    builder.clientCredentials("Aladdin", "open sesame");

    if (useDeprecatedMethod) {
      builder.encodeClientCredentialsInBody(true);
    } else {
      builder.withClientCredentialsIn(BODY);
    }

    AuthorizationCodeOAuthDancer minimalDancer = startDancer(builder);
    minimalDancer.refreshToken(null);

    ArgumentCaptor<HttpRequest> requestCaptor = forClass(HttpRequest.class);
    verify(httpClient).sendAsync(requestCaptor.capture(), any(HttpRequestOptions.class));

    assertThat(requestCaptor.getValue().getHeaderNames(), not(hasItem(equalToIgnoringCase(AUTHORIZATION))));

    assertThat(requestCaptor.getValue().getQueryParams(), not(hasKey("client_id")));
    assertThat(requestCaptor.getValue().getQueryParams(), not(hasKey("client_secret")));

    String requestBody = IOUtils.toString(requestCaptor.getValue().getEntity().getContent(), UTF_8);
    assertThat(requestBody, containsString("grant_type=refresh_token"));
    assertThat(requestBody, containsString("client_secret=open+sesame"));
    assertThat(requestBody, containsString("client_id=Aladdin"));
  }

  @Test
  public void authCodeCredentialsInBodyRefreshCompatibility() throws Exception {
    assertAuthCodeCredentialsInBodyRefresh(true);
  }

  @Test
  public void authCodeCredentialsInBodyRefresh() throws Exception {
    assertAuthCodeCredentialsInBodyRefresh(false);
  }

  @Test
  public void authCodeRefreshTokenWithQueryParams() throws Exception {
    final OAuthAuthorizationCodeDancerBuilder builder = baseAuthCodeDancerbuilder();
    builder.tokenUrl("http://host/token");
    builder.authorizationUrl("http://host/auth");
    builder.clientCredentials("Aladdin", "openSesame");

    AuthorizationCodeOAuthDancer minimalDancer = startDancer(builder);
    minimalDancer.refreshToken(null, true);

    ArgumentCaptor<HttpRequest> requestCaptor = forClass(HttpRequest.class);
    verify(httpClient).sendAsync(requestCaptor.capture(), any(HttpRequestOptions.class));

    assertThat(requestCaptor.getValue().getQueryParams().get("client_id"), is("Aladdin"));
    assertThat(requestCaptor.getValue().getQueryParams().get("client_secret"), is("openSesame"));
    assertThat(requestCaptor.getValue().getQueryParams().get("grant_type"), is("refresh_token"));
    assertThat(requestCaptor.getValue().getQueryParams().get("refresh_token"), is("refreshToken"));

    String requestBody = IOUtils.toString(requestCaptor.getValue().getEntity().getContent(), UTF_8);
    assertThat(requestBody, not(containsString("grant_type=refresh_token")));
    assertThat(requestBody, not(containsString("refresh_token=")));
    assertThat(requestBody, not(containsString("client_secret=openSesame")));
    assertThat(requestBody, not(containsString("client_id=Aladdin")));
  }

  @Test
  public void authCodeCredentialsAsQueryParams() throws Exception {
    final OAuthAuthorizationCodeDancerBuilder builder = baseAuthCodeDancerbuilder();
    builder.tokenUrl("http://host/token");
    builder.authorizationUrl("http://host/auth");
    builder.localCallback(httpServer, "/localCallback");
    builder.localAuthorizationUrlPath("/auth");
    builder.clientCredentials("Aladdin", "openSesame");
    builder.withClientCredentialsIn(QUERY_PARAMS);

    AuthorizationCodeOAuthDancer minimalDancer = startDancer(builder);
    localCallbackCaptor.getValue().handleRequest(buildLocalCallbackRequestContext(), mock(HttpResponseReadyCallback.class));

    ArgumentCaptor<HttpRequest> requestCaptor = forClass(HttpRequest.class);
    verify(httpClient).sendAsync(requestCaptor.capture(), any(HttpRequestOptions.class));

    assertThat(requestCaptor.getValue().getQueryParams().get("client_id"), is("Aladdin"));
    assertThat(requestCaptor.getValue().getQueryParams().get("client_secret"), is("openSesame"));

    assertThat(requestCaptor.getValue().getHeaderNames(), not(hasItem(equalToIgnoringCase(AUTHORIZATION))));

    String requestBody = IOUtils.toString(requestCaptor.getValue().getEntity().getContent(), UTF_8);
    assertThat(requestBody, containsString("code=authCode"));
    assertThat(requestBody, containsString("grant_type=authorization_code"));
    assertThat(requestBody, not(containsString("client_secret=openSesame")));
    assertThat(requestBody, not(containsString("client_id=Aladdin")));
  }

  @Override
  protected OAuthAuthorizationCodeDancerBuilder baseAuthCodeDancerbuilder() {
    DefaultResourceOwnerOAuthContext context =
        new DefaultResourceOwnerOAuthContext(new ReentrantLock(), DEFAULT_RESOURCE_OWNER_ID);
    context.setRefreshToken("refreshToken");
    Map<String, DefaultResourceOwnerOAuthContext> tokensMap = new HashMap<>();
    tokensMap.put(DEFAULT_RESOURCE_OWNER_ID, context);

    final OAuthAuthorizationCodeDancerBuilder builder =
        service.authorizationCodeGrantTypeDancerBuilder(lockFactory, tokensMap, mock(MuleExpressionLanguage.class));

    builder.clientCredentials("clientId", "clientSecret");
    return builder;
  }


}
