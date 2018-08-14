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
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.hamcrest.text.IsEqualIgnoringCase.equalToIgnoringCase;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mule.runtime.http.api.HttpConstants.Method.GET;
import static org.mule.runtime.http.api.HttpHeaders.Names.AUTHORIZATION;
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

import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;


public class AuthorizationCodeTokenTestCase extends AbstractOAuthTestCase {

  private ArgumentCaptor<RequestHandler> localCallbackCaptor = forClass(RequestHandler.class);

  @Before
  public void before() {
    when(httpServer.addRequestHandler(eq(singleton(GET.name())), eq("/localCallback"), localCallbackCaptor.capture()))
        .thenReturn(mock(RequestHandlerManager.class));
    when(httpServer.addRequestHandler(eq(singleton(GET.name())), eq("/auth"), any(RequestHandler.class)))
        .thenReturn(mock(RequestHandlerManager.class));
  }

  @Test
  public void authCodeCredentialsEncodedInHeader() throws Exception {
    final OAuthAuthorizationCodeDancerBuilder builder = baseAuthCodeDancerbuilder();
    builder.tokenUrl("http://host/token");
    builder.authorizationUrl("http://host/auth");
    builder.localCallback(httpServer, "/localCallback");
    builder.localAuthorizationUrlPath("/auth");
    builder.clientCredentials("Aladdin", "open sesame");
    builder.encodeClientCredentialsInBody(false);

    AuthorizationCodeOAuthDancer minimalDancer = startDancer(builder);
    localCallbackCaptor.getValue().handleRequest(buildLocalCallbackRequestContext(), mock(HttpResponseReadyCallback.class));

    ArgumentCaptor<HttpRequest> requestCaptor = forClass(HttpRequest.class);
    verify(httpClient).send(requestCaptor.capture(), any(HttpRequestOptions.class));

    assertThat(requestCaptor.getValue().getHeaderValue(AUTHORIZATION), is("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="));

    String requestBody = IOUtils.toString(requestCaptor.getValue().getEntity().getContent(), UTF_8);
    assertThat(requestBody, containsString("code=authCode"));
    assertThat(requestBody, containsString("grant_type=authorization_code"));
    assertThat(requestBody, not(containsString("client_secret=open+sesame")));
    assertThat(requestBody, not(containsString("client_id=Aladdin")));
  }

  @Test
  public void authCodeCredentialsInBody() throws Exception {
    final OAuthAuthorizationCodeDancerBuilder builder = baseAuthCodeDancerbuilder();
    builder.tokenUrl("http://host/token");
    builder.authorizationUrl("http://host/auth");
    builder.localCallback(httpServer, "/localCallback");
    builder.localAuthorizationUrlPath("/auth");
    builder.clientCredentials("Aladdin", "open sesame");

    AuthorizationCodeOAuthDancer minimalDancer = startDancer(builder);
    localCallbackCaptor.getValue().handleRequest(buildLocalCallbackRequestContext(), mock(HttpResponseReadyCallback.class));

    ArgumentCaptor<HttpRequest> requestCaptor = forClass(HttpRequest.class);
    verify(httpClient).send(requestCaptor.capture(), any(HttpRequestOptions.class));

    assertThat(requestCaptor.getValue().getHeaderNames(), not(hasItem(equalToIgnoringCase(AUTHORIZATION))));

    String requestBody = IOUtils.toString(requestCaptor.getValue().getEntity().getContent(), UTF_8);
    assertThat(requestBody, containsString("grant_type=authorization_code"));
    assertThat(requestBody, containsString("client_secret=open+sesame"));
    assertThat(requestBody, containsString("client_id=Aladdin"));
    assertThat(requestBody, containsString("code=authCode"));
  }

  private HttpRequestContext buildLocalCallbackRequestContext() {
    HttpRequest request = mock(HttpRequest.class);
    MultiMap<String, String> queryParams = new MultiMap<>();
    queryParams.put(CODE_PARAMETER, "authCode");
    when(request.getQueryParams()).thenReturn(queryParams);

    HttpRequestContext requestContext = mock(HttpRequestContext.class);
    when(requestContext.getRequest()).thenReturn(request);
    return requestContext;
  }

  @Test
  public void authCodeCredentialsEncodedInHeaderRefresh() throws Exception {
    final OAuthAuthorizationCodeDancerBuilder builder = baseAuthCodeDancerbuilder();
    builder.tokenUrl("http://host/token");
    builder.authorizationUrl("http://host/auth");
    builder.clientCredentials("Aladdin", "open sesame");
    builder.encodeClientCredentialsInBody(false);

    AuthorizationCodeOAuthDancer minimalDancer = startDancer(builder);
    minimalDancer.refreshToken(null);

    ArgumentCaptor<HttpRequest> requestCaptor = forClass(HttpRequest.class);
    verify(httpClient).send(requestCaptor.capture(), any(HttpRequestOptions.class));

    assertThat(requestCaptor.getValue().getHeaderValue(AUTHORIZATION), is("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="));

    String requestBody = IOUtils.toString(requestCaptor.getValue().getEntity().getContent(), UTF_8);
    assertThat(requestBody, containsString("grant_type=refresh_token"));
    assertThat(requestBody, not(containsString("client_secret=open+sesame")));
    assertThat(requestBody, not(containsString("client_id=Aladdin")));
  }

  @Test
  public void authCodeCredentialsInBodyRefresh() throws Exception {
    final OAuthAuthorizationCodeDancerBuilder builder = baseAuthCodeDancerbuilder();
    builder.tokenUrl("http://host/token");
    builder.authorizationUrl("http://host/auth");
    builder.clientCredentials("Aladdin", "open sesame");

    AuthorizationCodeOAuthDancer minimalDancer = startDancer(builder);
    minimalDancer.refreshToken(null);

    ArgumentCaptor<HttpRequest> requestCaptor = forClass(HttpRequest.class);
    verify(httpClient).send(requestCaptor.capture(), any(HttpRequestOptions.class));

    assertThat(requestCaptor.getValue().getHeaderNames(), not(hasItem(equalToIgnoringCase(AUTHORIZATION))));

    String requestBody = IOUtils.toString(requestCaptor.getValue().getEntity().getContent(), UTF_8);
    assertThat(requestBody, containsString("grant_type=refresh_token"));
    assertThat(requestBody, containsString("client_secret=open+sesame"));
    assertThat(requestBody, containsString("client_id=Aladdin"));
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
