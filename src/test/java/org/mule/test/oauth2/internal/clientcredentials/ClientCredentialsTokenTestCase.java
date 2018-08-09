/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.test.oauth2.internal.clientcredentials;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.hamcrest.text.IsEqualIgnoringCase.equalToIgnoringCase;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mule.runtime.core.api.lifecycle.LifecycleUtils.initialiseIfNeeded;
import static org.mule.runtime.core.api.lifecycle.LifecycleUtils.startIfNeeded;
import static org.mule.runtime.http.api.HttpHeaders.Names.AUTHORIZATION;

import org.mule.runtime.api.el.MuleExpressionLanguage;
import org.mule.runtime.api.exception.MuleException;
import org.mule.runtime.api.lifecycle.InitialisationException;
import org.mule.runtime.api.lock.LockFactory;
import org.mule.runtime.api.scheduler.SchedulerService;
import org.mule.runtime.http.api.HttpService;
import org.mule.runtime.http.api.client.HttpClient;
import org.mule.runtime.http.api.client.HttpClientFactory;
import org.mule.runtime.http.api.client.HttpRequestOptions;
import org.mule.runtime.http.api.domain.entity.InputStreamHttpEntity;
import org.mule.runtime.http.api.domain.message.request.HttpRequest;
import org.mule.runtime.http.api.domain.message.response.HttpResponse;
import org.mule.runtime.oauth.api.ClientCredentialsOAuthDancer;
import org.mule.runtime.oauth.api.OAuthService;
import org.mule.runtime.oauth.api.builder.OAuthClientCredentialsDancerBuilder;
import org.mule.runtime.oauth.api.builder.OAuthDancerBuilder;
import org.mule.service.oauth.internal.DefaultOAuthService;
import org.mule.tck.junit4.AbstractMuleContextTestCase;

import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.ReaderInputStream;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.io.StringReader;
import java.util.HashMap;

import javax.inject.Inject;


public class ClientCredentialsTokenTestCase extends AbstractMuleContextTestCase {

  private OAuthService service;
  private HttpClient httpClient;

  @Inject
  private LockFactory lockFactory;

  public ClientCredentialsTokenTestCase() {
    setStartContext(true);
  }

  @Override
  protected boolean doTestClassInjection() {
    return true;
  }

  @Before
  public void before() throws Exception {
    final HttpService httpService = mock(HttpService.class);
    final HttpClientFactory httpClientFactory = mock(HttpClientFactory.class);
    httpClient = mock(HttpClient.class);
    when(httpClientFactory.create(any())).thenReturn(httpClient);
    when(httpService.getClientFactory()).thenReturn(httpClientFactory);

    service = new DefaultOAuthService(httpService, mock(SchedulerService.class));

    final HttpResponse httpResponse = mock(HttpResponse.class);
    final InputStreamHttpEntity httpEntity = mock(InputStreamHttpEntity.class);
    when(httpEntity.getContent()).thenReturn(new ReaderInputStream(new StringReader("")));
    when(httpResponse.getEntity()).thenReturn(httpEntity);
    when(httpClient.send(any(), any())).thenReturn(httpResponse);
  }

  @Test
  public void clientCredentialsEncodedInHeader() throws Exception {
    final OAuthClientCredentialsDancerBuilder builder = baseClientCredentialsDancerBuilder();
    builder.tokenUrl("http://host/token");
    builder.clientCredentials("Aladdin", "open sesame");

    ClientCredentialsOAuthDancer minimalDancer = startDancer(builder);

    ArgumentCaptor<HttpRequest> requestCaptor = forClass(HttpRequest.class);
    verify(httpClient).send(requestCaptor.capture(), any(HttpRequestOptions.class));

    assertThat(requestCaptor.getValue().getHeaderValue(AUTHORIZATION), is("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="));

    String requestBody = IOUtils.toString(requestCaptor.getValue().getEntity().getContent(), UTF_8);
    assertThat(requestBody, containsString("grant_type=client_credentials"));
    assertThat(requestBody, not(containsString("client_secret=open+sesame")));
    assertThat(requestBody, not(containsString("client_id=Aladdin")));
  }

  @Test
  public void clientCredentialsInBody() throws Exception {
    final OAuthClientCredentialsDancerBuilder builder = baseClientCredentialsDancerBuilder();
    builder.tokenUrl("http://host/token");
    builder.clientCredentials("Aladdin", "open sesame");
    builder.encodeClientCredentialsInBody(true);

    ClientCredentialsOAuthDancer minimalDancer = startDancer(builder);

    ArgumentCaptor<HttpRequest> requestCaptor = forClass(HttpRequest.class);
    verify(httpClient).send(requestCaptor.capture(), any(HttpRequestOptions.class));

    assertThat(requestCaptor.getValue().getHeaderNames(), not(hasItem(equalToIgnoringCase(AUTHORIZATION))));

    String requestBody = IOUtils.toString(requestCaptor.getValue().getEntity().getContent(), UTF_8);
    assertThat(requestBody, containsString("grant_type=client_credentials"));
    assertThat(requestBody, containsString("client_secret=open+sesame"));
    assertThat(requestBody, containsString("client_id=Aladdin"));
  }

  private OAuthClientCredentialsDancerBuilder baseClientCredentialsDancerBuilder() {
    final OAuthClientCredentialsDancerBuilder builder =
        service.clientCredentialsGrantTypeDancerBuilder(lockFactory, new HashMap<>(), mock(MuleExpressionLanguage.class));

    builder.clientCredentials("clientId", "clientSecret");
    return builder;
  }

  private <D> D startDancer(final OAuthDancerBuilder<D> builder)
      throws InitialisationException, MuleException {
    final D dancer = builder.build();
    initialiseIfNeeded(dancer);
    startIfNeeded(dancer);

    return dancer;
  }

}
