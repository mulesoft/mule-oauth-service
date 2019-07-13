/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.test.oauth2.internal.clientcredentials;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.Executors.newFixedThreadPool;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.hamcrest.text.IsEqualIgnoringCase.equalToIgnoringCase;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mule.runtime.http.api.HttpHeaders.Names.AUTHORIZATION;
import static org.mule.runtime.oauth.api.builder.ClientCredentialsLocation.BASIC_AUTH_HEADER;
import static org.mule.runtime.oauth.api.builder.ClientCredentialsLocation.BODY;
import static org.mule.runtime.oauth.api.builder.ClientCredentialsLocation.QUERY_PARAMS;
import static org.mule.service.oauth.internal.ResourceOwnerOAuthContextUtils.isDancerStateNoToken;

import org.mule.runtime.api.exception.MuleRuntimeException;
import org.mule.runtime.api.util.MultiMap;
import org.mule.runtime.http.api.client.HttpRequestOptions;
import org.mule.runtime.http.api.domain.message.request.HttpRequest;
import org.mule.runtime.oauth.api.ClientCredentialsOAuthDancer;
import org.mule.runtime.oauth.api.builder.OAuthClientCredentialsDancerBuilder;
import org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext;
import org.mule.test.oauth.AbstractOAuthTestCase;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.stream.Stream;

import org.apache.commons.io.IOUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatcher;

import io.qameta.allure.Feature;

@Feature("OAuth Service")
public class ClientCredentialsTokenTestCase extends AbstractOAuthTestCase {

  private static final String ALADDIN = "Aladdin";
  private static final String OPEN_SESAME = "openSesame";
  private static final String CLIENT_ID = "client_id";
  private static final String CLIENT_SECRET = "client_secret";

  @Rule
  public ExpectedException expected = ExpectedException.none();

  @Test
  public void refreshTokenAfterInvalidate() throws Exception {
    final Map<String, ?> tokensStore = new HashMap<>();
    final OAuthClientCredentialsDancerBuilder builder = baseClientCredentialsDancerBuilder(tokensStore);
    builder.tokenUrl("http://host/token");
    ClientCredentialsOAuthDancer minimalDancer = startDancer(builder);

    assertThat(minimalDancer.accessToken().get(), not(nullValue()));
    tokensStore.clear();
    assertThat(minimalDancer.accessToken().get(), not(nullValue()));
    verify(httpClient, times(2)).sendAsync(any(HttpRequest.class), any(HttpRequestOptions.class));
  }

  @Test
  public void refreshTokenOnceAtATime() throws Exception {
    final Map<String, ?> tokensStore = new HashMap<>();
    final OAuthClientCredentialsDancerBuilder builder = baseClientCredentialsDancerBuilder(tokensStore);
    builder.tokenUrl("http://host/token");
    ClientCredentialsOAuthDancer minimalDancer = startDancer(builder);

    ExecutorService executor = newFixedThreadPool(2);
    tokensStore.clear();
    try {
      List<Future<?>> futures = new ArrayList<>();
      for (int i = 0; i < 2; ++i) {
        futures.add(executor.submit(() -> {
          try {
            minimalDancer.refreshToken().get();
          } catch (Exception e) {
            throw new MuleRuntimeException(e);
          }
        }));
      }

      for (Future<?> future : futures) {
        future.get(RECEIVE_TIMEOUT * 10, MILLISECONDS);
      }
      // One for the start, another for the 2 refreshes...
      verify(httpClient, times(2)).sendAsync(argThat(new HttpRequestUrlMatcher("http://host/token")),
                                             any(HttpRequestOptions.class));
    } finally {
      executor.shutdownNow();
    }
  }

  @Test
  public void refreshTokenOnceAtATimeSequential() throws Exception {
    final Map<String, ?> tokensStore = new HashMap<>();
    final OAuthClientCredentialsDancerBuilder builder = baseClientCredentialsDancerBuilder(tokensStore);
    builder.tokenUrl("http://host/token");
    ClientCredentialsOAuthDancer minimalDancer = startDancer(builder);

    tokensStore.clear();

    final CompletableFuture<Void> refreshToken1 = minimalDancer.refreshToken();
    final CompletableFuture<Void> refreshToken2 = minimalDancer.refreshToken();
    refreshToken1.get();
    refreshToken2.get();

    verify(httpClient, times(2)).sendAsync(argThat(new HttpRequestUrlMatcher("http://host/token")),
                                           any(HttpRequestOptions.class));
  }

  private static class HttpRequestUrlMatcher implements ArgumentMatcher<HttpRequest> {

    private final URI uri;

    public HttpRequestUrlMatcher(String url) throws URISyntaxException {
      this.uri = new URI("http://host/token");
    }

    @Override
    public boolean matches(HttpRequest request) {
      return request.getUri().equals(uri);
    }
  }

  private void assertClientCredentialsEncodedInHeader(boolean useDeprecatedMethod) throws Exception {
    final OAuthClientCredentialsDancerBuilder builder = baseClientCredentialsDancerBuilder();
    builder.tokenUrl("http://host/token");
    builder.clientCredentials(ALADDIN, "open sesame");
    if (useDeprecatedMethod) {
      builder.encodeClientCredentialsInBody(false);
    } else {
      builder.withClientCredentialsIn(BASIC_AUTH_HEADER);
    }

    startDancer(builder);

    ArgumentCaptor<HttpRequest> requestCaptor = forClass(HttpRequest.class);
    verify(httpClient).sendAsync(requestCaptor.capture(), any(HttpRequestOptions.class));

    assertThat(requestCaptor.getValue().getHeaderValue(AUTHORIZATION), is("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="));

    assertThat(requestCaptor.getValue().getQueryParams(), not(hasKey("client_id")));
    assertThat(requestCaptor.getValue().getQueryParams(), not(hasKey("client_secret")));

    String requestBody = IOUtils.toString(requestCaptor.getValue().getEntity().getContent(), UTF_8);
    assertThat(requestBody, containsString("grant_type=client_credentials"));
    assertThat(requestBody, not(containsString("client_secret=open+sesame")));
    assertThat(requestBody, not(containsString("client_id=Aladdin")));
  }

  @Test
  public void clientCredentialsEncodedInHeaderCompatibility() throws Exception {
    assertClientCredentialsEncodedInHeader(true);
  }

  @Test
  public void clientCredentialsEncodedInHeader() throws Exception {
    assertClientCredentialsEncodedInHeader(false);
  }

  @Test
  public void clientCredentialsEncodedInHeaderByDefault() throws Exception {
    final OAuthClientCredentialsDancerBuilder builder = baseClientCredentialsDancerBuilder();
    builder.tokenUrl("http://host/token");
    builder.clientCredentials(ALADDIN, "open sesame");

    startDancer(builder);

    ArgumentCaptor<HttpRequest> requestCaptor = forClass(HttpRequest.class);
    verify(httpClient).sendAsync(requestCaptor.capture(), any(HttpRequestOptions.class));

    assertThat(requestCaptor.getValue().getHeaderValue(AUTHORIZATION), is("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="));

    assertThat(requestCaptor.getValue().getQueryParams(), not(hasKey("client_id")));
    assertThat(requestCaptor.getValue().getQueryParams(), not(hasKey("client_secret")));

    String requestBody = IOUtils.toString(requestCaptor.getValue().getEntity().getContent(), UTF_8);
    assertThat(requestBody, containsString("grant_type=client_credentials"));
    assertThat(requestBody, not(containsString("client_secret=open+sesame")));
    assertThat(requestBody, not(containsString("client_id=Aladdin")));
  }

  private void assertClientCredentialsInBody(boolean useDeprecatedMethod) throws Exception {
    final OAuthClientCredentialsDancerBuilder builder = baseClientCredentialsDancerBuilder();
    builder.tokenUrl("http://host/token");
    builder.clientCredentials(ALADDIN, "open sesame");
    if (useDeprecatedMethod) {
      builder.encodeClientCredentialsInBody(true);
    } else {
      builder.withClientCredentialsIn(BODY);
    }

    startDancer(builder);

    ArgumentCaptor<HttpRequest> requestCaptor = forClass(HttpRequest.class);
    verify(httpClient).sendAsync(requestCaptor.capture(), any(HttpRequestOptions.class));

    assertThat(requestCaptor.getValue().getHeaderNames(), not(hasItem(equalToIgnoringCase(AUTHORIZATION))));

    assertThat(requestCaptor.getValue().getQueryParams(), not(hasKey("client_id")));
    assertThat(requestCaptor.getValue().getQueryParams(), not(hasKey("client_secret")));

    String requestBody = IOUtils.toString(requestCaptor.getValue().getEntity().getContent(), UTF_8);
    assertThat(requestBody, containsString("grant_type=client_credentials"));
    assertThat(requestBody, containsString("client_secret=open+sesame"));
    assertThat(requestBody, containsString("client_id=Aladdin"));
  }

  @Test
  public void clientCredentialsInBodyCompatibility() throws Exception {
    assertClientCredentialsInBody(true);
  }

  @Test
  public void clientCredentialsInBody() throws Exception {
    assertClientCredentialsInBody(false);
  }

  @Test
  public void clientCredentialsInQueryParams() throws Exception {
    final OAuthClientCredentialsDancerBuilder builder = baseClientCredentialsDancerBuilder();
    builder.tokenUrl("http://host/token");
    builder.clientCredentials(ALADDIN, OPEN_SESAME);
    builder.withClientCredentialsIn(QUERY_PARAMS);

    startDancer(builder);

    ArgumentCaptor<HttpRequest> requestCaptor = forClass(HttpRequest.class);
    verify(httpClient).sendAsync(requestCaptor.capture(), any(HttpRequestOptions.class));

    assertThat(requestCaptor.getValue().getHeaderNames(), not(hasItem(equalToIgnoringCase(AUTHORIZATION))));

    assertThat(requestCaptor.getValue().getQueryParams().get(CLIENT_ID), is(ALADDIN));
    assertThat(requestCaptor.getValue().getQueryParams().get(CLIENT_SECRET), is(OPEN_SESAME));

    String requestBody = IOUtils.toString(requestCaptor.getValue().getEntity().getContent(), UTF_8);
    assertThat(requestBody, containsString("grant_type=client_credentials"));
    assertThat(requestBody, not(containsString("client_secret=openSesame")));
    assertThat(requestBody, not(containsString("client_id=Aladdin")));
  }

  @Test
  public void clientCredentialsWithCustomQueryParams() throws Exception {
    final OAuthClientCredentialsDancerBuilder builder = baseClientCredentialsDancerBuilder();
    builder.tokenUrl("http://host/token");
    builder.clientCredentials(ALADDIN, OPEN_SESAME);
    builder.withClientCredentialsIn(QUERY_PARAMS);

    MultiMap<String, String> queryParams = new MultiMap<>();

    final String daenerys = "Daenerys";
    final String[] daenerysValues = new String[] {"First of her name", "Mother of Dragons", "Mad Queen"};
    final String jonSnow = "Jon Snow";
    final String[] snowValues = new String[] {"Commander of the Night Watch", "Looser"};

    Stream.of(daenerysValues).forEach(v -> queryParams.put(daenerys, v));
    Stream.of(snowValues).forEach(v -> queryParams.put(jonSnow, v));

    builder.customParameters(queryParams);

    startDancer(builder);

    ArgumentCaptor<HttpRequest> requestCaptor = forClass(HttpRequest.class);
    verify(httpClient).sendAsync(requestCaptor.capture(), any(HttpRequestOptions.class));

    HttpRequest request = requestCaptor.getValue();

    assertThat(request.getQueryParams().getAll(daenerys), containsInAnyOrder(daenerysValues));
    assertThat(request.getQueryParams().getAll(jonSnow), containsInAnyOrder(snowValues));
  }

  @Test
  public void clientCredentialsWithCustomHeaders() throws Exception {
    final OAuthClientCredentialsDancerBuilder builder = baseClientCredentialsDancerBuilder();
    builder.tokenUrl("http://host/token");
    builder.clientCredentials(ALADDIN, OPEN_SESAME);
    builder.withClientCredentialsIn(QUERY_PARAMS);

    MultiMap<String, String> customHeaders = new MultiMap<>();

    final String daenerys = "Daenerys";
    final String[] daenerysValues = new String[] {"First of her name", "Mother of Dragons", "Mad Queen"};
    final String jonSnow = "Jon Snow";
    final String[] snowValues = new String[] {"Commander of the Night Watch", "Looser"};

    Stream.of(daenerysValues).forEach(v -> customHeaders.put(daenerys, v));
    Stream.of(snowValues).forEach(v -> customHeaders.put(jonSnow, v));

    builder.customHeaders(customHeaders);

    startDancer(builder);

    ArgumentCaptor<HttpRequest> requestCaptor = forClass(HttpRequest.class);
    verify(httpClient).sendAsync(requestCaptor.capture(), any(HttpRequestOptions.class));

    HttpRequest request = requestCaptor.getValue();

    assertThat(request.getHeaders().getAll(daenerys), containsInAnyOrder(daenerysValues));
    assertThat(request.getHeaders().getAll(jonSnow), containsInAnyOrder(snowValues));
  }

  @Test
  public void exeptionOnTokenRequest() throws Exception {
    final IllegalStateException thrown = new IllegalStateException();
    when(httpClient.sendAsync(any(), any())).thenThrow(thrown);

    final Map<String, ? extends ResourceOwnerOAuthContext> tokensStore = new HashMap<>();
    final OAuthClientCredentialsDancerBuilder builder = baseClientCredentialsDancerBuilder(tokensStore);
    builder.tokenUrl("http://host/token");

    expected.expect(sameInstance(thrown));
    try {
      ClientCredentialsOAuthDancer minimalDancer = startDancer(builder);
    } finally {
      assertThat(isDancerStateNoToken(tokensStore.get("default")), is(true));
    }
  }

}
