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
import static org.mockito.Mockito.verify;
import static org.mule.runtime.http.api.HttpHeaders.Names.AUTHORIZATION;

import org.mule.runtime.http.api.client.HttpRequestOptions;
import org.mule.runtime.http.api.domain.message.request.HttpRequest;
import org.mule.runtime.oauth.api.ClientCredentialsOAuthDancer;
import org.mule.runtime.oauth.api.builder.OAuthClientCredentialsDancerBuilder;
import org.mule.test.oauth.AbstractOAuthTestCase;

import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.mockito.ArgumentCaptor;


public class ClientCredentialsTokenTestCase extends AbstractOAuthTestCase {

  @Test
  public void clientCredentialsEncodedInHeader() throws Exception {
    final OAuthClientCredentialsDancerBuilder builder = baseClientCredentialsDancerBuilder();
    builder.tokenUrl("http://host/token");
    builder.clientCredentials("Aladdin", "open sesame");

    ClientCredentialsOAuthDancer minimalDancer = startDancer(builder);

    ArgumentCaptor<HttpRequest> requestCaptor = forClass(HttpRequest.class);
    verify(httpClient).sendAsync(requestCaptor.capture(), any(HttpRequestOptions.class));

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
    verify(httpClient).sendAsync(requestCaptor.capture(), any(HttpRequestOptions.class));

    assertThat(requestCaptor.getValue().getHeaderNames(), not(hasItem(equalToIgnoringCase(AUTHORIZATION))));

    String requestBody = IOUtils.toString(requestCaptor.getValue().getEntity().getContent(), UTF_8);
    assertThat(requestBody, containsString("grant_type=client_credentials"));
    assertThat(requestBody, containsString("client_secret=open+sesame"));
    assertThat(requestBody, containsString("client_id=Aladdin"));
  }

}
