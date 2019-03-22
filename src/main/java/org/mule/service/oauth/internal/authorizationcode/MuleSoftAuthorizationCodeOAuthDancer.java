/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.service.oauth.internal.authorizationcode;

import org.mule.runtime.api.el.MuleExpressionLanguage;
import org.mule.runtime.api.exception.DefaultMuleException;
import org.mule.runtime.api.exception.MuleException;
import org.mule.runtime.api.exception.MuleRuntimeException;
import org.mule.runtime.api.lifecycle.InitialisationException;
import org.mule.runtime.api.lifecycle.Lifecycle;
import org.mule.runtime.api.lock.LockFactory;
import org.mule.runtime.api.metadata.MediaType;
import org.mule.runtime.api.util.MultiMap;
import org.mule.runtime.core.api.util.IOUtils;
import org.mule.runtime.core.api.util.StringUtils;
import org.mule.runtime.http.api.HttpConstants.HttpStatus;
import org.mule.runtime.http.api.HttpConstants.Method;
import org.mule.runtime.http.api.client.HttpClient;
import org.mule.runtime.http.api.domain.entity.ByteArrayHttpEntity;
import org.mule.runtime.http.api.domain.entity.EmptyHttpEntity;
import org.mule.runtime.http.api.domain.message.request.HttpRequest;
import org.mule.runtime.http.api.domain.message.response.HttpResponse;
import org.mule.runtime.http.api.domain.message.response.HttpResponseBuilder;
import org.mule.runtime.http.api.domain.request.HttpRequestContext;
import org.mule.runtime.http.api.server.HttpServer;
import org.mule.runtime.http.api.server.RequestHandler;
import org.mule.runtime.http.api.server.RequestHandlerManager;
import org.mule.runtime.http.api.server.async.HttpResponseReadyCallback;
import org.mule.runtime.http.api.server.async.ResponseStatusCallback;
import org.mule.runtime.oauth.api.AuthorizationCodeOAuthDancer;
import org.mule.runtime.oauth.api.AuthorizationCodeRequest;
import org.mule.runtime.oauth.api.builder.AuthorizationCodeDanceCallbackContext;
import org.mule.runtime.oauth.api.builder.AuthorizationCodeListener;
import org.mule.runtime.oauth.api.builder.ClientCredentialsLocation;
import org.mule.runtime.oauth.api.exception.RequestAuthenticationException;
import org.mule.runtime.oauth.api.exception.TokenNotFoundException;
import org.mule.runtime.oauth.api.exception.TokenUrlResponseException;
import org.mule.runtime.oauth.api.state.DefaultResourceOwnerOAuthContext;
import org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext;
import org.mule.service.oauth.internal.state.StateDecoder;
import org.mule.service.oauth.internal.state.StateEncoder;
import org.mule.service.oauth.internal.state.TokenResponse;
import org.slf4j.Logger;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.Lock;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Supplier;

import static java.lang.String.format;
import static java.lang.String.valueOf;
import static java.lang.Thread.currentThread;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singleton;
import static java.util.concurrent.CompletableFuture.completedFuture;
import static org.mule.runtime.api.i18n.I18nMessageFactory.createStaticMessage;
import static org.mule.runtime.api.metadata.MediaType.ANY;
import static org.mule.runtime.api.metadata.MediaType.parse;
import static org.mule.runtime.api.util.MultiMap.emptyMultiMap;
import static org.mule.runtime.api.util.Preconditions.checkArgument;
import static org.mule.runtime.core.api.util.ClassUtils.withContextClassLoader;
import static org.mule.runtime.core.api.util.StringUtils.isBlank;
import static org.mule.runtime.http.api.HttpConstants.HttpStatus.*;
import static org.mule.runtime.http.api.HttpConstants.Method.GET;
import static org.mule.runtime.http.api.HttpHeaders.Names.*;
import static org.mule.runtime.http.api.utils.HttpEncoderDecoderUtils.appendQueryParam;
import static org.mule.runtime.oauth.api.OAuthAuthorizationStatusCode.*;
import static org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext.DEFAULT_RESOURCE_OWNER_ID;
import static org.mule.service.oauth.internal.OAuthConstants.*;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Provides access token and refresh token from an external service, which performs the OAuth2 dance on our behalf.
 *
 * @since 1.0
 */
public class MuleSoftAuthorizationCodeOAuthDancer extends AbstractAuthorizationCodeOAuthDancer {

  private static final Map<String, CompletableFuture<Void>> activeRefreshFutures = new ConcurrentHashMap<>();

  public MuleSoftAuthorizationCodeOAuthDancer(String clientId, String clientSecret,
                                              String tokenUrl, String scopes, ClientCredentialsLocation clientCredentialsLocation,
                                              Charset encoding, String responseAccessTokenExpr, String responseRefreshTokenExpr,
                                              String responseExpiresInExpr, Map<String, String> customParametersExtractorsExprs, Function<String, String> resourceOwnerIdTransformer,
                                              LockFactory lockProvider, Map<String, DefaultResourceOwnerOAuthContext> tokensStore, HttpClient httpClient, MuleExpressionLanguage expressionEvaluator, List<AuthorizationCodeListener> listeners) {

    super(clientId, clientSecret, tokenUrl, encoding, scopes, clientCredentialsLocation, responseAccessTokenExpr,
            responseRefreshTokenExpr,
            responseExpiresInExpr, customParametersExtractorsExprs, resourceOwnerIdTransformer, lockProvider, tokensStore,
            httpClient, expressionEvaluator, listeners);
  }

  @Override
  public CompletableFuture<String> accessToken(String resourceOwnerId) throws RequestAuthenticationException {
    this.logDebug("Executing access token for user " + resourceOwnerId);

    final String accessToken = this.getContextForResourceOwner(resourceOwnerId).getAccessToken();

    if (accessToken == null) {
      this.logDebug("Access token not found in the ObjectStore. Starting request to obtain the token");
      return this.requestAccessTokenToMulesoftService(resourceOwnerId, null)
              .thenApply(result ->  this.getContextForResourceOwner(resourceOwnerId).getAccessToken());
    }


    // TODO MULE-11858 proactively refresh if the token has already expired based on its 'expiresIn' parameter
    return completedFuture(accessToken);
  }

  @Override
  public CompletableFuture<Void> refreshToken(String resourceOwnerId) {
    this.logDebug("Executing refresh token for resourceOwnerId " + resourceOwnerId);
    return this.refreshToken(resourceOwnerId, false);
  }

  @Override
  public CompletableFuture<Void> refreshToken(String resourceOwnerId, boolean useQueryParameters) {
    this.logDebug("Executing refresh token for resourceOwnerId " + resourceOwnerId);

    final String accessToken = this.getContextForResourceOwner(resourceOwnerId).getAccessToken();
    return this.requestAccessTokenToMulesoftService(resourceOwnerId, accessToken);
  }

  private CompletableFuture<Void> requestAccessTokenToMulesoftService(String resourceOwner, String accessToken) {
    final DefaultResourceOwnerOAuthContext resourceOwnerOAuthContext = (DefaultResourceOwnerOAuthContext) getContextForResourceOwner(resourceOwner);
    String nullSafeResourceOwner = "" + resourceOwner;
    CompletableFuture<Void> activeRefreshFuture = activeRefreshFutures.get(nullSafeResourceOwner);

    // Return the active future if present
    if (activeRefreshFuture != null) {
      return activeRefreshFuture;
    }

    Lock lock = resourceOwnerOAuthContext.getRefreshUserOAuthContextLock();
    final boolean lockWasAcquired = lock.tryLock();

    if (lockWasAcquired) {
      try {
        CompletableFuture<Void> refreshFuture = this.getCoreServicesAccessToken()
          .thenAccept(coreServicesAccessToken -> {

            // Define body to send to the request
            final MultiMap<String, String> queryParams = emptyMultiMap();
            final MultiMap<String, String> formData = new MultiMap<>();
            formData.put(GRANT_TYPE_PARAMETER, GRANT_TYPE_AUTHENTICATION_CODE);
            formData.put(ACCESS_TOKEN_PARAMETER, accessToken);

            // Create authorization header to authorize request to the tokenUrl
            String authorization = "Bearer " + coreServicesAccessToken;

            this.invokeTokenUrl(tokenUrl, formData, queryParams, authorization, true, encoding)
              .thenAccept(tokenResponse -> {
                lock.lock();
                try {
                  withContextClassLoader(MuleSoftAuthorizationCodeOAuthDancer.class.getClassLoader(), () -> {
                    this.logDebug("Update OAuth Context for resourceOwnerId " + resourceOwnerOAuthContext.getResourceOwnerId());
                    this.updateResourceOwnerState(resourceOwnerOAuthContext, null, tokenResponse);
                    this.updateResourceOwnerOAuthContext(resourceOwnerOAuthContext);
                    this.listeners.forEach(l -> l.onTokenRefreshed(resourceOwnerOAuthContext));
                  });
                } finally {
                  lock.unlock();
                }
              });
          });

        activeRefreshFutures.put(nullSafeResourceOwner, refreshFuture);
        refreshFuture.thenRun(() -> activeRefreshFutures.remove(nullSafeResourceOwner, refreshFuture));
        return refreshFuture;
      } finally {
        lock.unlock();
      }
    } else {
      lock.lock();
      try {
        return activeRefreshFutures.get(nullSafeResourceOwner);
      } finally {
        lock.unlock();
      }
    }
  }

  private CompletableFuture<String> getCoreServicesAccessToken() {
    this.logDebug("Getting Core Services access token");

    String clientId = System.getProperty("objectstore.client.clientId");
    String clientSecret = System.getProperty("objectstore.client.clientSecret");

    // TODO: Get CS API somehow
    // TODO: Add token caching
    // TODO: Check token expiration, if possible
    return completedFuture("core-services-access-token");
  }
}
