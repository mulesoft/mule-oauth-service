/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.service.oauth.internal;

import static java.lang.String.format;
import static java.lang.Thread.currentThread;
import static java.lang.Thread.sleep;
import static java.util.Collections.singletonMap;
import static java.util.concurrent.CompletableFuture.completedFuture;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.apache.commons.codec.binary.Base64.encodeBase64String;
import static org.mule.runtime.api.metadata.DataType.STRING;
import static org.mule.runtime.api.metadata.MediaType.ANY;
import static org.mule.runtime.api.metadata.MediaType.parse;
import static org.mule.runtime.api.scheduler.SchedulerConfig.config;
import static org.mule.runtime.core.api.util.ClassUtils.withContextClassLoader;
import static org.mule.runtime.http.api.HttpConstants.HttpStatus.BAD_REQUEST;
import static org.mule.runtime.http.api.HttpConstants.Method.POST;
import static org.mule.runtime.http.api.HttpHeaders.Names.AUTHORIZATION;
import static org.mule.runtime.http.api.HttpHeaders.Names.CONTENT_TYPE;
import static org.mule.runtime.http.api.HttpHeaders.Values.APPLICATION_X_WWW_FORM_URLENCODED;
import static org.mule.runtime.http.api.utils.HttpEncoderDecoderUtils.encodeString;
import static org.mule.runtime.oauth.api.builder.ClientCredentialsLocation.QUERY_PARAMS;
import static org.mule.runtime.oauth.api.state.DefaultResourceOwnerOAuthContext.createRefreshUserOAuthContextLock;
import static org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext.DEFAULT_RESOURCE_OWNER_ID;
import static org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext.DancerState.HAS_TOKEN;
import static org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext.DancerState.NO_TOKEN;
import static org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext.DancerState.REFRESHING_TOKEN;
import static org.mule.service.oauth.internal.OAuthConstants.CLIENT_ID_PARAMETER;
import static org.mule.service.oauth.internal.OAuthConstants.CLIENT_SECRET_PARAMETER;

import org.mule.runtime.api.el.BindingContext;
import org.mule.runtime.api.el.MuleExpressionLanguage;
import org.mule.runtime.api.exception.MuleException;
import org.mule.runtime.api.lifecycle.Startable;
import org.mule.runtime.api.lifecycle.Stoppable;
import org.mule.runtime.api.lock.LockFactory;
import org.mule.runtime.api.metadata.DataType;
import org.mule.runtime.api.metadata.MediaType;
import org.mule.runtime.api.metadata.TypedValue;
import org.mule.runtime.api.scheduler.Scheduler;
import org.mule.runtime.api.scheduler.SchedulerService;
import org.mule.runtime.api.util.MultiMap;
import org.mule.runtime.core.api.util.IOUtils;
import org.mule.runtime.http.api.client.HttpClient;
import org.mule.runtime.http.api.client.HttpRequestOptions;
import org.mule.runtime.http.api.domain.entity.ByteArrayHttpEntity;
import org.mule.runtime.http.api.domain.message.request.HttpRequest;
import org.mule.runtime.http.api.domain.message.request.HttpRequestBuilder;
import org.mule.runtime.oauth.api.builder.ClientCredentialsLocation;
import org.mule.runtime.oauth.api.exception.TokenNotFoundException;
import org.mule.runtime.oauth.api.exception.TokenUrlResponseException;
import org.mule.runtime.oauth.api.state.DefaultResourceOwnerOAuthContext;
import org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext;
import org.mule.service.oauth.internal.state.TokenResponse;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.locks.Lock;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Base implementations with behavior common to all grant-types.
 *
 * @since 1.0
 */
public abstract class AbstractOAuthDancer implements Startable, Stoppable {

  private static final int TOKEN_REQUEST_TIMEOUT_MILLIS = 60000;

  protected final String name;

  protected final String clientId;
  protected final String clientSecret;
  protected final String tokenUrl;
  protected final Charset encoding;
  protected final String scopes;
  protected final ClientCredentialsLocation clientCredentialsLocation;

  protected final String responseAccessTokenExpr;
  protected final String responseRefreshTokenExpr;
  protected final String responseExpiresInExpr;
  protected final Map<String, String> customParametersExtractorsExprs;
  protected final Function<String, String> resourceOwnerIdTransformer;

  private final SchedulerService schedulerService;
  private final LockFactory lockProvider;
  private final Map<String, ResourceOwnerOAuthContext> tokensStore;
  private final HttpClient httpClient;
  private final MuleExpressionLanguage expressionEvaluator;
  private Scheduler pollScheduler;

  protected AbstractOAuthDancer(String name, String clientId, String clientSecret, String tokenUrl, Charset encoding,
                                String scopes,
                                ClientCredentialsLocation clientCredentialsLocation, String responseAccessTokenExpr,
                                String responseRefreshTokenExpr, String responseExpiresInExpr,
                                Map<String, String> customParametersExtractorsExprs,
                                Function<String, String> resourceOwnerIdTransformer, SchedulerService schedulerService,
                                LockFactory lockProvider,
                                Map<String, ResourceOwnerOAuthContext> tokensStore, HttpClient httpClient,
                                MuleExpressionLanguage expressionEvaluator) {
    this.name = name;

    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.tokenUrl = tokenUrl;
    this.encoding = encoding;
    this.scopes = scopes;
    this.clientCredentialsLocation = clientCredentialsLocation;
    this.responseAccessTokenExpr = responseAccessTokenExpr;
    this.responseRefreshTokenExpr = responseRefreshTokenExpr;
    this.responseExpiresInExpr = responseExpiresInExpr;
    this.customParametersExtractorsExprs = customParametersExtractorsExprs;
    this.resourceOwnerIdTransformer = resourceOwnerIdTransformer;

    this.schedulerService = schedulerService;
    this.lockProvider = lockProvider;
    this.tokensStore = tokensStore;
    this.httpClient = httpClient;
    this.expressionEvaluator = expressionEvaluator;
  }

  @Override
  public void start() throws MuleException {
    httpClient.start();
    pollScheduler = schedulerService.ioScheduler(config()
        .withName(name + "-oauthDancer-tokenRefreshPoll")
        .withShutdownTimeout(0, MILLISECONDS));
  }

  @Override
  public void stop() throws MuleException {
    if (pollScheduler != null) {
      pollScheduler.stop();
    }
    httpClient.stop();
  }

  /**
   * Based on the value of {@code clientCredentialsLocation}, add the clientId and clientSecret values to the form or encode and
   * return them.
   *
   * @param formData
   */
  protected String handleClientCredentials(final Map<String, String> formData) {
    switch (clientCredentialsLocation) {
      case BASIC_AUTH_HEADER:
        return "Basic " + encodeBase64String(format("%s:%s", clientId, clientSecret).getBytes());
      case BODY:
        formData.put(CLIENT_ID_PARAMETER, clientId);
        formData.put(CLIENT_SECRET_PARAMETER, clientSecret);
    }
    return null;
  }

  /**
   * Method for refreshing tokens in a thread-safe manner across nodes of a cluster.
   */
  protected CompletableFuture<Void> doRefreshToken(Supplier<ResourceOwnerOAuthContext> oauthContextSupplier,
                                                   Function<ResourceOwnerOAuthContext, CompletableFuture<Void>> tokenRefreshRequester) {
    ResourceOwnerOAuthContext oauthContext = oauthContextSupplier.get();

    final Lock lock = oauthContext.getRefreshUserOAuthContextLock(name, getLockProvider());

    // If the context was just created, initialize it.
    if (oauthContext.getDancerState() == NO_TOKEN) {
      if (lock.tryLock()) {
        try {
          oauthContext = oauthContextSupplier.get();
          if (oauthContext.getDancerState() == HAS_TOKEN) {
            // Some other thread/node completed the refresh before lock was acquired here. Very quickly and quite improbable, but
            // possible.
            return completedFuture(null);
          } else if (oauthContext.getDancerState() == REFRESHING_TOKEN) {
            return pollForRefreshComplete(oauthContextSupplier);
          } else if (oauthContext.getDancerState() == NO_TOKEN) {
            ((DefaultResourceOwnerOAuthContext) oauthContext).setDancerState(REFRESHING_TOKEN);
            updateResourceOwnerOAuthContext(oauthContext);

            return tokenRefreshRequester.apply(oauthContext);
          }
        } finally {
          lock.unlock();
        }
      } else {
        return pollForRefreshComplete(oauthContextSupplier);
      }
    }

    // If there is a previous token, refresh it
    if (oauthContext.getDancerState() == HAS_TOKEN) {
      final String accessToken = oauthContext.getAccessToken();
      lock.lock();
      try {
        oauthContext = oauthContextSupplier.get();
        if (oauthContext.getDancerState() == HAS_TOKEN) {
          if (accessToken.equals(oauthContext.getAccessToken())) {
            ((DefaultResourceOwnerOAuthContext) oauthContext).setDancerState(REFRESHING_TOKEN);
            updateResourceOwnerOAuthContext(oauthContext);

            return tokenRefreshRequester.apply(oauthContext);
          } else {
            // Some other thread/node completed the refresh before lock was acquired here. Very quickly and quite improbable, but
            // possible.
            return completedFuture(null);
          }
        } else if (oauthContext.getDancerState() == REFRESHING_TOKEN) {
          return pollForRefreshComplete(oauthContextSupplier);
        } else if (oauthContext.getDancerState() == NO_TOKEN) {
          ((DefaultResourceOwnerOAuthContext) oauthContext).setDancerState(REFRESHING_TOKEN);
          updateResourceOwnerOAuthContext(oauthContext);

          return tokenRefreshRequester.apply(oauthContext);
        }
      } finally {
        lock.unlock();
      }
    }

    // In any other case, a refresh is being done elsewhere, so we poll for it
    return pollForRefreshComplete(oauthContextSupplier);
  }

  private CompletableFuture<Void> pollForRefreshComplete(Supplier<ResourceOwnerOAuthContext> oauthContextSupplier) {
    final CompletableFuture<Void> pendingResponse = new CompletableFuture<>();

    pollScheduler.execute(() -> {
      DefaultResourceOwnerOAuthContext ctx = (DefaultResourceOwnerOAuthContext) oauthContextSupplier.get();

      while (ctx.getDancerState() == REFRESHING_TOKEN) {
        try {
          sleep(10);
        } catch (InterruptedException e) {
          currentThread().interrupt();
          pendingResponse.completeExceptionally(e);
        }
        ctx = (DefaultResourceOwnerOAuthContext) oauthContextSupplier.get();
      }
      pendingResponse.complete(null);
    });

    return pendingResponse;
  }

  protected CompletableFuture<TokenResponse> invokeTokenUrl(String tokenUrl,
                                                            Map<String, String> tokenRequestFormToSend,
                                                            MultiMap<String, String> queryParams,
                                                            MultiMap<String, String> headers,
                                                            String authorization,
                                                            boolean retrieveRefreshToken,
                                                            Charset encoding) {
    final HttpRequestBuilder requestBuilder = HttpRequest.builder()
        .uri(tokenUrl).method(POST.name())
        .entity(new ByteArrayHttpEntity(encodeString(tokenRequestFormToSend, encoding).getBytes()))
        .addHeader(CONTENT_TYPE, APPLICATION_X_WWW_FORM_URLENCODED.toRfcString())
        .queryParams(queryParams)
        .headers(headers);

    if (authorization != null) {
      requestBuilder.addHeader(AUTHORIZATION, authorization);
    } else if (QUERY_PARAMS.equals(clientCredentialsLocation)) {
      requestBuilder.addQueryParam(CLIENT_ID_PARAMETER, clientId);
      requestBuilder.addQueryParam(CLIENT_SECRET_PARAMETER, clientSecret);
    }

    return httpClient.sendAsync(requestBuilder.build(), HttpRequestOptions.builder()
        .responseTimeout(TOKEN_REQUEST_TIMEOUT_MILLIS)
        .build())
        .exceptionally(t -> {
          return withContextClassLoader(AbstractOAuthDancer.class.getClassLoader(), () -> {
            if (t instanceof IOException) {
              throw new CompletionException(new TokenUrlResponseException(tokenUrl, (IOException) t));
            } else {
              throw new CompletionException(t);
            }
          });
        })
        .thenApply(response -> {
          return withContextClassLoader(AbstractOAuthDancer.class.getClassLoader(), () -> {
            String contentType = response.getHeaderValue(CONTENT_TYPE);
            MediaType responseContentType = contentType != null ? parse(contentType) : ANY;

            String body;
            try (InputStream content = response.getEntity().getContent()) {
              body = IOUtils.toString(content);

              if (response.getStatusCode() >= BAD_REQUEST.getStatusCode()) {
                try {
                  throw new CompletionException(new TokenUrlResponseException(tokenUrl, response, body));
                } catch (IOException e) {
                  throw new CompletionException(new TokenUrlResponseException(tokenUrl, e));
                }
              }
            }

            MultiMap<String, String> responseHeaders = response.getHeaders();

            TokenResponse tokenResponse = new TokenResponse();
            tokenResponse
                .setAccessToken(resolveExpression(responseAccessTokenExpr, body, responseHeaders, responseContentType));
            if (tokenResponse.getAccessToken() == null) {
              throw new CompletionException(new TokenNotFoundException(tokenUrl, response, body));
            }
            if (retrieveRefreshToken) {
              tokenResponse
                  .setRefreshToken(resolveExpression(responseRefreshTokenExpr, body, responseHeaders, responseContentType));
            }
            tokenResponse.setExpiresIn(resolveExpression(responseExpiresInExpr, body, responseHeaders, responseContentType));

            if (customParametersExtractorsExprs != null && !customParametersExtractorsExprs.isEmpty()) {
              Map<String, Object> customParams = new HashMap<>();
              for (Entry<String, String> customParamExpr : customParametersExtractorsExprs.entrySet()) {
                customParams.put(customParamExpr.getKey(),
                                 resolveExpression(customParamExpr.getValue(), body, responseHeaders, responseContentType));
              }
              tokenResponse.setCustomResponseParameters(customParams);
            }

            return tokenResponse;
          });
        });
  }

  protected <T> T resolveExpression(String expr, Object body, MultiMap<String, String> headers,
                                    MediaType responseContentType) {
    if (expr == null) {
      return null;
    } else if (!expressionEvaluator.isExpression(expr)) {
      return (T) expr;
    } else {
      BindingContext resultContext = BindingContext.builder()
          .addBinding("payload",
                      new TypedValue(body, DataType.builder().fromObject(body)
                          .mediaType(responseContentType).build()))

          .addBinding("attributes", new TypedValue(singletonMap("headers", headers.toImmutableMultiMap()),
                                                   DataType.fromType(Map.class)))
          .addBinding("dataType",
                      new TypedValue(DataType.builder().fromObject(body).mediaType(responseContentType)
                          .build(), DataType.fromType(DataType.class)))
          .build();

      return (T) expressionEvaluator.evaluate(expr, STRING, resultContext).getValue();
    }
  }

  protected <T> T resolveExpression(String expr, Object body, MultiMap<String, String> headers,
                                    MultiMap<String, String> queryParams, MediaType responseContentType) {
    if (expr == null) {
      return null;
    } else if (!expressionEvaluator.isExpression(expr)) {
      return (T) expr;
    } else {
      Map<Object, Object> attributes = new HashMap<>(2);
      attributes.put("headers", headers.toImmutableMultiMap());
      attributes.put("queryParams", queryParams.toImmutableMultiMap());

      BindingContext resultContext = BindingContext.builder()
          .addBinding("payload",
                      new TypedValue(body, DataType.builder().fromObject(body)
                          .mediaType(responseContentType).build()))

          .addBinding("attributes", new TypedValue(attributes, DataType.fromType(Map.class)))
          .addBinding("dataType",
                      new TypedValue(DataType.builder().fromObject(body).mediaType(responseContentType)
                          .build(), DataType.fromType(DataType.class)))
          .build();

      return (T) expressionEvaluator.evaluate(expr, DataType.STRING, resultContext).getValue();
    }
  }

  public void invalidateContext(String resourceOwner) {
    final Lock refreshUserOAuthContextLock =
        ((DefaultResourceOwnerOAuthContext) getContextForResourceOwner(resourceOwner))
            .getRefreshUserOAuthContextLock(name, getLockProvider());
    refreshUserOAuthContextLock.lock();
    try {
      tokensStore.remove(resourceOwnerIdTransformer.apply(resourceOwner));
    } finally {
      refreshUserOAuthContextLock.unlock();
    }
  }

  /**
   * Retrieves the oauth context for a particular user. If there's no state for that user a new state is retrieve so never returns
   * null.
   *
   * @param resourceOwnerId id of the user.
   * @return oauth state
   */
  public ResourceOwnerOAuthContext getContextForResourceOwner(String resourceOwnerId) {
    if (resourceOwnerId == null) {
      resourceOwnerId = DEFAULT_RESOURCE_OWNER_ID;
    }

    final String transformedResourceOwnerId = resourceOwnerIdTransformer.apply(resourceOwnerId);

    ResourceOwnerOAuthContext resourceOwnerOAuthContext = null;
    if (!tokensStore.containsKey(transformedResourceOwnerId)) {
      final Lock lock = createRefreshUserOAuthContextLock(name, lockProvider, resourceOwnerId);
      lock.lock();
      try {
        if (!tokensStore.containsKey(transformedResourceOwnerId)) {
          resourceOwnerOAuthContext = new DefaultResourceOwnerOAuthContext(resourceOwnerId);
          tokensStore.put(transformedResourceOwnerId, resourceOwnerOAuthContext);
        }
      } finally {
        lock.unlock();
      }
    }
    if (resourceOwnerOAuthContext == null) {
      resourceOwnerOAuthContext = tokensStore.get(transformedResourceOwnerId);
    }
    return resourceOwnerOAuthContext;
  }

  /**
   * Updates the resource owner oauth context information
   *
   * @param resourceOwnerOAuthContext
   */
  protected void updateResourceOwnerOAuthContext(ResourceOwnerOAuthContext resourceOwnerOAuthContext) {
    final Lock resourceOwnerContextLock =
        ((DefaultResourceOwnerOAuthContext) resourceOwnerOAuthContext)
            .getRefreshUserOAuthContextLock(name, getLockProvider());
    resourceOwnerContextLock.lock();
    try {
      tokensStore.put(resourceOwnerIdTransformer.apply(resourceOwnerOAuthContext.getResourceOwnerId()),
                      resourceOwnerOAuthContext);
    } finally {
      resourceOwnerContextLock.unlock();
    }
  }

  protected LockFactory getLockProvider() {
    return lockProvider;
  }
}
