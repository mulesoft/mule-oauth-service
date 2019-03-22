package org.mule.service.oauth.internal.builder;

import org.mule.runtime.api.el.MuleExpressionLanguage;
import org.mule.runtime.api.lock.LockFactory;
import org.mule.runtime.http.api.client.HttpClient;
import org.mule.runtime.http.api.domain.message.request.HttpRequest;
import org.mule.runtime.http.api.server.HttpServer;
import org.mule.runtime.http.api.server.async.HttpResponseReadyCallback;
import org.mule.runtime.oauth.api.AuthorizationCodeOAuthDancer;
import org.mule.runtime.oauth.api.AuthorizationCodeRequest;
import org.mule.runtime.oauth.api.builder.AuthorizationCodeDanceCallbackContext;
import org.mule.runtime.oauth.api.builder.AuthorizationCodeListener;
import org.mule.runtime.oauth.api.builder.ClientCredentialsLocation;
import org.mule.runtime.oauth.api.exception.RequestAuthenticationException;
import org.mule.runtime.oauth.api.state.DefaultResourceOwnerOAuthContext;
import org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext;
import org.mule.service.oauth.internal.authorizationcode.DefaultAuthorizationCodeOAuthDancer;
import org.mule.service.oauth.internal.authorizationcode.MuleSoftAuthorizationCodeOAuthDancer;

import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Supplier;

public class AuthorizationCodeOAuthDancerDelegate implements AuthorizationCodeOAuthDancer {

    private AuthorizationCodeOAuthDancer defaultAuthorizationCodeOAuthDancer;
    private AuthorizationCodeOAuthDancer mulesoftAuthorizationCodeOAuthDancer;
    private final String resourceOwnerIdPrefix = "MULESOFT-";

    public AuthorizationCodeOAuthDancerDelegate(Optional<HttpServer> httpServer, String clientId, String clientSecret,
                                                String tokenUrl, String scopes, ClientCredentialsLocation clientCredentialsLocation,
                                                String externalCallbackUrl, Charset encoding,
                                                String localCallbackUrlPath, String localAuthorizationUrlPath,
                                                String localAuthorizationUrlResourceOwnerId, String state, String authorizationUrl,
                                                String responseAccessTokenExpr, String responseRefreshTokenExpr,
                                                String responseExpiresInExpr, Supplier<Map<String, String>> customParameters,
                                                Map<String, String> customParametersExtractorsExprs,
                                                Function<String, String> resourceOwnerIdTransformer,
                                                LockFactory lockProvider, Map<String, DefaultResourceOwnerOAuthContext> tokensStore,
                                                HttpClient httpClient, MuleExpressionLanguage expressionEvaluator,
                                                Function<AuthorizationCodeRequest, AuthorizationCodeDanceCallbackContext> beforeDanceCallback,
                                                BiConsumer<AuthorizationCodeDanceCallbackContext, ResourceOwnerOAuthContext> afterDanceCallback,
                                                List<AuthorizationCodeListener> listeners) {

        this.defaultAuthorizationCodeOAuthDancer = new DefaultAuthorizationCodeOAuthDancer(httpServer, clientId, clientSecret,
                tokenUrl, scopes, clientCredentialsLocation, externalCallbackUrl, encoding,
                localCallbackUrlPath, localAuthorizationUrlPath,
                localAuthorizationUrlResourceOwnerId, state,
                authorizationUrl, responseAccessTokenExpr, responseRefreshTokenExpr,
                responseExpiresInExpr, customParameters, customParametersExtractorsExprs,
                resourceOwnerIdTransformer, lockProvider, tokensStore,
                httpClient, expressionEvaluator, beforeDanceCallback,
                afterDanceCallback, listeners);

        this.mulesoftAuthorizationCodeOAuthDancer = new MuleSoftAuthorizationCodeOAuthDancer(clientId, clientSecret,
                tokenUrl, scopes, clientCredentialsLocation, encoding,
                responseAccessTokenExpr, responseRefreshTokenExpr,
                responseExpiresInExpr, customParametersExtractorsExprs,
                resourceOwnerIdTransformer, lockProvider, tokensStore,
                httpClient, expressionEvaluator, listeners);
    }

    @Override
    public CompletableFuture<String> accessToken(String resourceOwnerId) throws RequestAuthenticationException {
        if (resourceOwnerId.startsWith(resourceOwnerIdPrefix)) {
            return this.mulesoftAuthorizationCodeOAuthDancer.accessToken(resourceOwnerId);
        }

        return this.defaultAuthorizationCodeOAuthDancer.accessToken(resourceOwnerId);
    }

    @Override
    public CompletableFuture<Void> refreshToken(String resourceOwnerId) {
        if (resourceOwnerId.startsWith(resourceOwnerIdPrefix)) {
            return this.mulesoftAuthorizationCodeOAuthDancer.refreshToken(resourceOwnerId);
        }

        return this.defaultAuthorizationCodeOAuthDancer.refreshToken(resourceOwnerId);
    }

    @Override
    public CompletableFuture<Void> refreshToken(String resourceOwnerId, boolean useQueryParameters) {
        if (resourceOwnerId.startsWith(resourceOwnerIdPrefix)) {
            return this.mulesoftAuthorizationCodeOAuthDancer.refreshToken(resourceOwnerId, useQueryParameters);
        }

        return this.defaultAuthorizationCodeOAuthDancer.refreshToken(resourceOwnerId, useQueryParameters);
    }

    @Override
    public void invalidateContext(String resourceOwnerId) {
        if (resourceOwnerId.startsWith(resourceOwnerIdPrefix)) {
            this.mulesoftAuthorizationCodeOAuthDancer.invalidateContext(resourceOwnerId);
            return;
        }

        this.defaultAuthorizationCodeOAuthDancer.invalidateContext(resourceOwnerId);
    }

    @Override
    public ResourceOwnerOAuthContext getContextForResourceOwner(String resourceOwnerId) {
        if (resourceOwnerId.startsWith(resourceOwnerIdPrefix)) {
            return this.mulesoftAuthorizationCodeOAuthDancer.getContextForResourceOwner(resourceOwnerId);
        }

        return this.defaultAuthorizationCodeOAuthDancer.getContextForResourceOwner(resourceOwnerId);
    }

    // TODO: we should find a way to decide which one to use for these three methods

    @Override
    public void handleLocalAuthorizationRequest(HttpRequest request, HttpResponseReadyCallback responseCallback) {
        this.defaultAuthorizationCodeOAuthDancer.handleLocalAuthorizationRequest(request, responseCallback);
    }

    @Override
    public void addListener(AuthorizationCodeListener listener) {
        this.defaultAuthorizationCodeOAuthDancer.addListener(listener);
    }

    @Override
    public void removeListener(AuthorizationCodeListener listener) {
        this.defaultAuthorizationCodeOAuthDancer.removeListener(listener);
    }
}