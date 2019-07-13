/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.service.oauth.internal;

import org.mule.runtime.api.exception.MuleRuntimeException;
import org.mule.runtime.api.lock.LockFactory;
import org.mule.runtime.oauth.api.state.DefaultResourceOwnerOAuthContext;
import org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;

/**
 * Provides a common utility layer to interact with the {@link ResourceOwnerOAuthContext} implementations in the OAuth service api
 * regardless of the changes introduced in 4.2.2.
 */
public final class ResourceOwnerOAuthContextUtils {

  private static Class<? extends ResourceOwnerOAuthContext> ctxWithStateClass;
  private static Method ctxWithStateSetAccessTokenMethod;
  private static Method ctxWithStateSetRefreshTokenMethod;
  private static Method ctxWithStateSetExpiresInMethod;
  private static Method ctxWithStateSetStateMethod;
  private static Class<Enum> dancerStateEnumClass;
  private static Method ctxWithStateGetDancerStateMethod;
  private static Method ctxWithStateSetDancerStateMethod;
  private static Method createRefreshUserOAuthContextLock = null;
  private static Method getRefreshUserOAuthContextLock = null;
  private static Constructor<? extends ResourceOwnerOAuthContext> ctxWithStateCtor;
  private static Constructor<? extends ResourceOwnerOAuthContext> ctxWithStateCopyConstructor;

  static {
    // This code uses reflection to detect what version of the OAuth service API is in the runtime.
    // In case the new methods are detected, those are called via reflection. Can't use them directly because this code has to
    // compile against the older version of the service API.
    // In case the new methods are not found, the original logic is executed.

    try {
      ctxWithStateClass = (Class<? extends ResourceOwnerOAuthContext>) Class
          .forName("org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContextWithRefreshState");

      ctxWithStateSetAccessTokenMethod = ctxWithStateClass.getDeclaredMethod("setAccessToken", String.class);
      ctxWithStateSetRefreshTokenMethod = ctxWithStateClass.getDeclaredMethod("setRefreshToken", String.class);
      ctxWithStateSetExpiresInMethod = ctxWithStateClass.getDeclaredMethod("setExpiresIn", String.class);
      ctxWithStateSetStateMethod = ctxWithStateClass.getDeclaredMethod("setState", String.class);
      dancerStateEnumClass = (Class<Enum>) Class.forName("org.mule.runtime.oauth.api.state.DancerState");
      ctxWithStateGetDancerStateMethod = ctxWithStateClass.getDeclaredMethod("getDancerState");
      ctxWithStateSetDancerStateMethod =
          ctxWithStateClass.getDeclaredMethod("setDancerState", dancerStateEnumClass);
      getRefreshUserOAuthContextLock =
          ctxWithStateClass.getDeclaredMethod("getRefreshOAuthContextLock", String.class, LockFactory.class);
      createRefreshUserOAuthContextLock =
          ctxWithStateClass.getDeclaredMethod("createRefreshOAuthContextLock", String.class, LockFactory.class, String.class);
      ctxWithStateCtor = ctxWithStateClass.getConstructor(String.class);
      ctxWithStateCopyConstructor = ctxWithStateClass.getConstructor(ResourceOwnerOAuthContext.class);

    } catch (NoSuchMethodException | ClassNotFoundException e) {
      // Nothing to do, this is just using an older version of the api
    } catch (SecurityException e) {
      throw e;
    }
  }

  private ResourceOwnerOAuthContextUtils() {
    // Nothing to do
  }

  public static ResourceOwnerOAuthContext createResourceOwnerOAuthContext(final Lock refreshUserOAuthContextLock,
                                                                          final String resourceOwnerId) {
    try {
      if (ctxWithStateCtor != null) {
        return ctxWithStateCtor.newInstance(resourceOwnerId);
      } else {
        return new DefaultResourceOwnerOAuthContext(refreshUserOAuthContextLock, resourceOwnerId);
      }
    } catch (InvocationTargetException e) {
      throw new MuleRuntimeException(e.getCause());
    } catch (InstantiationException | IllegalAccessException | IllegalArgumentException e) {
      throw new MuleRuntimeException(e);
    }
  }

  public static ResourceOwnerOAuthContext migrateContextIfNeeded(ResourceOwnerOAuthContext resourceOwnerOAuthContext, String name,
                                                                 LockFactory lockFactory) {
    if (ctxWithStateClass != null) {
      try {
        return ctxWithStateCopyConstructor.newInstance(resourceOwnerOAuthContext);
      } catch (InstantiationException | InvocationTargetException e) {
        throw new MuleRuntimeException(e.getCause());
      } catch (IllegalAccessException | IllegalArgumentException e) {
        throw new MuleRuntimeException(e);
      }
    } else {
      ((DefaultResourceOwnerOAuthContext) resourceOwnerOAuthContext)
          .setRefreshUserOAuthContextLock(createLockForResourceOwner(resourceOwnerOAuthContext.getResourceOwnerId(), name,
                                                                     lockFactory));
      return resourceOwnerOAuthContext;
    }
  }

  private static Lock createLockForResourceOwner(String resourceOwnerId, String configName, LockFactory lockFactory) {
    return lockFactory.createLock(configName + "-" + resourceOwnerId);
  }

  public static Lock getRefreshUserOAuthContextLock(ResourceOwnerOAuthContext resourceOwnerOAuthContext, String name,
                                                    LockFactory lockFactory) {
    if (getRefreshUserOAuthContextLock != null) {
      try {
        return (Lock) getRefreshUserOAuthContextLock.invoke(resourceOwnerOAuthContext, name, lockFactory);
      } catch (IllegalAccessException | IllegalArgumentException e) {
        throw new MuleRuntimeException(e);
      } catch (InvocationTargetException e) {
        throw new MuleRuntimeException(e.getCause());
      }
    } else {
      return ((DefaultResourceOwnerOAuthContext) resourceOwnerOAuthContext).getRefreshUserOAuthContextLock();
    }
  }

  public static Lock createRefreshUserOAuthContextLock(String lockNamePrefix, LockFactory lockProvider, String resourceOwnerId) {
    if (createRefreshUserOAuthContextLock != null) {
      try {
        return (Lock) createRefreshUserOAuthContextLock.invoke(null, lockNamePrefix, lockProvider, resourceOwnerId);
      } catch (IllegalAccessException | IllegalArgumentException e) {
        throw new MuleRuntimeException(e);
      } catch (InvocationTargetException e) {
        throw new MuleRuntimeException(e.getCause());
      }
    } else {
      return lockProvider.createLock(lockNamePrefix + "-config-oauth-context");
    }
  }

  /**
   * Sets the access token of the oauth context retrieved by the token request into the provided context.
   */
  public static void setAccessToken(ResourceOwnerOAuthContext resourceOwnerOAuthContext, String accessToken) {
    try {
      if (ctxWithStateSetAccessTokenMethod != null) {
        ctxWithStateSetAccessTokenMethod.invoke(resourceOwnerOAuthContext, accessToken);
      } else {
        ((DefaultResourceOwnerOAuthContext) resourceOwnerOAuthContext).setAccessToken(accessToken);
      }
    } catch (InvocationTargetException e) {
      throw new MuleRuntimeException(e.getCause());
    } catch (IllegalAccessException | IllegalArgumentException e) {
      throw new MuleRuntimeException(e);
    }
  }

  /**
   * Sets the refresh token of the oauth context retrieved by the token request into the provided context.
   */
  public static void setRefreshToken(ResourceOwnerOAuthContext resourceOwnerOAuthContext, String refreshToken) {
    try {
      if (ctxWithStateSetRefreshTokenMethod != null) {
        ctxWithStateSetRefreshTokenMethod.invoke(resourceOwnerOAuthContext, refreshToken);
      } else {
        ((DefaultResourceOwnerOAuthContext) resourceOwnerOAuthContext).setRefreshToken(refreshToken);
      }
    } catch (InvocationTargetException e) {
      throw new MuleRuntimeException(e.getCause());
    } catch (IllegalAccessException | IllegalArgumentException e) {
      throw new MuleRuntimeException(e);
    }
  }

  /**
   * Sets the expires in value retrieved by the token request into the provided context.
   */
  public static void setExpiresIn(ResourceOwnerOAuthContext resourceOwnerOAuthContext, String expiresIn) {
    try {
      if (ctxWithStateSetExpiresInMethod != null) {
        ctxWithStateSetExpiresInMethod.invoke(resourceOwnerOAuthContext, expiresIn);
      } else {
        ((DefaultResourceOwnerOAuthContext) resourceOwnerOAuthContext).setExpiresIn(expiresIn);
      }
    } catch (InvocationTargetException e) {
      throw new MuleRuntimeException(e.getCause());
    } catch (IllegalAccessException | IllegalArgumentException e) {
      throw new MuleRuntimeException(e);
    }
  }

  /**
   * Sets the state of the oauth context send in the authorization request into the provided context.
   */
  public static void setState(ResourceOwnerOAuthContext resourceOwnerOAuthContext, String state) {
    try {
      if (ctxWithStateSetStateMethod != null) {
        ctxWithStateSetStateMethod.invoke(resourceOwnerOAuthContext, state);
      } else {
        ((DefaultResourceOwnerOAuthContext) resourceOwnerOAuthContext).setState(state);
      }
    } catch (InvocationTargetException e) {
      throw new MuleRuntimeException(e.getCause());
    } catch (IllegalAccessException | IllegalArgumentException e) {
      throw new MuleRuntimeException(e);
    }
  }

  private static final Map<String, CompletableFuture<Void>> activeRefreshFutures = new ConcurrentHashMap<>();

  /**
   * There is already a request executing to refresh the token.
   */
  public static void setDancerStateRefreshingToken(ResourceOwnerOAuthContext resourceOwnerOAuthContext,
                                                   CompletableFuture<Void> refreshFuture) {
    if (ctxWithStateSetDancerStateMethod != null) {
      try {
        ctxWithStateSetDancerStateMethod.invoke(resourceOwnerOAuthContext,
                                                Enum.valueOf(dancerStateEnumClass, "REFRESHING_TOKEN"));
      } catch (InvocationTargetException e) {
        throw new MuleRuntimeException(e.getCause());
      } catch (IllegalAccessException | IllegalArgumentException e) {
        throw new MuleRuntimeException(e);
      }
    } else {
      activeRefreshFutures.put("" + resourceOwnerOAuthContext.getResourceOwnerId(), refreshFuture);
    }
  }

  /**
   * @return {@code true} if there is already a request executing to refresh the token.
   */
  public static boolean isDancerStateRefreshingToken(ResourceOwnerOAuthContext resourceOwnerOAuthContext) {
    if (ctxWithStateGetDancerStateMethod != null) {
      try {
        return Enum.valueOf(dancerStateEnumClass, "REFRESHING_TOKEN")
            .equals(ctxWithStateGetDancerStateMethod.invoke(resourceOwnerOAuthContext));
      } catch (InvocationTargetException e) {
        throw new MuleRuntimeException(e.getCause());
      } catch (IllegalAccessException | IllegalArgumentException e) {
        throw new MuleRuntimeException(e);
      }
    } else {
      return activeRefreshFutures.containsKey("" + resourceOwnerOAuthContext.getResourceOwnerId());
    }
  }

  /**
   * There is a token present and it is valid to use.
   */
  public static void setDancerStateHasToken(ResourceOwnerOAuthContext resourceOwnerOAuthContext) {
    if (ctxWithStateSetDancerStateMethod != null) {
      try {
        ctxWithStateSetDancerStateMethod.invoke(resourceOwnerOAuthContext,
                                                Enum.valueOf(dancerStateEnumClass, "HAS_TOKEN"));
      } catch (InvocationTargetException e) {
        throw new MuleRuntimeException(e.getCause());
      } catch (IllegalAccessException | IllegalArgumentException e) {
        throw new MuleRuntimeException(e);
      }
    } else {
      activeRefreshFutures.remove("" + resourceOwnerOAuthContext.getResourceOwnerId());
    }
  }

  /**
   * @return {@code true} if there is a token present and it is valid to use.
   */
  public static boolean isDancerStateHasToken(ResourceOwnerOAuthContext resourceOwnerOAuthContext) {
    if (ctxWithStateGetDancerStateMethod != null) {
      try {
        return Enum.valueOf(dancerStateEnumClass, "HAS_TOKEN")
            .equals(ctxWithStateGetDancerStateMethod.invoke(resourceOwnerOAuthContext));
      } catch (InvocationTargetException e) {
        throw new MuleRuntimeException(e.getCause());
      } catch (IllegalAccessException | IllegalArgumentException e) {
        throw new MuleRuntimeException(e);
      }
    } else {
      return !activeRefreshFutures.containsKey("" + resourceOwnerOAuthContext.getResourceOwnerId())
          && resourceOwnerOAuthContext.getAccessToken() != null;
    }
  }

  /**
   * The owner has not fetched a token yet, or a previous attempt to fetch it has failed.
   */
  public static void setDancerStateNoToken(ResourceOwnerOAuthContext resourceOwnerOAuthContext) {
    if (ctxWithStateSetDancerStateMethod != null) {
      try {
        ctxWithStateSetDancerStateMethod.invoke(resourceOwnerOAuthContext,
                                                Enum.valueOf(dancerStateEnumClass, "NO_TOKEN"));
      } catch (InvocationTargetException e) {
        throw new MuleRuntimeException(e.getCause());
      } catch (IllegalAccessException | IllegalArgumentException e) {
        throw new MuleRuntimeException(e);
      }
    } else {
      String nullSafeResourceOwner = "" + resourceOwnerOAuthContext.getResourceOwnerId();
      activeRefreshFutures.remove(nullSafeResourceOwner);
    }
  }

  /**
   * @return {@code true} if the owner has not fetched a token yet, or a previous attempt to fetch it has failed.
   */
  public static boolean isDancerStateNoToken(ResourceOwnerOAuthContext resourceOwnerOAuthContext) {
    if (ctxWithStateGetDancerStateMethod != null) {
      try {
        return Enum.valueOf(dancerStateEnumClass, "NO_TOKEN")
            .equals(ctxWithStateGetDancerStateMethod.invoke(resourceOwnerOAuthContext));
      } catch (InvocationTargetException e) {
        throw new MuleRuntimeException(e.getCause());
      } catch (IllegalAccessException | IllegalArgumentException e) {
        throw new MuleRuntimeException(e);
      }
    } else {
      return !activeRefreshFutures.containsKey("" + resourceOwnerOAuthContext.getResourceOwnerId())
          && resourceOwnerOAuthContext.getAccessToken() == null;
    }
  }

}
