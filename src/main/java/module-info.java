/*
 * Copyright 2023 Salesforce, Inc. All rights reserved.
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
import org.mule.api.annotation.jpms.ServiceModule;

/**
 * Provides OAuth authentication services.
 *
 * @moduleGraph
 * @since 2.2
 */
@ServiceModule
module org.mule.service.oauth {

  requires org.mule.oauth.client.api;
  requires org.mule.oauth.client.impl;
  requires org.mule.runtime.oauth.api;
  // lifecycle api
  requires org.mule.runtime.core;

  // Allow invocation and injection into providers by the Mule Runtime
  exports org.mule.service.oauth.provider to
      org.mule.runtime.service;
  opens org.mule.service.oauth.provider to
      org.mule.runtime.service;

  exports org.mule.service.oauth.internal to
      com.mulesoft.mule.service.oauth.ee,
      org.mule.test.service.oauth,
      com.mulesoft.test.mule.service.oauth.ee;

  exports org.mule.service.oauth.internal.builder to
      org.mule.test.service.oauth;

}
