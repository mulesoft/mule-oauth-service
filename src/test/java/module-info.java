/*
 * Copyright 2023 Salesforce, Inc. All rights reserved.
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */

/**
 * Provides OAuth authentication services.
 *
 * @moduleGraph
 * @since 2.2
 */
module org.mule.test.service.oauth {

  requires org.mule.oauth.client.api;
  requires org.mule.oauth.client.impl;
  requires org.mule.runtime.oauth.api;
  // lifecycle api
  requires org.mule.runtime.core;
  requires org.mule.test.unit;
  // To avoid duplicating the tests just for the coverage of the legacy dancers and builders
  requires org.mule.test.oauth.client.impl;

  requires org.mule.service.oauth;
  requires org.hamcrest;
  requires org.mockito;
  requires junit;
  requires io.qameta.allure.commons;

  exports org.mule.test.oauth.internal to junit;
}