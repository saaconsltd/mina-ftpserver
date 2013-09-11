/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.ftpserver.authority;

import org.apache.ftpserver.ftplet.Authority;
import org.apache.ftpserver.ftplet.AuthorizationRequest;
import org.apache.ftpserver.ftplet.ConcurrentLoginAuthorizationRequest;

/**
 * Controls how many logins are valid for a given user.  This is
 * checked at login time by passing an instance to the 
 * {@link User#authorize(AuthorizationRequest)} method.  This
 * class first checks that the user logging in will not exceed
 * the limits, and if valid will set the max values within the
 * {@link AuthorizationRequest}.
 *
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class ConcurrentLoginPermission implements Authority {

    private final int maxConcurrentLogins;

    private final int maxConcurrentLoginsPerIP;

    public ConcurrentLoginPermission(int maxConcurrentLogins,
            int maxConcurrentLoginsPerIP) {
        this.maxConcurrentLogins = maxConcurrentLogins;
        this.maxConcurrentLoginsPerIP = maxConcurrentLoginsPerIP;
    }

    /**
     * @see Authority#authorize(AuthorizationRequest)
     */
    public AuthorizationRequest authorize(AuthorizationRequest request) {
        if (request instanceof ConcurrentLoginAuthorizationRequest) {
            ConcurrentLoginAuthorizationRequest concurrentLoginRequest = (ConcurrentLoginAuthorizationRequest) request;

            if (maxConcurrentLogins != 0
                    && maxConcurrentLogins < concurrentLoginRequest
                            .getConcurrentLogins()) {
                return null;
            } else if (maxConcurrentLoginsPerIP != 0
                    && maxConcurrentLoginsPerIP < concurrentLoginRequest
                            .getConcurrentLoginsFromThisIP()) {
                return null;
            } else {
                concurrentLoginRequest
                        .setMaxConcurrentLogins(maxConcurrentLogins);
                concurrentLoginRequest
                        .setMaxConcurrentLoginsPerIP(maxConcurrentLoginsPerIP);

                return concurrentLoginRequest;
            }
        } else {
            return null;
        }
    }

    /**
     * @see Authority#canAuthorize(AuthorizationRequest)
     */
    public boolean canAuthorize(AuthorizationRequest request) {
        return request instanceof ConcurrentLoginAuthorizationRequest;
    }
}
