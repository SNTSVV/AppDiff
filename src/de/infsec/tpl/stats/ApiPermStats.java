/*
 * Copyright (c) 2015-2018  Erik Derr [derr@cs.uni-saarland.de]
 * Copyright (c) 2018-2019  Erik Derr,  University of Luxembourg [erik.derr@uni.lu]
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package de.infsec.tpl.stats;

import java.io.Serializable;

/**
 * Created by ederr on 17.07.17.
 */
public class ApiPermStats implements Serializable {
    public String api;
    public String permissions;
    public boolean libPackageMatch;
    public String libPackageName;
    public boolean appMatch;

    public ApiPermStats(String api, String permissions, boolean libPackageMatch, String libPackageName, boolean appMatch) {
        this.api = api;
        this.permissions = permissions;
        this.libPackageMatch = libPackageMatch;
        this.libPackageName = libPackageName;
        this.appMatch = appMatch;
    }
}
