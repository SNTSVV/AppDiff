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

package de.infsec.tpl.hashtree.node;

import java.io.Serializable;
import java.util.Arrays;


public class MethodNode extends Node implements Serializable {
    private static final long serialVersionUID = 5590771073564531337L;
    public String signature;

    public MethodNode(byte[] hash, String signature) {
        super(hash);
        this.signature = signature;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof MethodNode))
            return false;

        return Arrays.equals(((Node) obj).hash, this.hash);
    }

    @Override
    public String toString() {
        return "MNode(" + signature + (versions.isEmpty()? ")" : " / versions " + versions + ")");
    }

    public String identifier() {
        return signature;
    }
}
