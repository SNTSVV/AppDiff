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

import de.infsec.tpl.hashtree.HashUtils;

import java.io.Serializable;
import java.util.*;


public class Node implements Serializable {
    private static final long serialVersionUID = 6690771073564531337L;

    public byte[] hash;
    public List<Node> childs;
    public Set<Short> versions;

    public Node(byte[] hash) {
        this.hash = hash;
        this.childs = new ArrayList<>();
        this.versions = new TreeSet<>();  // TODO not optimal for normal hashtree (overhead)
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof Node))
            return false;

        return Arrays.equals(((Node) obj).hash, this.hash);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(hash) + childs.size();
    }

    @Override
    public String toString() {
        return "Node(" + identifier() + (versions.isEmpty()? ")" : " / versions " + versions + ")");
    }

    public int numberOfChilds() {
        return this.childs.size();
    }

    public boolean isLeaf() {
        return childs.isEmpty();
    }

    public boolean isMultiVersionNode() {
        return versions != null && versions.size() > 1;
    }

    public String identifier() {
        return HashUtils.hash2Str(hash);
    }
}
