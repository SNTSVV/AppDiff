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

package de.infsec.tpl.hashtree;


import de.infsec.tpl.hashtree.node.Node;

import java.util.Comparator;

public class HashUtils {

    public static String hash2Str(byte[] hash) {
        String format = "%" + (hash.length*2) + "x";
        return String.format(format, new java.math.BigInteger(1, hash));
    }

    public static final NodeComparator comp = new NodeComparator();

    public static class NodeComparator implements Comparator<Node> {
        public NodeComparator() {}

        private int compare(byte[] left, byte[] right) {
            for (int i = 0, j = 0; i < left.length && j < right.length; i++, j++) {
                int a = (left[i] & 0xff);
                int b = (right[j] & 0xff);
                if (a != b) {
                    return a - b;
                }
            }
            return left.length - right.length;
        }

        @Override
        public int compare(Node n0, Node n1) {
            return compare(n0.hash, n1.hash);
        }
    }
}
