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

import com.google.common.hash.HashFunction;
import com.google.common.hash.Hasher;
import com.google.common.hash.Hashing;
import de.infsec.tpl.hash.AccessFlags;
import de.infsec.tpl.utils.Utils;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class TreeConfig implements Serializable {
    private static final long serialVersionUID = 1190771073563431337L;

    public HashFunction hf = Hashing.md5();
    public AccessFlags accessFlagsFilter = AccessFlags.NO_FLAG;

    // verboseness
    public boolean keepPackageNames = true;
    public boolean keepClassNames = false;
    public boolean keepMethodSignatures = false;

    // node pruning
    public boolean pruneClasses = false;
    public boolean pruneMethods = true;


    public Hasher getHasher() {
        return hf.newHasher();
    }

    @Override
    public String toString() {
        List<String> l = new ArrayList<>();
        if (keepPackageNames) l.add("PN");
        if (keepClassNames) l.add("CN");
        if (keepMethodSignatures) l.add("MSIG");
        String keep = l.isEmpty()? "" : Utils.join(l, "|");

        l = new ArrayList<>();
        if (pruneClasses) l.add("CN");
        if (pruneMethods) l.add("MSIG");
        String prune = l.isEmpty()? "" : Utils.join(l, "|");

        return hf.toString()
            + " | Flags: " + accessFlagsFilter
            + (keep.isEmpty()? "" : " | Keep: " + keep)
            + (prune.isEmpty()? "" : " | Prune: " + prune);
    }
}
