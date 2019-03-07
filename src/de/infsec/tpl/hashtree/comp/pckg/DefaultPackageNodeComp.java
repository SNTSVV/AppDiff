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

package de.infsec.tpl.hashtree.comp.pckg;

import com.ibm.wala.ipa.cha.IClassHierarchy;
import de.infsec.tpl.hashtree.HashTree;
import de.infsec.tpl.hashtree.TreeConfig;
import de.infsec.tpl.hashtree.node.Node;
import de.infsec.tpl.hashtree.node.PackageNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;

public class DefaultPackageNodeComp implements IPackageNodeComp {
    private static final Logger logger = LoggerFactory.getLogger(HashTree.class);

    @Override
    public PackageNode comp(Collection<? extends Node> classNodes, String packageName, IClassHierarchy cha, TreeConfig config) {

        // default behaviour, just create hash from child nodes
        PackageNode pn = new PackageNode(HashTree.compNode(classNodes, false, config.getHasher()).hash, (config.keepPackageNames? packageName : ""));
        if (!config.pruneClasses) pn.childs = new ArrayList<>(classNodes);

        return pn;
    }
}
