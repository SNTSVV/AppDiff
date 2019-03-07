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

package de.infsec.tpl.hashtree.comp.clazz;

import com.ibm.wala.classLoader.IClass;
import de.infsec.tpl.hashtree.TreeConfig;
import de.infsec.tpl.hashtree.node.ClassNode;
import de.infsec.tpl.hashtree.node.Node;

import java.util.Collection;

public interface IClassNodeComp {
    ClassNode comp(Collection<? extends Node> methodNodes, IClass clazz, TreeConfig config);
}
