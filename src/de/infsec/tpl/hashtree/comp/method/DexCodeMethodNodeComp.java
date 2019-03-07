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

package de.infsec.tpl.hashtree.comp.method;

import com.google.common.hash.Hasher;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.dalvik.classLoader.DexIMethod;
import com.ibm.wala.dalvik.dex.instructions.Instruction;
import de.infsec.tpl.hashtree.TreeConfig;
import de.infsec.tpl.hashtree.node.MethodNode;

import java.util.Arrays;

public class DexCodeMethodNodeComp implements IMethodNodeComp {
    @Override
    public MethodNode comp(IMethod m, TreeConfig config) {
        if (m.isAbstract() || m.isNative())
            return new SignatureMethodNodeComp().comp(m, config);

        Instruction[] ins = ((DexIMethod) m).getDexInstructions();
        Hasher h = config.getHasher();
        h.putBytes(SignatureMethodNodeComp.getNormalizedDescriptor(m).getBytes());
        Arrays.stream(ins).forEach(i -> h.putUnencodedChars(i.getOpcode().name));   // TODO only opcode for the moment, full instructions requires additional effort

        return new MethodNode(h.hash().asBytes(), m.getSignature());
    }
}
