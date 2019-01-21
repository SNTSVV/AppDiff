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
