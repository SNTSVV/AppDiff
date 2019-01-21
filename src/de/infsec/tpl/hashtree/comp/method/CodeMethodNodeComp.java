package de.infsec.tpl.hashtree.comp.method;

import com.google.common.hash.HashCode;
import com.google.common.hash.Hashing;
import com.google.common.hash.HashingInputStream;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.classLoader.ShrikeBTMethod;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.shrikeBT.IInstruction;
import com.ibm.wala.shrikeCT.InvalidClassFileException;
import de.infsec.tpl.hashtree.HashTree;
import de.infsec.tpl.hashtree.TreeConfig;
import de.infsec.tpl.hashtree.node.MethodNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Set;
import java.util.TreeSet;

public class CodeMethodNodeComp implements IMethodNodeComp {
    private static final Logger logger = LoggerFactory.getLogger(HashTree.class);


    @Override
    public MethodNode comp(IMethod m, TreeConfig config) {
        IClassHierarchy cha = m.getDeclaringClass().getClassHierarchy();

        // TODO incl. fuzzydesc even for code;

        if (m.isAbstract() || m.isNative())
            return new SignatureMethodNodeComp().comp(m, config);

        // TODO java vs android >> have to work on IR rather than ShrikeBTMethod / DexIMethod
        // need new wala stuff
        return null;
/*                ShrikeBTMethod bt = (ShrikeBTMethod) m;
                HashCode h1 = hashBytecode(bt);


// NEED BLOCKWISE DIFF
                    TreeSet<String> s1 = (TreeSet<String>) iinstructions2set(bt.getInstructions());

        String signature = HashTree.Config.keepMethodSignatures? m.getSignature() : "";
        return new MethodNode(HashTree.getHasher().putBytes(desc.getBytes()).hash().asBytes(), signature);

        */
    }

    private Set<String> iinstructions2set(IInstruction[] ins) {
        TreeSet<String> res = new TreeSet<String>();
        for (IInstruction iins : ins) {
            res.add(iins.toString());
        }
        return res;
    }

    // TODO normalize bytecode (id renaming)
    private HashCode hashBytecode(ShrikeBTMethod bt) throws InvalidClassFileException, IOException {
        final byte[] bytesIn = new byte[4096];

        // hash bytecode content
        StringBuilder sb = new StringBuilder();
        for (IInstruction ii : bt.getInstructions())
            sb.append(ii.toString());
        ByteArrayInputStream bis = new ByteArrayInputStream(sb.toString().getBytes());

        try (HashingInputStream his = new HashingInputStream(Hashing.md5(),bis)) {  // todo configurable
            while (his.read(bytesIn) != -1) { /* go */ }
            return his.hash();
        }
    }
}
