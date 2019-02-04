package de.infsec.tpl.hashtree.comp.method;

import com.google.common.hash.HashCode;
import com.google.common.hash.Hasher;
import com.google.common.hash.Hashing;
import com.google.common.hash.HashingInputStream;
import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.classLoader.ShrikeBTMethod;
import com.ibm.wala.dalvik.classLoader.DexIRFactory;
import com.ibm.wala.ipa.callgraph.AnalysisCacheImpl;
import com.ibm.wala.ipa.callgraph.IAnalysisCacheView;
import com.ibm.wala.ipa.callgraph.impl.Everywhere;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.shrikeBT.IInstruction;
import com.ibm.wala.shrikeCT.InvalidClassFileException;
import com.ibm.wala.ssa.*;
import com.ibm.wala.types.ClassLoaderReference;
import com.ibm.wala.types.TypeReference;
import de.infsec.tpl.hashtree.HashTree;
import de.infsec.tpl.hashtree.TreeConfig;
import de.infsec.tpl.hashtree.node.MethodNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.*;


public class CodeMethodNodeComp implements IMethodNodeComp {
    private static final Logger logger = LoggerFactory.getLogger(HashTree.class);

    private static boolean ID_RENAMING_RESILIENT;
    private static final String PLACEHOLDER = "X";

    public CodeMethodNodeComp() {
        this(false);
    }

    public CodeMethodNodeComp(boolean normalize) {
        ID_RENAMING_RESILIENT = normalize;
    }


    private boolean debug(IMethod m) {
        String sig = m.getSignature().replaceAll("mygson", "gson");
        return
                //m.getSignature().startsWith("com.google.gson") ||
                  //      m.getSignature().startsWith("com.google.mygson");

                sig.equals("com.google.gson.internal.Excluder.<init>()V") ||
                sig.equals("com.google.gson.internal.bind.DateTypeAdapter.deserializeToDate(Ljava/lang/String;)Ljava/util/Date;") ||
                sig.equals("com.google.gson.internal.bind.DateTypeAdapter.write(Lcom/google/gson/stream/JsonWriter;Ljava/util/Date;)V") ;

    }



    @Override
    public MethodNode comp(IMethod m, TreeConfig config) {

        if (m.isAbstract() || m.isNative())
            return new SignatureMethodNodeComp().comp(m, config);
//logger.info("## Method: " + m.getSignature());
        IAnalysisCacheView cache = new AnalysisCacheImpl(new DexIRFactory(), SSAOptions.defaultOptions());
        IR ir = cache.getIR(m, Everywhere.EVERYWHERE);

        // TODO TODO
        // -- TEST support-v4  09/10??
        // TODO TODO

        ArrayList<String> bbIns = new ArrayList<>();
        for (SSAInstruction ins: ir.getInstructions()) {
            if (ins != null) {
                String n = normalize(m, ins, ir); //.replaceAll("mygson", "gson");
                if (!n.isEmpty()) bbIns.add(n);
            }
        }
        StringBuilder sb = new StringBuilder();
        bbIns.stream().sorted().forEach(ins -> sb.append(ins));

/*        if (debug(m)) {
            logger.info("m:: " +m.getSignature());
            bbIns.stream().sorted().forEach(ins -> logger.info("-ins : " + ins));
        }
  */
        Hasher h = config.getHasher();
        h.putBytes(SignatureMethodNodeComp.getNormalizedDescriptor(m).getBytes());
        h.putBytes(sb.toString().getBytes());//putUnencodedChars(sb.toString());



        HashCode hcc =  h.hash();
//if (debug(m)) logger.info("M: " + m.getSignature() + " -> " + hcc.toString());

        // TODO return new MethodNode(h.hash().asBytes(), m.getSignature());
        return new MethodNode(hcc.asBytes(), m.getSignature());
    }




    private String normalize(IMethod m, SSAInstruction ins, IR ir) {
        IClassHierarchy cha = m.getClassHierarchy();
        String res;

        if (ins instanceof SSAArrayLengthInstruction) {
            SSAArrayLengthInstruction ssaIns = (SSAArrayLengthInstruction) ins;
            return normalizeID(ir, ssaIns.getDef()) + " = arraylength " + normalizeID(ir, ssaIns.getArrayRef());
        }
        else if (ins instanceof SSAArrayLoadInstruction) {
            SSAArrayLoadInstruction ssaIns = (SSAArrayLoadInstruction) ins;
            return  normalizeID(ir, ssaIns.getDef()) + " = arrayload " + normalizeID(ir, ssaIns.getArrayRef()) + "[" + normalizeID(ir, ssaIns.getIndex()) + "]";
        }
        else if (ins instanceof SSAArrayStoreInstruction) {
            SSAArrayStoreInstruction ssaIns = (SSAArrayStoreInstruction) ins;
            return "arraystore " + normalizeID(ir, ssaIns.getArrayRef()) + "[" + normalizeID(ir, ssaIns.getIndex()) + "] = " + normalizeID(ir, ssaIns.getValue());
        }
        else if (ins instanceof SSABinaryOpInstruction) {
            return  "comparison" ; //normalizeID(ir, ssaIns.getDef()) + " = binaryop(" + ssaIns.getOperator() + ") " + normalizeID(ir, ssaIns.getUse(0)) + " , " + normalizeID(ir, ssaIns.getUse(1));
        }
        else if (ins instanceof SSACheckCastInstruction) {
            SSACheckCastInstruction ssaIns = (SSACheckCastInstruction) ins;

            res = normalizeID(ir, ssaIns.getDef()) + " = checkcast ";
            for(TypeReference tr: ssaIns.getDeclaredResultTypes()) {
                res += normalizeType(cha, tr) + " ";
            }
            res += normalizeID(ir, ssaIns.getUse(0));
            return res;
        }
        else if (ins instanceof SSAConditionalBranchInstruction) {
            SSAConditionalBranchInstruction ssaIns = (SSAConditionalBranchInstruction) ins;
            //return "cond-branch(" + ssaIns.getOperator() + /*", to " + ssaIns.getTarget() + ") "*/ normalizeID(ir, ssaIns.getUse(0)) + "," + normalizeID(ir, ssaIns.getUse(1)) + ")";

            // normalize op as this is CF-dependent (then/else branch ordering)
            return "cond-branch(" + normalizeID(ir, ssaIns.getUse(0)) + "," + normalizeID(ir, ssaIns.getUse(1)) + ")";
        }

        else if (ins instanceof SSAComparisonInstruction) {
            return "comparison" ; //TODO normalizeID(ir, ssaIns.getDef()) + " = compare " + normalizeID(ir, ssaIns.getUse(0)) + "," + normalizeID(ir, ssaIns.getUse(1)) + " opcode=" + ssaIns.getOperator();
        }
        else if (ins instanceof SSAConversionInstruction) {
            SSAConversionInstruction ssaIns = (SSAConversionInstruction) ins;
            return normalizeID(ir, ssaIns.getDef()) + " = conversion(" + normalizeType(cha, ssaIns.getToType()) + ") " + normalizeID(ir, ssaIns.getUse(0));
        }
        else if (ins instanceof SSAGetCaughtExceptionInstruction) {
            SSAGetCaughtExceptionInstruction ssaIns = (SSAGetCaughtExceptionInstruction) ins;
            return  normalizeID(ir, ssaIns.getException()) + " = getCaughtException ";
        }
        else if (ins instanceof SSAGetInstruction) {
            // v3 = getfield < Application, Lcom/google/mygson/GsonBuilder, excluder, <Application,Lcom/google/mygson/internal/Excluder> > v1
            SSAGetInstruction ssaIns = (SSAGetInstruction) ins;

            return ssaIns.isStatic() ?
                    normalizeID(ir, ssaIns.getDef()) + " = getstatic " + normalizeType(cha, ssaIns.getDeclaredFieldType()) :
                    normalizeID(ir, ssaIns.getDef()) + " = getfield " + normalizeType(cha, ssaIns.getDeclaredFieldType()) + " " + normalizeID(ir, ssaIns.getRef());
        }
        else if (ins instanceof SSAGotoInstruction) {
            //SSAGotoInstruction ssaIns = (SSAGotoInstruction) ins;
            return "" ; // TODO cancel cf-instructions "goto";
        }
        else if (ins instanceof SSAInstanceofInstruction) {
            SSAInstanceofInstruction ssaIns = (SSAInstanceofInstruction) ins;
            return normalizeID(ir, ssaIns.getDef()) + " = instanceof " + normalizeID(ir, ssaIns.getUse(0)) + " " + normalizeType(cha, ssaIns.getCheckedType());
        }
        else if (ins instanceof SSAMonitorInstruction) {
            SSAMonitorInstruction ssaIns = (SSAMonitorInstruction) ins;
            return "monitor" + (ssaIns.isMonitorEnter() ? "enter " : "exit ") + normalizeID(ir, ssaIns.getUse(0));  // TODO shorter?
        }
        else if (ins instanceof SSAPhiInstruction) {
            return "";  //cancel CF-instructions
        }
        else if (ins instanceof SSAPutInstruction) {
            SSAPutInstruction ssaIns = (SSAPutInstruction) ins;

            return ssaIns.isStatic() ?
                    "putstatic " + normalizeType(cha, ssaIns.getDeclaredFieldType()) + " = " + normalizeID(ir, ssaIns.getVal()) :
                    "putfield " + normalizeID(ir, ssaIns.getRef()) + ":" + normalizeType(cha, ssaIns.getDeclaredFieldType()) + " = " + normalizeID(ir, ssaIns.getVal());
        }
        else if (ins instanceof SSAReturnInstruction) {
            //SSAReturnInstruction ssaIns = (SSAReturnInstruction) ins;
            return ""; // normalize  ssaIns.returnsVoid()? "return void" : "return " + normalizeID(ir, ssaIns.getResult());
        }
        else if (ins instanceof SSANewInstruction) {
            SSANewInstruction ssaIns = (SSANewInstruction) ins;

            res = normalizeID(ir, ssaIns.getDef()) + " = new " + normalizeType(cha, ssaIns.getConcreteType());
            for (int i = 0; i < ssaIns.getNumberOfUses(); i++) {
                res += (normalizeID(ir, ssaIns.getUse(i)));
                res += " ";
            }

            return res;
        }

        else if (ins instanceof SSAInvokeInstruction) {
            SSAInvokeInstruction ssaIns = (SSAInvokeInstruction) ins;

            StringBuilder s = new StringBuilder();
            if (ssaIns.hasDef()) {
                s.append(normalizeID(ir, ssaIns.getDef())).append(" = ");
            }

            s.append("invoke").append(ssaIns.getCallSite().getInvocationString());
            s.append(' ');
            s.append(ssaIns.getCallSite().getDeclaredTarget().toString());
            if (ssaIns.getNumberOfPositionalParameters() > 0) {
                s.append(" ").append(normalizeID(ir, ssaIns.getUse(0)));

                for(int i = 1; i < ssaIns.getNumberOfPositionalParameters(); ++i) {
                    s.append(",").append(normalizeID(ir, ssaIns.getUse(i)));
                }
            }

            return s.toString();
        }

        else if (ins instanceof SSALoadMetadataInstruction) {
            SSALoadMetadataInstruction ssaIns = (SSALoadMetadataInstruction) ins;
            res = normalizeID(ir, ssaIns.getDef()) + " = load_metadata: " + normalizeType(cha, ssaIns.getType());
            return res;
        }
        else if (ins instanceof SSASwitchInstruction) {
            SSASwitchInstruction ssaIns = (SSASwitchInstruction) ins;
            return "switch " + normalizeID(ir, ssaIns.getUse(0)); //+ " " + Arrays.toString(ssaIns.getCasesAndLabels());
        }

        else if (ins instanceof SSAThrowInstruction) {
            SSAThrowInstruction ssaIns = (SSAThrowInstruction) ins;
            return "throw " + normalizeID(ir, ssaIns.getUse(0));  // TODO just throw?
        }

        else if (ins instanceof SSAUnaryOpInstruction) {
            SSAUnaryOpInstruction ssaIns = (SSAUnaryOpInstruction) ins;
            return normalizeID(ir, ssaIns.getDef()) + " = " + ssaIns.getOpcode() + " " + normalizeID(ir, ssaIns.getUse(0));  // TODO shorten to opcode?
        }

        else {
            /*
              TODO not yet seen/integrated

              if (ins instanceof SSAAddressOfInstruction) {
              } else if (ins instanceof SSAInvokeDynamicInstruction) {
              } else if (ins instanceof SSALoadIndirectInstruction) {
              } else if (ins instanceof SSAPiInstruction) {
              } else if (ins instanceof SSAStoreIndirectInstruction) {

             */

            //if (debug(m))
            logger.error("[UNCHECKED]  -ins: " + ins.toString() + "    fancy:: " + ins.toString(ir.getSymbolTable()));

            return ins.toString(ir.getSymbolTable());
        }
    }


    private String normalizeType(IClassHierarchy cha, TypeReference tr) {
        if (!ID_RENAMING_RESILIENT) return tr.getName().toString();

        if (tr.isPrimitiveType()) return tr.getName().toString();

        // apparently only using the classloader info stored in the TypeReference is not enough
        IClass ic = cha.lookupClass(tr);
        return ic == null || ic.getClassLoader().getReference().equals(ClassLoaderReference.Application) ? PLACEHOLDER : tr.getName().toString();
    }


    private String normalizeID(IR ir, int valueNumber) {
        Value value = ir.getSymbolTable().getValue(valueNumber);

        if (value != null && ir.getSymbolTable().isConstant(valueNumber))
            return value.toString().equals("#null")? "#0" : value.toString();   // normalize #null == #0

        if (value == null) {
            value = ir.getSymbolTable().getPhiValue(valueNumber);
        }

        // don't know what this is
        if (value == null || (value != null && !ir.getSymbolTable().isConstant(valueNumber) && value.toString().startsWith("v"))) {
            return "v";
        }

        return value.toString();
    }



    /*
     *  NOT IN USE
     */


    private String getBasicBlock(TreeConfig conf, ISSABasicBlock bb, IMethod m, IR ir) {
        StringBuilder sb = new StringBuilder();
        for (SSAInstruction ins: bb) {
            sb.append(normalize(m, ins,ir).replaceAll("mygson", "gson"));
        }

        return sb.toString();
    }


    private String hashBasicBlock(TreeConfig conf, ISSABasicBlock bb, IMethod m, IR ir) {
        StringBuilder sb = new StringBuilder();
        for (SSAInstruction ins: bb) {
            sb.append(normalize(m, ins,ir).replaceAll("mygson", "gson"));
        }

        return conf.getHasher().putUnencodedChars(sb.toString()).hash().toString();
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
