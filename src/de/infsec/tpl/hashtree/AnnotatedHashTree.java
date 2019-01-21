package de.infsec.tpl.hashtree;

import com.ibm.wala.ipa.cha.IClassHierarchy;
import de.infsec.tpl.hashtree.comp.clazz.DefaultClassNodeComp;
import de.infsec.tpl.hashtree.comp.clazz.IClassNodeComp;
import de.infsec.tpl.hashtree.comp.method.IMethodNodeComp;
import de.infsec.tpl.hashtree.comp.method.SignatureMethodNodeComp;
import de.infsec.tpl.hashtree.comp.pckg.DefaultPackageNodeComp;
import de.infsec.tpl.hashtree.comp.pckg.IPackageNodeComp;
import de.infsec.tpl.hashtree.node.Node;
import de.infsec.tpl.hashtree.node.PackageNode;
import de.infsec.tpl.utils.VersionWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.Map;
import java.util.TreeMap;

public class AnnotatedHashTree extends HashTree implements Serializable {
    private static final long serialVersionUID = 8811771073564531337L;

    transient private static final Logger logger = LoggerFactory.getLogger(AnnotatedHashTree.class);

    private Map<Short,String> id2VersionStr;

    public AnnotatedHashTree() {
        this(new DefaultPackageNodeComp(), new DefaultClassNodeComp(), new SignatureMethodNodeComp());
    }

    public AnnotatedHashTree(IPackageNodeComp pnComp, IClassNodeComp cnComp, IMethodNodeComp mnComp) {
        super(pnComp, cnComp, mnComp);
    }

    @Override
    public void generate(IClassHierarchy cha) {
        throw new UnsupportedOperationException("You need to use the API that allows providing a version string");
    }

    public void generate(IClassHierarchy cha, String version) {
        short id = addVersion(version);
        generate(cha);
    }

    public void setRootNode(Node n) {
        this.rootNode = n;
    }

    public short addVersion(String version) {
        if (id2VersionStr == null) {
            id2VersionStr = new TreeMap<>();
        }

        // normalize version string
        version = VersionWrapper.valueOf(version).toString();

        short id = (short) (id2VersionStr.size() + 1);
        id2VersionStr.put(id, version);
        logger.info("   id: " + id);
        return id;
    }

    public short newVersion() {
        if (id2VersionStr == null) {
            id2VersionStr = new TreeMap<>();
        }

        short id = (short) (id2VersionStr.size() + 1);
        id2VersionStr.put(id, String.valueOf(id));
        return id;
    }

    /*public PackageNode hasPackageNode(PackageNode pn) {
        return rootNode.childs.contains(pn)? (PackageNode) rootNode.childs.get(rootNode.childs.indexOf(pn)) : null;
    }*/

    public PackageNode hasPackageNode(PackageNode pn) {
        for (Node pnn: rootNode.childs) {
            if (pn.equals(pnn) || pn.packageName.equals(((PackageNode)pnn).packageName))
                return (PackageNode) pnn;
        }
        return null;
    }



    // recursively annotates nodes with specified id
    public static void annotate(Node n, short id, boolean recursive) {
        n.versions.add(id);

        if (recursive && !n.childs.isEmpty()) {
            n.childs.forEach(c -> annotate(c, id, recursive));
        }
    }

    public void addPackageNode(Node n, short id) {
        AnnotatedHashTree.annotate(n, id, true);

        if (n instanceof PackageNode) {
            rootNode.childs.add(n);
        } else {
            logger.error("Provided node is not a PackageNode");
        }
    }

    public short getCurrentVersion() {
        return (short) (id2VersionStr == null ? 0 : id2VersionStr.size());
    }

}
