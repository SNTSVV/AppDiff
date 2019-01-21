package de.infsec.tpl.modules.appdiff;

import de.infsec.tpl.hashtree.AnnotatedHashTree;
import de.infsec.tpl.hashtree.HashTree;
import de.infsec.tpl.hashtree.node.MethodNode;
import de.infsec.tpl.hashtree.node.Node;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;


public class TreeMerger {
    private static final Logger logger = LoggerFactory.getLogger(AnnotatedHashTree.class);

    public static AnnotatedHashTree merge(List<HashTree> trees) {
        if (trees == null || trees.size() < 2)
            return null;

        AnnotatedHashTree aTree = new AnnotatedHashTree();
        aTree.setConfig(trees.get(0).getConfig());

        for (HashTree hTree: trees)
            merge(aTree, hTree);

        return aTree;
   }


   private static void merge(AnnotatedHashTree aTree, HashTree hTree) {
       // TODO only merge if configs match
/*       if (!aTree.getConfig().equals(hTree.getConfig())) {
           logger.error("Merge error:: Config mismatch");
           return;
       }
*/
       short id = aTree.newVersion();
       logger.info("New Tree version: " + id);

       // copy first tree
       if (aTree.getRootNode() == null) {
           aTree.setRootNode(hTree.getRootNode());
           AnnotatedHashTree.annotate(aTree.getRootNode(), id, true);
           return;
       }

       AnnotatedHashTree.annotate(aTree.getRootNode(), id, false);
       merge(aTree.getRootNode(), hTree.getRootNode(), id);
   }


   // merge package nodes that have code changes (hash differs) but same package name
    // TODO normalize annonymous inner classes
   private static void merge(Node anode, Node hnode, short id) {
        List<Node> nodesToAdd = new ArrayList<>();

        for (Node n: hnode.childs) {
            int idx = anode.childs.indexOf(n);

            if (idx > -1) {
                // multiple matches?
                int lastIdx = anode.childs.lastIndexOf(n);    // TODO : need better hash (not only op)

                if (idx != lastIdx) {
                    logger.trace("Multiple matches found for " + n + "   idx: " + idx + "  lastidx: " + lastIdx);

                    // check if there is a single match by identifier()
                    boolean found = false;
                    for (int i = idx; i < lastIdx+1; i++) {
                        if (anode.childs.get(i).equals(n) && anode.childs.get(i).identifier().equals(n.identifier())) {
                            logger.trace("   >  matches(" + i + "): " + anode.childs.get(i));
                            AnnotatedHashTree.annotate(anode.childs.get(i), id, true);
                            found = true;
                            break;
                        }
                    }

                    // TODO multiple matches could also indicate a newly added method that has the same hash than existing -- ignore this atm, until we have better hash
                    if (!found) {
                        logger.trace("   > No match by identifier for " + n + "  ( new method/class? ) -- add to tree and annotate");
                        AnnotatedHashTree.annotate(n, id, true);
                        nodesToAdd.add(n);
                    }
                } else {
                    // exact match + single match -> annotate anode
                    AnnotatedHashTree.annotate(anode.childs.get(idx), id, true);
                }

            } else {
                // check whether a node with different hash but same identifier exists
                Node match = anode.childs.stream()
                     .filter(nn -> nn.identifier().equals(n.identifier()))
                     .findAny().orElse(null);

                if (match == null) {
                    // add new node
                    logger.trace("Add new node: " + n);
                    AnnotatedHashTree.annotate(n, id, true);
                    nodesToAdd.add(n);

                } else {
                    // identifier match, annotate match node only and recursively check children
                    if (match instanceof MethodNode) {
                        logger.trace("Code of node: " + match + "  has changed");
                        AnnotatedHashTree.annotate(n, id, false);
                        nodesToAdd.add(n);
                    } else {
                        logger.trace("Found existing node: " + match + "  -- has changed");
                        AnnotatedHashTree.annotate(match, id, false);
                        merge(match, n, id);
                    }
                }
            }
        }

        if (!nodesToAdd.isEmpty())
            anode.childs.addAll(nodesToAdd);
   }
}
