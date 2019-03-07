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

package de.infsec.tpl.modules.appdiff;

import com.ibm.wala.dalvik.util.AndroidAnalysisScope;
import com.ibm.wala.ipa.callgraph.AnalysisScope;
import com.ibm.wala.ipa.cha.ClassHierarchy;
import com.ibm.wala.ipa.cha.ClassHierarchyException;
import com.ibm.wala.ipa.cha.ClassHierarchyFactory;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import de.infsec.tpl.config.LibScoutConfig;
import de.infsec.tpl.hashtree.AnnotatedHashTree;
import de.infsec.tpl.hashtree.HashTree;
import de.infsec.tpl.hashtree.TreeConfig;
import de.infsec.tpl.hashtree.comp.clazz.DefaultClassNodeComp;
import de.infsec.tpl.hashtree.comp.method.DexCodeMethodNodeComp;
import de.infsec.tpl.hashtree.comp.pckg.DefaultPackageNodeComp;
import de.infsec.tpl.hashtree.node.ClassNode;
import de.infsec.tpl.hashtree.node.MethodNode;
import de.infsec.tpl.hashtree.node.Node;
import de.infsec.tpl.hashtree.node.PackageNode;
import de.infsec.tpl.manifest.ProcessManifest;
import de.infsec.tpl.pkg.PackageTree;
import de.infsec.tpl.profile.Profile;
import de.infsec.tpl.stats.AppStats;
import de.infsec.tpl.utils.Utils;
import de.infsec.tpl.utils.WalaUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;


public class AppDiff {
    private static final Logger logger = LoggerFactory.getLogger(AppDiff.class);

    private AppDiff(File app1, File app2) {
        this.app1 = app1.getAbsolutePath();
        this.app2 = app2.getAbsolutePath();
    }

    public String app1;
    public String app2;

    public Set<String> packagesAdded;
    public Set<String> packagesRemoved;

    public Set<String> classesAdded;
    public Set<String> classesRemoved;

    public Set<String> methodsAdded;
    public Set<String> methodsChanged;
    public Set<String> methodsRemoved;


    // focus on app dev code only or remove only libs that are the same
    public static AppDiff diffApks(File app1, File app2) {
        logger.info("= diff apks =");

        try {
            AppDiff diff = new AppDiff(app1, app2);

            final TreeConfig conf = new TreeConfig();
            conf.keepClassNames = true;
            conf.keepMethodSignatures = true;
            conf.pruneMethods = false;

            logger.info("  - app1: " + app1);
            AppStats stats1 = new AppStats(app1);
            stats1.manifest = parseManifest(app1);
            IClassHierarchy cha1 = createCHA(stats1);

            HashTree ht1 = new HashTree(new DefaultPackageNodeComp(), new DefaultClassNodeComp(), new DexCodeMethodNodeComp());
            ht1.setConfig(conf);
            ht1.generate(cha1);

            logger.info("  - app2: " + app2);
            AppStats stats2 = new AppStats(app2);
            stats2.manifest = parseManifest(app2);
            IClassHierarchy cha2 = createCHA(stats2);
            stats2.pTree = Profile.generatePackageTree(cha2);
            //stats2.pTree.print(true);

            HashTree ht2 = new HashTree(new DefaultPackageNodeComp(), new DefaultClassNodeComp(), new DexCodeMethodNodeComp());
            ht2.setConfig(conf);
            ht2.generate(cha2);

            // merge trees and compute diff
            AnnotatedHashTree aTree = TreeMerger.merge(Arrays.asList(ht1,ht2));
            diff.compute(aTree);
            diff.print();

            // build diff tree
            DiffTree dtree = DiffTree.make(diff);  // TODO: verbose or not?
            dtree.print(true);

            // write to json
            try {
                File targetFile = new File(LibScoutConfig.jsonDir + File.separator + "appdiff.json");
                logger.info("Write diff to " + targetFile);
                Utils.obj2JsonFile(targetFile, diff);
            } catch (Exception e) {
                logger.error(Utils.stacktrace2Str(e));
            }

            return diff;
        } catch (Exception e) {
            logger.error(Utils.stacktrace2Str(e));
            return null;
        }
    }



    private void compute(AnnotatedHashTree aTree) {
        logger.info("Root node: " + aTree.getRootNode().versions);
        List<Node> nodes = new ArrayList<>();
        dumpSingleVersionNodes(aTree.getRootNode(), nodes);

        crunchData(nodes);
    }


    private void print() {
        if (!packagesRemoved.isEmpty() || !packagesAdded.isEmpty()) {
            logger.info("# Packages (#removed: " + packagesRemoved.size() + " / #added: " + packagesAdded.size() + ")");
            packagesRemoved.forEach(id -> logger.info(Utils.INDENT + " - " + id));
            packagesAdded.forEach(id -> logger.info(Utils.INDENT + " + " + id));
        }

        if (!classesRemoved.isEmpty() || !classesAdded.isEmpty()) {
            logger.info("# Classes (#removed: " + classesRemoved.size() + " / #added: " + classesAdded.size() + ")");
            classesRemoved.forEach(id -> logger.info(Utils.INDENT + " - " + id));
            classesAdded.forEach(id -> logger.info(Utils.INDENT + " + " + id));
        }

        if (!methodsChanged.isEmpty() || !methodsRemoved.isEmpty() || !methodsAdded.isEmpty()) {
            logger.info("# Methods (#removed: " + methodsRemoved.size() + " / #changed: " + methodsChanged.size() + " / #added: " + methodsAdded.size() + ")");
            methodsRemoved.forEach(n -> logger.info(Utils.INDENT + " - " + n));
            methodsChanged.forEach(mn -> logger.info(Utils.INDENT + "<> " + mn));
            methodsAdded.forEach(n -> logger.info(Utils.INDENT + " + " + n));
        }
    }


    private void crunchData(List<Node> nodes) {
        // TODO filter annonymous inner classes -->> in treemerger ?

        logger.info("");
        logger.info("Crunch data");

        this.packagesRemoved = new TreeSet<>();
        this.packagesAdded = new TreeSet<>();
        nodes.stream()
            .filter(n -> n instanceof PackageNode)
            .forEach(pn -> { if (pn.versions.iterator().next() == 1) this.packagesRemoved.add(pn.identifier()); else this.packagesAdded.add(pn.identifier()); });

        this.classesRemoved = new TreeSet<>();
        this.classesAdded = new TreeSet<>();
        nodes.stream()
            .filter(n -> n instanceof ClassNode)
            .forEach(pn -> { if (pn.versions.iterator().next() == 1) this.classesRemoved.add(pn.identifier()); else this.classesAdded.add(pn.identifier()); });

        this.methodsAdded = new TreeSet<>();
        this.methodsRemoved = new TreeSet<>();

        nodes.stream()
            .filter(n -> n instanceof MethodNode)
            .forEach(mn -> { if (mn.versions.iterator().next() == 1) this.methodsRemoved.add(mn.identifier()); else this.methodsAdded.add(mn.identifier()); });

        this.methodsChanged = this.methodsRemoved.stream().filter(sig -> this.methodsAdded.contains(sig)).collect(Collectors.toSet());  // those that are changed
        this.methodsRemoved.removeAll(this.methodsChanged);
        this.methodsAdded.removeAll(this.methodsChanged);
    }


    private static void dumpSingleVersionNodes(Node n, List<Node> res) {
        if (!n.isMultiVersionNode()) {
            logger.debug(n.toString());
            res.add(n);
        } else
            n.childs.forEach(c -> AppDiff.dumpSingleVersionNodes(c, res));
    }


    private static ProcessManifest parseManifest(File apk) {
        // parse AndroidManifest.xml
        try {
            ProcessManifest manifest = new ProcessManifest();
            manifest.loadManifestFile(apk.getAbsolutePath());
            return manifest;
        } catch (Exception e) {
            logger.error(Utils.stacktrace2Str(e));
            return null;
        }
    }

    private static IClassHierarchy createCHA(AppStats stats) throws IOException, ClassHierarchyException {
        // create analysis scope and generate class hierarchy
        final AnalysisScope scope = AndroidAnalysisScope.setUpAndroidAnalysisScope(new File(stats.appFile.getAbsolutePath()).toURI(), null /* no exclusions */, null /* we always pass an android lib */, LibScoutConfig.pathToAndroidJar.toURI());
        IClassHierarchy cha = ClassHierarchyFactory.makeWithRoot(scope);

        WalaUtils.getChaStats(cha);
        return cha;
    }

}
