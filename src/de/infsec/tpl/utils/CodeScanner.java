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

package de.infsec.tpl.utils;

import com.ibm.wala.classLoader.CallSiteReference;
import com.ibm.wala.classLoader.IBytecodeMethod;
import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.shrikeCT.InvalidClassFileException;
import de.infsec.tpl.pkg.PackageUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.Files;
import java.util.*;
import java.util.stream.Stream;

public class CodeScanner {
    private static final Logger logger = LoggerFactory.getLogger(de.infsec.tpl.utils.CodeScanner.class);

    public static void scanForPermissionAPIs(IClassHierarchy cha, File permMappingFile, String appPackage) {
        Map<String, String> api2Perm = new HashMap<String, String>();

        /**
         * Assuming a file format  signature  ::  permission[,permission]
         */
        try (BufferedReader br = new BufferedReader(new FileReader((permMappingFile)))) {
            for (String line; (line = br.readLine()) != null; ) {
                if (!line.isEmpty()) {
                    String[] map = line.split("  ::  ");
                    api2Perm.put(map[0], map[1]);
                }
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

     //   for (String api : api2Perm.keySet())
       //     System.out.println("- " + api + "  perms: " + api2Perm.get(api));
        logger.info("Read: " + api2Perm.size() + "  permission mappings");
        logger.info("App Package: " + appPackage);

        String shortPckgName = appPackage;
        int depth = PackageUtils.packageDepth(appPackage);
        if (depth > 2)
            shortPckgName = PackageUtils.getSubPackageOfDepth(appPackage, depth-1);

        TreeMap<String,Set> results = new TreeMap<String,Set>();  // unique packages -> required perms


        for (IClass clazz: cha) {
            if (WalaUtils.isAppClass(clazz)) {
                if (WalaUtils.simpleName(clazz).startsWith("android.support."))
                    continue;  // TODO: remove gplay services as well, LibScout integration

                try {
                    for (IMethod m : clazz.getDeclaredMethods()) {

                        for (CallSiteReference csf : com.ibm.wala.classLoader.CodeScanner.getCallSites(m)) {
                            String signature = csf.getDeclaredTarget().getSignature();
                            String prettySig = prettyMethodSdkMap(signature);

                            // TODO: checkout libscout results to check whether sink resides in app/lib code
                            if (api2Perm.keySet().contains(prettySig)) {
//                                logger.info("  - Found pCall in " + ((depth > 1 && WalaUtils.simpleName(clazz).startsWith(shortPckgName))? "[APP]":"[LIB]") + ": " + WalaUtils.simpleName(clazz) + "  sink: " + signature + "  (" + api2Perm.get(prettySig) + ")");

                                String pckg = PackageUtils.getPackageName(clazz);
                                if (!results.containsKey(pckg))
                                    results.put(pckg, new TreeSet());
                                results.get(pckg).add(api2Perm.get(prettySig));
                            }
                        }
                    }
                } catch (InvalidClassFileException e) {
                    logger.error(Utils.stacktrace2Str(e));
                }
            }
        }

        for (String pckg: results.keySet()) {
            String comp = (depth > 1 && pckg.startsWith(shortPckgName))? "[APP]":"[LIB]";
            logger.info("- " + comp + ": " + pckg + " : "+ results.get(pckg));
        }
    }


    public static String prettyMethodSdkMap(String methodSignature) {
        List<String> args = Utils.parseMethodArguments(methodSignature, true);
        return methodSignature.substring(0, methodSignature.indexOf('(') + 1) + Utils.join(args, ",") + ")" + getReturnType(methodSignature, false);
    }

    public static String getReturnType(final String methodSignature, boolean bytecodeNotation) {
        final String retType = methodSignature.substring(methodSignature.lastIndexOf(")") + 1); // strip anything but the return type

        if (retType.length() == 1 && VARTYPES.containsKey(retType.charAt(0))) {
            return VARTYPES.get(retType.charAt(0));
        } else {
            return bytecodeNotation ? retType : convertToFullClassName(retType);
        }
    }

    public static String convertToFullClassName(String className) {
        if (className.endsWith(";")) {
            className = className.substring(0, className.length() - 1);
        }

        // convert array types
        while (className.startsWith("["))
            className = className.substring(1) + "[]";

        // remove type identifier
        if (className.startsWith("L")) className = className.replaceFirst("L", "");

        return className.replaceAll("/", "\\.");
    }

    /**
     * Vartypes used in Dex bytecode and their mnemonics
     */
    public static final HashMap<Character, String> VARTYPES = new HashMap<Character, String>() {
        private static final long serialVersionUID = 1L;

        {
            put('V', "void");    // can only be used for return types
            put('Z', "boolean");
            put('B', "byte");
            put('S', "short");
            put('C', "char");
            put('I', "int");
            put('J', "long");    // 64 bits
            put('F', "float");
            put('D', "double");  // 64 bits
        }
    };

/*            // put all apis to scan for in a set once for efficiency
        Set<String> apiSet = new HashSet<String>() {

        for (List<String> l: apisToScanFor.values())
            apiSet.addAll(l);

        int sinksInBytecode = 0;

        for (IClass clazz: cha) {
            if (WalaUtils.isAppClass(clazz)) {
                if (WalaUtils.simpleName(clazz).startsWith("android.support.")) continue;  // TODO: remove gplay services as well, LibScout integration

                logger.debug(LogConfig.INDENT + "- class: " + WalaUtils.simpleName(clazz));
                try {
                    for (IMethod m: clazz.getDeclaredMethods()) {

                        for (CallSiteReference csf: com.ibm.wala.classLoader.CodeScanner.getCallSites(m)) {
                            String signature = csf.getDeclaredTarget().getSignature();
                            logger.trace(LogConfig.INDENT2 + "- signature: " + signature);

                            // TODO: checkout libscout results to check whether sink resides in app/lib code
                            if (apiSet.contains(signature)) {
                                AndroidClassType type = WalaUtils.classifyClazz(clazz);
                                logger.debug("  - Found sink in (" + type.toString() + "): " + WalaUtils.simpleName(clazz) + "  sink: " + signature +  "  (" + sinks.get(signature) + ")");
                                sinksInBytecode++;
                            }
                        }
                    }
                } catch (InvalidClassFileException e) {
                    logger.error(Utils.stacktrace2Str(e));
                }
            }
        }

        logger.info("= Scan for sinks =");
        logger.info(LogConfig.INDENT + ">> Found " + sinksInBytecode + " sinks!");
        return sinksInBytecode;
    }*/

}
