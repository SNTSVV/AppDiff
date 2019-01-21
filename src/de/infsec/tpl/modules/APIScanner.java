package de.infsec.tpl.modules;


import com.ibm.wala.classLoader.CallSiteReference;
import com.ibm.wala.classLoader.CodeScanner;
import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.shrikeCT.InvalidClassFileException;
import de.infsec.tpl.utils.AndroidClassType;
import de.infsec.tpl.utils.MapUtils;
import de.infsec.tpl.utils.Utils;
import de.infsec.tpl.utils.WalaUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.*;


public class APIScanner {
    private static final Logger logger = LoggerFactory.getLogger(de.infsec.tpl.modules.APIScanner.class);

	public static Map<String, String> init(File apiFile) throws FileNotFoundException {
		// load api file
		return APIScanner.loadResource(apiFile);
	}


	/**
	 * Loads API definitions defined in the following format:
	 *   <api-signature>  ::  [comma-separated optional list of android permissions]
	 * Lines starting with '#' are considered comments.
	 * @param file  input {@link File}
	 * @return Mapping of <api-signatures> to list of required permissions
	 */
	private static Map<String, String> loadResource(final File file) throws FileNotFoundException {
		if (!file.exists() || !file.isFile())
			throw new FileNotFoundException("Could not load file: " + file.getName());

		// API -> list of required permissions
		Map<String, String> result = new HashMap<String, String>();

		try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
			String line;
			while ((line = reader.readLine()) != null) {
				if (line.isEmpty() || line.startsWith("#")) continue;

				String[] token = line.split("  ::  ");

				if (token.length > 2) {
					logger.debug("Skip invalid entry: " + line + "  (expected format: <api-signature>  ::  perm1, perm2, ..)");
					continue;
				} else if (token.length == 2) {
					result.put(token[0], token.length == 2? token[1] : "");
                }
			}
		} catch (Exception e) {
			logger.error(Utils.stacktrace2Str(e));
		}

//		for (String k: result.keySet()) {
//			logger.debug("Parse: " + k + "  -> " + result.get(k));
//		}

		return result;
	}


	/**
	 * Scan bytecode for APIs in terms of method signatures. Very fast as it does not require any graph structure
	 * @param cha
	 * @return  mapping of found APIs and their code location in terms of enclosing method signature
	 */
	public static Map<String, List<String>> scanBytecodeForApis(IClassHierarchy cha, Map<String, String> apiToPermissions) {
	    // api signature -> list of bytecode methods
        Map<String, List<String>> results = new HashMap<String, List<String>>();

		for (IClass clazz: cha) {
			if (WalaUtils.isAppClass(clazz)) {
//				logger.debug(Utils.INDENT + "- class: " + WalaUtils.simpleName(clazz));

				try {
					for (IMethod m: clazz.getDeclaredMethods()) {
						for (CallSiteReference csf: CodeScanner.getCallSites(m)) {
							String signature = prettyPrint(csf.getDeclaredTarget().getSignature());

							if (apiToPermissions.keySet().contains(signature)) {
								AndroidClassType type = WalaUtils.classifyClazz(clazz);
								String permissions = apiToPermissions.get(signature);
								MapUtils.addValue(results, signature, m.getSignature());
								logger.debug("  - Class (" + type.toString() + "): " + WalaUtils.simpleName(clazz) + "  api: " + signature +  (permissions.isEmpty()? "" : "  (" + permissions + ")"));
							}
						}
					}
				} catch (InvalidClassFileException e) {
					logger.error(Utils.stacktrace2Str(e));
				}
			}
		}

		logger.info("= Scan for sinks =");
		logger.info(Utils.INDENT + ">> Found " + results.size() + " sinks!");
		return results;
	}


	public static String prettyPrint(String methodSignature) {
		List<String> args = Utils.parseMethodArguments(methodSignature, true);

		return methodSignature.substring(0, methodSignature.indexOf('(') + 1) + Utils.join(args, ",") + ")"; //TODO + Utils.getReturnType(methodSignature, false);
	}
}
