package de.infsec.tpl.hash;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

//import com.ibm.wala.ipa.cha.ClassHierarchyFactory;
//import com.ibm.wala.ipa.cha.ClassHierarchyFactory;
import de.infsec.tpl.config.LibScoutConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Charsets;
import com.google.common.collect.Sets;
import com.google.common.collect.Sets.SetView;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.google.common.hash.HashCode;
import com.google.common.hash.HashingInputStream;
import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.classLoader.ShrikeBTMethod;
import com.ibm.wala.ipa.callgraph.AnalysisScope;
import com.ibm.wala.ipa.cha.ClassHierarchy;
import com.ibm.wala.ipa.cha.ClassHierarchyException;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.shrikeBT.IInstruction;
import com.ibm.wala.shrikeCT.InvalidClassFileException;
import com.ibm.wala.types.ClassLoaderReference;

import de.infsec.tpl.utils.Utils;
import de.infsec.tpl.utils.WalaUtils;


// TODO how to find methods to compare if id renamed differently across versions?
// -> identify root package, package level, dec methods, fuzzy desc?



//TEST	in TPLCLI.main()	
//		File f1 = new File("/data/dev/projects/tpl-repo/android-third-party-libs/lib-sdks/SocialMedia/Facebook/4.8.0/classes.jar");
//		File f2 = new File("/data/dev/projects/tpl-repo/android-third-party-libs/lib-sdks/SocialMedia/Facebook/4.8.1/classes.jar");
		
//		File f1 = new File("/data/dev/projects/tpl-repo/android-third-party-libs/lib-sdks/Utilities/Gson/2.2.1/gson-2.2.1.jar");
//		File f2 = new File("/data/dev/projects/tpl-repo/android-third-party-libs/lib-sdks/Utilities/Gson/2.2.2/gson-2.2.2.jar");

//		File f1 = new File("/data/dev/projects/tpl-repo/android-third-party-libs/lib-sdks/Utilities/apache-commons-lang/3.3.1/commons-lang3-3.3.1.jar");
//		File f2 = new File("/data/dev/projects/tpl-repo/android-third-party-libs/lib-sdks/Utilities/apache-commons-lang/3.3.2/commons-lang3-3.3.2.jar");

//		File f1 = new File("/data/dev/projects/tpl-repo/android-third-party-libs/lib-sdks/SocialMedia/vkontakte/1.6.5/classes.jar");
//		File f2 = new File("/data/dev/projects/tpl-repo/android-third-party-libs/lib-sdks/SocialMedia/vkontakte/1.6.6/classes.jar");
//
//		
//		new HashTest(f1,f2);
//		System.exit(0);
//TEST 

public class HashTest {
	private static final Logger logger = LoggerFactory.getLogger(de.infsec.tpl.hash.HashTest.class);

	private HashFunction hashF;

	public HashTest(File f1, File f2) {
		logger.info("=== HASH TEST ===");
		logger.info("Input files: " + f1 + "  +  " + f2);

		this.hashF = Hashing.md5();

		try {
			ZipFile lib1 = new ZipFile(f1);
			Map<String, String> map1 = calcFileHashes(lib1);

			ZipFile lib2 = new ZipFile(f2);
			Map<String, String> map2 = calcFileHashes(lib2);


			// compare per file hashes
			logger.info("= compare per file hashes");
			Set<String> classNames = new TreeSet<String>();
			for (String cName : map1.keySet()) {
				if (!map1.get(cName).equals(map2.get(cName))) {
					logger.info("entry : " + cName + "  first: " + map1.get(cName) + "    second: " + map2.get(cName) + "   EQUALS::" + map1.get(cName).equals(map2.get(cName)));
					classNames.add(cName.replaceFirst("\\.class", ""));
				}
			}

			logger.info("");
			logger.info("Classes with diffs: " + classNames);
			logger.info("");

			IClassHierarchy cha1 = createCha(f1);
			IClassHierarchy cha2 = createCha(f2);

			for (String cname : classNames) {
				logger.info("-> klass: " + cname);
				IClass ic1 = WalaUtils.lookupClass(cha1, cname);

				for (IMethod im : ic1.getDeclaredMethods()) {
					if (im.isAbstract() || im.isNative()) continue;

					ShrikeBTMethod bt = (ShrikeBTMethod) im;
					HashCode h1 = hashBytecode(bt);

					ShrikeBTMethod bt2 = (ShrikeBTMethod) WalaUtils.getIMethod(cha2, im.getSignature());
					HashCode h2 = hashBytecode(bt2);

					if (!h1.equals(h2)) {
						logger.info("  -> bytecode hash diff in " + im.getSignature() + "  old bm size: " + bt.getInstructions().length + "  new bm size: " + bt2.getInstructions().length);

//						logger.info("OLD:");
//						printBytecode(bt);
//						
//						logger.info("NEW:");
//						printBytecode(bt2);

// NEED BLOCKWISE DIFF						
						TreeSet<String> s1 = (TreeSet<String>) iinstructions2set(bt.getInstructions());
						TreeSet<String> s2 = (TreeSet<String>) iinstructions2set(bt2.getInstructions());
						SetView<String> svA = Sets.difference(s1, s2);
						SetView<String> svB = Sets.difference(s2, s1);

						logger.info("    per ins diff:");
						for (String s : svA) {
							logger.info("    > diff: " + s);
						}
						for (String s : svB) {
							logger.info("    < diff: " + s);
						}


//NECESSARY?						
//						ArrayList<String> a1 = iinstructions2list(bt.getInstructions());
//						ArrayList<String> a2 = iinstructions2list(bt2.getInstructions());
//						a1.removeAll(a2);
//						logger.info("    per ins diff (ordered):");
//						for (String s: a1) {
//							logger.info("    > diff: "+ s);
//						}
//						
//						a1 = iinstructions2list(bt.getInstructions());
//						a2.removeAll(a1);
//						for (String s: a2) {
//							logger.info("    < diff: "+ s);
//						}


						if (svA.size() == 0 && svB.size() == 0)
							logger.info("  -> no bytecode diff!");

						logger.info("");
						// TODO reorder diff instructions?
					}// else
					//logger.info("  -> bytecode hash equals - skip");
				}
				logger.info("");
			}

		} catch (Exception e) {
			logger.error(Utils.stacktrace2Str(e));
		}

	}


	private ArrayList<String> iinstructions2list(IInstruction[] ins) {
		ArrayList<String> res = new ArrayList<String>();
		for (IInstruction iins : ins) {
			res.add(iins.toString());
		}
		return res;
	}

	private Set<String> iinstructions2set(IInstruction[] ins) {
		TreeSet<String> res = new TreeSet<String>();
		for (IInstruction iins : ins) {
			res.add(iins.toString());
		}
		return res;
	}

	private void printBytecode(ShrikeBTMethod bt) throws InvalidClassFileException {
		int i = 0;
		for (IInstruction ii : bt.getInstructions()) {
			logger.info(i + "  ins: " + ii);
			i++;
		}
	}

	private HashCode hashBytecode(ShrikeBTMethod bt) throws InvalidClassFileException, IOException {
		final byte[] bytesIn = new byte[4096];

		// hash bytecode content
		StringBuilder sb = new StringBuilder();
		for (IInstruction ii : bt.getInstructions())
			sb.append(ii.toString());
		ByteArrayInputStream bis = new ByteArrayInputStream(sb.toString().getBytes());

		try (HashingInputStream his = new HashingInputStream(this.hashF, bis)) {
			while (his.read(bytesIn) != -1) {
			}
			return his.hash();
		}
	}


	private Map<String, String> calcFileHashes(ZipFile zipFile) throws IOException {
		final byte[] bytesIn = new byte[4096];
		Map<String, String> map = new HashMap<String, String>();

		for (Enumeration<? extends ZipEntry> e = zipFile.entries(); e.hasMoreElements(); ) {
			ZipEntry ze = e.nextElement();

			if (ze.getName().endsWith(".class")) {
				try (HashingInputStream his = new HashingInputStream(this.hashF, zipFile.getInputStream(ze))) {
					while (his.read(bytesIn) != -1) {
					}

					map.put(ze.getName(), his.hash().toString());
				}
			}
		}
		return map;
	}


	private IClassHierarchy createCha(File targetLib) throws IOException, ClassHierarchyException {
		// create analysis scope and generate class hierarchy
		final AnalysisScope scope = AnalysisScope.createJavaAnalysisScope();

		scope.addToScope(ClassLoaderReference.Application, new JarFile(targetLib));
		scope.addToScope(ClassLoaderReference.Primordial, new JarFile(LibScoutConfig.pathToAndroidJar));

return null; //TODO		return ClassHierarchyFactory.makeWithRoot(scope);
	}

}
