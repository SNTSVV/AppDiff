/*
 * Copyright (c) 2015-2017  Erik Derr [derr@cs.uni-saarland.de]
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

package de.infsec.tpl.stats;

import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import de.infsec.tpl.config.LibScoutConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.infsec.tpl.hash.HashTreeOLD;
import de.infsec.tpl.profile.LibProfile;
import de.infsec.tpl.profile.SerializableProfileMatch;
import de.infsec.tpl.utils.Pair;
import de.infsec.tpl.utils.Utils;

// TODO to be removed!
@Deprecated
public class ApiUsageSQLStats {
	private static final Logger logger = LoggerFactory.getLogger(de.infsec.tpl.stats.ApiUsageSQLStats.class);

	public static File DB_FILE = new File("appStats-libusage.sqlite");
	
	// library table
	public static final String T_LIBRARY = "libraries";
	public static final String COL_CATEGORY = "category";
	public static final String COL_RELEASEDATE = "releaseDate";
	public static final String COL_LIB_PACKAGES = "libPackages";
	public static final String COL_LIB_CLASSES = "libClasses";
	public static final String COL_LIB_METHODS = "libMethods";
	public static final String COL_ROOT_PACKAGE = "rootPackage";

	// profile table
	public static final String T_PROFILE = "profiles";
	public static final String COL_LIBID = "libId";
	public static final String COL_APPID = "appId";
	public static final String COL_MATCHLEVEL = "matchLevel";
	public static final String COL_ISOBFUSCATED = "isObfuscated";
	public static final String COL_ROOTPCKG_PRESENT = "rootPckgPresent";
	public static final String COL_SIMSCORE = "simScore";

	
	// lib usage table (including API signatures)
	public static final String T_APIUSAGE = "libusage";//apiusage";
	public static final String COL_PROFILEID = "profileId";
	public static final String COL_API = "api";

	public static final String COL_APIID = "apiId";
	public static final String T_LIBAPI = "libapi";

	// shared columns
	public static final String COL_ID = "id";
	public static final String COL_NAME = "name";
	public static final String COL_VERSION = "version";

	
	
	public static void stats2DB(List<LibProfile> profiles) {
		try {
			logger.info("Generate Api Usage DBs (per library) from stats mode!");
			logger.info(Utils.INDENT + "Loaded " + profiles.size() + " profiles from disk");
			List<SerializableAppStats> appStats = loadAppStats(LibScoutConfig.statsDir);
			generateDB(profiles, appStats);
		} catch (Exception e) {
			logger.error(Utils.stacktrace2Str(e));
			System.exit(1);
		}
	}
	
	
	public static List<SerializableAppStats> loadAppStats(File dir) throws ClassNotFoundException, IOException {
		// de-serialize app stats
		long s = System.currentTimeMillis();
		List<SerializableAppStats> appStats = new ArrayList<SerializableAppStats>();
		for (File f: Utils.collectFiles(dir, new String[]{"data"})) {
			SerializableAppStats ap = (SerializableAppStats) Utils.disk2Object(f);
			appStats.add(ap);
		}
		
		logger.info(Utils.INDENT + "Loaded " + appStats.size() + " app stats from disk (in " + Utils.millisecondsToFormattedTime(System.currentTimeMillis() - s) + ")");
		logger.info("");
		
		return appStats;
	}


	public static void generateDB(List<LibProfile> profiles, List<SerializableAppStats> appStats) {
	    // load the sqlite-JDBC driver using the current class loader
		try {
			Class.forName("org.sqlite.JDBC");
		} catch (ClassNotFoundException e) {
			logger.error("Could not load class org.sqlite.JDBC - skip creating DB");
			return;
		}

		// export one DB file per library including app API usage stats
//		Set<String> uniqueLibraries = new TreeSet<String>(LibProfile.getUniqueLibraries(profiles).keySet());
		
	    Connection connection = null;
//	    for (String lib: uniqueLibraries) {
//	    	logger.info(Utils.INDENT + "= Export lib: " + lib + " =");
		    
		    try {
//		    	File baseDir = new File("./lib-databases");
//		    	if (!baseDir.exists())
//		    		baseDir.mkdirs();

		    	File dbFile = DB_FILE; //new File(baseDir + File.separator + "libusage-" + lib + ".sqlite");
		    	
		    	if (dbFile.exists())
		    		logger.warn("DB file " + DB_FILE + " exists! -- No updates will be performed - Abort!");
		    	else {
			    	// create a database connection
					connection = DriverManager.getConnection("jdbc:sqlite:" + dbFile.getName());
					
					createDB(connection);
					updateDB(connection, "", profiles, appStats);
		    	}
	
		    } catch(SQLException e) {
		    	logger.warn(Utils.stacktrace2Str(e));
		    } finally {
		    	try {
			        if (connection != null)
			          connection.close();
		    	} catch (SQLException e) {
		    		// connection close failed.
			    	logger.warn(Utils.stacktrace2Str(e));
		    	}
		    }	
//	    }
	}
	
	
	private static void createDB(Connection con) throws SQLException {
		logger.info("Create Database..");
		
		Statement stmt = con.createStatement();
		stmt.setQueryTimeout(30);  // set timeout to 30 sec.

		// create library description table
		String sql = "CREATE TABLE IF NOT EXISTS " + T_LIBRARY +  "(" +
			COL_ID + " INTEGER, " +
			COL_NAME + " VARCHAR(255) not NULL, " +         // library name
			COL_CATEGORY + " VARCHAR(255) not NULL, " +     // one of:  Advertising, Analytics, Android, Tracker, SocialMedia, Cloud, Utilities
			COL_VERSION + " VARCHAR(255) not NULL, " +      // library version
			COL_RELEASEDATE + " INTEGER not NULL, " +       // long milliseconds since beginning
			COL_LIB_PACKAGES + " INTEGER not NULL, " +      // number of non-empty lib packages
			COL_LIB_CLASSES + " INTEGER not NULL, " +       // number of lib classes
			COL_LIB_METHODS + " INTEGER, " +                // number of lib methods
			COL_ROOT_PACKAGE + " VARCHAR(255), " +          // library root package, might be null if ambigious
			"PRIMARY KEY (" + COL_NAME + ", " + COL_VERSION + ")"
		+ ")";
		stmt.executeUpdate(sql);

		// create profile match table
		sql = "CREATE TABLE IF NOT EXISTS " + T_PROFILE +  "(" +
			COL_ID + " INTEGER PRIMARY KEY, " +                 
			COL_APPID + " INTEGER NOT NULL, " +               // App id
			COL_LIBID + " INTEGER NOT NULL, " +               // Reference to T_LIBRARY.COL_ID
			COL_ISOBFUSCATED + " INTEGER NOT NULL, " +        // boolean, either 0 or 1
			COL_ROOTPCKG_PRESENT  + " INTEGER NOT NULL "      // boolean, either 0 or 1
		+ ")";
		stmt.executeUpdate(sql);
		
		// create library api usage table
		sql = "CREATE TABLE IF NOT EXISTS " + T_APIUSAGE +  "(" +
			COL_APIID + " INTEGER NOT NULL, " +              // Reference to T_LIBAPI.COL_ID
			COL_PROFILEID + " INTEGER NOT NULL "             // Reference to T_PROFILE.COL_ID
		+ ")";
		stmt.executeUpdate(sql);
		
		// create library api usage table
		sql = "CREATE TABLE IF NOT EXISTS " + T_LIBAPI +  "(" +
			COL_ID + " INTEGER NOT NULL, " +
			COL_API + " VARCHAR(255) NOT NULL "             // api signature
		+ ")";
		stmt.executeUpdate(sql);
	}
	
	
	public static void updateDB(Connection con, String libName, List<LibProfile> profiles, List<SerializableAppStats> stats) throws SQLException {
		logger.info("Update Database..");

		long starttime = System.currentTimeMillis();

		final PreparedStatement ps_library = con.prepareStatement("INSERT INTO " + T_LIBRARY + " VALUES (?,?,?,?,?,?,?,?,?)");
		final PreparedStatement ps_profile = con.prepareStatement("INSERT INTO " + T_PROFILE + " VALUES (?,?,?,?,?)");
		final PreparedStatement ps_apiUsage = con.prepareStatement("INSERT INTO " + T_APIUSAGE + " VALUES (?,?)");
		final PreparedStatement ps_libapi = con.prepareStatement("INSERT INTO " + T_LIBAPI + " VALUES (?,?)");
		
		// add all library profiles
		HashMap<Pair<String,String>, Integer> profile2ID = new HashMap<Pair<String,String>, Integer>();
		
		for (int i = 0; i < profiles.size(); i++) {
			LibProfile lib = profiles.get(i);
			
			ps_library.setInt(1, i+1);
			ps_library.setString(2, lib.description.name);
			ps_library.setString(3, lib.description.category.toString());
			ps_library.setString(4, lib.description.version);
			ps_library.setLong(5, lib.description.date == null? 0 : lib.description.date.getTime());
			ps_library.setInt(6, lib.packageTree.getNumberOfNonEmptyPackages());
			ps_library.setInt(7, lib.packageTree.getNumberOfAppClasses());
			ps_library.setInt(8, lib.hashTrees.get(0).getNumberOfMethods());  // TODO first version
			
			ps_library.setString(9, lib.packageTree.getRootPackage());

			ps_library.execute();
			
			profile2ID.put(lib.getLibIdentifier(), i+1);
			logger.info(Utils.INDENT + "- Added library (" + (i+1) + "/" + profiles.size() + "): " + lib.getLibIdentifier());
		}

		
		// update app / profile match table
		int profileId = 0;  // global profile counter
		int apiId = 0; // global api counter
		
		// signature to apiId idx
		HashMap<String, Integer> api2Idx = new HashMap<String,Integer>();

		// class name -> <sig, idx> , prevent item explosion of one hashmap		
//		Map<String, Map<String, Integer>> api2Id = new HashMap<String, Map<String, Integer>>();
		
		// for all apps
		for (int i = 0; i < stats.size(); i++) {
			SerializableAppStats appStat = stats.get(i);
			
			Set<String> matchedLibs = new HashSet<String>();
			
			// for all matched libraries
			for (SerializableProfileMatch pm: appStat.pMatches) {
				
// TODO TODO  vuln lib selection				
				if (!(pm.libName.equals("Supersonic") ||
					pm.libName.startsWith("Airpush") ||
					pm.libName.equals("MoPub") ||
					pm.libName.equals("Vungle")))
					continue;
//TODO TODO
					
				
				// filter PM's
				if (!(pm.matchLevel == SerializableProfileMatch.MATCH_ALL_CONFIGS &&   // only export full match
					matchedLibs.add(pm.libName)))                                    // if ambiguous, only export one ProfileMatch (as they are signature-identical)
					continue;  

				profileId++; // increment global profile id counter
				
				int libId = profile2ID.get(pm.getLibIdentifier());
								
				ps_profile.setInt(1, profileId);
				ps_profile.setInt(2, i+1);  // some unique app id to be able to distinguish profilematches of different apps
				ps_profile.setInt(3, libId);
				ps_profile.setBoolean(4, pm.isLibObfuscated);
				ps_profile.setInt(5, pm.libRootPackagePresent? 1 : 0);
				
//TODO				ps_profile.execute();
				ps_profile.addBatch();
				
				if (!pm.usedLibMethods.isEmpty()) {
					for (String sig: pm.usedLibMethods) {   // foreach api signature

		int idx;
		if (api2Idx.containsKey(sig))
			idx = api2Idx.get(sig);
		else {
			apiId++;
			idx = apiId;

			ps_libapi.setInt(1, idx);
			ps_libapi.setString(2, sig);
// TODO			ps_libapi.execute();
			ps_libapi.addBatch();
		}

		ps_apiUsage.setInt(1, idx);
		ps_apiUsage.setInt(2, profileId);
		// TODOps_apiUsage.execute();
		ps_apiUsage.addBatch();

						
//						String clazzName = Utils.getFullClassName(sig);
//						if (!api2Id.containsKey(clazzName))
//							api2Id.put(clazzName, new HashMap<String, Integer>());
						
//						if (!api2Id.get(clazzName).containsKey(sig)) {
//							apiId++;
//							api2Id.get(clazzName).put(sig,  apiId);
//							
//							ps_libapi.setInt(1, apiId);
//							ps_libapi.setString(2, sig);
//							ps_libapi.execute();
//						}
//						
//						ps_apiUsage.setInt(1, apiId);
//						ps_apiUsage.setInt(2, profileId);
//						ps_apiUsage.execute();
					}
				}
				
			}
			
			if (i % 1000 == 0) {
				ps_profile.executeBatch();
				ps_libapi.executeBatch();
				ps_apiUsage.executeBatch();
				logger.info("## App/Profile batch " + i + "/" + stats.size() + "  executed");
			}			

			
			//logger.info(Utils.INDENT + "- Added app (" + (i+1) + "/" + stats.size() + "): " + appStat.manifest.getPackageName() + " (" + appStat.manifest.getVersionCode() + ")");
		}

		logger.info("DB Update (" + profiles.size() + " lib profiles, " + stats.size() + " app stats) done in " + Utils.millisecondsToFormattedTime(System.currentTimeMillis() - starttime));
	}
}
