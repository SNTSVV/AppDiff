# AppDiff

AppDiff is an extension of [LibScout](https://github.com/reddr/LibScout), a light-weight and effective static analysis tool to detect third-party libraries in Android/Java apps.
AppDiff finds code changes across two versions of an app, i.e. changes in methods with the same signature, added/deleted classes/packages.



##  AppDiff 101

 * AppDiff requires Java 1.8 or higher and can be build with Gradle.
 * Generate a runnable jar with the gradle wrapper <i>gradlew</i> (Linux/MacOS) or <i>gradlew.bat</i> (Windows), by invoking it with the <i>build</i> task, e.g. <i>./gradlew build</i><br>
   The <i>AppDiff.jar</i> is output to the <i>build/libs</i> directory.
 * Some less frequently changing options can be configured via LibScout's config file [LibScout.toml](config/LibScout.toml).
 * Most LibScout modules require an Android SDK (jar) to distinguish app code from framework code (via the -a switch).
Refer to <a href="https://developer.android.com/studio/">https://developer.android.com/studio/</a> for download instructions.
 * By default, LibScout logs to stdout. Use the -d switch to redirect output to files. The -m switch disables any text output. Depending on the operation mode (see below), LibScout's results can be written to disk in JSON format or JAVA serialization.
 * Repo structure in a nutshell:<br>

<pre><code>
|_ gradlew / gradlew.bat (gradle wrappers to generate runnable LibScout.jar)
|_ assets
|    |_ library.xml (Library meta-data template)
|_ config
|    |_ LibScout.toml (LibScout's config file)
|    |_ logback.xml (log4j configuration file)
|_ data
|    |_ app-version-codes.csv (Google Play app packages with valid version codes)
|_ lib
|    Android axml
|_ scripts
|    |_ library-specs (pre-defined library specs)
|    |_ library-scraper.py   (scraper for mvn-central, jcenter, custom mvn)
|    |_ library-profile-generator.sh (convenience profile generator)
|_ src
    source directory of LibScout (de/infsec/tpl). Find the appdiff code in de/infsec/tpl/modules/appdiff.
</code></pre>

### Application Version Diff (-o diff)

AppDiff takes two (subsequent) versions of the same app and reports on any changes in the bytecode, these includes changes in methods with the same signature, addition/removal of methods/classes/packages.
The log output further visualizes the changes in a diff tree. All changes are additionally written to a json file (-j switch). By default, it computes a method hash over the method signature. Use the -h switch
to enable method hashing over the entire code.

<pre>java -jar appdiff.jar -o diff -a <i>android_sdk_jar</i> [-h] -j <i>json_dir</i> <i>path_to_apk_old_version<i> <i>path_to_apk_new_version<i> </pre>

