package de.infsec.tpl.stats;

import java.io.Serializable;

/**
 * Created by ederr on 17.07.17.
 */
public class ApiPermStats implements Serializable {
    public String api;
    public String permissions;
    public boolean libPackageMatch;
    public String libPackageName;
    public boolean appMatch;

    public ApiPermStats(String api, String permissions, boolean libPackageMatch, String libPackageName, boolean appMatch) {
        this.api = api;
        this.permissions = permissions;
        this.libPackageMatch = libPackageMatch;
        this.libPackageName = libPackageName;
        this.appMatch = appMatch;
    }
}
