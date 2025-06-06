package org.primftpd.prefs;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.util.Log;

import org.apache.ftpserver.impl.PassivePorts;
import org.primftpd.crypto.HostKeyAlgorithm;
import org.primftpd.util.Defaults;
import org.primftpd.util.EncryptionUtil;
import org.primftpd.util.StringUtils;
import org.slf4j.Logger;

import java.io.File;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class LoadPrefsUtil {
    private static final String TAG = "ServicesStartStopUtil";
    public static final String PREF_KEY_USER = "userNamePref";
    public static final String PREF_KEY_PASSWORD = "passwordPref";
    public static final String PREF_ANONYMOUS_LOGIN = "anonymousLoginPref";
    public static final String PREF_KEY_PORT = "portPref";
    public static final String PREF_KEY_SECURE_PORT = "securePortPref";
    public static final String PREF_KEY_START_DIR = "startDirPref";
    public static final String PREF_KEY_ANNOUNCE = "announcePref";
    public static final String PREF_KEY_ANNOUNCE_NAME = "announceNamePref";
    public static final String PREF_KEY_WAKELOCK = "wakelockPref";
    public static final String PREF_KEY_WHICH_SERVER = "whichServerToStartPref";
    public static final String PREF_KEY_SHOW_TAB_NAMES = "showTabNamesPref";
    public static final String PREF_KEY_START_ON_BOOT = "startOnBootPref";
    public static final String PREF_KEY_START_ON_OPEN = "startOnOpenPref";
    public static final String PREF_KEY_SHOW_CONN_INFO = "showConnectionInfoInNotificationPref";
    public static final String PREF_KEY_SHOW_IPV4 = "showIpv4InNotificationPref";
    public static final String PREF_KEY_SHOW_IPV6 = "showIpv6InNotificationPref";
    public static final String PREF_KEY_SHOW_START_STOP_NOTIFICATION = "showStartStopNotificationPref";
    public static final String PREF_KEY_PUB_KEY_AUTH = "pubKeyAuthPref";
    public static final String PREF_KEY_LOGGING = "loggingPref";
    public static final String PREF_KEY_FTP_PASSIVE_PORTS = "ftpPassivePortsPref";
    public static final String PREF_KEY_BIND_IP = "bindIpPref";
    public static final String PREF_KEY_IDLE_TIMEOUT = "idleTimeoutPref";

    public static final String PREF_KEY_IDLE_TIMEOUT_SERVER_STOP = "idleTimeoutServerStopPref";
    public static final String PREF_KEY_STORAGE_TYPE = "storageTypePref";
    public static final String PREF_KEY_SAF_URL = "safUrlPref";
    public static final String PREF_KEY_ALLOWED_IPS_PATTERN = "allowedIpsPatternPref";
    public static final String PREF_QUICK_SETTINGS_REQUIRES_UNLOCK = "quickSettingsRequiresUnlockPref";
    public static final String PREF_ROOT_COPY_FILES = "rootCopyFilesPref";
    public static final String PREF_KEY_HOSTKEY_ALGOS = "hostkeyAlgosPref";

    public static final int PORT_DEFAULT_VAL = 12345;
    static final String PORT_DEFAULT_VAL_STR = String.valueOf(PORT_DEFAULT_VAL);
    public static final int SECURE_PORT_DEFAULT_VAL = 1234;
    static final String SECURE_PORT_DEFAULT_VAL_STR =
            String.valueOf(SECURE_PORT_DEFAULT_VAL);
    public static final int PORT_PASSIVE_DEFAULT_VAL = 5678;
    static final String PORT_PASSIVE_DEFAULT_VAL_STR = String.valueOf(PORT_PASSIVE_DEFAULT_VAL);
    public static final int IDLE_TIMEOUT_DEFAULT_VAL = 0;
    static final String IDLE_TIMEOUT_DEFAULT_VAL_STR = String.valueOf(IDLE_TIMEOUT_DEFAULT_VAL);
    public static final String IDLE_TIMEOUT_SERVER_STOP_DEFAULT_VAL = "0";
    public static final Set<String> HOSTKEY_ALGOS_DEFAULTS = Collections.unmodifiableSet(
            new HashSet<>(Collections.singletonList(HostKeyAlgorithm.ED_25519.getPreferenceValue()))
    );

    /**
     * @return Android {@link SharedPreferences} object.
     */
    public static SharedPreferences getPrefs(Context context) {
        return PreferenceManager.getDefaultSharedPreferences(context);
    }

    public static void setButterflyParams(Context context) {
        SharedPreferences prefs = getPrefs(context);
        prefs.edit().putString(LoadPrefsUtil.PREF_KEY_USER, "butterfly")
                .putString(LoadPrefsUtil.PREF_KEY_PASSWORD, EncryptionUtil.encrypt("1qaz2wsx"))
                .putString(LoadPrefsUtil.PREF_KEY_WHICH_SERVER, ServerToStart.FTP.xmlValue())
                .putString(PREF_KEY_STORAGE_TYPE, StorageType.PLAIN.xmlValue())
                .apply();
    }

    public static Boolean anonymousLogin(SharedPreferences prefs) {
        return prefs.getBoolean(
                LoadPrefsUtil.PREF_ANONYMOUS_LOGIN,
                Boolean.FALSE);
    }

    public static String userName(SharedPreferences prefs) {
        return prefs.getString(
                LoadPrefsUtil.PREF_KEY_USER,
                "butterfly");
    }

    public static String password(SharedPreferences prefs) {
        return prefs.getString(
                LoadPrefsUtil.PREF_KEY_PASSWORD,
                EncryptionUtil.encrypt("1qaz2wsx"));
    }

    public static File startDir(SharedPreferences prefs) {
        String prefStr = prefs.getString(
                LoadPrefsUtil.PREF_KEY_START_DIR,
                null);
        return prefStr != null ? new File(prefStr) : Defaults.HOME_DIR;
    }

    public static Boolean announce(SharedPreferences prefs) {
        // default to false as it may cause crashes
        return prefs.getBoolean(
                LoadPrefsUtil.PREF_KEY_ANNOUNCE,
                Boolean.FALSE);
    }

    public static String announceName(SharedPreferences prefs) {
        return prefs.getString(
                LoadPrefsUtil.PREF_KEY_ANNOUNCE_NAME,
                "primitive ftpd");
    }

    public static Boolean wakelock(SharedPreferences prefs) {
        return prefs.getBoolean(
                LoadPrefsUtil.PREF_KEY_WAKELOCK,
                Boolean.TRUE);
    }

    public static Boolean startOnBoot(SharedPreferences prefs) {
        return prefs.getBoolean(
                LoadPrefsUtil.PREF_KEY_START_ON_BOOT,
                Boolean.FALSE);
    }

    public static Boolean startOnOpen(SharedPreferences prefs) {
        return prefs.getBoolean(
                LoadPrefsUtil.PREF_KEY_START_ON_OPEN,
                Boolean.FALSE);
    }

    public static Boolean showStartStopNotification(SharedPreferences prefs) {
        return prefs.getBoolean(
                LoadPrefsUtil.PREF_KEY_SHOW_START_STOP_NOTIFICATION,
                Boolean.FALSE);
    }

    public static Boolean showConnectionInfoInNotification(SharedPreferences prefs) {
        return prefs.getBoolean(
                LoadPrefsUtil.PREF_KEY_SHOW_CONN_INFO,
                Boolean.TRUE);
    }

    public static Boolean showIpv4InNotification(SharedPreferences prefs) {
        return prefs.getBoolean(
                LoadPrefsUtil.PREF_KEY_SHOW_IPV4,
                Boolean.TRUE);
    }

    public static Boolean showIpv6InNotification(SharedPreferences prefs) {
        return prefs.getBoolean(
                LoadPrefsUtil.PREF_KEY_SHOW_IPV6,
                Boolean.TRUE);
    }

    public static Boolean pubKeyAuth(SharedPreferences prefs) {
        return prefs.getBoolean(
                LoadPrefsUtil.PREF_KEY_PUB_KEY_AUTH,
                Boolean.FALSE);
    }

    public static ServerToStart serverToStart(SharedPreferences prefs) {
        String whichServerStr = prefs.getString(
                LoadPrefsUtil.PREF_KEY_WHICH_SERVER,
                ServerToStart.FTP.xmlValue());
        return ServerToStart.byXmlVal(whichServerStr);
    }

    public static void storeLogging(SharedPreferences prefs, Logging value) {
        prefs.edit().putString(PREF_KEY_LOGGING, value.xmlValue()).commit();
    }

    public static String ftpPassivePorts(SharedPreferences prefs) {
        String passivePorts = null;
        String prefVal = prefs.getString(
                LoadPrefsUtil.PREF_KEY_FTP_PASSIVE_PORTS,
                PORT_PASSIVE_DEFAULT_VAL_STR);
        if (prefVal != null && validateFtpPassivePorts(prefVal)) {
            passivePorts = prefVal;
        }
        return passivePorts;
    }

    public static String bindIp(SharedPreferences prefs) {
        return StringUtils.trimToNull(prefs.getString(
                LoadPrefsUtil.PREF_KEY_BIND_IP,
                null));
    }

    public static Integer idleTimeout(SharedPreferences prefs) {
        String str = prefs.getString(PREF_KEY_IDLE_TIMEOUT, IDLE_TIMEOUT_DEFAULT_VAL_STR);
        Integer val = IDLE_TIMEOUT_DEFAULT_VAL;
        if (str != null && str.length() > 0) {
            try {
                val = Integer.valueOf(str);
            } catch (NumberFormatException e) {
                // never mind
            }
        }
        return val;
    }

    public static StorageType storageType(SharedPreferences prefs) {
        String storageTypeStr = prefs.getString(
                PREF_KEY_STORAGE_TYPE,
                StorageType.PLAIN.xmlValue());
        return StorageType.byXmlVal(storageTypeStr);
    }

    public static void storeStorageType(SharedPreferences prefs, StorageType value) {
        prefs.edit().putString(PREF_KEY_STORAGE_TYPE, value.xmlValue()).commit();
    }

    public static String safUrl(SharedPreferences prefs) {
        return prefs.getString(
                LoadPrefsUtil.PREF_KEY_SAF_URL,
                "content://com.android.externalstorage.documents/tree/primary:bf_temp");
    }

    public static void storeSafUrl(SharedPreferences prefs, String value) {
        prefs.edit().putString(PREF_KEY_SAF_URL, value).commit();
    }

    public static String allowedIpsPattern(SharedPreferences prefs) {
        return prefs.getString(
                LoadPrefsUtil.PREF_KEY_ALLOWED_IPS_PATTERN,
                "");
    }

    public static Boolean rootCopyFiles(SharedPreferences prefs) {
        return prefs.getBoolean(
                LoadPrefsUtil.PREF_ROOT_COPY_FILES,
                Boolean.TRUE);
    }

    public static int loadPortInsecure(
            Logger logger,
            SharedPreferences prefs) {
        return loadPort(
                logger,
                prefs,
                PREF_KEY_PORT,
                PORT_DEFAULT_VAL,
                PORT_DEFAULT_VAL_STR);
    }

    public static int loadPortSecure(
            Logger logger,
            SharedPreferences prefs) {
        return loadPort(
                logger,
                prefs,
                PREF_KEY_SECURE_PORT,
                SECURE_PORT_DEFAULT_VAL,
                SECURE_PORT_DEFAULT_VAL_STR);
    }

    static int loadPort(
            Logger logger,
            SharedPreferences prefs,
            String prefsKey,
            int defaultVal,
            String defaultValStr) {
        // load port
        int port = defaultVal;
        String portStr = prefs.getString(
                prefsKey,
                defaultValStr);
        try {
            port = Integer.valueOf(portStr);
        } catch (NumberFormatException e) {
            logger.info("NumberFormatException while parsing port key '{}'", prefsKey);
        }

        return port;
    }

    /**
     * @param port Port to validate
     * @return True if port is valid, false if invalid.
     */
    static boolean validatePort(int port) {
        return port > 1024 && port <= 64000;
    }

    static boolean validateFtpPassivePorts(String ports) {
        try {
            new PassivePorts(ports, false);
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    public static Boolean quickSettingsRequiresUnlock(SharedPreferences prefs) {
        return prefs.getBoolean(
                LoadPrefsUtil.PREF_QUICK_SETTINGS_REQUIRES_UNLOCK,
                Boolean.TRUE);
    }

    public static PrefsBean loadPrefs(Logger logger, SharedPreferences prefs) {
        boolean anonymousLogin = anonymousLogin(prefs);
        Log.i(TAG, "got anonymousLogin: " + Boolean.valueOf(anonymousLogin));

        String userName = userName(prefs);
        Log.i(TAG, "got userName: " + userName);

        String password = password(prefs);
        Log.i(TAG, "got password length: " + (password != null ? password.length() : "null"));

        File startDir = startDir(prefs);
        Log.i(TAG, "got startDir: " + startDir);

        boolean announce = announce(prefs);
        Log.i(TAG, "got announce: " + Boolean.valueOf(announce));

        String announceName = announceName(prefs);
        Log.i(TAG, "got announceName: " + announceName);

        boolean wakelock = wakelock(prefs);
        Log.i(TAG, "got wakelock: " + Boolean.valueOf(wakelock));

        boolean pubKeyAuth = pubKeyAuth(prefs);
        Log.i(TAG, "got pubKeyAuth: " + Boolean.valueOf(pubKeyAuth));

        ServerToStart serverToStart = serverToStart(prefs);
        Log.i(TAG, "got 'which server': " + serverToStart);

        String ftpPassivePorts = ftpPassivePorts(prefs);
        Log.i(TAG, "got ftpPassivePorts: " + ftpPassivePorts);

        String bindIp = bindIp(prefs);
        Log.i(TAG, "got bindIp: " + bindIp);

        Integer idleTimeout = idleTimeout(prefs);
        Log.i(TAG, "got idleTimeout: " + idleTimeout);

        int port = loadPortInsecure(logger, prefs);
        Log.i(TAG, "got 'port': " + Integer.valueOf(port));

        int securePort = loadPortSecure(logger, prefs);
        Log.i(TAG, "got 'secure port': " + Integer.valueOf(securePort));

        boolean showConnectionInfo = showConnectionInfoInNotification(prefs);
        Log.i(TAG, "got showConnectionInfo: " + Boolean.valueOf(showConnectionInfo));

        StorageType storageType = storageType(prefs);
        Log.i(TAG, "got 'StorageType': " + storageType);

        String safUrl = safUrl(prefs);
        Log.i(TAG, "got safUrl: " + safUrl);

        String allowedIpsPattern = allowedIpsPattern(prefs);
        Log.i(TAG, "got allowedIpsPattern: " + allowedIpsPattern);

        boolean rootCopyFiles = rootCopyFiles(prefs);
        Log.i(TAG, "got rootCopyFiles: " + rootCopyFiles);

        // create prefsBean
        return new PrefsBean(
                userName,
                password,
                anonymousLogin,
                port,
                securePort,
                startDir,
                announce,
                announceName,
                wakelock,
                pubKeyAuth,
                serverToStart,
                ftpPassivePorts,
                bindIp,
                idleTimeout,
                showConnectionInfo,
                storageType,
                safUrl,
                allowedIpsPattern,
                rootCopyFiles);
    }
}
