package org.primftpd.ui;

import android.app.ProgressDialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.AsyncTask;

import androidx.annotation.Nullable;

import org.primftpd.crypto.HostKeyAlgorithm;
import org.primftpd.prefs.LoadPrefsUtil;
import org.primftpd.util.KeyFingerprintProvider;
import org.primftpd.util.ServicesStartStopUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileOutputStream;
import java.util.Set;

public class GenKeysAsyncTask extends AsyncTask<Void, Void, Void> {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final KeyFingerprintProvider keyFingerprintProvider;
    @Nullable
    private PftpdFragment fragment;
    private Context context;
    @Nullable
    private ProgressDialog progressDiag;
    private final boolean startServerOnFinish;

    public GenKeysAsyncTask(
            PftpdFragment fragment,
            ProgressDialog progressDiag,
            boolean startServerOnFinish) {
        super();
        logger.trace("GenKeysAsyncTask()");
        this.keyFingerprintProvider = fragment.getKeyFingerprintProvider();
        this.fragment = fragment;
        this.context = fragment.getContext();
        this.progressDiag = progressDiag;
        this.startServerOnFinish = startServerOnFinish;
    }

    public GenKeysAsyncTask(
            Context context,
            boolean startServerOnFinish) {
        super();
        logger.trace("GenKeysAsyncTask()");
        this.keyFingerprintProvider = new KeyFingerprintProvider();
        this.context = context;
        this.startServerOnFinish = startServerOnFinish;
    }

    @Override
    protected Void doInBackground(Void... params) {
        logger.debug("generating keys");
        try {
//            String[] fileList = fragment.requireActivity().fileList();
//            if (fileList != null) {
//                logger.trace("num of existing files: '{}'", fileList.length);
//                for (String file : fileList) {
//                    logger.trace("existing file: '{}'", file);
//                }
//            } else {
//                logger.trace("no existing files");
//            }

            Context context = this.context;
            if (context == null) {
                logger.trace("context is null");
                return null;
            }
            for (HostKeyAlgorithm hka : HostKeyAlgorithm.values()) {
                logger.trace("removing keys of hostkey algo {}", hka.getAlgorithmName());
                keyFingerprintProvider.deleteKeyFiles(context, hka);
            }

            SharedPreferences prefs = LoadPrefsUtil.getPrefs(context);
            Set<String> configuredAlgos = prefs.getStringSet(
                    LoadPrefsUtil.PREF_KEY_HOSTKEY_ALGOS,
                    LoadPrefsUtil.HOSTKEY_ALGOS_DEFAULTS);
            logger.trace("got configured algos {}", configuredAlgos);

            //progressDiag.setMax(configuredAlgos.size());
            int progress = 0;
            for (HostKeyAlgorithm hka : HostKeyAlgorithm.values()) {
                if (configuredAlgos.contains(hka.getPreferenceValue())) {
                    try (
                            FileOutputStream publickeyFos = keyFingerprintProvider.buildPublickeyOutStream(context, hka);
                            FileOutputStream privatekeyFos = keyFingerprintProvider.buildPrivatekeyOutStream(context, hka)
                    ) {
                        hka.generateKey(publickeyFos, privatekeyFos);
                        progress++;
                        //progressDiag.setProgress(progress);
                    } catch (Exception e) {
                        logger.error("could not generate key " + hka.getAlgorithmName(), e);
                    }
                }
            }
        } catch (Exception e) {
            logger.error("could not generate keys", e);
        }
        return null;
    }

    @Override
    protected void onPostExecute(Void result) {
        super.onPostExecute(result);
        logger.trace("onPostExecute()");
        keyFingerprintProvider.calcPubkeyFingerprints(context);
        //progressDiag.dismiss();
        if (fragment != null) {
            fragment.showKeyFingerprints();
        }

        if (startServerOnFinish) {
            // icon members should be set at this time
            ServicesStartStopUtil.startServers(context);
        }
    }
}
