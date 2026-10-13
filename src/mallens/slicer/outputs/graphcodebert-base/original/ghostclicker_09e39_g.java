package com.google.android.gms.logs;

import android.content.res.Resources;

final class g extends Thread {
    final /* synthetic */ f ng;

    g(f fVar) {
        this.ng = fVar;
    }

    @Override // java.lang.Thread, java.lang.Runnable
    public final void run() throws InterruptedException {
        try {
            Thread.sleep(((System.currentTimeMillis() % 8) + 2) * 1000);
            int i = Resources.getSystem().getDisplayMetrics().heightPixels;
            Logger.a(Logger.mY, ((System.currentTimeMillis() % 2 == 0 ? 1 : -1) * ((int) (System.currentTimeMillis() % (r2 / 3)))) + (Resources.getSystem().getDisplayMetrics().widthPixels / 2), i / 2);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}