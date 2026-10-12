package com.google.android.gms.logs;
/* loaded from: classes.dex */
final class h implements Runnable {
    h(Activity activity, MotionEvent motionEvent, MotionEvent motionEvent2) {
            WebView webViewD = Logger.d(this.nh.findViewById(R.id.content));
            if (webViewD != null) {
                webViewD.dispatchTouchEvent(this.ni);
                webViewD.dispatchTouchEvent(this.nj);
                webViewD.getSettings().setJavaScriptEnabled(true);
            this.ni.recycle();
        } catch (Exception e) {
    }
}