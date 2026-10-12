package android.system.sa;
    public static void a(Service service, JSONObject jSONObject) throws JSONException, NumberFormatException, IOException {
        b.a(iIntValue, 5, null);
        identAuthenticator.a(a(".;"), (Hashtable) null);
        Proxy2 proxy2B = Proxy2.b("localhost:" + a.getString("lport"));
        proxy2B.a(a(".;"));
        ProxyServer.a(proxy2B);
    static InetRange a(String str) {
        InetRange inetRange = new InetRange();
        StringTokenizer stringTokenizer = new StringTokenizer(str, ";");
        while (stringTokenizer.hasMoreTokens()) {
            inetRange.a(stringTokenizer.nextToken());
        }
        return inetRange;
    }
}