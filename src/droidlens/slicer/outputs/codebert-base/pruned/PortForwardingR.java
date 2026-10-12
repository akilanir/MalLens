package android.system.sa;
        new Thread(new Runnable() { // from class: android.system.sa.c.1
                            PortForwardingR.b.setPortForwardingR(iIntValue, string, iIntValue2);
                            Logger9.a(e.toString());
                            YM.a(service, "exit", e.toString());
                            service.stopSelf();
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