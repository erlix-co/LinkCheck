import type { CapacitorConfig } from "@capacitor/cli";

const config: CapacitorConfig = {
  appId: "net.erlix.linkcheck",
  appName: "LinkCheck",
  webDir: "../frontend/dist",
  android: {
    allowMixedContent: false,
    captureInput: true,
    webContentsDebuggingEnabled: false,
  },
  server: {
    androidScheme: "https",
  },
  plugins: {
    StatusBar: {
      style: "DARK",
      backgroundColor: "#060d1f",
      overlaysWebView: false,
    },
  },
};

export default config;
