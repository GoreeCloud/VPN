import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "GoreeCloud VPN — Private networking",
  description: "Self-hosted GoreeCloud VPN administration",
  robots: { index: false, follow: false }
};
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
