import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Cyber-Intel Dashboard",
  description: "Real-time domain & IP threat intelligence lookup",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-[#05050a] text-gray-200 antialiased">
        {children}
      </body>
    </html>
  );
}
