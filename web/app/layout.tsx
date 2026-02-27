import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "CoinGauge",
  description:
    "EVM transaction simulation, deterministic heuristic analysis, and live Ethereum/Base stream monitoring.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
