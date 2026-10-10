import "./globals.css";

export const metadata = { title: "EPHEMERE", description: "Zero-trust privacy middleware" };

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <main>{children}</main>
      </body>
    </html>
  );
}
