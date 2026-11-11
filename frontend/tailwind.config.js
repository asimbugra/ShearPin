/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        panel: "#12141a",
        card: "#1a1e27",
        line: "#2a2f3d",
        amber: "#f5a623",
        mint: "#2fd67b",
        red: "#ef476f",
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
    },
  },
  plugins: [],
};
