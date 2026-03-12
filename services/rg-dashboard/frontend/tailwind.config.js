/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        forge: {
          amber:       "#d4943c",
          amberLight:  "#e8b060",
          amberDim:    "#b07828",
          navy:        "#080e1a",
          navyMid:     "#0c1526",
          navyLight:   "#111d35",
          panel:       "#0f1520",
          panelLight:  "#1a2230",
          steel:       "#8899ad",
          steelDim:    "#6b7d91",
          ink:         "#e2e8f0",
          bg:          "#06090f",
          bgAlt:       "#0a0e18",
          success:     "#22c55e",
          warning:     "#f59e0b",
          error:       "#ef4444",
        },
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "-apple-system", "sans-serif"],
        mono: ["IBM Plex Mono", "SF Mono", "ui-monospace", "Menlo", "Consolas", "monospace"],
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
};
