/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        slate: {
          950: '#0b0f19',
          900: '#0f172a',
          850: '#151e32',
          800: '#1e293b',
          700: '#334155',
        },
      },
    },
  },
  plugins: [],
}
