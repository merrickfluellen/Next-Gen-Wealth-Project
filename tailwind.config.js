// Tailwind build config for deploy/tailwind.css (replaces the cdn.tailwindcss.com Play CDN).
// Rebuild after changing classes in deploy/*.html:   npm ci && npm run build:css
// app.html had no inline `tailwind.config = {...}`, so Tailwind defaults apply (same as the Play CDN).
// The scanner reads every string in the HTML, including JS. Class names built by string
// concatenation (e.g. 'bg-' + color) are NOT seen: write full class names, or add them to safelist.
/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./deploy/*.html'],
  safelist: [],
  theme: { extend: {} },
  plugins: [],
};
