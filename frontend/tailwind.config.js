export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      boxShadow: {
        glow: '0 0 0 1px rgba(59, 130, 246, 0.28), 0 24px 60px rgba(15, 23, 42, 0.42)',
      },
      fontFamily: {
        sans: ['"Space Grotesk"', '"Segoe UI"', 'sans-serif'],
      },
      backgroundImage: {
        'grid-fade':
          'linear-gradient(rgba(148, 163, 184, 0.08) 1px, transparent 1px), linear-gradient(90deg, rgba(148, 163, 184, 0.08) 1px, transparent 1px)',
      },
    },
  },
  plugins: [],
};
