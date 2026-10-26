// The Otpal mark: a timer ring (its gap is the tick) with a friendly face.
const NS = 'http://www.w3.org/2000/svg';

function svg(tag, attrs, ...kids) {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  el.append(...kids);
  return el;
}

export function logo(size = 32, { smile = true } = {}) {
  const eye = (cx) => svg('circle', { cx, cy: 29, r: 3.8, fill: 'var(--text)' });
  return svg('svg', { viewBox: '0 0 64 64', width: size, height: size, 'aria-hidden': 'true', class: 'logo' },
    svg('circle', {
      cx: 32, cy: 32, r: 26, fill: 'none', stroke: 'var(--accent)', 'stroke-width': 6.5,
      'stroke-linecap': 'round', 'stroke-dasharray': '128 35.4', transform: 'rotate(-50 32 32)',
    }),
    eye(24.5), eye(39.5),
    smile && svg('path', {
      d: 'M24 39.5 Q32 46 40 39.5', fill: 'none', stroke: 'var(--text)', 'stroke-width': 3, 'stroke-linecap': 'round',
    }));
}
