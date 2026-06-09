// Deterministic, well-spread color per zone id (golden-angle hue).
// Returns inline styles tuned to read on both light and dark themes
// (translucent background of the hue + a mid-tone text/border of the same hue).
export function zoneHue(id) {
  return Math.round((Number(id) * 137.508 + 40) % 360)
}

export function zoneStyle(id) {
  const h = zoneHue(id)
  return {
    background: `hsla(${h}, 70%, 50%, 0.18)`,
    color: `hsl(${h}, 65%, 48%)`,
    border: `1px solid hsla(${h}, 70%, 50%, 0.4)`,
  }
}
