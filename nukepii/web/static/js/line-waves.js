/* LineWaves — vanilla-JS port of the React Bits component (ogl, no React).
 * Fixed-background usage: window tracks the mouse since the layer is
 * pointer-events:none so page controls stay clickable.
 */

import { Renderer, Program, Mesh, Triangle } from 'ogl';

function hexToVec3(hex) {
  const h = String(hex || '#ffffff').replace('#', '');
  const full = h.length === 3 ? h.split('').map((c) => c + c).join('') : h;
  return [
    parseInt(full.slice(0, 2), 16) / 255,
    parseInt(full.slice(2, 4), 16) / 255,
    parseInt(full.slice(4, 6), 16) / 255
  ];
}

const vertexShader = `
attribute vec2 uv;
attribute vec2 position;
varying vec2 vUv;
void main() {
  vUv = uv;
  gl_Position = vec4(position, 0, 1);
}
`;

const fragmentShader = `
precision highp float;

uniform float uTime;
uniform vec3 uResolution;
uniform float uSpeed;
uniform float uInnerLines;
uniform float uOuterLines;
uniform float uWarpIntensity;
uniform float uRotation;
uniform float uEdgeFadeWidth;
uniform float uColorCycleSpeed;
uniform float uBrightness;
uniform vec3 uColor1;
uniform vec3 uColor2;
uniform vec3 uColor3;
uniform vec2 uMouse;
uniform float uMouseInfluence;
uniform bool uEnableMouse;
uniform float uLightMode;

#define HALF_PI 1.5707963

float hashF(float n) {
  return fract(sin(n * 127.1) * 43758.5453123);
}

float smoothNoise(float x) {
  float i = floor(x);
  float f = fract(x);
  float u = f * f * (3.0 - 2.0 * f);
  return mix(hashF(i), hashF(i + 1.0), u);
}

float displaceA(float coord, float t) {
  float result = sin(coord * 2.123) * 0.2;
  result += sin(coord * 3.234 + t * 4.345) * 0.1;
  result += sin(coord * 0.589 + t * 0.934) * 0.5;
  return result;
}

float displaceB(float coord, float t) {
  float result = sin(coord * 1.345) * 0.3;
  result += sin(coord * 2.734 + t * 3.345) * 0.2;
  result += sin(coord * 0.189 + t * 0.934) * 0.3;
  return result;
}

vec2 rotate2D(vec2 p, float angle) {
  float c = cos(angle);
  float s = sin(angle);
  return vec2(p.x * c - p.y * s, p.x * s + p.y * c);
}

void main() {
  vec2 coords = gl_FragCoord.xy / uResolution.xy;
  coords = coords * 2.0 - 1.0;
  coords = rotate2D(coords, uRotation);

  float halfT = uTime * uSpeed * 0.5;
  float fullT = uTime * uSpeed;

  float mouseWarp = 0.0;
  if (uEnableMouse) {
    vec2 mPos = rotate2D(uMouse * 2.0 - 1.0, uRotation);
    float mDist = length(coords - mPos);
    mouseWarp = uMouseInfluence * exp(-mDist * mDist * 4.0);
  }

  float warpAx = coords.x + displaceA(coords.y, halfT) * uWarpIntensity + mouseWarp;
  float warpAy = coords.y - displaceA(coords.x * cos(fullT) * 1.235, halfT) * uWarpIntensity;
  float warpBx = coords.x + displaceB(coords.y, halfT) * uWarpIntensity + mouseWarp;
  float warpBy = coords.y - displaceB(coords.x * sin(fullT) * 1.235, halfT) * uWarpIntensity;

  vec2 fieldA = vec2(warpAx, warpAy);
  vec2 fieldB = vec2(warpBx, warpBy);
  vec2 blended = mix(fieldA, fieldB, mix(fieldA, fieldB, 0.5));

  float fadeTop = smoothstep(uEdgeFadeWidth, uEdgeFadeWidth + 0.4, blended.y);
  float fadeBottom = smoothstep(-uEdgeFadeWidth, -(uEdgeFadeWidth + 0.4), blended.y);
  float vMask = 1.0 - max(fadeTop, fadeBottom);

  float tileCount = mix(uOuterLines, uInnerLines, vMask);
  float scaledY = blended.y * tileCount;
  float nY = smoothNoise(abs(scaledY));

  float ridge = pow(
    step(abs(nY - blended.x) * 2.0, HALF_PI) * cos(2.0 * (nY - blended.x)),
    5.0
  );

  float lines = 0.0;
  for (float i = 1.0; i < 3.0; i += 1.0) {
    lines += pow(max(fract(scaledY), fract(-scaledY)), i * 2.0);
  }

  float pattern = vMask * lines;

  float cycleT = fullT * uColorCycleSpeed;
  float rChannel = (pattern + lines * ridge) * (cos(blended.y + cycleT * 0.234) * 0.5 + 1.0);
  float gChannel = (pattern + vMask * ridge) * (sin(blended.x + cycleT * 1.745) * 0.5 + 1.0);
  float bChannel = (pattern + lines * ridge) * (cos(blended.x + cycleT * 0.534) * 0.5 + 1.0);

  vec3 col = (rChannel * uColor1 + gChannel * uColor2 + bChannel * uColor3) * uBrightness;
  float alpha = clamp(length(col), 0.0, 1.0);

  if (uLightMode > 0.5) {
    vec3 weights = pow(max(vec3(rChannel, gChannel, bChannel), vec3(0.0)), vec3(3.0));
    float weightSum = max(weights.r + weights.g + weights.b, 0.0001);
    vec3 chroma = (weights.r * uColor1 + weights.g * uColor2 + weights.b * uColor3) / weightSum;
    float neutral = min(chroma.r, min(chroma.g, chroma.b));
    chroma = max(chroma - vec3(neutral * 0.92), vec3(0.0));
    float peak = max(chroma.r, max(chroma.g, chroma.b));
    chroma = pow(clamp(chroma / max(peak, 0.0001), 0.0, 1.0), vec3(1.08));
    float ink = clamp(max(rChannel, max(gChannel, bChannel)) * uBrightness * 1.15, 0.0, 0.92);
    gl_FragColor = vec4(mix(vec3(1.0), chroma, ink), 1.0);
  } else {
    gl_FragColor = vec4(col, alpha);
  }
}
`;

export function initLineWaves(container, opts = {}) {
  const o = {
    speed: 0.3,
    innerLineCount: 32.0,
    outerLineCount: 36.0,
    warpIntensity: 1.8,
    rotation: -137,
    edgeFadeWidth: 0.65,
    colorCycleSpeed: 2.6,
    brightness: 0.3,
    color1: '#0BAE55',
    color2: '#0E2F23',
    color3: '#10B981',
    enableMouseInteraction: true,
    mouseInfluence: 1.7,
    ...opts
  };
  if (!container) return () => {};

  let renderer;
  try {
    renderer = new Renderer({ alpha: true, premultipliedAlpha: false });
  } catch {
    container.style.display = 'none';
    return () => {};
  }
  const gl = renderer.gl;
  gl.clearColor(0, 0, 0, 0);
  try {
    renderer.dpr = Math.min(window.devicePixelRatio || 1, 1.5);
  } catch {
    /* ignore */
  }

  const isLight = () => document.documentElement.classList.contains('light');

  const program = new Program(gl, {
    vertex: vertexShader,
    fragment: fragmentShader,
    uniforms: {
      uTime: { value: 0 },
      uResolution: { value: [gl.canvas.width, gl.canvas.height, 1] },
      uSpeed: { value: o.speed },
      uInnerLines: { value: o.innerLineCount },
      uOuterLines: { value: o.outerLineCount },
      uWarpIntensity: { value: o.warpIntensity },
      uRotation: { value: (o.rotation * Math.PI) / 180 },
      uEdgeFadeWidth: { value: o.edgeFadeWidth },
      uColorCycleSpeed: { value: o.colorCycleSpeed },
      uBrightness: { value: o.brightness },
      uColor1: { value: hexToVec3(o.color1) },
      uColor2: { value: hexToVec3(o.color2) },
      uColor3: { value: hexToVec3(o.color3) },
      uMouse: { value: new Float32Array([0.5, 0.5]) },
      uMouseInfluence: { value: o.mouseInfluence },
      uEnableMouse: { value: o.enableMouseInteraction },
      uLightMode: { value: isLight() ? 1 : 0 }
    }
  });

  const mesh = new Mesh(gl, { geometry: new Triangle(gl), program });
  container.appendChild(gl.canvas);

  const targetMouse = [0.5, 0.5];
  const currentMouse = [0.5, 0.5];

  function onWindowMouse(e) {
    targetMouse[0] = e.clientX / window.innerWidth;
    targetMouse[1] = 1.0 - e.clientY / window.innerHeight;
  }
  function onLeave() {
    targetMouse[0] = 0.5;
    targetMouse[1] = 0.5;
  }
  if (o.enableMouseInteraction) {
    window.addEventListener('mousemove', onWindowMouse, { passive: true });
    document.documentElement.addEventListener('mouseleave', onLeave);
  }

  function resize() {
    const w = container.clientWidth || window.innerWidth;
    const h = container.clientHeight || window.innerHeight;
    renderer.setSize(w, h);
    program.uniforms.uResolution.value = [gl.canvas.width, gl.canvas.height, gl.canvas.width / gl.canvas.height];
  }
  window.addEventListener('resize', resize);
  resize();

  const themeObs = new MutationObserver(() => {
    program.uniforms.uLightMode.value = isLight() ? 1 : 0;
  });
  themeObs.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });

  // NOTE: site owner explicitly wants motion, so this always animates
  // (no prefers-reduced-motion gate).
  let raf = 0;
  let running = true;

  function frame(time) {
    if (!running) return;
    raf = requestAnimationFrame(frame);
    program.uniforms.uTime.value = time * 0.001;
    currentMouse[0] += 0.05 * (targetMouse[0] - currentMouse[0]);
    currentMouse[1] += 0.05 * (targetMouse[1] - currentMouse[1]);
    program.uniforms.uMouse.value[0] = currentMouse[0];
    program.uniforms.uMouse.value[1] = currentMouse[1];
    renderer.render({ scene: mesh });
  }

  raf = requestAnimationFrame(frame);
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      running = false;
      cancelAnimationFrame(raf);
    } else {
      running = true;
      raf = requestAnimationFrame(frame);
    }
  });

  return () => {
    running = false;
    cancelAnimationFrame(raf);
    window.removeEventListener('resize', resize);
    window.removeEventListener('mousemove', onWindowMouse);
    document.documentElement.removeEventListener('mouseleave', onLeave);
    themeObs.disconnect();
    try {
      container.removeChild(gl.canvas);
    } catch {
      /* ignore */
    }
    gl.getExtension('WEBGL_lose_context')?.loseContext();
  };
}
