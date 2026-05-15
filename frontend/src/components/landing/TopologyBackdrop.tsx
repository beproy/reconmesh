/**
 * TopologyBackdrop
 *
 * A faint, static node-and-edge graph rendered behind hero areas
 * (landing page, empty states, error pages). Provides the "intelligence
 * platform" texture without crossing into hacker-cliché territory.
 *
 * Design constraints:
 *   - Deterministic positions — same graph every render
 *   - No animation, no resize handler, no useEffect
 *   - preserveAspectRatio="xMidYMid slice" so it crops at narrow widths
 *     rather than distorting (preserves the spatial feel of the graph)
 *   - pointer-events: none so it never intercepts clicks
 *   - Low opacity default (0.18) so foreground content always dominates
 *
 * Reuse: drop this behind any hero block by wrapping the area in
 * `position: relative` and rendering <TopologyBackdrop /> as the first child.
 */

import React from 'react';

interface TopologyBackdropProps {
  /** Override the default opacity (0.18) */
  opacity?: number;
  /** Override the default accent color for nodes */
  nodeColor?: string;
  /** Override the default accent color for edges */
  edgeColor?: string;
}

const NODES: ReadonlyArray<readonly [number, number, number]> = [
  [120, 80,  2.5],
  [240, 140, 3.0],
  [400, 90,  2.5],
  [560, 150, 3.0],
  [680, 100, 2.5],
  [180, 280, 3.0],
  [340, 340, 3.5],
  [500, 290, 3.0],
  [620, 360, 2.5],
  [200, 430, 2.5],
  [380, 460, 3.0],
  [650, 440, 2.5],
] as const;

const EDGES: ReadonlyArray<readonly [number, number]> = [
  [0, 1], [1, 2], [2, 3], [3, 4],
  [1, 5], [5, 6], [6, 7], [7, 8],
  [2, 7], [0, 5], [4, 8],
  [6, 9], [7, 11], [9, 10], [10, 11],
] as const;

export const TopologyBackdrop: React.FC<TopologyBackdropProps> = ({
  opacity = 0.18,
  nodeColor = '#22d3ee',
  edgeColor = '#4ade80',
}) => {
  return (
    <svg
      viewBox="0 0 800 500"
      xmlns="http://www.w3.org/2000/svg"
      preserveAspectRatio="xMidYMid slice"
      aria-hidden="true"
      style={{
        position: 'absolute',
        inset: 0,
        width: '100%',
        height: '100%',
        opacity,
        pointerEvents: 'none',
      }}
    >
      <g stroke={edgeColor} strokeWidth="0.5" fill="none" opacity="0.6">
        {EDGES.map(([from, to], i) => {
          const [x1, y1] = NODES[from];
          const [x2, y2] = NODES[to];
          return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} />;
        })}
      </g>
      <g fill={nodeColor}>
        {NODES.map(([cx, cy, r], i) => (
          <circle key={i} cx={cx} cy={cy} r={r} />
        ))}
      </g>
    </svg>
  );
};

export default TopologyBackdrop;
