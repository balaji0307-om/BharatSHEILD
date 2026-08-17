import React, { useRef, useMemo } from 'react';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';

/**
 * Scan animation shown when analysis is loading.
 */
const ThreatScanner = React.memo(({ reducedMotion, active, score }) => {
  const ringsRef = useRef([]);

  const color = useMemo(() => {
    if (active || score === undefined) return '#00d4ff';
    if (score <= 30) return '#00ff88';
    if (score <= 55) return '#f2b83b';
    if (score <= 75) return '#f28c3b';
    return '#ff3355';
  }, [active, score]);

  const colorObj = useMemo(() => new THREE.Color(color), [color]);

  useFrame((state, delta) => {
    if (document.hidden || reducedMotion) return;
    
    ringsRef.current.forEach((ring, i) => {
      if (ring) {
        const speedMultiplier = active ? 3 : 0.5;
        ring.rotation.x += delta * (0.2 + i * 0.1) * speedMultiplier;
        ring.rotation.y += delta * (0.15 + i * 0.05) * speedMultiplier;
      }
    });
  });

  return (
    <group>
      {[1, 1.5, 2, 2.5].map((radius, i) => (
        <mesh 
          key={i} 
          ref={el => ringsRef.current[i] = el}
          rotation={[Math.random() * Math.PI, Math.random() * Math.PI, 0]}
        >
          <torusGeometry args={[radius, 0.02, 8, 32]} />
          <meshBasicMaterial 
            color={colorObj} 
            transparent 
            opacity={active ? 0.6 : 0.3} 
          />
        </mesh>
      ))}
    </group>
  );
});

export default ThreatScanner;
