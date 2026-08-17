import React, { useRef, useMemo } from 'react';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';

/**
 * Background particle field representing the threat landscape.
 */
const ThreatParticles = React.memo(({ reducedMotion, threatLevel = 0 }) => {
  const pointsRef = useRef();
  
  const particleCount = 300;
  
  const { positions, colors } = useMemo(() => {
    const pos = new Float32Array(particleCount * 3);
    const col = new Float32Array(particleCount * 3);
    
    const colorCyan = new THREE.Color('#00d4ff');
    const colorOrange = new THREE.Color('#f29b2f');
    const colorRed = new THREE.Color('#ff3355');
    
    const threatRatio = threatLevel / 100;
    
    for (let i = 0; i < particleCount; i++) {
      // Random spherical distribution
      const r = 5 + Math.random() * 10;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      
      pos[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      pos[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
      pos[i * 3 + 2] = r * Math.cos(phi);
      
      // Assign color based on threat level
      let c = colorCyan;
      if (Math.random() < threatRatio) {
        c = Math.random() > 0.5 ? colorRed : colorOrange;
      } else if (Math.random() < 0.1) {
        c = colorOrange; // Base scattered orange
      }
      
      col[i * 3] = c.r;
      col[i * 3 + 1] = c.g;
      col[i * 3 + 2] = c.b;
    }
    
    return { positions: pos, colors: col };
  }, [threatLevel]);

  useFrame((state, delta) => {
    if (document.hidden || reducedMotion || !pointsRef.current) return;
    
    pointsRef.current.rotation.y += delta * 0.05;
    pointsRef.current.rotation.x += delta * 0.02;
  });

  return (
    <points ref={pointsRef}>
      <bufferGeometry>
        <bufferAttribute
          attach="attributes-position"
          count={particleCount}
          array={positions}
          itemSize={3}
        />
        <bufferAttribute
          attach="attributes-color"
          count={particleCount}
          array={colors}
          itemSize={3}
        />
      </bufferGeometry>
      <pointsMaterial
        size={0.03}
        vertexColors
        transparent
        opacity={0.6}
        sizeAttenuation
      />
    </points>
  );
});

export default ThreatParticles;
