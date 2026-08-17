import React, { useRef, useMemo } from 'react';
import { useFrame } from '@react-three/fiber';
import { Html } from '@react-three/drei';
import * as THREE from 'three';

/**
 * Holographic radial risk meter.
 */
const ScanGauge3D = React.memo(({ score = 0, risk, confidence, reducedMotion }) => {
  const groupRef = useRef();

  const color = useMemo(() => {
    if (score <= 30) return '#00ff88';
    if (score <= 55) return '#f2b83b';
    if (score <= 75) return '#f28c3b';
    return '#ff3355';
  }, [score]);

  useFrame((state, delta) => {
    if (document.hidden || reducedMotion || !groupRef.current) return;
    groupRef.current.rotation.z += delta * 0.2;
  });

  const thetaLength = (score / 100) * Math.PI * 2;

  return (
    <group>
      <group ref={groupRef}>
        {/* Background track */}
        <mesh>
          <ringGeometry args={[1.2, 1.4, 64]} />
          <meshBasicMaterial color="#0a1628" transparent opacity={0.5} side={THREE.DoubleSide} />
        </mesh>
        
        {/* Value track */}
        <mesh>
          <ringGeometry args={[1.2, 1.4, 64, 1, Math.PI / 2, thetaLength]} />
          <meshBasicMaterial color={color} side={THREE.DoubleSide} />
        </mesh>
      </group>
      
      <Html center>
        <div style={{ 
          textAlign: 'center', 
          color: '#e0e8f0',
          fontFamily: 'monospace'
        }}>
          <div style={{ fontSize: '2rem', fontWeight: 'bold', color }}>{score}</div>
          <div style={{ fontSize: '0.8rem', textTransform: 'uppercase' }}>{risk}</div>
          {confidence && (
            <div style={{ fontSize: '0.6rem', opacity: 0.7 }}>Conf: {confidence}%</div>
          )}
        </div>
      </Html>
    </group>
  );
});

export default ScanGauge3D;
