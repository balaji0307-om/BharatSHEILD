import React, { useRef, useMemo } from 'react';
import { useFrame } from '@react-three/fiber';
import { Html } from '@react-three/drei';
import * as THREE from 'three';

/**
 * QR visualization for scan results.
 */
const QRHologram = React.memo(({ reducedMotion, qrData }) => {
  const groupRef = useRef();
  const scanLineRef = useRef();
  
  const isTampered = qrData?.tamper_detected;
  const baseColor = isTampered ? '#ff3355' : '#00d4ff';
  
  // 10x10 Grid for QR mock
  const gridCount = 10;
  const gridSize = 3;
  const cellOffset = gridSize / gridCount;
  
  const boxes = useMemo(() => {
    const arr = [];
    for (let i = 0; i < gridCount; i++) {
      for (let j = 0; j < gridCount; j++) {
        // Randomly skip some blocks to look like a QR code
        if (Math.random() > 0.3) {
          arr.push({
            x: (i - gridCount / 2) * cellOffset + cellOffset / 2,
            y: (j - gridCount / 2) * cellOffset + cellOffset / 2
          });
        }
      }
    }
    return arr;
  }, []);

  useFrame((state, delta) => {
    if (document.hidden || reducedMotion) return;
    
    // Gentle floating
    if (groupRef.current) {
      groupRef.current.position.y = Math.sin(state.clock.elapsedTime) * 0.1;
      groupRef.current.rotation.y = Math.sin(state.clock.elapsedTime * 0.5) * 0.1;
    }
    
    // Sweep line
    if (scanLineRef.current) {
      const time = state.clock.elapsedTime;
      scanLineRef.current.position.y = Math.sin(time * 2) * (gridSize / 2);
    }
  });

  return (
    <group ref={groupRef}>
      <group>
        {boxes.map((pos, i) => (
          <mesh key={i} position={[pos.x, pos.y, 0]}>
            <boxGeometry args={[cellOffset * 0.8, cellOffset * 0.8, 0.05]} />
            <meshBasicMaterial 
              color={baseColor}
              transparent 
              opacity={0.7} 
            />
          </mesh>
        ))}
      </group>
      
      {/* Scan Sweep Line */}
      <mesh ref={scanLineRef} position={[0, 0, 0.1]}>
        <planeGeometry args={[gridSize + 0.5, 0.05]} />
        <meshBasicMaterial color={baseColor} transparent opacity={0.8} />
      </mesh>
      
      {isTampered && (
        <Html position={[0, -2, 0]} center>
          <div style={{ color: '#ff3355', fontWeight: 'bold', textShadow: '0 0 10px #ff3355' }}>
            TAMPER DETECTED
          </div>
        </Html>
      )}
    </group>
  );
});

export default QRHologram;
