import React, { useRef } from 'react';
import { useFrame } from '@react-three/fiber';
import { RoundedBox } from '@react-three/drei';
import * as THREE from 'three';

/**
 * Floating case card visualization.
 */
const SecurityCaseScene = React.memo(({ reducedMotion, cases = [] }) => {
  const groupRef = useRef();
  
  const displayCases = cases.slice(0, 3);
  
  const getStatusColor = (status) => {
    switch(status?.toLowerCase()) {
      case 'suspected': return '#f2b83b';
      case 'verified': return '#00ff88';
      case 'needs review': return '#00d4ff';
      default: return '#00d4ff';
    }
  };

  useFrame((state, delta) => {
    if (document.hidden || reducedMotion || !groupRef.current) return;
    
    const time = state.clock.elapsedTime;
    
    groupRef.current.children.forEach((child, i) => {
      child.position.y = Math.sin(time * 2 + i) * 0.1;
      child.rotation.y = Math.sin(time + i * 0.5) * 0.05;
    });
  });

  return (
    <group ref={groupRef}>
      {displayCases.map((c, i) => {
        const offset = (i - (displayCases.length - 1) / 2) * 2.5;
        const color = getStatusColor(c?.investigation?.status);
        
        return (
          <group key={c.case_id || i} position={[offset, 0, 0]}>
            <RoundedBox args={[2, 3, 0.1]} radius={0.1} smoothness={4}>
              <meshBasicMaterial color="#0a1628" transparent opacity={0.8} />
            </RoundedBox>
            
            {/* Edge glow */}
            <RoundedBox args={[2.05, 3.05, 0.05]} radius={0.15} smoothness={4}>
              <meshBasicMaterial color={color} wireframe transparent opacity={0.3} />
            </RoundedBox>
          </group>
        );
      })}
    </group>
  );
});

export default SecurityCaseScene;
