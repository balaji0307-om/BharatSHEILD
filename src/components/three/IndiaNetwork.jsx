import React, { useRef, useMemo } from 'react';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';

/**
 * Abstract India topology network visualization.
 */
const IndiaNetwork = React.memo(({ reducedMotion }) => {
  const groupRef = useRef();
  const linesRef = useRef();
  const threatsRef = useRef();

  // Generate roughly India shaped points
  const nodes = useMemo(() => {
    const pts = [];
    const count = 40;
    for(let i=0; i<count; i++) {
      const x = (Math.random() - 0.5) * 6;
      const y = (Math.random() - 0.3) * 8 - (Math.abs(x) * 0.5); 
      // constrain to diamond shape resembling India
      if (y > -4 && y < 4 && Math.abs(x) < 3) {
         pts.push(new THREE.Vector3(x, y, (Math.random() - 0.5) * 1));
      } else {
         pts.push(new THREE.Vector3(x * 0.3, y * 0.5, (Math.random() - 0.5) * 1));
      }
    }
    return pts;
  }, []);

  const lineGeo = useMemo(() => {
    const points = [];
    for(let i=0; i<nodes.length; i++) {
      for(let j=i+1; j<nodes.length; j++) {
        if(nodes[i].distanceTo(nodes[j]) < 2.5) {
          points.push(nodes[i], nodes[j]);
        }
      }
    }
    const geo = new THREE.BufferGeometry().setFromPoints(points);
    return geo;
  }, [nodes]);

  const threats = useMemo(() => {
    return Array(4).fill().map(() => ({
      source: Math.floor(Math.random() * nodes.length),
      target: Math.floor(Math.random() * nodes.length),
      progress: Math.random(),
      speed: 0.2 + Math.random() * 0.3
    }));
  }, [nodes.length]);

  useFrame((state, delta) => {
    if (document.hidden || reducedMotion) return;
    const time = state.clock.elapsedTime;
    
    if (linesRef.current) {
      linesRef.current.material.opacity = 0.15 + Math.sin(time * 2) * 0.05;
    }

    if (threatsRef.current) {
      threats.forEach((threat, i) => {
        threat.progress += delta * threat.speed;
        if (threat.progress >= 1) {
          threat.progress = 0;
          threat.source = threat.target;
          threat.target = Math.floor(Math.random() * nodes.length);
        }
        
        const s = nodes[threat.source];
        const t = nodes[threat.target];
        const child = threatsRef.current.children[i];
        if (child && s && t) {
          child.position.lerpVectors(s, t, threat.progress);
        }
      });
    }
  });

  return (
    <group ref={groupRef} position={[-4, 0, -2]} rotation={[0, 0.3, 0]} scale={[0.8, 0.8, 0.8]}>
      <lineSegments ref={linesRef} geometry={lineGeo}>
        <lineBasicMaterial color="#00d4ff" transparent opacity={0.2} />
      </lineSegments>
      
      {nodes.map((node, i) => (
        <mesh key={i} position={node}>
          <sphereGeometry args={[0.04, 8, 8]} />
          <meshBasicMaterial color="#00d4ff" transparent opacity={0.6} />
        </mesh>
      ))}

      <group ref={threatsRef}>
        {threats.map((_, i) => (
          <mesh key={`threat-${i}`}>
            <sphereGeometry args={[0.06, 8, 8]} />
            <meshBasicMaterial color="#ff3355" />
          </mesh>
        ))}
      </group>
    </group>
  );
});

export default IndiaNetwork;
